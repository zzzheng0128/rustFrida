//! 用户态堆栈回溯 + 地址→模块偏移解析。
//!
//! 解析策略(对齐 stackplz):
//! - `resolve_addr`: /proc/<pid>/maps 查 addr → "libxxx.so+0x偏移";
//!   代码段被匿名化(maps 丢名字)时回退到历史命名缓存 → "libxxx.so+0x偏移(hist)"
//! - `backtrace_fp`: 沿 x29(fp) 链回溯,帧地址校验必须落在可执行映射(过滤垃圾值)
//! - `stack_scan`: stackplz 主力方案——直接扫描 sp 栈区 qword,
//!   落在可执行映射里的值即候选返回地址,去重后逐个解析。
//!   不依赖帧指针,omit-frame-pointer 的库也能出栈
//! - `full_backtrace`: fp 链 + 栈扫描合并去重,全部解析成模块相对地址
//!
//! maps/历史命名缓存跨线程共享,每条报告持有不可变快照:
//! 报告构建在独立 worker 线程,LIB_FILTER 的 maps 刷新在 runtime 线程,
//! 锁仅保护快照获取/发布; /proc 读取、索引构建、地址查询均在锁外完成。

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

const MAPS_REFRESH_INTERVAL: Duration = Duration::from_secs(2);
const MAPS_RETRY_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Clone, Debug)]
pub struct Mapping {
    pub start: u64,
    pub end: u64,
    pub file_offset: u64,
    /// 可执行映射(r-x)
    pub exec: bool,
    pub path: String,
}

#[derive(Clone, Debug)]
struct ModuleInfo {
    base: u64,
    name: Arc<str>,
}

#[derive(Default)]
struct CurrentMaps {
    maps: Vec<Mapping>,
    modules: Vec<Option<ModuleInfo>>,
}

impl CurrentMaps {
    fn new(mut maps: Vec<Mapping>) -> Self {
        maps.retain(|m| m.start < m.end);
        maps.sort_unstable_by_key(|m| m.start);
        let mut modules: HashMap<&str, ModuleInfo> = HashMap::new();
        for m in &maps {
            if m.path.starts_with('/') {
                modules.entry(&m.path).or_insert_with(|| ModuleInfo {
                    base: m.start,
                    name: Arc::from(m.path.rsplit('/').next().unwrap_or(&m.path)),
                });
            }
        }
        let indexed = maps.iter().map(|m| modules.get(m.path.as_str()).cloned()).collect();
        Self { maps, modules: indexed }
    }

    fn lookup(&self, addr: u64) -> Option<(&Mapping, Option<&ModuleInfo>)> {
        let i = self.maps.partition_point(|m| m.start <= addr).checked_sub(1)?;
        let m = &self.maps[i];
        (addr < m.end).then(|| (m, self.modules[i].as_ref()))
    }
}

type HistEntry = (u64, u64, String);

struct HistSegment {
    start: u64,
    end: u64,
    entry_index: usize,
    module: ModuleInfo,
}

#[derive(Default)]
struct HistoryMaps {
    // 保留插入顺序:历史区间重叠时仍选择最早记录,与原实现一致。
    entries: Vec<HistEntry>,
    segments: Vec<HistSegment>,
}

impl HistoryMaps {
    fn new(entries: Vec<HistEntry>) -> Self {
        let mut modules: HashMap<&str, ModuleInfo> = HashMap::new();
        for (start, _, path) in &entries {
            let module = modules.entry(path).or_insert_with(|| ModuleInfo {
                base: *start,
                name: Arc::from(path.rsplit('/').next().unwrap_or(path)),
            });
            module.base = module.base.min(*start);
        }
        let mut boundaries: Vec<u64> = entries
            .iter()
            .filter(|(s, e, _)| s < e)
            .flat_map(|(s, e, _)| [*s, *e])
            .collect();
        boundaries.sort_unstable();
        boundaries.dedup();
        let mut starts: Vec<usize> = (0..entries.len()).filter(|&i| entries[i].0 < entries[i].1).collect();
        starts.sort_unstable_by_key(|&i| entries[i].0);
        let mut next_start = 0;
        let mut active = BinaryHeap::new();
        let mut segments: Vec<HistSegment> = Vec::new();
        for pair in boundaries.windows(2) {
            let (start, end) = (pair[0], pair[1]);
            while next_start < starts.len() && entries[starts[next_start]].0 <= start {
                let i = starts[next_start];
                active.push(Reverse((i, entries[i].1)));
                next_start += 1;
            }
            while active.peek().is_some_and(|Reverse((_, end))| *end <= start) {
                active.pop();
            }
            if let Some(&Reverse((i, _))) = active.peek() {
                if let Some(last) = segments.last_mut() {
                    if last.end == start && last.entry_index == i {
                        last.end = end;
                        continue;
                    }
                }
                segments.push(HistSegment {
                    start,
                    end,
                    entry_index: i,
                    module: modules[entries[i].2.as_str()].clone(),
                });
            }
        }
        Self { entries, segments }
    }

    fn lookup(&self, addr: u64) -> Option<&ModuleInfo> {
        let i = self.segments.partition_point(|s| s.start <= addr).checked_sub(1)?;
        let segment = &self.segments[i];
        (addr < segment.end).then_some(&segment.module)
    }

    fn merged(self: &Arc<Self>, additions: impl IntoIterator<Item = HistEntry>) -> Arc<Self> {
        let mut known: HashSet<&HistEntry> = self.entries.iter().collect();
        let additions: Vec<_> = additions.into_iter().collect();
        let mut unique = Vec::new();
        for item in &additions {
            if known.insert(item) {
                unique.push(item.clone());
            }
        }
        if unique.is_empty() {
            return Arc::clone(self);
        }
        let mut entries = self.entries.clone();
        entries.extend(unique);
        Arc::new(Self::new(entries))
    }
}

#[derive(Default)]
struct MapsData {
    current: Arc<CurrentMaps>,
    history: Arc<HistoryMaps>,
}

/// 一条报告使用同一份当前/历史映射;查询只访问不可变索引,不持锁或读取 /proc。
#[derive(Clone, Default)]
pub(crate) struct MapsSnapshot {
    data: Arc<MapsData>,
    refresh_requested: Arc<AtomicBool>,
}

#[derive(Default)]
struct CacheState {
    snapshot: MapsSnapshot,
    last_attempt: Option<Instant>,
    initialized: bool,
    refreshing: bool,
}

#[derive(Default)]
struct CacheEntry {
    state: Mutex<CacheState>,
    ready: Condvar,
}

/// 锁外读取/索引构建若 unwind,恢复刷新状态并唤醒首次读取等待者。
/// 报告 worker 会捕获 panic,因此不能把缓存永久留在 refreshing 状态。
struct RefreshReset<'a> {
    entry: &'a CacheEntry,
    active: bool,
}

impl Drop for RefreshReset<'_> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut state = self.entry.state.lock().unwrap_or_else(|poison| poison.into_inner());
        state.refreshing = false;
        // 本轮没有发布新快照,允许下一位读者立即重试。
        state.last_attempt = None;
        self.entry.ready.notify_all();
    }
}

#[derive(Default)]
struct MapsCache {
    entries: Mutex<HashMap<u32, Arc<CacheEntry>>>,
}

impl MapsCache {
    fn entry(&self, pid: u32) -> Arc<CacheEntry> {
        Arc::clone(self.entries.lock().unwrap().entry(pid).or_default())
    }

    fn cached_snapshot(&self, pid: u32) -> Option<MapsSnapshot> {
        let entry = {
            let entries = self.entries.lock().unwrap_or_else(|poison| poison.into_inner());
            entries.get(&pid).cloned()?
        };
        let state = entry.state.lock().unwrap_or_else(|poison| poison.into_inner());
        let snapshot = &state.snapshot;
        if snapshot.data.current.maps.is_empty() && snapshot.data.history.segments.is_empty() {
            return None;
        }
        // Use only a previously published snapshot, including while the first
        // or a later refresh is in progress. Never wait for that refresh.
        Some(snapshot.clone())
    }

    fn snapshot_with(&self, pid: u32, now: Instant, read: impl FnOnce() -> Vec<Mapping>) -> MapsSnapshot {
        let entry = self.entry(pid);
        let mut state = entry.state.lock().unwrap();
        // 首次读取合并为一次;已有快照时刷新中的其他报告立即使用旧快照。
        while state.refreshing && !state.initialized {
            state = entry.ready.wait(state).unwrap();
        }
        if state.refreshing {
            return state.snapshot.clone();
        }
        let retry =
            state.snapshot.data.current.maps.is_empty() || state.snapshot.refresh_requested.load(Ordering::Relaxed);
        let interval = if retry {
            MAPS_RETRY_INTERVAL
        } else {
            MAPS_REFRESH_INTERVAL
        };
        if state
            .last_attempt
            .is_some_and(|last| now.saturating_duration_since(last) < interval)
        {
            return state.snapshot.clone();
        }
        state.refreshing = true;
        state.last_attempt = Some(now);
        state.snapshot.refresh_requested.store(false, Ordering::Relaxed);
        drop(state);
        let mut reset = RefreshReset {
            entry: &entry,
            active: true,
        };

        // /proc I/O、解析、排序和历史索引构建均在锁外执行。
        let current = Arc::new(CurrentMaps::new(read()));
        loop {
            let previous = entry.state.lock().unwrap().snapshot.clone();
            let history = previous.data.history.merged(
                current
                    .maps
                    .iter()
                    .filter(|m| m.path.starts_with('/'))
                    .map(|m| (m.start, m.end, m.path.clone())),
            );
            let next = MapsSnapshot {
                data: Arc::new(MapsData {
                    current: Arc::clone(&current),
                    history,
                }),
                refresh_requested: Arc::clone(&previous.refresh_requested),
            };
            let mut state = entry.state.lock().unwrap();
            // 历史注入可能与读取并行,发布前核对版本,避免覆盖刚加入的历史。
            if !Arc::ptr_eq(&state.snapshot.data, &previous.data) {
                continue;
            }
            state.snapshot = next.clone();
            state.initialized = true;
            state.refreshing = false;
            reset.active = false;
            entry.ready.notify_all();
            return next;
        }
    }

    fn add_history(&self, pid: u32, entries: &[HistEntry]) {
        if entries.is_empty() {
            return;
        }
        let entry = self.entry(pid);
        loop {
            let previous = entry.state.lock().unwrap().snapshot.clone();
            let history = previous.data.history.merged(entries.iter().cloned());
            if Arc::ptr_eq(&history, &previous.data.history) {
                return;
            }
            let next = MapsSnapshot {
                data: Arc::new(MapsData {
                    current: Arc::clone(&previous.data.current),
                    history,
                }),
                refresh_requested: Arc::clone(&previous.refresh_requested),
            };
            let mut state = entry.state.lock().unwrap();
            if Arc::ptr_eq(&state.snapshot.data, &previous.data) {
                state.snapshot = next;
                return;
            }
        }
    }
}

static MAPS_CACHE: OnceLock<MapsCache> = OnceLock::new();

fn maps_cache() -> &'static MapsCache {
    MAPS_CACHE.get_or_init(MapsCache::default)
}

/// 每报告获取一次。常规刷新 2s;空缓存/匿名/miss 的重试按 PID 最快 100ms 一次。
/// miss 请求由下一次获取快照处理,避免单份报告在地址查询之间切换映射版本。
pub(crate) fn snapshot(pid: u32) -> MapsSnapshot {
    maps_cache().snapshot_with(pid, Instant::now(), || read_maps(pid))
}

/// Read an already published snapshot without creating an entry, refreshing,
/// reading /proc, or waiting for a refresh. A missing or empty cache is `None`.
/// History still follows the normal current-mapping validation rules.
pub(crate) fn cached_snapshot(pid: u32) -> Option<MapsSnapshot> {
    MAPS_CACHE.get()?.cached_snapshot(pid)
}

/// LIB_FILTER 扫到短暂出现的命名映射时调用;下一份快照立即可见更新。
pub fn add_hist_mappings(pid: u32, entries: &[(u64, u64, String)]) {
    maps_cache().add_history(pid, entries);
}

fn read_maps(pid: u32) -> Vec<Mapping> {
    std::fs::read_to_string(format!("/proc/{}/maps", pid))
        .map(|text| parse_maps(&text))
        .unwrap_or_default()
}

fn parse_maps(text: &str) -> Vec<Mapping> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let (Some(range), Some(perms), Some(offset)) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        let Some((lo, hi)) = range.split_once('-') else {
            continue;
        };
        let (Ok(start), Ok(end), Ok(file_offset)) = (
            u64::from_str_radix(lo, 16),
            u64::from_str_radix(hi, 16),
            u64::from_str_radix(offset, 16),
        ) else {
            continue;
        };
        if start >= end {
            continue;
        }
        let _dev = parts.next();
        let _inode = parts.next();
        out.push(Mapping {
            start,
            end,
            file_offset,
            exec: perms.starts_with("r-x"),
            path: parts.next().unwrap_or("").to_string(),
        });
    }
    out
}

/// 用户态代码地址的粗校验(过滤 0x1a 之类的栈垃圾)
fn plausible_code_addr(addr: u64) -> bool {
    (0x0000_0001_0000..0x0000_8000_0000_0000).contains(&addr)
}

impl MapsSnapshot {
    fn in_exec_range(&self, addr: u64) -> bool {
        self.data.current.lookup(addr).is_some_and(|(m, _)| m.exec)
    }

    fn named_module(&self, addr: u64) -> Option<(&ModuleInfo, bool)> {
        let (m, module) = self.data.current.lookup(addr)?;
        if let Some(module) = module {
            return Some((module, false));
        }
        // 历史回退仅适用于当前仍存在的匿名可执行映射。
        if m.exec {
            return self.data.history.lookup(addr).map(|module| (module, true));
        }
        None
    }

    pub(crate) fn resolve_addr(&self, addr: u64) -> Option<String> {
        let lookup = self.data.current.lookup(addr);
        if !matches!(lookup, Some((_, Some(_)))) {
            self.refresh_requested.store(true, Ordering::Relaxed);
        }
        if let Some((module, historical)) = self.named_module(addr) {
            return Some(format!(
                "{}+0x{:x}{}",
                module.name,
                addr - module.base,
                if historical { "(hist)" } else { "" }
            ));
        }
        lookup.map(|_| format!("0x{:x}(anon)", addr))
    }

    pub(crate) fn resolve_addr_named(&self, addr: u64) -> Option<String> {
        if !plausible_code_addr(addr) {
            return None;
        }
        self.named_module(addr).map(|(module, historical)| {
            format!(
                "{}+0x{:x}{}",
                module.name,
                addr - module.base,
                if historical { "(hist)" } else { "" }
            )
        })
    }

    /// 保持原语义:当前命名映射取模块最低 start,匿名映射取当前区间 start。
    pub(crate) fn resolve_base(&self, addr: u64) -> Option<u64> {
        let (m, module) = self.data.current.lookup(addr)?;
        Some(module.map_or(m.start, |module| module.base))
    }

    /// 沿 fp 链回溯。fp = x29, lr0 = 当前 lr(x30)。
    /// 帧地址校验:必须落在可执行映射(过滤栈垃圾),最多 max_frames 帧。
    fn backtrace_fp(&self, pid: u32, fp: u64, lr0: u64, max_frames: usize) -> Vec<String> {
        let mut frames = Vec::new();
        if lr0 != 0 && plausible_code_addr(lr0) {
            if let Some(s) = self.resolve_addr(lr0) {
                frames.push(s);
            }
        }
        let mut cur = fp;
        for _ in 0..max_frames {
            if cur == 0 || cur & 0xf != 0 {
                break;
            }
            // [fp] = prev_fp, [fp+8] = lr
            let Some(b) = crate::argspec::read_mem_pub(pid, cur, 16) else {
                break;
            };
            if b.len() < 16 {
                break;
            }
            let prev_fp = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
            let ret = u64::from_le_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]);
            // 链必须向高地址单调增长
            if prev_fp <= cur || prev_fp >= 0x0000_8000_0000_0000 {
                break;
            }
            // ret 必须像代码地址且落在可执行映射(否则视为垃圾,终止本链)
            if ret != 0 && plausible_code_addr(ret) {
                let ok = self.in_exec_range(ret);
                if !ok {
                    break;
                }
                frames.push(self.resolve_addr(ret).unwrap_or_else(|| format!("0x{:x}", ret)));
            }
            cur = prev_fp;
        }
        frames
    }

    /// stackplz 风格栈扫描:从 sp 开始扫 scan_bytes 字节,落在可执行映射的
    /// qword 即候选返回地址,按出现顺序去重,全部解析成模块相对地址。
    /// 不依赖帧指针,omit-frame-pointer 的库(如加固后的 metasec)也能出栈。
    fn stack_scan(&self, pid: u32, sp: u64, scan_bytes: usize, max_frames: usize) -> Vec<String> {
        let mut frames: Vec<String> = Vec::new();
        let mut seen: Vec<u64> = Vec::new();
        if sp == 0 || sp >= 0x0000_8000_0000_0000 {
            return frames;
        }
        let base = sp & !0xf;
        let Some(buf) = crate::argspec::read_mem_pub(pid, base, scan_bytes) else {
            return frames;
        };
        let skip = (sp - base) as usize;
        let mut i = skip;
        while i + 8 <= buf.len() && frames.len() < max_frames {
            let v = u64::from_le_bytes([
                buf[i],
                buf[i + 1],
                buf[i + 2],
                buf[i + 3],
                buf[i + 4],
                buf[i + 5],
                buf[i + 6],
                buf[i + 7],
            ]);
            i += 8;
            if !plausible_code_addr(v) || seen.contains(&v) {
                continue;
            }
            let ok = self.in_exec_range(v);
            if !ok {
                continue;
            }
            seen.push(v);
            frames.push(self.resolve_addr(v).unwrap_or_else(|| format!("0x{:x}", v)));
        }
        frames
    }

    /// 完整回溯:fp 链(顺序可靠) + 栈扫描(覆盖 omit-frame-pointer)合并去重。
    /// fp 链帧在前,扫描发现的额外帧追加在后,最多 max_frames 帧。
    pub(crate) fn full_backtrace(&self, pid: u32, fp: u64, lr: u64, sp: u64, max_frames: usize) -> Vec<String> {
        let mut frames = self.backtrace_fp(pid, fp, lr, max_frames);
        if frames.len() < max_frames {
            let scan = self.stack_scan(pid, sp, 2048, max_frames * 2);
            for f in scan {
                if frames.len() >= max_frames {
                    break;
                }
                if !frames.contains(&f) {
                    frames.push(f);
                }
            }
        }
        frames
    }
}

/// 兼容单地址调用;报告构建应复用 snapshot(pid),避免逐地址获取缓存锁。
pub fn resolve_addr(pid: u32, addr: u64) -> Option<String> {
    snapshot(pid).resolve_addr(addr)
}

pub fn resolve_addr_named(pid: u32, addr: u64) -> Option<String> {
    if !plausible_code_addr(addr) {
        return None;
    }
    snapshot(pid).resolve_addr_named(addr)
}

pub fn resolve_base(pid: u32, addr: u64) -> Option<u64> {
    snapshot(pid).resolve_base(addr)
}

pub fn backtrace_fp(pid: u32, fp: u64, lr0: u64, max_frames: usize) -> Vec<String> {
    snapshot(pid).backtrace_fp(pid, fp, lr0, max_frames)
}

pub fn stack_scan(pid: u32, sp: u64, scan_bytes: usize, max_frames: usize) -> Vec<String> {
    snapshot(pid).stack_scan(pid, sp, scan_bytes, max_frames)
}

pub fn full_backtrace(pid: u32, fp: u64, lr: u64, sp: u64, max_frames: usize) -> Vec<String> {
    snapshot(pid).full_backtrace(pid, fp, lr, sp, max_frames)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    fn mapping(start: u64, end: u64, exec: bool, path: &str) -> Mapping {
        Mapping {
            start,
            end,
            file_offset: 0,
            exec,
            path: path.into(),
        }
    }

    fn fixture(maps: Vec<Mapping>, history: Vec<HistEntry>) -> MapsSnapshot {
        MapsSnapshot {
            data: Arc::new(MapsData {
                current: Arc::new(CurrentMaps::new(maps)),
                history: Arc::new(HistoryMaps::new(history)),
            }),
            refresh_requested: Arc::default(),
        }
    }

    // 原实现的纯查找路径,用于核对索引输出,不读取真实进程。
    fn linear_resolve(maps: &[Mapping], history: &[HistEntry], addr: u64) -> Option<String> {
        let m = maps.iter().find(|m| addr >= m.start && addr < m.end)?;
        if m.path.starts_with('/') {
            let base = maps.iter().filter(|x| x.path == m.path).map(|x| x.start).min()?;
            return Some(format!("{}+0x{:x}", m.path.rsplit('/').next()?, addr - base));
        }
        if m.exec {
            if let Some((_, _, path)) = history.iter().find(|(s, e, _)| addr >= *s && addr < *e) {
                let base = history.iter().filter(|(_, _, p)| p == path).map(|(s, _, _)| *s).min()?;
                return Some(format!("{}+0x{:x}(hist)", path.rsplit('/').next()?, addr - base));
            }
        }
        Some(format!("0x{:x}(anon)", addr))
    }

    #[test]
    fn parse_and_lookup_mapping_boundaries_and_module_base() {
        let maps = parse_maps(
            "20000-21000 r-xp 00001000 00:01 2 /lib/a.so\n\
            10000-11000 r--p 00000000 00:01 2 /lib/a.so\n\
            30000-31000 rw-p 00000000 00:00 0\n\
            40000-41000 r-xp 00000000 00:00 0 [anon:code]\n\
            invalid line\n50000-40000 r-xp 0 00:00 0 /bad.so\n",
        );
        assert_eq!(maps.len(), 4);
        assert_eq!(maps[0].file_offset, 0x1000);
        let s = fixture(maps, Vec::new());
        assert_eq!(s.resolve_addr(0x20010).as_deref(), Some("a.so+0x10010"));
        assert_eq!(s.resolve_addr_named(0x10008).as_deref(), Some("a.so+0x8"));
        assert_eq!(s.resolve_base(0x20010), Some(0x10000));
        assert_eq!(s.resolve_base(0x30010), Some(0x30000));
        assert_eq!(s.resolve_addr(0x30010).as_deref(), Some("0x30010(anon)"));
        assert_eq!(s.resolve_addr_named(0x30010), None);
        for addr in [0xffff, 0x11000, 0x1ffff, 0x21000, u64::MAX] {
            assert_eq!(s.resolve_addr(addr), None);
            assert_eq!(s.resolve_base(addr), None);
        }
        assert!(s.in_exec_range(0x20000));
        assert!(!s.in_exec_range(0x10000));
    }

    #[test]
    fn history_index_preserves_overlap_precedence_and_current_mapping_rules() {
        let maps = vec![
            mapping(0x10000, 0x20000, true, ""),
            mapping(0x20000, 0x30000, false, ""),
            mapping(0x30000, 0x40000, true, "/new.so"),
            mapping(0x40000, 0x50000, true, "[anon:code]"),
        ];
        let history = vec![
            (0x15000, 0x18000, "/first.so".into()),
            (0x11000, 0x20000, "/later.so".into()),
            (0x10000, 0x12000, "/first.so".into()),
            (0x25000, 0x35000, "/old.so".into()),
            (0x45000, 0x60000, "/old.so".into()),
            (0x70000, 0x70000, "/empty.so".into()),
        ];
        let s = fixture(maps.clone(), history.clone());
        for addr in (0xfff0..0x60010).step_by(7) {
            assert_eq!(s.resolve_addr(addr), linear_resolve(&maps, &history, addr), "{addr:x}");
        }
        assert_eq!(s.resolve_addr_named(0x16000).as_deref(), Some("first.so+0x6000(hist)"));
        assert_eq!(s.resolve_addr_named(0x26000), None);
        assert_eq!(s.resolve_addr_named(0x31000).as_deref(), Some("new.so+0x1000"));
        assert_eq!(s.resolve_addr_named(0x46000).as_deref(), Some("old.so+0x21000(hist)"));
        // 匿名基址保留旧行为,不因历史标签改变。
        assert_eq!(s.resolve_base(0x16000), Some(0x10000));
        assert_eq!(s.resolve_addr(0x55000), None);
    }

    #[test]
    fn empty_and_missed_maps_reads_are_throttled() {
        let cache = MapsCache::default();
        let now = Instant::now();
        let empty = cache.snapshot_with(1, now, Vec::new);
        assert_eq!(empty.resolve_addr(0x10000), None);
        cache.snapshot_with(1, now + Duration::from_millis(99), || panic!("empty retry too soon"));
        let first = cache.snapshot_with(1, now + MAPS_RETRY_INTERVAL, || {
            vec![mapping(0x10000, 0x11000, true, "/a.so")]
        });
        assert_eq!(first.resolve_addr(0x10001).as_deref(), Some("a.so+0x1"));
        cache.snapshot_with(1, now + Duration::from_millis(1999), || panic!("not stale"));
        // 下一报告响应 miss,同一报告保留一致快照。
        assert_eq!(first.resolve_addr(0x20001), None);
        let second = cache.snapshot_with(1, now + Duration::from_secs(2), || {
            vec![mapping(0x20000, 0x21000, true, "/b.so")]
        });
        assert_eq!(second.resolve_addr(0x20001).as_deref(), Some("b.so+0x1"));
        assert_eq!(first.resolve_addr(0x20001), None);
        cache.snapshot_with(1, now + Duration::from_millis(2050), || panic!("miss retry too soon"));
    }

    #[test]
    fn named_maps_refresh_at_the_regular_interval_without_a_miss() {
        let cache = MapsCache::default();
        let now = Instant::now();
        let first = cache.snapshot_with(1, now, || vec![mapping(0x10000, 0x11000, true, "/a.so")]);
        cache.snapshot_with(1, now + Duration::from_millis(1999), || panic!("not stale"));
        let next = cache.snapshot_with(1, now + MAPS_REFRESH_INTERVAL, || {
            vec![mapping(0x10000, 0x11000, true, "/b.so")]
        });
        assert_eq!(first.resolve_addr(0x10001).as_deref(), Some("a.so+0x1"));
        assert_eq!(next.resolve_addr(0x10001).as_deref(), Some("b.so+0x1"));
    }

    #[test]
    fn cached_lookup_does_not_create_entries_or_expose_empty_snapshots() {
        let cache = MapsCache::default();
        for pid in 1..100 {
            assert!(cache.cached_snapshot(pid).is_none());
        }
        assert!(cache.entries.lock().unwrap().is_empty());
        cache.snapshot_with(1, Instant::now(), Vec::new);
        assert!(cache.cached_snapshot(1).is_none());
        cache.add_history(2, &[(0x10000, 0x10000, "/empty.so".into())]);
        assert!(cache.cached_snapshot(2).is_none());
        assert_eq!(cache.entries.lock().unwrap().len(), 2);
    }

    #[test]
    fn cached_lookup_neither_reads_nor_changes_refresh_state() {
        let cache = MapsCache::default();
        let now = Instant::now();
        let reads = std::cell::Cell::new(0);
        let original = cache.snapshot_with(1, now, || {
            reads.set(reads.get() + 1);
            vec![mapping(0x10000, 0x11000, true, "/a.so")]
        });
        let old_attempt = now - MAPS_REFRESH_INTERVAL;
        {
            let entry = cache.entry(1);
            let mut state = entry.state.lock().unwrap();
            state.last_attempt = Some(old_attempt);
            state.snapshot.refresh_requested.store(true, Ordering::Relaxed);
        }
        for _ in 0..100 {
            let cached = cache.cached_snapshot(1).unwrap();
            assert!(Arc::ptr_eq(&cached.data, &original.data));
            assert_eq!(cached.resolve_addr_named(0x10001).as_deref(), Some("a.so+0x1"));
        }
        let entry = cache.entry(1);
        let state = entry.state.lock().unwrap();
        assert_eq!(reads.get(), 1);
        assert_eq!(state.last_attempt, Some(old_attempt));
        assert!(state.snapshot.refresh_requested.load(Ordering::Relaxed));
        assert!(!state.refreshing);
    }

    #[test]
    fn cached_lookup_observes_new_publications_without_mutating_old_snapshots() {
        let cache = MapsCache::default();
        let now = Instant::now();
        cache.snapshot_with(1, now, || vec![mapping(0x10000, 0x12000, true, "")]);
        let old = cache.cached_snapshot(1).unwrap();
        cache.add_history(1, &[(0x10000, 0x12000, "/saved.so".into())]);
        let historical = cache.cached_snapshot(1).unwrap();
        assert_eq!(old.resolve_addr_named(0x10001), None);
        assert_eq!(
            historical.resolve_addr_named(0x10001).as_deref(),
            Some("saved.so+0x1(hist)")
        );
        cache.snapshot_with(1, now + MAPS_REFRESH_INTERVAL, || {
            vec![mapping(0x10000, 0x12000, true, "/new.so")]
        });
        let newest = cache.cached_snapshot(1).unwrap();
        assert_eq!(newest.resolve_addr_named(0x10001).as_deref(), Some("new.so+0x1"));
        assert_eq!(
            historical.resolve_addr_named(0x10001).as_deref(),
            Some("saved.so+0x1(hist)")
        );
        assert_eq!(old.resolve_addr_named(0x10001), None);
    }

    #[test]
    fn cached_history_only_snapshot_preserves_current_mapping_validation() {
        let cache = MapsCache::default();
        cache.add_history(1, &[(0x10000, 0x12000, "/saved.so".into())]);
        let historical = cache.cached_snapshot(1).unwrap();
        assert_eq!(historical.data.history.entries.len(), 1);
        // A past mapping alone is not proof that this address is currently
        // executable. Cached lookup must not synthesize a current mapping.
        assert_eq!(historical.resolve_addr_named(0x10001), None);
        let entry = cache.entry(1);
        let state = entry.state.lock().unwrap();
        assert!(!state.initialized);
        assert_eq!(state.last_attempt, None);
    }

    #[test]
    fn cached_lookup_does_not_wait_for_an_initial_refresh() {
        let cache = Arc::new(MapsCache::default());
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let refresh_cache = cache.clone();
        let refresher = std::thread::spawn(move || {
            refresh_cache.snapshot_with(1, Instant::now(), || {
                started_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                vec![mapping(0x10000, 0x11000, true, "/ready.so")]
            })
        });
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let (result_tx, result_rx) = mpsc::channel();
        let reader_cache = cache.clone();
        let reader = std::thread::spawn(move || {
            result_tx.send(reader_cache.cached_snapshot(1).is_none()).unwrap();
        });
        let result = result_rx.recv_timeout(Duration::from_secs(2));
        release_tx.send(()).unwrap();
        reader.join().unwrap();
        refresher.join().unwrap();
        assert_eq!(result.unwrap(), true, "cached read waited for the first maps read");
        assert_eq!(cache.entries.lock().unwrap().len(), 1);
        assert_eq!(
            cache.cached_snapshot(1).unwrap().resolve_addr_named(0x10001).as_deref(),
            Some("ready.so+0x1")
        );
    }

    #[test]
    fn refresh_panic_allows_immediate_retry_and_preserves_existing_snapshot() {
        let cache = MapsCache::default();
        let now = Instant::now();
        let failure = std::panic::catch_unwind(|| cache.snapshot_with(1, now, || panic!("synthetic first read panic")));
        assert!(failure.is_err());
        let first = cache.snapshot_with(1, now, || vec![mapping(0x10000, 0x11000, true, "/a.so")]);
        assert_eq!(first.resolve_addr(0x10001).as_deref(), Some("a.so+0x1"));
        let failure = std::panic::catch_unwind(|| {
            cache.snapshot_with(1, now + MAPS_REFRESH_INTERVAL, || {
                panic!("synthetic subsequent read panic")
            })
        });
        assert!(failure.is_err());
        let entry = cache.entry(1);
        {
            let state = entry.state.lock().unwrap();
            assert!(!state.refreshing);
            assert!(Arc::ptr_eq(&state.snapshot.data, &first.data));
        }
        let retry = cache.snapshot_with(1, now + MAPS_REFRESH_INTERVAL, || {
            vec![mapping(0x10000, 0x11000, true, "/b.so")]
        });
        assert_eq!(retry.resolve_addr(0x10001).as_deref(), Some("b.so+0x1"));
    }

    #[test]
    fn refresh_panic_wakes_initial_read_waiters() {
        let cache = Arc::new(MapsCache::default());
        let now = Instant::now();
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let worker_cache = Arc::clone(&cache);
        let worker = std::thread::spawn(move || {
            let failure = std::panic::catch_unwind(|| {
                worker_cache.snapshot_with(1, now, || {
                    started_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                    panic!("synthetic first read panic with waiter");
                })
            });
            assert!(failure.is_err());
        });
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let (waiting_tx, waiting_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel();
        let waiter_cache = Arc::clone(&cache);
        let waiter = std::thread::spawn(move || {
            let entry = waiter_cache.entry(1);
            let mut state = entry.state.lock().unwrap();
            assert!(state.refreshing && !state.initialized);
            // 持锁时通知主线程,确保 panic 清理只能在 wait 释放锁后唤醒我们。
            waiting_tx.send(()).unwrap();
            while state.refreshing && !state.initialized {
                let (next, timeout) = entry.ready.wait_timeout(state, Duration::from_secs(2)).unwrap();
                state = next;
                assert!(!timeout.timed_out(), "panic cleanup did not notify first-read waiter");
            }
            drop(state);
            let retry = waiter_cache.snapshot_with(1, now, || vec![mapping(0x10000, 0x11000, true, "/retry.so")]);
            result_tx.send(retry.resolve_addr(0x10001)).unwrap();
        });
        waiting_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        release_tx.send(()).unwrap();
        worker.join().unwrap();
        assert_eq!(
            result_rx.recv_timeout(Duration::from_secs(5)).unwrap().as_deref(),
            Some("retry.so+0x1")
        );
        waiter.join().unwrap();
    }

    #[test]
    fn history_publication_is_visible_next_report_without_changing_existing_snapshot() {
        let cache = MapsCache::default();
        let now = Instant::now();
        let first = cache.snapshot_with(1, now, || vec![mapping(0x10000, 0x12000, true, "")]);
        let entries = vec![(0x10000, 0x12000, "/saved.so".into())];
        cache.add_history(1, &entries);
        cache.add_history(1, &entries);
        let next = cache.snapshot_with(1, now, || panic!("history injection should not read maps"));
        assert_eq!(first.resolve_addr(0x10001).as_deref(), Some("0x10001(anon)"));
        assert_eq!(next.resolve_addr(0x10001).as_deref(), Some("saved.so+0x1(hist)"));
        assert_eq!(next.data.history.entries.len(), 1);
    }

    #[test]
    fn refresh_io_does_not_block_cached_readers_or_lose_history() {
        let cache = Arc::new(MapsCache::default());
        let now = Instant::now();
        let old = cache.snapshot_with(1, now, || vec![mapping(0x10000, 0x11000, true, "/a.so")]);
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let worker_cache = Arc::clone(&cache);
        let worker = std::thread::spawn(move || {
            worker_cache.snapshot_with(1, now + MAPS_REFRESH_INTERVAL, || {
                started_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                vec![mapping(0x10000, 0x12000, true, "")]
            })
        });
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let (read_tx, read_rx) = mpsc::channel();
        let reader_cache = Arc::clone(&cache);
        let reader = std::thread::spawn(move || {
            let current = reader_cache.snapshot_with(1, now + MAPS_REFRESH_INTERVAL, || panic!("duplicate refresh"));
            reader_cache.add_history(1, &[(0x11000, 0x12000, "/during.so".into())]);
            read_tx.send(current).unwrap();
        });
        let cached = read_rx.recv_timeout(Duration::from_secs(2));
        release_tx.send(()).unwrap();
        let cached = cached.expect("reader or history writer held behind maps I/O");
        assert!(Arc::ptr_eq(&old.data, &cached.data));
        reader.join().unwrap();
        let refreshed = worker.join().unwrap();
        assert_eq!(refreshed.resolve_addr(0x10001).as_deref(), Some("a.so+0x1(hist)"));
        assert_eq!(refreshed.resolve_addr(0x11001).as_deref(), Some("during.so+0x1(hist)"));
    }

    #[test]
    fn concurrent_history_writers_preserve_all_entries() {
        let cache = Arc::new(MapsCache::default());
        let mut threads = Vec::new();
        for n in 0..8_u64 {
            let cache = Arc::clone(&cache);
            threads.push(std::thread::spawn(move || {
                for i in 0..8_u64 {
                    let start = 0x10000 + (n * 8 + i) * 0x1000;
                    cache.add_history(1, &[(start, start + 0x1000, format!("/lib/{n}-{i}.so"))]);
                }
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }
        let s = cache.snapshot_with(1, Instant::now(), Vec::new);
        assert_eq!(s.data.history.entries.len(), 64);
    }

    #[test]
    fn backtrace_uses_the_snapshots_lr_resolution() {
        let s = fixture(vec![mapping(0x10000, 0x11000, true, "/a.so")], Vec::new());
        // fp/sp 为 0,不读取任何进程内存。
        assert_eq!(s.full_backtrace(1, 0, 0x10004, 0, 8), vec!["a.so+0x4"]);
    }

    #[test]
    #[ignore = "synthetic benchmark; run with --ignored --nocapture and rustc -O"]
    fn benchmark_repeated_linear_queries_vs_report_snapshot() {
        let maps: Vec<_> = (0..2048_u64)
            .map(|i| {
                mapping(
                    0x10000 + i * 0x2000,
                    0x11000 + i * 0x2000,
                    true,
                    &format!("/lib/lib{}.so", i / 4),
                )
            })
            .collect();
        let addresses: Vec<_> = (0..35_u64).map(|i| 0x10008 + ((i * 59) % 2048) * 0x2000).collect();
        let old_cache = Mutex::new(maps.clone());
        let cache = MapsCache::default();
        let now = Instant::now();
        let s = cache.snapshot_with(1, now, || maps.clone());
        for &addr in &addresses {
            assert_eq!(s.resolve_addr_named(addr), linear_resolve(&maps, &[], addr));
        }
        let reports = 4000;
        let start = Instant::now();
        for _ in 0..reports {
            for &addr in &addresses {
                std::hint::black_box(linear_resolve(
                    &old_cache.lock().unwrap(),
                    &[],
                    std::hint::black_box(addr),
                ));
            }
        }
        let linear = start.elapsed();
        let start = Instant::now();
        for _ in 0..reports {
            let s = cache.snapshot_with(1, now, || panic!("benchmark must not refresh"));
            for &addr in &addresses {
                std::hint::black_box(s.resolve_addr_named(std::hint::black_box(addr)));
            }
        }
        let indexed = start.elapsed();
        eprintln!(
            "synthetic: {reports} reports × {} addresses, {} maps; linear {:?}, snapshot {:?}, {:.2}x",
            addresses.len(),
            maps.len(),
            linear,
            indexed,
            linear.as_secs_f64() / indexed.as_secs_f64()
        );
    }
}
