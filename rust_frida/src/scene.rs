//! app 死亡监控 + 现场保护（scene guard）。
//!
//! - 事件循环每条事件调用 `record_event`：维护最近 N 条事件的环形缓冲、
//!   已知 pid 集合；第一个见到事件的 pid 视为主进程。
//! - watcher 线程每 250ms 轮询 /proc/<pid>：
//!   - 主进程额外缓存"生前快照"（status/stat/wchan/syscall/kernel stack）
//!   - 进程消失 → 落盘现场文件 /data/local/tmp/kt_scene_<pkg>_<pid>_<ts>.jsonl
//!     （先写 .tmp 再 rename，保证原子性，事后可 adb pull 复盘）
//!   - 现场内容：元信息 + 死因线索（僵尸态 exit_code 若抓到）+ 该 pid 死前
//!     最后 N 条 svc/断点事件（含 regs/args/locations/stack）；主进程死亡时
//!     附带全部 pid 的完整事件上下文。

#![cfg(all(target_os = "android", target_arch = "aarch64", feature = "kernel-trace"))]

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

const RING_CAPACITY: usize = 2000;
const SCENE_EVENT_LIMIT: usize = 300;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExitStatus {
    raw_wait_status: u16,
    term_signal: Option<u8>,
    exit_status: Option<u8>,
}

impl ExitStatus {
    /// /proc/<pid>/stat field 52 uses wait(2) encoding, not a plain exit value.
    /// Only accept terminal statuses; stopped/continued/malformed values are omitted.
    fn decode(raw: u16) -> Option<Self> {
        let signal = (raw & 0x7f) as u8;
        if raw & 0xff == 0 {
            Some(Self {
                raw_wait_status: raw,
                term_signal: None,
                exit_status: Some((raw >> 8) as u8),
            })
        } else if raw & 0xff00 == 0 && (1..=64).contains(&signal) {
            Some(Self {
                raw_wait_status: raw,
                term_signal: Some(signal),
                exit_status: None,
            })
        } else {
            None
        }
    }

    fn append_json_fields(self, out: &mut String) {
        out.push_str(&format!(",\"raw_wait_status\":{}", self.raw_wait_status));
        if let Some(signal) = self.term_signal {
            out.push_str(&format!(",\"term_signal\":{}", signal));
        }
        if let Some(status) = self.exit_status {
            out.push_str(&format!(",\"exit_status\":{}", status));
        }
    }
}

struct ProcStat {
    state: char,
    exit: Option<ExitStatus>,
}

fn parse_proc_stat(pid: u32, stat: &str) -> Option<ProcStat> {
    let (pid_text, remainder) = stat.split_once('(')?;
    if pid_text.trim().parse::<u32>().ok()? != pid {
        return None;
    }
    // comm may contain whitespace and ')'; fields start after its final ')'.
    let (_, fields) = remainder.rsplit_once(')')?;
    let mut fields = fields.split_whitespace();
    let state = match fields.next()? {
        "R" => 'R',
        "S" => 'S',
        "D" => 'D',
        "Z" => 'Z',
        "T" => 'T',
        "t" => 't',
        "X" => 'X',
        "x" => 'x',
        "K" => 'K',
        "W" => 'W',
        "P" => 'P',
        "I" => 'I',
        _ => return None,
    };
    // We consumed field 3; skip fields 4..51 to reach exit_code (field 52).
    let exit = if state == 'Z' {
        fields
            .nth(48)
            .and_then(|value| value.parse().ok())
            .and_then(ExitStatus::decode)
    } else {
        None
    };
    Some(ProcStat { state, exit })
}

fn live_state(state: char) -> bool {
    !matches!(state, 'Z' | 'X' | 'x')
}

fn status_is_live(status: &str) -> bool {
    status
        .lines()
        .find_map(|line| line.strip_prefix("State:"))
        .and_then(|state| state.split_whitespace().next())
        .is_some_and(|state| matches!(state, "R" | "S" | "D" | "T" | "t" | "K" | "W" | "P" | "I"))
}

struct FinalState {
    stat: String,
    exit: Option<ExitStatus>,
}

#[derive(Default)]
struct ProcessSnapshot {
    live: Option<String>,
    final_state: Option<FinalState>,
}

pub(crate) struct SceneGuard {
    ring: Mutex<VecDeque<String>>,
    pids: Mutex<HashMap<u32, String>>,
    snapshots: Mutex<HashMap<u32, ProcessSnapshot>>,
    main_pid: Mutex<Option<u32>>,
    dumped: Mutex<HashSet<u32>>,
    pkg: String,
}

impl SceneGuard {
    pub(crate) fn new(pkg: &str) -> Arc<Self> {
        Arc::new(Self {
            ring: Mutex::new(VecDeque::with_capacity(RING_CAPACITY)),
            pids: Mutex::new(HashMap::new()),
            snapshots: Mutex::new(HashMap::new()),
            main_pid: Mutex::new(None),
            dumped: Mutex::new(HashSet::new()),
            pkg: pkg.to_string(),
        })
    }

    /// 在输出前记录事件;复制到环形缓存内复用的字符串,调用方保留格式化缓冲。
    /// 此处只更新内存,不执行 I/O。
    pub(crate) fn record_event(&self, pid: u32, comm: &str, line: &str) {
        {
            let mut pids = self.pids.lock().unwrap();
            pids.entry(pid).or_insert_with(|| comm.to_string());
        }
        {
            let mut main = self.main_pid.lock().unwrap();
            if main.is_none() {
                *main = Some(pid);
            }
        }
        let mut ring = self.ring.lock().unwrap();
        let mut reusable = if ring.len() >= RING_CAPACITY {
            ring.pop_front().unwrap_or_default()
        } else {
            String::new()
        };
        reusable.clear();
        reusable.push_str(line);
        ring.push_back(reusable);
    }

    pub(crate) fn set_main_pid(&self, pid: u32) {
        *self.main_pid.lock().unwrap() = Some(pid);
    }

    fn is_main(&self, pid: u32) -> bool {
        self.main_pid.lock().unwrap().map(|m| m == pid).unwrap_or(false)
    }

    /// 返回是否观察到 zombie;终态另存,绝不覆盖最近一次有效生前快照。
    fn take_snapshot(&self, pid: u32) -> bool {
        self.take_snapshot_with(pid, |name| {
            std::fs::read_to_string(format!("/proc/{}/{}", pid, name)).ok()
        })
    }

    fn take_snapshot_with(&self, pid: u32, mut read: impl FnMut(&str) -> Option<String>) -> bool {
        let Some(stat) = read("stat") else { return false };
        let Some(parsed) = parse_proc_stat(pid, &stat) else {
            return false;
        };
        if parsed.state == 'Z' {
            self.record_final_state(pid, stat, parsed.exit);
            return true;
        }
        if !live_state(parsed.state) {
            return false;
        }

        let mut snapshot = String::new();
        let mut valid_status = false;
        for name in ["status", "wchan", "syscall", "stack", "cmdline"] {
            if let Some(content) = read(name) {
                if name == "status" {
                    valid_status = status_is_live(&content);
                }
                snapshot.push_str(&format!("=== /proc/{}/{} ===\n{}\n", pid, name, content));
            }
        }
        // The process can exit while the separate proc files are being read.
        // Recheck stat before replacing the live snapshot, and preserve an older
        // snapshot if the final stat/status is missing, malformed or already dead.
        let Some(stat) = read("stat") else { return false };
        let Some(parsed) = parse_proc_stat(pid, &stat) else {
            return false;
        };
        if parsed.state == 'Z' {
            self.record_final_state(pid, stat, parsed.exit);
            return true;
        }
        if valid_status && live_state(parsed.state) {
            snapshot.push_str(&format!("=== /proc/{}/stat ===\n{}\n", pid, stat));
            self.snapshots.lock().unwrap().entry(pid).or_default().live = Some(snapshot);
        }
        false
    }

    fn record_final_state(&self, pid: u32, stat: String, exit: Option<ExitStatus>) {
        self.snapshots.lock().unwrap().entry(pid).or_default().final_state = Some(FinalState { stat, exit });
    }

    /// 落盘一个进程的现场
    fn dump_scene(&self, pid: u32, reason: &str) {
        {
            let mut dumped = self.dumped.lock().unwrap();
            if !dumped.insert(pid) {
                return; // 已落过
            }
        }
        let comm = self
            .pids
            .lock()
            .unwrap()
            .get(&pid)
            .cloned()
            .unwrap_or_else(|| "?".to_string());
        let is_main = self.is_main(pid);
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let path = format!(
            "/data/local/tmp/kt_scene_{}_{}_{}.jsonl",
            self.pkg.replace('.', "_"),
            pid,
            ts
        );

        let mut out = String::new();
        {
            let snapshots = self.snapshots.lock().unwrap();
            let snapshot = snapshots.get(&pid);
            let final_state = snapshot.and_then(|snapshot| snapshot.final_state.as_ref());
            out.push_str(&format!(
                "{{\"type\":\"scene.meta\",\"pkg\":{},\"pid\":{},\"comm\":{},\"is_main\":{},\"reason\":{},\"ts\":{}",
                serde_json_str(&self.pkg),
                pid,
                serde_json_str(&comm),
                is_main,
                serde_json_str(reason),
                ts
            ));
            if let Some(exit) = final_state.and_then(|state| state.exit) {
                exit.append_json_fields(&mut out);
            }
            out.push_str("}\n");
            // 保留既有 scene.snapshot/data 格式,内容始终来自最近一次非终态采样。
            if let Some(live) = snapshot.and_then(|snapshot| snapshot.live.as_ref()) {
                out.push_str(&format!(
                    "{{\"type\":\"scene.snapshot\",\"pid\":{},\"data\":{}}}\n",
                    pid,
                    serde_json_str(live)
                ));
            }
            // 单独保留终态 stat,没有合法 exit_code 时也不猜测退出原因。
            if let Some(final_state) = final_state {
                out.push_str(&format!(
                    "{{\"type\":\"scene.exit\",\"pid\":{},\"state\":\"Z\",\"stat\":{}",
                    pid,
                    serde_json_str(&final_state.stat)
                ));
                if let Some(exit) = final_state.exit {
                    exit.append_json_fields(&mut out);
                }
                out.push_str("}\n");
            }
        }
        // 事件上下文：主进程死亡 → 全量；否则只留该 pid 的
        let ring = self.ring.lock().unwrap();
        let mut kept = 0usize;
        for line in ring.iter().rev() {
            if kept >= SCENE_EVENT_LIMIT {
                break;
            }
            if is_main || line.contains(&format!("\"pid\":{}", pid)) {
                out.push_str(line);
                out.push('\n');
                kept += 1;
            }
        }
        drop(ring);
        out.push_str(&format!(
            "{{\"type\":\"scene.end\",\"pid\":{},\"events_kept\":{}}}\n",
            pid, kept
        ));

        // 原子写:先 .tmp 再 rename
        let tmp = format!("{}.tmp", path);
        if let Err(error) = std::fs::write(&tmp, out) {
            let message = format!(
                "[scene] 进程 {} ({}) 死亡({}),写入现场临时文件 {} 失败: {}",
                pid, comm, reason, tmp, error
            );
            crate::logger::stderr_line(&message, &message);
            return;
        }
        if let Err(error) = std::fs::rename(&tmp, &path) {
            let message = format!(
                "[scene] 进程 {} ({}) 死亡({}),现场临时文件 {} 重命名为 {} 失败: {}",
                pid, comm, reason, tmp, path, error
            );
            crate::logger::stderr_line(&message, &message);
            return;
        }
        let message = if is_main {
            format!(
                "[scene] 💀 主进程 {} ({}) 死亡({}),现场已保存: {}",
                pid, comm, reason, path
            )
        } else {
            format!("[scene] 进程 {} ({}) 死亡({}),现场已保存: {}", pid, comm, reason, path)
        };
        crate::logger::stderr_line(&message, &message);
    }

    /// 启动 watcher 线程。stop 置位后退出。
    pub(crate) fn start_watcher(self: &Arc<Self>, stop: Arc<AtomicBool>) {
        let me = self.clone();
        std::thread::Builder::new()
            .name("scene-watch".into())
            .spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    let pids: Vec<u32> = me.pids.lock().unwrap().keys().copied().collect();
                    for pid in pids {
                        let proc_dir = format!("/proc/{}", pid);
                        if std::path::Path::new(&proc_dir).exists() {
                            // 主进程持续刷新生前快照;顺带抓僵尸态
                            if me.is_main(pid) && me.take_snapshot(pid) {
                                me.dump_scene(pid, "zombie (crashed/exited, awaiting reap)");
                            }
                        } else {
                            me.dump_scene(pid, "process gone");
                        }
                    }
                    std::thread::sleep(std::time::Duration::from_millis(250));
                }
            })
            .ok();
    }
}

/// 极简 JSON 字符串转义（scene 快照用）
fn serde_json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_stat(pid: u32, state: &str, exit_code: &str) -> String {
        let mut fields = vec!["0"; 50];
        fields[0] = state;
        fields[49] = exit_code;
        format!("{pid} (synthetic name ) with spaces) {}\n", fields.join(" "))
    }

    fn record_live_sample(guard: &SceneGuard, status: &str) {
        assert!(!guard.take_snapshot_with(2147, |name| match name {
            "stat" => Some(synthetic_stat(2147, "S", "0")),
            "status" => Some(status.to_string()),
            _ => None,
        }));
    }

    #[test]
    fn wait_status_distinguishes_exit_nine_from_sigkill() {
        let normal = parse_proc_stat(2147, &synthetic_stat(2147, "Z", "2304"))
            .unwrap()
            .exit
            .unwrap();
        assert_eq!(normal.raw_wait_status, 2304);
        assert_eq!(normal.exit_status, Some(9));
        assert_eq!(normal.term_signal, None);
        let killed = parse_proc_stat(2147, &synthetic_stat(2147, "Z", "9"))
            .unwrap()
            .exit
            .unwrap();
        assert_eq!(killed.raw_wait_status, 9);
        assert_eq!(killed.term_signal, Some(9));
        assert_eq!(killed.exit_status, None);
        let mut fields = String::new();
        normal.append_json_fields(&mut fields);
        assert_eq!(fields, ",\"raw_wait_status\":2304,\"exit_status\":9");
        fields.clear();
        killed.append_json_fields(&mut fields);
        assert_eq!(fields, ",\"raw_wait_status\":9,\"term_signal\":9");
    }

    #[test]
    fn absent_or_invalid_terminal_status_is_not_inferred() {
        for raw in ["-1", "65536", "65535", "127", "128", "4991", "2313", "65", "garbage"] {
            let parsed = parse_proc_stat(2147, &synthetic_stat(2147, "Z", raw)).unwrap();
            assert_eq!(parsed.state, 'Z');
            assert!(parsed.exit.is_none(), "unexpected exit status for {raw}");
        }
        assert!(parse_proc_stat(2147, "2147 (short stat) Z 1 2 3")
            .unwrap()
            .exit
            .is_none());
        assert!(parse_proc_stat(2147, &synthetic_stat(2147, "S", "9"))
            .unwrap()
            .exit
            .is_none());
        assert!(parse_proc_stat(2147, &synthetic_stat(999, "Z", "9")).is_none());
        assert!(parse_proc_stat(2147, "not a proc stat").is_none());
    }

    #[test]
    fn zombie_observation_preserves_the_latest_live_resource_snapshot() {
        let guard = SceneGuard::new("synthetic");
        record_live_sample(&guard, "State:\tS (sleeping)\nVmRSS:\t4096 kB\nThreads:\t7\n");
        record_live_sample(&guard, "State:\tS (sleeping)\nVmRSS:\t8192 kB\nThreads:\t9\n");
        let last_live = guard.snapshots.lock().unwrap()[&2147].live.clone().unwrap();
        assert!(last_live.contains("VmRSS:\t8192 kB"));
        assert!(last_live.contains("Threads:\t9"));
        let zombie_stat = synthetic_stat(2147, "Z", "9");
        assert!(guard.take_snapshot_with(2147, |name| {
            assert_eq!(name, "stat", "a known zombie must not replace live proc data");
            Some(zombie_stat.clone())
        }));
        let snapshots = guard.snapshots.lock().unwrap();
        let saved = &snapshots[&2147];
        assert_eq!(saved.live.as_deref(), Some(last_live.as_str()));
        let final_state = saved.final_state.as_ref().unwrap();
        assert_eq!(final_state.stat, zombie_stat);
        assert_eq!(final_state.exit.unwrap().term_signal, Some(9));
    }

    #[test]
    fn exit_during_proc_reads_does_not_replace_live_data_with_a_mixed_snapshot() {
        let guard = SceneGuard::new("synthetic");
        record_live_sample(&guard, "State:\tS (sleeping)\nVmRSS:\t4096 kB\nThreads:\t7\n");
        let last_live = guard.snapshots.lock().unwrap()[&2147].live.clone().unwrap();
        let mut stat_reads = 0;
        assert!(guard.take_snapshot_with(2147, |name| match name {
            "stat" => {
                stat_reads += 1;
                Some(synthetic_stat(2147, if stat_reads == 1 { "S" } else { "Z" }, "2304"))
            }
            "status" => Some("State:\tZ (zombie)\nThreads:\t1\n".into()),
            _ => None,
        }));
        let snapshots = guard.snapshots.lock().unwrap();
        let saved = &snapshots[&2147];
        assert_eq!(saved.live.as_deref(), Some(last_live.as_str()));
        assert_eq!(saved.final_state.as_ref().unwrap().exit.unwrap().exit_status, Some(9));
    }

    #[test]
    fn unreadable_or_dead_status_preserves_the_previous_live_snapshot() {
        let guard = SceneGuard::new("synthetic");
        record_live_sample(&guard, "State:\tS (sleeping)\nVmRSS:\t4096 kB\nThreads:\t7\n");
        let last_live = guard.snapshots.lock().unwrap()[&2147].live.clone().unwrap();
        for status in [None, Some("State:\tZ (zombie)\n"), Some("incomplete status")] {
            assert!(!guard.take_snapshot_with(2147, |name| match name {
                "stat" => Some(synthetic_stat(2147, "S", "0")),
                "status" => status.map(str::to_string),
                _ => None,
            }));
        }
        let mut stat_reads = 0;
        assert!(!guard.take_snapshot_with(2147, |name| match name {
            "stat" => {
                stat_reads += 1;
                (stat_reads == 1).then(|| synthetic_stat(2147, "S", "0"))
            }
            "status" => Some("State:\tS (sleeping)\nVmRSS:\t0 kB\n".into()),
            _ => None,
        }));
        let snapshots = guard.snapshots.lock().unwrap();
        let saved = &snapshots[&2147];
        assert_eq!(saved.live.as_deref(), Some(last_live.as_str()));
        assert!(saved.final_state.is_none());
    }

    #[test]
    fn event_ring_preserves_fifo_and_reuses_the_evicted_allocation() {
        let guard = SceneGuard::new("synthetic");
        let first = String::from("event-0");
        guard.record_event(1, "main", &first);
        assert_eq!(first, "event-0");
        let (first_ptr, first_capacity) = {
            let ring = guard.ring.lock().unwrap();
            let saved = ring.front().unwrap();
            (saved.as_ptr(), saved.capacity())
        };
        for index in 1..RING_CAPACITY {
            guard.record_event(1, "main", &format!("event-{index}"));
        }
        guard.record_event(1, "main", "newest");
        let next_ptr = {
            let ring = guard.ring.lock().unwrap();
            assert_eq!(ring.len(), RING_CAPACITY);
            for (index, line) in ring.iter().take(RING_CAPACITY - 1).enumerate() {
                assert_eq!(line, &format!("event-{}", index + 1));
            }
            assert_eq!(ring.back().unwrap(), "newest");
            assert_eq!(ring.back().unwrap().as_ptr(), first_ptr);
            assert_eq!(ring.back().unwrap().capacity(), first_capacity);
            ring.front().unwrap().as_ptr()
        };
        guard.record_event(1, "main", "reused");
        let ring = guard.ring.lock().unwrap();
        assert_eq!(ring.len(), RING_CAPACITY);
        assert_eq!(ring.front().unwrap(), "event-2");
        assert_eq!(ring.back().unwrap(), "reused");
        assert_eq!(ring.back().unwrap().as_ptr(), next_ptr);
        assert_eq!(ring[RING_CAPACITY - 2].as_ptr(), first_ptr);
    }

    #[test]
    fn recording_keeps_pid_registration_and_main_pid_semantics() {
        let guard = SceneGuard::new("synthetic");
        guard.record_event(10, "first", "a");
        guard.record_event(20, "second", "b");
        guard.record_event(10, "renamed", "c");
        assert_eq!(*guard.main_pid.lock().unwrap(), Some(10));
        let pids = guard.pids.lock().unwrap();
        assert_eq!(pids.len(), 2);
        assert_eq!(pids.get(&10).unwrap(), "first");
        assert_eq!(pids.get(&20).unwrap(), "second");
        drop(pids);
        guard.set_main_pid(20);
        guard.record_event(30, "third", "d");
        assert_eq!(*guard.main_pid.lock().unwrap(), Some(20));
    }
}
