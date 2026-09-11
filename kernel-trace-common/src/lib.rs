#![cfg_attr(not(feature = "user"), no_std)]

// user feature 启用时引入 alloc，让 to_json / itoa_u64 等宿主函数可用；
// ebpf 编译路径不启用 user feature，整段被 no_std 隔离掉。
#[cfg(feature = "user")]
extern crate alloc;
#[cfg(feature = "user")]
use alloc::string::{String, ToString};

/// Linux `TASK_COMM_LEN` (comm 字段长度，含末尾 NUL)。
pub const TASK_COMM_LEN: usize = 16;

pub mod thread_names;

/// Stable indices in the per-CPU `TRACE_STATS` map. Append new counters so older
/// readers can still read the existing prefix; userspace and eBPF share the size.
pub mod trace_stats {
    pub const SVC_RING_DROPPED: u32 = 0;
    pub const UPROBE_RING_DROPPED: u32 = 1;
    pub const SVC_SUBMITTED: u32 = 2;
    pub const UPROBE_SUBMITTED: u32 = 3;
    pub const SVC_THREAD_FILTERED: u32 = 4;
    pub const UPROBE_THREAD_FILTERED: u32 = 5;
    pub const HWBP_RING_DROPPED: u32 = 6;
    pub const HWBP_SUBMITTED: u32 = 7;
    /// BPF program entries, counted before UID/PID filtering. This does not
    /// count hardware exceptions that never enter this BPF program.
    pub const HWBP_ENTERED: u32 = 8;
    /// UID rejects have priority when both UID and PID would reject an event.
    pub const HWBP_UID_FILTERED: u32 = 9;
    pub const HWBP_PID_FILTERED: u32 = 10;
    pub const COUNT: u32 = 11;
}

/// TID 黑名单槽位数（与 stackplz 对齐）。
pub const MAX_TID_BLACKLIST_COUNT: usize = 5;

/// raw_tracepoint/sys_enter 上报的完整事件(含 33 GPR)。
///
/// 字段顺序对齐 stackplz 的 ctx_regs_t + 事件头:
/// `[pid, tid, timestamp_ns, comm[16], nr, regs[31], sp, pc, pstate]`
///
/// 数据来源:BPF 内核态直接读 `struct pt_regs`(args[0] of bpf_raw_tracepoint_args),
/// 一次读全,不需要用户态读 /proc。
///
/// 大小:8+8+8+16+8 + 31*8 + 8+8+8 = 304 字节,远低于 perf event 上限 65536。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SyscallEnterEvent {
    pub pid: u32,
    pub tid: u32,
    pub timestamp_ns: u64,
    pub comm: [u8; TASK_COMM_LEN],
    pub nr: i64,
    /// x0..x30(x30 = lr)
    pub regs: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

/// 用户态 uprobe 触发的完整事件(含 33 GPR,与 SyscallEnterEvent 同构,无 nr)。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct UprobeEvent {
    pub pid: u32,
    pub tid: u32,
    pub timestamp_ns: u64,
    pub comm: [u8; TASK_COMM_LEN],
    /// x0..x30(x30 = lr)
    pub regs: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

/// 硬件断点/观察点类型（与 perf_event_attr bp_type 对应，用户态↔内核态共享语义）。
pub const HW_BP_KIND_R: u32 = 0;
pub const HW_BP_KIND_W: u32 = 1;
pub const HW_BP_KIND_RW: u32 = 2;
/// 执行断点（指令地址，len 恒为 4）。
pub const HW_BP_KIND_X: u32 = 3;

/// perf_event 硬件断点/观察点命中事件。
///
/// 数据来源：`BPF_PROG_TYPE_PERF_EVENT` 程序读 `bpf_perf_event_data`
/// （`regs` 为用户态 `user_pt_regs` 前缀，`addr` 为观察点命中时的访问地址 far，
/// 执行断点时 addr 无意义，用 pc 匹配）。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct HwBpEvent {
    pub pid: u32,
    pub tid: u32,
    pub timestamp_ns: u64,
    pub comm: [u8; TASK_COMM_LEN],
    /// 命中地址：观察点=被访问的 far 地址；执行断点=pc（通常等于断点地址）。
    pub addr: u64,
    /// x0..x30(x30 = lr)
    pub regs: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

/// 共享过滤器（uid / pid / nr / tid_blacklist / lib_only）。
///
/// - uid == 0 → 不过滤
/// - pid == 0 → 不过滤
/// - nr == -1 → 不过滤（仅 SyscallFilter 关心）
/// - tid_blacklist_mask 是位图，最多 5 个槽位
/// - full_tname == 0 → 启用默认线程名排除；非零只关闭这项排除
/// - lib_only != 0 → sys_enter 额外要求 lr(x30) 落在 LIB_RANGES[pid] 的
///   目标库可执行区间内（内核态过滤，治 perf ring Lost 的根本手段）
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Filter {
    pub uid: u32,
    pub pid: u32,
    pub nr: i32,
    pub tid_blacklist_mask: u32,
    pub tid_blacklist: [u32; MAX_TID_BLACKLIST_COUNT],
    pub lib_only: u32,
    /// lib_only 的"上膛"标志(仅 lib_only=1 时有意义):
    /// 0 = 尚未在任何进程发现目标库区间 → sys_enter 全放行(fail-open),
    ///     靠用户态 backstop 过滤,保证激活前的早期事件不丢;
    /// 1 = 已有区间写入 LIB_RANGES → 转 fail-closed,内核态精确过滤。
    /// 由用户态刷新器在首次写入区间时置 1。
    pub lib_armed: u32,
    /// 非零时关闭默认线程名黑名单；显式 PID/UID/TID 等过滤仍生效。
    pub full_tname: u32,
}

/// LIB_RANGES map 单个进程最多记录的库可执行区间数。
/// 单库通常 1 段 r-xp;包名模式("抖音全部 so")下每个库 1 段,
/// 抖音加载几十个原生库,64 段够用。
pub const MAX_LIB_RANGES: usize = 64;

/// LIB_RANGES map 的 value：一个进程(tgid)内目标库的可执行区间集合。
/// 由用户态周期扫 /proc/<pid>/maps 填充（库加载晚于 attach 的 spawn 场景
/// 也能在加载后 1s 内生效）。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LibRanges {
    pub count: u32,
    /// [start, end) 区间对（半开区间）
    pub ranges: [[u64; 2]; MAX_LIB_RANGES],
}

impl LibRanges {
    pub const fn zero() -> Self {
        LibRanges {
            count: 0,
            ranges: [[0u64; 2]; MAX_LIB_RANGES],
        }
    }
}

impl Filter {
    pub const fn any() -> Self {
        Filter {
            uid: 0,
            pid: 0,
            nr: -1,
            tid_blacklist_mask: 0,
            tid_blacklist: [0u32; MAX_TID_BLACKLIST_COUNT],
            lib_only: 0,
            lib_armed: 0,
            full_tname: 0,
        }
    }

    pub fn add_tid_blacklist(&mut self, tid: u32) -> bool {
        for i in 0..MAX_TID_BLACKLIST_COUNT {
            if (self.tid_blacklist_mask & (1 << i)) == 0 {
                self.tid_blacklist[i] = tid;
                self.tid_blacklist_mask |= 1 << i;
                return true;
            }
        }
        false
    }
}

#[cfg(feature = "user")]
pub mod groups;
#[cfg(feature = "user")]
pub mod syscall;
pub mod syscall_table_aarch64;

#[cfg(feature = "user")]
pub use groups::{parse_process_group, uid_matches_groups, PROCESS_GROUPS};
#[cfg(feature = "user")]
pub use syscall::{dedup_sorted, name_to_nr, nr_to_name, parse_syscall_list};

// =====================================================================
// 用户态侧实现（kernel-trace feature="user"）
// =====================================================================

impl SyscallEnterEvent {
    #[cfg(feature = "user")]
    pub fn comm_str(&self) -> &str {
        trim_comm(&self.comm)
    }

    /// x30 = lr(link register)。
    #[cfg(feature = "user")]
    pub fn lr(&self) -> u64 {
        self.regs[30]
    }

    #[cfg(feature = "user")]
    pub fn to_json(&self) -> String {
        let mut s = String::new();
        s.push_str("{\"type\":\"svc.enter\"");
        push_kv_u32(&mut s, "pid", self.pid, true);
        push_kv_u32(&mut s, "tid", self.tid, false);
        push_kv_u64(&mut s, "timestamp_ns", self.timestamp_ns, false);
        push_kv_str(&mut s, "comm", self.comm_str(), false);
        push_kv_i64(&mut s, "nr", self.nr, false);
        push_kv_u64(&mut s, "sp", self.sp, false);
        push_kv_u64(&mut s, "pc", self.pc, false);
        push_kv_u64(&mut s, "pstate", self.pstate, false);
        push_kv_u64(&mut s, "lr", self.lr(), false);
        s.push_str(",\"regs\":{");
        for (i, v) in self.regs.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str("\"x");
            s.push_str(&itoa_u64(i as u64));
            s.push_str("\":\"0x");
            s.push_str(&hex_u64(*v));
            s.push('"');
        }
        s.push('}');
        s.push('}');
        s
    }
}

impl UprobeEvent {
    #[cfg(feature = "user")]
    pub fn comm_str(&self) -> &str {
        trim_comm(&self.comm)
    }

    #[cfg(feature = "user")]
    pub fn lr(&self) -> u64 {
        self.regs[30]
    }
    #[cfg(feature = "user")]
    pub fn to_json(&self) -> String {
        let mut s = String::new();
        s.push_str("{\"type\":\"uprobe.hit\"");
        push_kv_u32(&mut s, "pid", self.pid, true);
        push_kv_u32(&mut s, "tid", self.tid, false);
        push_kv_u64(&mut s, "timestamp_ns", self.timestamp_ns, false);
        push_kv_str(&mut s, "comm", self.comm_str(), false);
        push_kv_u64(&mut s, "sp", self.sp, false);
        push_kv_u64(&mut s, "pc", self.pc, false);
        push_kv_u64(&mut s, "lr", self.lr(), false);
        s.push_str(",\"regs\":{");
        for (i, v) in self.regs.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str("\"x");
            s.push_str(&itoa_u64(i as u64));
            s.push_str("\":\"0x");
            s.push_str(&hex_u64(*v));
            s.push('"');
        }
        s.push('}');
        s.push('}');
        s
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SyscallEnterEvent {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for UprobeEvent {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for HwBpEvent {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Filter {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for LibRanges {}

impl HwBpEvent {
    #[cfg(feature = "user")]
    pub fn comm_str(&self) -> &str {
        trim_comm(&self.comm)
    }

    #[cfg(feature = "user")]
    pub fn lr(&self) -> u64 {
        self.regs[30]
    }

    /// 硬件断点类型名（"r"/"w"/"rw"/"x"）。
    #[cfg(feature = "user")]
    pub fn kind_name(kind: u32) -> &'static str {
        match kind {
            HW_BP_KIND_R => "r",
            HW_BP_KIND_W => "w",
            HW_BP_KIND_RW => "rw",
            HW_BP_KIND_X => "x",
            _ => "?",
        }
    }

    /// 解析 "w:0x7f001234" / "w:0x7f001234:4" / "x:0x7f00abcd" 形式的断点规格。
    /// 数据观察点缺省 len=8（arm64 要求地址按 len 对齐，8 最宽容）。
    #[cfg(feature = "user")]
    pub fn parse_spec(s: &str) -> Option<HwBpSpec> {
        let mut it = s.split(':');
        let kind = match it.next()?.trim() {
            "r" => HW_BP_KIND_R,
            "w" => HW_BP_KIND_W,
            "rw" => HW_BP_KIND_RW,
            "x" => HW_BP_KIND_X,
            _ => return None,
        };
        let addr_str = it.next()?.trim();
        let addr = if let Some(h) = addr_str.strip_prefix("0x").or_else(|| addr_str.strip_prefix("0X")) {
            u64::from_str_radix(h, 16).ok()?
        } else {
            addr_str.parse::<u64>().ok()?
        };
        let len = match it.next() {
            Some(l) => {
                let n: u32 = l.trim().parse().ok()?;
                match n {
                    1 | 2 | 4 | 8 => n,
                    _ => return None,
                }
            }
            None => 8,
        };
        if it.next().is_some() {
            return None;
        }
        if kind == HW_BP_KIND_X {
            return Some(HwBpSpec { kind, addr, len: 4 });
        }
        // arm64 观察点：地址必须按 len 对齐
        if addr % len as u64 != 0 {
            return None;
        }
        Some(HwBpSpec { kind, addr, len })
    }
}

/// 硬件断点/观察点规格（用户态侧配置，不进 BPF）。
#[cfg(feature = "user")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HwBpSpec {
    pub kind: u32,
    pub addr: u64,
    pub len: u32,
}

// =====================================================================
// mini-itoa / JSON 序列化工具（避免 alloc 标准库 / serde）
// =====================================================================

#[cfg(feature = "user")]
fn trim_comm(comm: &[u8; TASK_COMM_LEN]) -> &str {
    let mut end = comm.len();
    while end > 0 && comm[end - 1] == 0 {
        end -= 1;
    }
    core::str::from_utf8(&comm[..end]).unwrap_or("")
}

#[cfg(feature = "user")]
fn push_kv_u32(s: &mut String, k: &str, v: u32, first: bool) {
    if !first {
        s.push(',');
    }
    s.push('"');
    s.push_str(k);
    s.push_str("\":");
    s.push_str(&itoa_u64(v as u64));
}

#[cfg(feature = "user")]
fn push_kv_u64(s: &mut String, k: &str, v: u64, first: bool) {
    if !first {
        s.push(',');
    }
    s.push('"');
    s.push_str(k);
    s.push_str("\":");
    s.push_str(&itoa_u64(v));
}

#[cfg(feature = "user")]
fn push_kv_i64(s: &mut String, k: &str, v: i64, first: bool) {
    if !first {
        s.push(',');
    }
    s.push('"');
    s.push_str(k);
    s.push_str("\":");
    s.push_str(&itoa_i64(v));
}

#[cfg(feature = "user")]
fn push_kv_str(s: &mut String, k: &str, v: &str, first: bool) {
    if !first {
        s.push(',');
    }
    s.push('"');
    s.push_str(k);
    s.push_str("\":\"");
    s.push_str(&json_escape(v));
    s.push('"');
}

#[cfg(feature = "user")]
fn itoa_u64(mut n: u64) -> String {
    if n == 0 {
        return "0".to_string();
    }
    let mut buf = [0u8; 20];
    let mut i = 0;
    while n > 0 {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    let mut s = String::with_capacity(i);
    while i > 0 {
        i -= 1;
        s.push(buf[i] as char);
    }
    s
}

#[cfg(feature = "user")]
fn itoa_i64(n: i64) -> String {
    if n >= 0 {
        itoa_u64(n as u64)
    } else {
        let neg = n as i128;
        let abs = if neg == i64::MIN as i128 {
            (i64::MAX as u64) + 1
        } else {
            (-neg) as u64
        };
        let mut s = String::from("-");
        s.push_str(&itoa_u64(abs));
        s
    }
}

#[cfg(feature = "user")]
fn hex_u64(mut n: u64) -> String {
    if n == 0 {
        return "0".to_string();
    }
    let mut buf = [0u8; 16];
    let mut i = 0;
    while n > 0 {
        let d = (n & 0xf) as u8;
        buf[i] = if d < 10 { b'0' + d } else { b'a' + (d - 10) };
        n >>= 4;
        i += 1;
    }
    let mut s = String::with_capacity(i);
    while i > 0 {
        i -= 1;
        s.push(buf[i] as char);
    }
    s
}

#[cfg(feature = "user")]
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
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
    out
}
