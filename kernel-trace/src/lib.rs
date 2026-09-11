//! kernel-trace — 基于 aya 的内核态 syscall/uprobe 取证器。
//!
//! 设计目标：把 stackplz 的"小功能"全部并入 rustfrida：
//! - tracepoint/raw_syscalls/sys_enter → JSONL
//! - 通用 uprobe（attach 时指定 lib+offset） → JSONL
//! - 用户态补 ShowRegs（读 /proc/<pid>/syscall）、UnwindStack（读 /proc/<pid>/stack）、
//!   Map/Symbol 反查（/proc/<pid>/maps + /proc/kallsyms）— 仿 stackplz StackConfig 设计。
//! - syscall 名解析（306 aarch64 syscalls） + % 分组展开
//! - 进程分组（app/iso/root/system/shell）+ UID 黑名单
//! - 路径白/黑名单 + eq/ne/bx 过滤规则（filter.rs）
//! - --kill SIGSTOP + 终端 'c' 恢复（kill.rs）
//! - --dumphex + --color 输出（output.rs）
//!
//! 与 ldmonitor/src/lib.rs 同样的模式：后台线程 + tokio + AsyncFd<PerfEventArrayBuffer>。

use aya::{
    maps::HashMap,
    programs::{
        perf_event::{
            BreakpointConfig, PerfBreakpointLength, PerfBreakpointType, PerfEvent as AyaPerfEvent, PerfEventConfig,
            PerfEventLink, PerfEventScope, SamplePolicy,
        },
        RawTracePoint, UProbe,
    },
    Ebpf,
};
use kernel_trace_common::{
    trace_stats, uid_matches_groups, Filter, HwBpEvent, HwBpSpec, LibRanges, SyscallEnterEvent, UprobeEvent,
    HW_BP_KIND_R, HW_BP_KIND_RW, HW_BP_KIND_W, HW_BP_KIND_X, MAX_LIB_RANGES,
};
use std::fs;
use std::io::{BufReader, Read};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context as _};

pub mod argspec;
pub mod arm64_disasm;
pub mod filter;
mod hwbp_lifecycle;
mod instance_lock;
pub mod kill;
mod load;
pub mod output;
mod procinfo;
mod report_queue;
pub mod sink;
pub mod stackwalk;
pub mod stats;
pub use arm64_disasm::InstructionInfo;
use hwbp_lifecycle::{configure_fd, list_tasks, read_task_identity, CancellationLedger, PendingRequest, TaskIdentity};
pub use stats::TraceStats;
use stats::{EventKind, PipelineCounters, Queued};

const RAW_QUEUE_CAPACITY: usize = 8192;
const UPROBE_QUEUE_CAPACITY: usize = 1024;
// Hardware hits are sparse but latency-sensitive. Keep a separate bounded
// lane so a noisy uprobe stream cannot delay or discard a breakpoint report.
const HWBP_QUEUE_CAPACITY: usize = 256;
const REPORT_QUEUE_CAPACITY: usize = 2048;
const UPROBE_REPORT_QUEUE_CAPACITY: usize = 256;
const SVC_WORKERS: usize = 2;
const UPROBE_WORKERS: usize = 1;
const HWBP_WORKERS: usize = 1;
const RING_BATCH_SIZE: usize = 256;

static DIAGNOSTIC_SINK: std::sync::OnceLock<fn(&str)> = std::sync::OnceLock::new();

/// Route diagnostic lines to the embedding application's logger. The callback
/// must return promptly and must not call back into this diagnostic path.
pub fn set_diagnostic_sink(sink: fn(&str)) -> Result<(), fn(&str)> {
    DIAGNOSTIC_SINK.set(sink)
}

fn emit_diagnostic(args: std::fmt::Arguments<'_>) {
    if let Some(sink) = DIAGNOSTIC_SINK.get() {
        sink(&args.to_string());
    } else {
        eprintln!("{args}");
    }
}

macro_rules! trace_diag {
    ($($arg:tt)*) => { emit_diagnostic(format_args!($($arg)*)) };
}

/// ring 消费者 → 报告 worker 的原始事件。
/// 消费者只搬运不加工:参数解码/堆栈回溯/寄存器标注这类重活全在 worker 线程,
/// 否则单线程 runtime 上消费者会把主循环(刷新/对账/指令)饿死
enum RawEvent {
    Sys(SyscallEnterEvent),
    Uprobe(UprobeEvent),
    /// 硬件断点/观察点命中（独立的低延迟车道）
    HwBp(HwBpEvent),
}

impl RawEvent {
    fn kind(&self) -> EventKind {
        match self {
            Self::Sys(_) => EventKind::Svc,
            Self::Uprobe(_) => EventKind::Uprobe,
            Self::HwBp(_) => EventKind::HwBp,
        }
    }

    fn pid(&self) -> u32 {
        match self {
            RawEvent::Sys(ev) => ev.pid,
            RawEvent::Uprobe(ev) => ev.pid,
            RawEvent::HwBp(ev) => ev.pid,
        }
    }
}

pub use filter::{event_passes, parse_filter_list, FilterRule};
pub use kernel_trace_common::syscall::nr_to_name;
pub use kernel_trace_common::{parse_process_group, parse_syscall_list};
pub use kill::{parse_signal, KillController};
pub use output::{color_enabled, dumphex, paint, C_RESET};

// =====================================================================
// PID namespace 翻译（与 ldmonitor/src/lib.rs 保持一致）
// =====================================================================

/// 从 /proc/<pid>/status 读取 NSpid 字段，返回各 namespace 层级的 PID 列表。
fn get_nspid(host_pid: u32) -> Option<Vec<u32>> {
    let status_path = format!("/proc/{}/status", host_pid);
    let content = fs::read_to_string(&status_path).ok()?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("NSpid:") {
            let pids: Vec<u32> = rest.split_whitespace().filter_map(|s| s.parse().ok()).collect();
            if !pids.is_empty() {
                return Some(pids);
            }
        }
    }
    None
}

/// 把 host PID 翻译成当前 namespace 的 PID（如果同 ns 直接返回最内层）。
pub fn translate_pid_to_current_ns(host_pid: u32) -> Option<u32> {
    let nspids = get_nspid(host_pid)?;
    if nspids.len() == 1 {
        return Some(nspids[0]);
    }
    // 当前实现走最内层 PID，与 ldmonitor/lib.rs::translate_pid_to_current_ns 一致
    nspids.last().copied()
}

// =====================================================================
// 选项
// =====================================================================

#[derive(Clone, Debug)]
pub struct TraceOptions {
    /// 只跟踪这个 PID（0 = 不过滤）
    pub pid: u32,
    /// 只跟踪这个 UID（0 = 不过滤）
    pub uid: u32,
    /// 只跟踪这个 syscall nr（-1 = 不过滤）
    pub nr: i32,
    /// TID 黑名单
    pub tid_blacklist: Vec<u32>,
    /// 关闭默认线程名排除；不会扩展 comm 长度或关闭显式过滤。
    pub full_tname: bool,
    /// 用户态读 /proc/<pid>/syscall 抓 33 GPR
    pub show_regs: bool,
    /// 用户态读 /proc/<pid>/stack 拿 kernel backtrace
    pub unwind_stack: bool,
    /// 单 reg 提取模式（Some("x1") / "lr" / "sp" / "pc"）
    pub reg_name: Option<String>,
    /// 通用 uprobe：目标库绝对路径（None = 不挂 uprobe）
    pub uprobe_lib: Option<String>,
    /// uprobe 偏移（与 uprobe_lib 配对）
    pub uprobe_offset: u64,
    /// sys_enter 是否挂（true = always-on 时挂上）
    pub enable_syscall: bool,
    // ===== stackplz 风格扩展 =====
    /// syscall 名白名单（如 "openat,connect,sendto"），用 `kernel_trace_common::parse_syscall_list` 解析为 nr 列表
    pub syscall_names: Vec<i64>,
    /// syscall 名黑名单（如 "openat,recvfrom"）
    pub no_syscall_names: Vec<i64>,
    /// UID 黑名单（逗号分隔）
    pub uid_blacklist: Vec<u32>,
    /// 进程分组（app/iso/root/system/shell/media）
    pub process_groups: Vec<&'static str>,
    /// 过滤规则（w:/ b:/ eq: ne: bx:）
    pub filter_rules: Vec<FilterRule>,
    /// 命中事件时给目标进程发信号（Some(19) = SIGSTOP），None = 不发
    pub kill_signal: Option<i32>,
    /// 输出时把 buffer 字段以 hex+ASCII 显示
    pub dumphex: bool,
    /// 输出用 ANSI 颜色
    pub color: bool,
    /// 输出文件路径（None = stdout）
    pub output_path: Option<std::path::PathBuf>,
    // ===== 参数语义解析 =====
    /// 解码 syscall 参数（字符串解引用、buffer 预览；dumphex 控制完整十六进制块）
    pub decode_args: bool,
    /// lr 落在该名字（子串）的可执行映射中时标记 lib_hit（如 "libmetasec_ml.so"）
    pub lib_range: Option<String>,
    /// 只输出 lib_hit 命中的事件（需配合 lib_range）
    pub lib_only: bool,
    /// 用户态 fp 链堆栈回溯（默认开）；关闭后 svc 仍解析 LR/PC 模块归属
    pub stack_trace: bool,
    /// Disable the default budget/queue-age guard for optional report details.
    pub full_detail: bool,
    /// 硬件断点/观察点规格（启动时挂上；pid 必须非 0，断点按目标线程挂）
    pub hw_breakpoints: Vec<HwBpSpec>,
}

impl Default for TraceOptions {
    fn default() -> Self {
        TraceOptions {
            pid: 0,
            uid: 0,
            nr: -1,
            tid_blacklist: Vec::new(),
            full_tname: false,
            show_regs: false,
            unwind_stack: false,
            reg_name: None,
            uprobe_lib: None,
            uprobe_offset: 0,
            enable_syscall: true,
            syscall_names: Vec::new(),
            no_syscall_names: Vec::new(),
            uid_blacklist: Vec::new(),
            process_groups: Vec::new(),
            filter_rules: Vec::new(),
            kill_signal: None,
            dumphex: false,
            color: false,
            output_path: None,
            decode_args: false,
            lib_range: None,
            lib_only: false,
            stack_trace: true,
            full_detail: false,
            hw_breakpoints: Vec::new(),
        }
    }
}

// =====================================================================
// 报告（用户态增强后的事件）
// =====================================================================

#[derive(Debug, Clone)]
pub struct TraceReport {
    /// None = requested details attempted; Some = base event only, with reason.
    pub detail_skipped: Option<&'static str>,
    pub event_kind: &'static str,
    pub host_pid: u32,
    pub ns_pid: Option<u32>,
    pub tid: u32,
    pub timestamp_ns: u64,
    pub comm: String,
    pub nr: Option<i64>,
    pub regs: Option<Vec<(String, u64)>>,
    pub kernel_stack: Option<String>,
    /// lr 是否命中 lib_range 指定的 so（如 libmetasec_ml.so）
    pub lib_hit: bool,
    /// 语义解析后的参数（"name=value" 列表）
    pub decoded_args: Option<Vec<String>>,
    /// buf 参数的 xxd hexdump 块（打印在 JSON 行之后）
    pub dump_blocks: Vec<String>,
    /// 内部保留的 lr 模块相对地址；序列化时并入 locations，host 文本直接内联。
    pub lr_off: Option<String>,
    /// 内部保留的 pc 模块相对地址；序列化时并入 locations，host 文本直接内联。
    pub pc_off: Option<String>,
    /// 寄存器值中能解析出模块归属的标注；序列化时并入 locations。
    pub regs_off: Option<Vec<(String, String)>>,
    /// lr / pc 原始值，始终保持为可直接解析的数值。
    pub lr: u64,
    pub pc: u64,
    /// 归属 so 短名(svc 取 lr_off,uprobe 取 pc_off;未知名为 "anon")
    pub so_tag: String,
    /// 归属映射的加载基址(svc 取 lr 所在映射,uprobe 取 pc;未命中为 None)
    pub so_base: Option<u64>,
    /// 用户态堆栈回溯（fp 链，模块+偏移）
    pub stack: Option<Vec<String>>,
    /// 硬件断点命中类型（HwBpEvent 的 HW_BP_KIND_*，None = 非硬件断点事件）
    pub bp_kind: Option<u32>,
    /// 命中地址：观察点=被访问的 far 地址；执行断点=pc
    pub bp_addr: Option<u64>,
    /// HWBP 命中 PC 处的 4 字节 AArch64 指令及可读汇编。
    /// 只对硬件断点填充，避免给高频 svc/uprobe 增加 /proc 读取开销。
    pub instruction: Option<InstructionInfo>,
    /// 从 HWBP 命中 PC 开始的连续指令窗口。通常包含命中指令和后续
    /// 15 条指令，便于在现场直接判断读写指令的控制流。
    pub instructions: Option<Vec<InstructionInfo>>,
}

impl TraceReport {
    pub fn to_jsonl(&self) -> String {
        let mut s = String::with_capacity(256 + self.regs.as_ref().map_or(0, |r| r.len() * 24));
        self.write_jsonl(&mut s);
        s
    }

    /// Append one JSON object without clearing the caller's reusable buffer.
    pub fn write_jsonl(&self, s: &mut String) {
        s.push_str("{\"type\":\"");
        s.push_str(self.event_kind);
        s.push('"');
        s.push_str(",\"detail\":\"");
        s.push_str(if self.detail_skipped.is_some() { "basic" } else { "full" });
        s.push('"');
        if let Some(reason) = self.detail_skipped {
            s.push_str(",\"detail_reason\":\"");
            s.push_str(reason);
            s.push('"');
        }
        s.push_str(",\"pid\":");
        push_u64(s, self.host_pid as u64);
        if let Some(ns) = self.ns_pid {
            s.push_str(",\"ns_pid\":");
            push_u64(s, ns as u64);
        }
        s.push_str(",\"tid\":");
        push_u64(s, self.tid as u64);
        s.push_str(",\"timestamp_ns\":");
        push_u64(s, self.timestamp_ns);
        s.push_str(",\"so\":\"");
        push_json_escaped(s, &self.so_tag);
        s.push('"');
        s.push_str(",\"comm\":\"");
        push_json_escaped(s, &self.comm);
        s.push('"');
        if let Some(nr) = self.nr {
            s.push_str(",\"nr\":");
            push_i64(s, nr);
            s.push_str(",\"name\":\"");
            s.push_str(kernel_trace_common::syscall::nr_to_name(nr).unwrap_or("?"));
            s.push('"');
        }
        if let Some(ref regs) = self.regs {
            s.push_str(",\"regs\":{");
            for (i, (name, val)) in regs.iter().enumerate() {
                if i > 0 {
                    s.push(',');
                }
                s.push('"');
                s.push_str(name);
                s.push_str("\":\"0x");
                push_hex(s, *val);
                s.push('"');
            }
            s.push('}');
        }
        if let Some(ref kstack) = self.kernel_stack {
            s.push_str(",\"kernel_stack\":\"");
            push_json_escaped(s, kstack);
            s.push('"');
        }
        if self.lib_hit {
            s.push_str(",\"lib_hit\":true");
        }
        if let Some(kind) = self.bp_kind {
            s.push_str(",\"bp\":{\"kind\":\"");
            s.push_str(kernel_trace_common::HwBpEvent::kind_name(kind));
            s.push_str("\",\"addr\":\"0x");
            push_hex(s, self.bp_addr.unwrap_or(0));
            s.push_str("\"}");
        }
        if let Some(ref instruction) = self.instruction {
            s.push_str(",\"instruction\":{\"word\":\"0x");
            push_hex(s, instruction.word as u64);
            s.push_str("\",\"bytes\":\"");
            for byte in instruction.bytes {
                push_hex_fixed_byte(s, byte);
            }
            s.push_str("\",\"asm\":\"");
            push_json_escaped(s, &instruction.asm);
            s.push_str("\"}");
        }
        if let Some(ref instructions) = self.instructions {
            s.push_str(",\"instructions\":[");
            for (index, instruction) in instructions.iter().enumerate() {
                if index > 0 {
                    s.push(',');
                }
                s.push('{');
                s.push_str("\"pc\":\"0x");
                push_hex(s, self.pc.saturating_add(index as u64 * 4));
                s.push_str("\",\"word\":\"0x");
                push_hex(s, instruction.word as u64);
                s.push_str("\",\"bytes\":\"");
                for byte in instruction.bytes {
                    push_hex_fixed_byte(s, byte);
                }
                s.push_str("\",\"asm\":\"");
                push_json_escaped(s, &instruction.asm);
                s.push_str("\"}");
            }
            s.push(']');
        }
        if let Some(ref args) = self.decoded_args {
            s.push_str(",\"args\":[");
            for (i, a) in args.iter().enumerate() {
                if i > 0 {
                    s.push(',');
                }
                s.push('"');
                push_json_escaped(s, a);
                s.push('"');
            }
            s.push(']');
        }
        s.push_str(",\"lr\":\"0x");
        push_hex(s, self.lr);
        s.push('"');
        s.push_str(",\"pc\":\"0x");
        push_hex(s, self.pc);
        s.push('"');
        // 地址本身保持可直接解析的十六进制字符串；模块相对位置集中放在
        // locations，避免再生成 lr_off/pc_off/regs_off 这类平行字段。
        let locations = self.regs_off.as_deref().unwrap_or(&[]);
        let lr_location = self
            .lr_off
            .as_deref()
            .filter(|_| report_reg_annotation(locations, "lr").is_none());
        let pc_location = self
            .pc_off
            .as_deref()
            .filter(|_| report_reg_annotation(locations, "pc").is_none());
        if !locations.is_empty() || lr_location.is_some() || pc_location.is_some() {
            s.push_str(",\"locations\":{");
            let mut first = true;
            for (name, value) in locations {
                if !first {
                    s.push(',');
                }
                first = false;
                s.push('"');
                push_json_escaped(s, name);
                s.push_str("\":\"");
                push_json_escaped(s, value);
                s.push('"');
            }
            for (name, value) in [("lr", lr_location), ("pc", pc_location)] {
                let Some(value) = value else { continue };
                if !first {
                    s.push(',');
                }
                first = false;
                s.push('"');
                s.push_str(name);
                s.push_str("\":\"");
                push_json_escaped(s, value);
                s.push('"');
            }
            s.push('}');
        }
        if let Some(ref stack) = self.stack {
            if !stack.is_empty() {
                s.push_str(",\"stack\":[");
                for (i, f) in stack.iter().enumerate() {
                    if i > 0 {
                        s.push(',');
                    }
                    s.push('"');
                    push_json_escaped(s, f);
                    s.push('"');
                }
                s.push(']');
            }
        }
        if !self.dump_blocks.is_empty() {
            // hexdump 块也进 JSON(转义多行),保证 JS 回调拿到与 host 打印一致的数据
            s.push_str(",\"dumps\":[");
            for (i, d) in self.dump_blocks.iter().enumerate() {
                if i > 0 {
                    s.push(',');
                }
                s.push('"');
                push_json_escaped(s, d);
                s.push('"');
            }
            s.push(']');
        }
        s.push('}');
    }

    /// Append the compact form used by the live JS callback bridge.
    ///
    /// The full JSONL record remains unchanged and keeps the 16-instruction
    /// window, stack and dump blocks for offline analysis.  Sending all of
    /// that through one `jseval` for every HWBP hit makes QuickJS spend most
    /// of its time parsing/allocating payloads.  The callback only needs the
    /// hit kind/address, registers, current instruction and locations; this
    /// bounded form keeps the callback responsive without reducing the file
    /// record or the host-side pretty output.
    pub fn write_callback_jsonl(&self, s: &mut String) {
        s.push_str("{\"type\":\"");
        push_json_escaped(s, self.event_kind);
        s.push_str("\",\"detail\":\"");
        s.push_str(if self.detail_skipped.is_some() { "basic" } else { "full" });
        s.push('"');
        if let Some(reason) = self.detail_skipped {
            s.push_str(",\"detail_reason\":\"");
            push_json_escaped(s, reason);
            s.push('"');
        }
        s.push_str(",\"pid\":");
        push_u64(s, self.host_pid as u64);
        if let Some(ns) = self.ns_pid {
            s.push_str(",\"ns_pid\":");
            push_u64(s, ns as u64);
        }
        s.push_str(",\"tid\":");
        push_u64(s, self.tid as u64);
        s.push_str(",\"timestamp_ns\":");
        push_u64(s, self.timestamp_ns);
        s.push_str(",\"so\":\"");
        push_json_escaped(s, &self.so_tag);
        s.push_str("\",\"comm\":\"");
        push_json_escaped(s, &self.comm);
        s.push('"');
        if let Some(ref regs) = self.regs {
            s.push_str(",\"regs\":{");
            for (i, (name, val)) in regs.iter().enumerate() {
                if i > 0 {
                    s.push(',');
                }
                s.push('"');
                push_json_escaped(s, name);
                s.push_str("\":\"0x");
                push_hex(s, *val);
                s.push('"');
            }
            s.push('}');
        }
        if let Some(kind) = self.bp_kind {
            s.push_str(",\"bp\":{\"kind\":\"");
            push_json_escaped(s, kernel_trace_common::HwBpEvent::kind_name(kind));
            s.push_str("\",\"addr\":\"0x");
            push_hex(s, self.bp_addr.unwrap_or(0));
            s.push_str("\"}");
            // Keep a top-level address for simple JS consumers.  `bp.addr`
            // remains the canonical field and is still emitted above.
            if kind != HW_BP_KIND_X {
                s.push_str(",\"addr\":\"0x");
                push_hex(s, self.bp_addr.unwrap_or(0));
                s.push('"');
            }
        }
        if let Some(ref instruction) = self.instruction {
            s.push_str(",\"instruction\":{\"word\":\"0x");
            push_hex(s, instruction.word as u64);
            s.push_str("\",\"bytes\":\"");
            for byte in instruction.bytes {
                push_hex_fixed_byte(s, byte);
            }
            s.push_str("\",\"asm\":\"");
            push_json_escaped(s, &instruction.asm);
            s.push_str("\"}");
        }
        s.push_str(",\"lr\":\"0x");
        push_hex(s, self.lr);
        s.push_str("\",\"pc\":\"0x");
        push_hex(s, self.pc);
        s.push('"');
        let locations = self.regs_off.as_deref().unwrap_or(&[]);
        let lr_location = self
            .lr_off
            .as_deref()
            .filter(|_| report_reg_annotation(locations, "lr").is_none());
        let pc_location = self
            .pc_off
            .as_deref()
            .filter(|_| report_reg_annotation(locations, "pc").is_none());
        if !locations.is_empty() || lr_location.is_some() || pc_location.is_some() {
            s.push_str(",\"locations\":{");
            let mut first = true;
            for (name, value) in locations {
                if !first {
                    s.push(',');
                }
                first = false;
                s.push('"');
                push_json_escaped(s, name);
                s.push_str("\":\"");
                push_json_escaped(s, value);
                s.push('"');
            }
            for (name, value) in [("lr", lr_location), ("pc", pc_location)] {
                let Some(value) = value else { continue };
                if !first {
                    s.push(',');
                }
                first = false;
                s.push('"');
                s.push_str(name);
                s.push_str("\":\"");
                push_json_escaped(s, value);
                s.push('"');
            }
            s.push('}');
        }
        s.push('}');
    }

    /// 人类可读多行格式(host 终端/日志文件用;JSONL 仍供 -o 文件与 JS 桥接):
    ///
    /// ```text
    /// [libmetasec_ml.so] svc.enter pid=.. tid=.. comm=.. nr=63 mt=read ts=..
    ///   args: fd=468 buf=0x..(hex 前 32B) count=1024
    ///   regs: x0=0x1ce x1=0x76d7fbebc0(libc++_shared.so+0xae844) x2=0x80 x3=0x8
    ///         x4=0xffffffff ... (每行 4 个,lr/pc 在末尾)
    ///   stack: libmetasec_ml.so+0x1354f0 <- libc.so+0x8b2c4 <- ...
    /// ```
    /// regs 中能解析出模块归属的值内联标注 (so+0xoff);不再单独输出 lr_off/pc_off。
    pub fn to_pretty(&self) -> String {
        let mut s = String::with_capacity(128 + self.regs.as_ref().map_or(0, |r| r.len() * 20));
        self.write_pretty(&mut s);
        s
    }

    /// Append the display form without clearing the caller's reusable buffer.
    pub fn write_pretty(&self, s: &mut String) {
        // 头部行
        s.push('[');
        s.push_str(&self.so_tag);
        if let Some(base) = self.so_base {
            s.push_str(" @0x");
            push_hex(s, base);
        }
        s.push_str("] ");
        s.push_str(self.event_kind);
        if let Some(kind) = self.bp_kind {
            s.push_str(" bp=");
            s.push_str(kernel_trace_common::HwBpEvent::kind_name(kind));
            s.push_str(" bp_addr=0x");
            let bp_addr = self.bp_addr.unwrap_or(0);
            push_hex(s, bp_addr);
            let annotations = self.regs_off.as_deref().unwrap_or(&[]);
            let bp_location = report_reg_annotation(annotations, "addr").or_else(|| {
                if kind == HW_BP_KIND_X {
                    report_reg_annotation(annotations, "pc")
                } else {
                    None
                }
            });
            if let Some(location) = bp_location {
                s.push('(');
                s.push_str(location);
                s.push(')');
            }
        }
        s.push_str(" pid=");
        push_u64(s, self.host_pid as u64);
        s.push_str(" tid=");
        push_u64(s, self.tid as u64);
        s.push(' ');
        s.push_str(&self.comm);
        if let Some(nr) = self.nr {
            s.push_str(" nr=");
            push_i64(s, nr);
            s.push_str(" mt=");
            s.push_str(kernel_trace_common::syscall::nr_to_name(nr).unwrap_or("?"));
        }
        s.push_str(" ts=");
        push_u64(s, self.timestamp_ns);
        if let Some(reason) = self.detail_skipped {
            s.push_str(" detail=basic reason=");
            s.push_str(reason);
            // Keep raw values visible without expanding a busy terminal into
            // multiple detail lines; cached module annotations are appended inline.
            if let Some(regs) = &self.regs {
                let annotations = self.regs_off.as_deref().unwrap_or(&[]);
                for (name, value) in regs {
                    s.push(' ');
                    s.push_str(name);
                    s.push_str("=0x");
                    push_hex(s, *value);
                    let annotation = report_reg_annotation(annotations, name).or_else(|| match name.as_str() {
                        "lr" => self.lr_off.as_deref(),
                        "pc" => self.pc_off.as_deref(),
                        _ => None,
                    });
                    if let Some(offset) = annotation {
                        s.push('(');
                        s.push_str(offset);
                        s.push(')');
                    }
                }
            }
            if let Some(ref instruction) = self.instruction {
                s.push_str(" insn=0x");
                push_hex(s, instruction.word as u64);
                s.push_str(" bytes=");
                for byte in instruction.bytes {
                    push_hex_fixed_byte(s, byte);
                }
                s.push_str(" asm=");
                s.push_str(&instruction.asm);
            }
            if let Some(ref instructions) = self.instructions {
                s.push_str(" disasm16=");
                write_disasm_window(s, self.pc, self.pc_off.as_deref(), instructions, " | ");
            }
            s.push('\n');
            return;
        }
        s.push('\n');

        if let Some(ref instruction) = self.instruction {
            s.push_str("  insn: 0x");
            push_hex(s, instruction.word as u64);
            s.push_str(" bytes=");
            for (i, byte) in instruction.bytes.iter().enumerate() {
                if i > 0 {
                    s.push(' ');
                }
                push_hex_fixed_byte(s, *byte);
            }
            s.push_str(" asm=");
            s.push_str(&instruction.asm);
            s.push('\n');
        }
        if let Some(ref instructions) = self.instructions {
            s.push_str("  disasm16:\n");
            for (index, instruction) in instructions.iter().enumerate() {
                s.push_str("    #");
                push_u64(s, index as u64);
                s.push_str(" @0x");
                push_hex(s, self.pc.saturating_add(index as u64 * 4));
                if let Some(pc_off) = self.pc_off.as_deref() {
                    write_module_offset_annotation(s, pc_off, index as u64);
                }
                s.push_str(" 0x");
                push_hex(s, instruction.word as u64);
                s.push_str(" ");
                s.push_str(&instruction.asm);
                s.push('\n');
            }
        }

        // args 一行
        if let Some(ref args) = self.decoded_args {
            if !args.is_empty() {
                s.push_str("  args: ");
                push_joined(s, args, " ");
                s.push('\n');
            }
        }

        // regs 分行(每行 4 个),值能解析出模块归属的内联标注
        if let Some(ref regs) = self.regs {
            let annotations = self.regs_off.as_deref().unwrap_or(&[]);
            let mut known_annotations = [None; 34];
            for (name, value) in annotations {
                if let Some(index) = report_reg_index(name) {
                    known_annotations[index] = Some(value.as_str());
                }
            }
            for (li, chunk) in regs.chunks(4).enumerate() {
                s.push_str(if li == 0 { "  regs: " } else { "        " });
                for (i, (name, val)) in chunk.iter().enumerate() {
                    if i > 0 {
                        s.push(' ');
                    }
                    s.push_str(name);
                    s.push_str("=0x");
                    push_hex(s, *val);
                    let annotation = match report_reg_index(name) {
                        Some(index) => known_annotations[index],
                        // Public reports may contain arbitrary register names.
                        // Preserve HashMap's last-value-wins behavior for them.
                        None => annotations
                            .iter()
                            .rev()
                            .find(|(n, _)| n == name)
                            .map(|(_, value)| value.as_str()),
                    };
                    if let Some(off) = annotation {
                        s.push('(');
                        s.push_str(off);
                        s.push(')');
                    }
                }
                s.push('\n');
            }
        } else {
            // 没开 show_regs 时至少给出 lr/pc(带模块相对地址)
            s.push_str("  lr=0x");
            push_hex(s, self.lr);
            if let Some(ref o) = self.lr_off {
                s.push('(');
                s.push_str(o);
                s.push(')');
            }
            s.push_str(" pc=0x");
            push_hex(s, self.pc);
            if let Some(ref o) = self.pc_off {
                s.push('(');
                s.push_str(o);
                s.push(')');
            }
            s.push('\n');
        }

        // stack 单独一行
        if let Some(ref stack) = self.stack {
            if !stack.is_empty() {
                s.push_str("  stack: ");
                push_joined(s, stack, " <- ");
                s.push('\n');
            }
        }
    }
}

// =====================================================================
// 取证:regs 现在直接来自 BPF 事件的 pt_regs(无需读 /proc)。
// /proc/<pid>/stack 仅用于 kernel backtrace,与 pt_regs 无关。
// =====================================================================

// =====================================================================
// 取证：读 /proc/<pid>/stack 拿 kernel backtrace（文本形式）
// =====================================================================

fn read_kernel_stack(pid: u32) -> Option<String> {
    let path = format!("/proc/{}/stack", pid);
    let s = fs::read_to_string(&path).ok()?;
    if s.trim().is_empty() {
        return None;
    }
    Some(s.trim().to_string())
}

// =====================================================================
// 用户态 → 内核态 动态指令通道
// trace 运行期间从 stdin 读命令,实时改 FILTER map / 动态挂 uprobe 断点。
// =====================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceCommand {
    /// 改 pid 过滤(0 = 不过滤)
    SetPid(u32),
    /// 改 uid 过滤(0 = 不过滤)
    SetUid(u32),
    /// 改 nr 过滤(-1 = 不过滤)
    SetNr(i32),
    /// 清空显式 map 过滤，保留启动时的线程名排除设置
    ClearFilter,
    /// 动态下发 uprobe 断点:库路径 + 文件偏移
    AttachUprobe { lib: String, offset: u64 },
    /// 动态下发硬件断点/观察点。lib 为 Some 时 addr 字段是库内偏移，
    /// 由 apply_command 解析 /proc/<pid>/maps 换算成绝对地址。
    AttachHwBp {
        kind: u32,
        lib: Option<String>,
        offset: u64,
        len: u32,
    },
    /// 按地址移除硬件断点（所有类型）
    DetachHwBp(u64),
    /// SIGSTOP 指定进程
    Pause(u32),
    /// SIGCONT 指定进程
    Cont(u32),
}

impl TraceCommand {
    /// 解析一行 stdin 命令。支持:
    ///   pid 1234 | uid 10283 | nr 56 | nr -1 | any
    ///   brk /path/lib.so 0x135ff8
    ///   w 0x7f001234 [len] | r ... | rw ... | x 0x7f00abcd   （硬件断点）
    ///   bpdel 0x7f001234
    ///   pause 1234 | cont 1234
    pub fn parse(line: &str) -> Option<TraceCommand> {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let mut it = line.split_whitespace();
        let cmd = it.next()?;
        let num = |s: Option<&str>| -> Option<u64> {
            let s = s?;
            if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                u64::from_str_radix(h, 16).ok()
            } else {
                s.parse::<u64>().ok()
            }
        };
        match cmd {
            "pid" => Some(TraceCommand::SetPid(num(it.next())? as u32)),
            "uid" => Some(TraceCommand::SetUid(num(it.next())? as u32)),
            "nr" => {
                let s = it.next()?;
                let v: i64 = if let Some(h) = s.strip_prefix("0x") {
                    i64::from_str_radix(h, 16).ok()?
                } else {
                    s.parse().ok()?
                };
                Some(TraceCommand::SetNr(v as i32))
            }
            "any" | "clear" => Some(TraceCommand::ClearFilter),
            "brk" | "uprobe" => {
                let lib = it.next()?.to_string();
                let offset = num(it.next())?;
                Some(TraceCommand::AttachUprobe { lib, offset })
            }
            "w" | "r" | "rw" | "x" => {
                // 语法: w 0xADDR [len] 或 w libname.so+0xoff [len]
                let target = it.next()?.to_string();
                let len = match it.next() {
                    Some(l) => l.trim().parse::<u32>().ok().filter(|n| matches!(n, 1 | 2 | 4 | 8))?,
                    None => 8,
                };
                let kind = match cmd {
                    "w" => kernel_trace_common::HW_BP_KIND_W,
                    "r" => kernel_trace_common::HW_BP_KIND_R,
                    "rw" => kernel_trace_common::HW_BP_KIND_RW,
                    _ => kernel_trace_common::HW_BP_KIND_X,
                };
                // "0x..." = 绝对地址；"name+0xoff" = 库内偏移（so 名可能含 '+'，
                // 优先按 ".so+" 边界切，如 libc++_shared.so+0x1234）
                let (lib, offset) = if let Some(_h) = target.strip_prefix("0x").or_else(|| target.strip_prefix("0X")) {
                    (None, num(Some(&target))?)
                } else {
                    let split = match target.rfind(".so+").map(|i| i + 3).or_else(|| target.find('+')) {
                        Some(s) => s,
                        None => return None,
                    };
                    let name = target[..split].to_string();
                    let off = num(Some(&target[split + 1..]))?;
                    (Some(name), off)
                };
                if kind == kernel_trace_common::HW_BP_KIND_X {
                    return Some(TraceCommand::AttachHwBp {
                        kind,
                        lib,
                        offset,
                        len: 4,
                    });
                }
                if lib.is_none() && offset % len as u64 != 0 {
                    return None;
                }
                Some(TraceCommand::AttachHwBp { kind, lib, offset, len })
            }
            "bpdel" => Some(TraceCommand::DetachHwBp(num(it.next())?)),
            "pause" | "stop" => Some(TraceCommand::Pause(num(it.next())? as u32)),
            "cont" => Some(TraceCommand::Cont(num(it.next())? as u32)),
            _ => None,
        }
    }
}

// =====================================================================
// Tracer
// =====================================================================

pub struct KernelTracer {
    receiver: report_queue::Receiver<Queued<TraceReport>>,
    cmd_tx: mpsc::Sender<TraceCommand>,
    stop_flag: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    counters: Arc<PipelineCounters>,
    _instance_lock: instance_lock::InstanceLock,
}

impl KernelTracer {
    /// 启动 eBPF + 后台 reader。
    /// opts 决定哪些事件类型 + 过滤条件。
    pub fn start(opts: TraceOptions) -> anyhow::Result<Self> {
        // 硬件断点按目标线程挂（per-task），必须指定 pid
        if !opts.hw_breakpoints.is_empty() && opts.pid == 0 {
            return Err(anyhow!(
                "--bp 硬件断点需要 -p <pid>：观察点是 per-task 资源，必须挂到目标线程上"
            ));
        }
        let instance_lock = instance_lock::InstanceLock::acquire().context("acquire kernel-trace instance lock")?;
        // memlock 上限（仿 ldmonitor）
        let rlim = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        unsafe {
            libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim);
        }

        let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/kernel-trace")))
            .context("load embedded eBPF object and create maps")?;

        // 1) 写 FILTER map
        let mut filter_map: HashMap<_, u32, Filter> =
            HashMap::try_from(ebpf.take_map("FILTER").ok_or_else(|| anyhow!("FILTER map missing"))?)?;
        let mut f = Filter::any();
        f.uid = opts.uid;
        f.pid = opts.pid;
        f.nr = opts.nr;
        f.full_tname = u32::from(opts.full_tname);
        for tid in &opts.tid_blacklist {
            f.add_tid_blacklist(*tid);
        }
        // 内核态 lib 区间过滤:lib_only + 指定了目标库时启用。
        // 启用后 sys_enter 里 lr 不在 LIB_RANGES[pid] 的事件直接丢弃,
        // ring 流量从"全 app"降到"只有目标库",是治 Lost 的根本手段。
        if opts.lib_only && opts.lib_range.is_some() {
            f.lib_only = 1;
            trace_diag!(
                "[trace] LIB_FILTER 内核态过滤已启用(目标:{},区间就绪前的事件将丢弃)",
                opts.lib_range.as_deref().unwrap_or("")
            );
            trace_diag!("[trace] 库来源按 LR 判断：应用 SO 调用保留，系统库来源排除；PC 可以位于 libc");
        }
        filter_map.insert(0u32, f, 0).context("initialize eBPF FILTER map")?;

        // 2) 挂 sys_enter raw_tracepoint
        if opts.enable_syscall {
            let prog: &mut RawTracePoint = ebpf
                .program_mut("raw_sys_sys_enter")
                .ok_or_else(|| anyhow!("sys_enter program missing"))?
                .try_into()?;
            prog.load().context("load sys_enter tracing program")?;
            prog.attach("sys_enter").context("attach sys_enter tracing program")?;

            // 2.5) 挂 sys_exit raw_tracepoint:clone/clone3 返回时把子进程 pid
            // 加入 child_parent_map,实现"指定主进程 pid 自动跟踪整个进程树"。
            // pid 模式必需;lib_only 模式也需要——fork 时把目标库区间复制给
            // 子进程,否则 metasec 的短命反调试子进程(process_vm_readv/ptrace)
            // 活不过用户态 1s 刷新周期,svc 会被 fail-closed 丢掉。
            if opts.pid != 0 || (opts.lib_only && opts.lib_range.is_some()) {
                let prog: &mut RawTracePoint = ebpf
                    .program_mut("raw_sys_sys_exit")
                    .ok_or_else(|| anyhow!("sys_exit program missing"))?
                    .try_into()?;
                prog.load().context("load sys_exit tracing program")?;
                prog.attach("sys_exit").context("attach sys_exit tracing program")?;
            }
        }

        // 3) 挂 uprobe（如果指定）
        // aya 0.14 UProbe::attach 签名:
        //   attach<'a, T: AsRef<Path>, Point: Into<UProbeAttachPoint<'a>>>(
        //       &mut self, point: Point, filename: T, scope: UProbeScope) -> Result<...>
        // Point 可以是 u64 (AbsoluteOffset)、&str (Symbol) 或 UProbeAttachPoint。
        // UProbeScope 决定监听哪些进程(AllProcesses/CallingProcess/OneProcess(pid))。
        // 3) 挂 uprobe（如果指定）
        // aya 0.14 UProbe::attach 签名:
        //   attach<'a, T: AsRef<Path>, Point: Into<UProbeAttachPoint<'a>>>(
        //       &mut self, point: Point, filename: T, scope: UProbeScope) -> Result<...>
        // Point 可以是 u64 (AbsoluteOffset)、&str (Symbol) 或 UProbeAttachPoint。
        // UProbeScope 决定监听哪些进程(AllProcesses/CallingProcess/OneProcess(pid))。
        // lib 可以是全路径(/data/app/...)或纯 so 名(libmetasec_ml.so):
        // 纯名字时延迟解析——spawn 场景库尚未加载,reader 每 1s 扫目标进程
        // maps,出现后自动解析全路径再 attach(最多重试 90s)。
        // (so 名, offset, 已尝试次数):启动参数和动态 brk 命令共用的待解析队列
        let mut pending_resolve: Vec<(String, u64, u32)> = Vec::new();
        if let Some(lib) = opts.uprobe_lib.as_ref() {
            if lib.starts_with('/') {
                use aya::programs::uprobe::UProbeScope;
                let prog: &mut UProbe = ebpf
                    .program_mut("generic_uprobe")
                    .ok_or_else(|| anyhow!("uprobe program missing"))?
                    .try_into()?;
                prog.load()?;
                let scope = if opts.pid != 0 {
                    UProbeScope::OneProcess(std::num::NonZeroU32::new(opts.pid).unwrap())
                } else {
                    UProbeScope::AllProcesses
                };
                prog.attach(opts.uprobe_offset, lib.as_str(), scope)?;
            } else {
                trace_diag!(
                    "[trace] uprobe 目标 {lib} +0x{:x}:等待库加载后自动解析 attach...",
                    opts.uprobe_offset
                );
                pending_resolve.push((lib.clone(), opts.uprobe_offset, 0));
            }
        }

        let (sender, receiver) = report_queue::channel(REPORT_QUEUE_CAPACITY, UPROBE_REPORT_QUEUE_CAPACITY);
        let counters = PipelineCounters::new(
            RAW_QUEUE_CAPACITY,
            UPROBE_QUEUE_CAPACITY,
            HWBP_QUEUE_CAPACITY,
            REPORT_QUEUE_CAPACITY,
            UPROBE_REPORT_QUEUE_CAPACITY,
        );
        trace_diag!(
            "[trace] 详情模式={} workers=svc:{SVC_WORKERS}/uprobe:{UPROBE_WORKERS}/hwbp:{HWBP_WORKERS} raw=svc:{RAW_QUEUE_CAPACITY}/uprobe:{UPROBE_QUEUE_CAPACITY}/hwbp:{HWBP_QUEUE_CAPACITY}",
            if opts.full_detail { "完整(不限详情预算)" } else { "自适应(svc 200ms/s,uprobe 50ms/s;排队超过100ms仅基础事件)" }
        );
        let reader_counters = counters.clone();
        let (cmd_tx, cmd_rx) = mpsc::channel::<TraceCommand>();
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_flag_clone = stop_flag.clone();

        // 硬件断点规格共享表：manager 更新，report worker 用于给事件打 kind 标
        let hwbp_specs = Arc::new(std::sync::Mutex::new(Vec::<HwBpSpec>::new()));

        // --kill:命中事件后挂起目标进程
        let kill_controller = opts.kill_signal.map(|sig| KillController::new(sig));

        let opts_clone = opts.clone();
        let handle = thread::Builder::new().name("ktrace".into()).spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            rt.block_on(async move {
                if let Err(e) = run_reader(
                    ebpf,
                    filter_map,
                    sender,
                    cmd_rx,
                    stop_flag_clone,
                    opts_clone,
                    kill_controller,
                    pending_resolve,
                    reader_counters,
                    hwbp_specs,
                )
                .await
                {
                    trace_diag!("kernel-trace reader error: {e}");
                }
            });
        })?;

        Ok(Self {
            receiver,
            cmd_tx,
            stop_flag,
            handle: Some(handle),
            counters,
            _instance_lock: instance_lock,
        })
    }

    /// 拿一个命令发送端（可跨线程 clone），用于 stdin 动态下发指令
    pub fn command_tx(&self) -> mpsc::Sender<TraceCommand> {
        self.cmd_tx.clone()
    }

    pub fn recv(&self) -> Option<TraceReport> {
        self.receiver.recv().ok().map(|queued| self.deliver(queued))
    }

    pub fn try_recv(&self) -> Option<TraceReport> {
        self.receiver.try_recv().ok().map(|queued| self.deliver(queued))
    }

    /// Wait at most `timeout`, allowing output callers to flush an idle buffer.
    pub fn recv_timeout(&self, timeout: Duration) -> Result<TraceReport, mpsc::RecvTimeoutError> {
        self.receiver.recv_timeout(timeout).map(|queued| self.deliver(queued))
    }

    fn deliver(&self, queued: Queued<TraceReport>) -> TraceReport {
        let (report, _) = queued.dequeue();
        self.counters
            .event_kind(match report.event_kind {
                "svc.enter" => EventKind::Svc,
                "hwbp.hit" => EventKind::HwBp,
                _ => EventKind::Uprobe,
            })
            .delivered
            .fetch_add(1, Ordering::Relaxed);
        report
    }

    /// Live per-session statistics. Delivery means returned to the caller;
    /// only the caller can confirm a subsequent file or terminal write.
    pub fn stats(&self) -> TraceStats {
        self.counters.snapshot()
    }

    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for KernelTracer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

struct ReportWorkers {
    handles: Vec<JoinHandle<()>>,
    stop: Arc<AtomicBool>,
}

impl Drop for ReportWorkers {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for handle in &self.handles {
            handle.thread().unpark();
        }
        for handle in self.handles.drain(..) {
            let _ = handle.join();
        }
    }
}

fn report_worker(
    receiver: Arc<std::sync::Mutex<mpsc::Receiver<Queued<RawEvent>>>>,
    sender: report_queue::Sender<Queued<TraceReport>>,
    stop: Arc<AtomicBool>,
    counters: Arc<PipelineCounters>,
    opts: TraceOptions,
    kill_controller: Option<KillController>,
    load: load::LoadController,
    hwbp_specs: Arc<std::sync::Mutex<Vec<HwBpSpec>>>,
) {
    struct ActiveWorker(Arc<PipelineCounters>);
    impl Drop for ActiveWorker {
        fn drop(&mut self) {
            self.0.active_workers.fetch_sub(1, Ordering::Relaxed);
        }
    }
    counters.active_workers.fetch_add(1, Ordering::Relaxed);
    let _active = ActiveWorker(counters.clone());
    while !stop.load(Ordering::Relaxed) {
        let queued = {
            let Ok(rx) = receiver.lock() else { break };
            if stop.load(Ordering::Relaxed) {
                break;
            }
            rx.recv_timeout(Duration::from_millis(100))
        };
        let queued = match queued {
            Ok(q) => q,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        };
        let (raw, wait) = queued.dequeue();
        let syscall = matches!(&raw, RawEvent::Sys(_));
        let ec = counters.event_kind(raw.kind());
        ec.start(wait);
        let started = Instant::now();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let admission = (!opts.full_detail).then(|| load.begin(syscall, wait));
            let skipped = admission.as_ref().and_then(|a| a.as_ref().err()).copied();
            // The permit is dropped immediately after building, including on panic.
            match raw {
                RawEvent::Sys(ev) => build_report_sys(&ev, &opts, skipped),
                RawEvent::Uprobe(ev) => build_report_uprobe(&ev, &opts, skipped),
                RawEvent::HwBp(ev) => {
                    let specs = hwbp_specs.lock().map(|g| g.clone()).unwrap_or_default();
                    build_report_hwbp(&ev, &opts, skipped, &specs)
                }
            }
        }));
        ec.finish(started.elapsed());
        let report = match result {
            Ok(Some(report)) => report,
            Ok(None) => {
                ec.filtered.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            Err(_) => {
                ec.failed.fetch_add(1, Ordering::Relaxed);
                continue;
            }
        };
        if let Some(reason) = report.detail_skipped {
            if reason == "queue_delay" {
                ec.basic_queue_delay.fetch_add(1, Ordering::Relaxed);
            } else {
                ec.basic_budget.fetch_add(1, Ordering::Relaxed);
            }
        } else {
            ec.full_detail.fetch_add(1, Ordering::Relaxed);
        }
        // Reserve bounded output capacity before performing an event action.
        // This prevents a full report queue from hiding a newly paused process.
        let report_queue = if syscall {
            &counters.report_queue
        } else {
            &counters.uprobe_report_queue
        };
        let queued = match Queued::try_new(report, report_queue) {
            Ok(queued) => queued,
            Err(_) => {
                ec.reports_dropped.fetch_add(1, Ordering::Relaxed);
                continue;
            }
        };
        if let Some(kc) = kill_controller.as_ref() {
            kc.kill_target(queued.value().host_pid);
        }
        match sender.try_send(syscall, queued) {
            Ok(()) => {
                ec.reports_enqueued.fetch_add(1, Ordering::Relaxed);
            }
            Err(mpsc::TrySendError::Full(_)) => {
                ec.reports_dropped.fetch_add(1, Ordering::Relaxed);
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                ec.reports_dropped.fetch_add(1, Ordering::Relaxed);
                stop.store(true, Ordering::SeqCst);
                break;
            }
        }
    }
}

fn print_stats(
    current: &TraceStats,
    previous: &TraceStats,
    elapsed: Duration,
    kernel: Option<[u64; trace_stats::COUNT as usize]>,
) {
    let seconds = elapsed.as_secs_f64().max(0.001);
    for (name, event, prev, pass_idx, drop_idx, thread_idx) in [
        (
            "svc",
            &current.svc,
            &previous.svc,
            trace_stats::SVC_SUBMITTED,
            trace_stats::SVC_RING_DROPPED,
            Some(trace_stats::SVC_THREAD_FILTERED),
        ),
        (
            "uprobe",
            &current.uprobe,
            &previous.uprobe,
            trace_stats::UPROBE_SUBMITTED,
            trace_stats::UPROBE_RING_DROPPED,
            Some(trace_stats::UPROBE_THREAD_FILTERED),
        ),
        (
            "hwbp",
            &current.hwbp,
            &previous.hwbp,
            trace_stats::HWBP_SUBMITTED,
            trace_stats::HWBP_RING_DROPPED,
            None,
        ),
    ] {
        let (pass, ring_drop, thread_filtered) = kernel
            .map(|v| {
                (
                    v[pass_idx as usize].to_string(),
                    v[drop_idx as usize].to_string(),
                    thread_idx.map_or_else(|| "不适用".into(), |i| v[i as usize].to_string()),
                )
            })
            .unwrap_or_else(|| ("?".into(), "?".into(), "?".into()));
        let received = event.received.saturating_sub(prev.received);
        let done = event.completed.saturating_sub(prev.completed);
        let started = event.started.saturating_sub(prev.started);
        let wait_us = event.queue_wait_ns.saturating_sub(prev.queue_wait_ns) as f64 / started.max(1) as f64 / 1000.0;
        let build_us = event.build_ns.saturating_sub(prev.build_ns) as f64 / done.max(1) as f64 / 1000.0;
        trace_diag!(
            "[trace] 对账 dt={seconds:.2}s {name}: 内核通过={pass} 用户态实收={} ring丢弃={ring_drop} 线程名过滤={thread_filtered} 队列丢弃={} 报告丢弃={} 已交付={} 后置过滤={} 构建异常={} 无效记录={} | 增量实收={received} 增量队列丢弃={} 增量报告丢弃={} 完成={:.0}/s 排队均值={wait_us:.1}us 构建均值={build_us:.1}us",
            event.received, event.queue_dropped, event.reports_dropped, event.delivered,
            event.filtered, event.failed, event.invalid,
            event.queue_dropped.saturating_sub(prev.queue_dropped),
            event.reports_dropped.saturating_sub(prev.reports_dropped),
            done as f64 / seconds,
        );
        trace_diag!(
            "[trace] 详情 {name}: 完整={} 基础(预算)={} 基础(排队)={} | 增量完整={} 增量基础={}",
            event.full_detail,
            event.basic_budget,
            event.basic_queue_delay,
            event.full_detail.saturating_sub(prev.full_detail),
            event.basic_budget.saturating_sub(prev.basic_budget)
                + event.basic_queue_delay.saturating_sub(prev.basic_queue_delay),
        );
    }
    if let Some(v) = kernel {
        trace_diag!(
            "[trace] hwbp BPF入口={} UID拒绝={} PID拒绝={} ring提交={} ring丢弃={} (周期快照)",
            v[trace_stats::HWBP_ENTERED as usize],
            v[trace_stats::HWBP_UID_FILTERED as usize],
            v[trace_stats::HWBP_PID_FILTERED as usize],
            v[trace_stats::HWBP_SUBMITTED as usize],
            v[trace_stats::HWBP_RING_DROPPED as usize]
        );
    }
    trace_diag!(
        "[trace] 队列: svc_raw={}/{} 峰值={} uprobe_raw={}/{} 峰值={} hwbp_raw={}/{} 峰值={} svc_report={}/{} 峰值={} uprobe_report={}/{} 峰值={} workers={}",
        current.raw_queue.pending,
        current.raw_queue.capacity,
        current.raw_queue.high_water,
        current.uprobe_raw_queue.pending,
        current.uprobe_raw_queue.capacity,
        current.uprobe_raw_queue.high_water,
        current.hwbp_raw_queue.pending,
        current.hwbp_raw_queue.capacity,
        current.hwbp_raw_queue.high_water,
        current.report_queue.pending,
        current.report_queue.capacity,
        current.report_queue.high_water,
        current.uprobe_report_queue.pending,
        current.uprobe_report_queue.capacity,
        current.uprobe_report_queue.high_water,
        current.active_workers,
    );
}

async fn run_reader(
    mut ebpf: Ebpf,
    mut filter_map: HashMap<aya::maps::MapData, u32, Filter>,
    sender: report_queue::Sender<Queued<TraceReport>>,
    cmd_rx: mpsc::Receiver<TraceCommand>,
    stop_flag: Arc<AtomicBool>,
    opts: TraceOptions,
    kill_controller: Option<KillController>,
    mut pending_resolve: Vec<(String, u64, u32)>,
    counters: Arc<PipelineCounters>,
    hwbp_specs: Arc<std::sync::Mutex<Vec<HwBpSpec>>>,
) -> anyhow::Result<()> {
    // 事件统计 map(内核侧 pass/drop 计数,这里周期读取对账上报)
    let stats_map: Option<aya::maps::PerCpuArray<aya::maps::MapData, u64>> = match ebpf.take_map("TRACE_STATS") {
        Some(m) => match aya::maps::PerCpuArray::try_from(m) {
            Ok(a) => Some(a),
            Err(e) => {
                trace_diag!("[trace] TRACE_STATS map 转换失败: {e}");
                None
            }
        },
        None => {
            trace_diag!("[trace] TRACE_STATS map 不存在(对账不可用)");
            None
        }
    };

    // LIB_FILTER:内核态区间过滤的 map handle(仅 lib_only 模式用)
    let lib_filter_active = opts.lib_only && opts.lib_range.is_some();
    let mut lib_ranges_map: Option<HashMap<aya::maps::MapData, u32, LibRanges>> = if lib_filter_active {
        match ebpf.take_map("LIB_RANGES") {
            Some(m) => Some(HashMap::try_from(m)?),
            None => {
                trace_diag!("[trace] LIB_RANGES map not found, 内核态 lib 过滤退化为用户态过滤");
                None
            }
        }
    } else {
        None
    };
    // pid 模式下扫 fork 子进程(fork 继承 mm 区间相同)
    let child_map: Option<HashMap<aya::maps::MapData, u32, u32>> = if lib_filter_active && opts.pid != 0 {
        ebpf.take_map("CHILD_PARENT_MAP")
            .and_then(|m| HashMap::try_from(m).ok())
    } else {
        None
    };
    // Independent lanes keep occasional probes out of the syscall backlog.
    let (svc_tx, svc_rx) = mpsc::sync_channel::<Queued<RawEvent>>(RAW_QUEUE_CAPACITY);
    let (uprobe_tx, uprobe_rx) = mpsc::sync_channel::<Queued<RawEvent>>(UPROBE_QUEUE_CAPACITY);
    let (hwbp_tx, hwbp_rx) = mpsc::sync_channel::<Queued<RawEvent>>(HWBP_QUEUE_CAPACITY);
    let load = load::LoadController::new();
    let mut workers = ReportWorkers {
        handles: Vec::new(),
        stop: stop_flag.clone(),
    };
    for (name, rx, count) in [
        ("svc", svc_rx, SVC_WORKERS),
        ("uprobe", uprobe_rx, UPROBE_WORKERS),
        ("hwbp", hwbp_rx, HWBP_WORKERS),
    ] {
        let rx = Arc::new(std::sync::Mutex::new(rx));
        for wid in 0..count {
            let opts_w = opts.clone();
            let sender_w = sender.clone();
            let kc_w = kill_controller.clone();
            let rx_w = rx.clone();
            let stop_w = stop_flag.clone();
            let counters_w = counters.clone();
            let load_w = load.clone();
            let specs_w = hwbp_specs.clone();
            workers.handles.push(
                thread::Builder::new()
                    .name(format!("kt-{name}-{wid}"))
                    .spawn(move || report_worker(rx_w, sender_w, stop_w, counters_w, opts_w, kc_w, load_w, specs_w))?,
            );
        }
    }
    drop(sender);

    // Synchronous /proc scans run independently of the ring consumer runtime.
    let (armed_tx, armed_rx) = mpsc::sync_channel(1);
    if let (Some(mut ranges), Some(needle)) = (lib_ranges_map.take(), opts.lib_range.clone()) {
        let stop = stop_flag.clone();
        let pid = opts.pid;
        let uid = opts.uid;
        workers
            .handles
            .push(thread::Builder::new().name("kt-maps".into()).spawn(move || {
                let mut cache = std::collections::HashMap::new();
                let mut armed = false;
                while !stop.load(Ordering::Relaxed) {
                    if refresh_lib_ranges(&mut ranges, &needle, pid, uid, child_map.as_ref(), &mut cache) && !armed {
                        armed = true;
                        let _ = armed_tx.try_send(());
                    }
                    std::thread::park_timeout(if armed {
                        Duration::from_secs(1)
                    } else {
                        Duration::from_millis(100)
                    });
                }
            })?);
    }

    // ===== 硬件断点/观察点管理器 =====
    let mut hwbp = HwBpManager::new(hwbp_specs.clone());
    for spec in &opts.hw_breakpoints {
        let process = read_task_identity(opts.pid, opts.pid).context("read initial hwbp process identity")?;
        let coverage = hwbp
            .attach(&mut ebpf, *spec, process, true)
            .with_context(|| format!("硬件断点 {spec:?} attach 失败"))?;
        trace_diag!(
            "[trace] hwbp attached: {} 0x{:x} len={} pid={} active={} target={} partial={}",
            kernel_trace_common::HwBpEvent::kind_name(spec.kind),
            spec.addr,
            spec.len,
            opts.pid,
            coverage.active,
            coverage.target,
            coverage.active != coverage.target
        );
    }

    // 事件流里的第一个目标 pid（已过 uid 过滤），spawn 模式解析硬件断点目标用
    let hwbp_pid_hint = Arc::new(AtomicU32::new(0));
    for kind in ["SYSCALL_EVENTS", "UPROBE_EVENTS", "HWBP_EVENTS"] {
        let map = ebpf
            .take_map(kind)
            .ok_or_else(|| anyhow!("ringbuf map {kind} missing"))?;
        let ring = aya::maps::RingBuf::try_from(map)?;
        // Register before spawning so startup errors propagate to run_reader.
        let mut async_fd = tokio::io::unix::AsyncFd::new(ring)?;
        let syscall = kind == "SYSCALL_EVENTS";
        let event_kind = match kind {
            "SYSCALL_EVENTS" => EventKind::Svc,
            "HWBP_EVENTS" => EventKind::HwBp,
            _ => EventKind::Uprobe,
        };
        let raw_tx_c = match event_kind {
            EventKind::Svc => svc_tx.clone(),
            EventKind::Uprobe => uprobe_tx.clone(),
            EventKind::HwBp => hwbp_tx.clone(),
        };
        let raw_queue = match event_kind {
            EventKind::Svc => counters.raw_queue.clone(),
            EventKind::Uprobe => counters.uprobe_raw_queue.clone(),
            EventKind::HwBp => counters.hwbp_raw_queue.clone(),
        };
        let stop = stop_flag.clone();
        let counters = counters.clone();
        let hwbp_pid_hint = hwbp_pid_hint.clone();
        tokio::spawn(async move {
            let ec = counters.event_kind(event_kind);
            while !stop.load(Ordering::Relaxed) {
                let mut guard = match async_fd.readable_mut().await {
                    Ok(guard) => guard,
                    Err(e) => {
                        trace_diag!("[trace] {kind} reader failed: {e}");
                        stop.store(true, Ordering::SeqCst);
                        return;
                    }
                };
                let mut exhausted = false;
                for _ in 0..RING_BATCH_SIZE {
                    let Some(item) = guard.get_inner_mut().next() else {
                        exhausted = true;
                        break;
                    };
                    let bytes: &[u8] = &item;
                    let raw = if syscall {
                        if bytes.len() != core::mem::size_of::<SyscallEnterEvent>() {
                            ec.invalid.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        RawEvent::Sys(unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast()) })
                    } else if kind == "UPROBE_EVENTS" {
                        if bytes.len() != core::mem::size_of::<UprobeEvent>() {
                            ec.invalid.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        RawEvent::Uprobe(unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast()) })
                    } else {
                        if bytes.len() != core::mem::size_of::<HwBpEvent>() {
                            ec.invalid.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        RawEvent::HwBp(unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast()) })
                    };
                    // 记录第一个事件的目标 pid：spawn 模式下硬件断点按此解析目标
                    // （事件已过 uid 过滤，pid 必然属于目标进程）
                    let _ = hwbp_pid_hint.compare_exchange(0, raw.pid(), Ordering::SeqCst, Ordering::SeqCst);
                    ec.received.fetch_add(1, Ordering::Relaxed);
                    match raw_tx_c.try_send(Queued::new(raw, &raw_queue)) {
                        Ok(()) => {
                            ec.enqueued.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(mpsc::TrySendError::Full(_)) => {
                            ec.queue_dropped.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(mpsc::TrySendError::Disconnected(_)) => {
                            ec.queue_dropped.fetch_add(1, Ordering::Relaxed);
                            stop.store(true, Ordering::SeqCst);
                            return;
                        }
                    }
                }
                // Do not clear readiness on a partial batch: unread records may
                // not generate another notification until the ring is drained.
                if exhausted {
                    guard.clear_ready();
                }
                drop(guard);
                tokio::task::yield_now().await;
            }
        });
    }
    drop(svc_tx);
    drop(uprobe_tx);
    drop(hwbp_tx);

    let mut resolve_ticks = 0u32;
    let mut hwbp_sweep_ticks = 0u32;
    // 硬件断点目标 pid：-p 给了就用；spawn 模式启动时为 0，首次下发时按 uid 解析
    let mut hwbp_pid = opts.pid;
    // Only unresolved targets are retried. Kernel attach failures are terminal
    // for that request; they must not repeatedly consume resources.
    let mut pending_hwbp: Vec<PendingRequest<TraceCommand>> = Vec::new();
    let mut last_stats = counters.snapshot();
    let mut last_stats_at = Instant::now();
    while !stop_flag.load(Ordering::SeqCst) {
        // Bound command work so a busy command sender cannot monopolize the reader.
        for _ in 0..64 {
            if stop_flag.load(Ordering::SeqCst) {
                break;
            }
            let Ok(cmd) = cmd_rx.try_recv() else { break };
            let epoch = hwbp.cancellations.current();
            let mut expected_process = None;
            // Explicit resubmission replaces, rather than duplicates, a wait.
            pending_hwbp.retain(|request| request.value != cmd);
            match apply_command(
                cmd.clone(),
                &mut ebpf,
                &mut filter_map,
                &mut hwbp_pid,
                opts.uid,
                &mut pending_resolve,
                &mut hwbp,
                epoch,
                &mut expected_process,
                true,
            ) {
                Ok(true) => {
                    let mut request = PendingRequest::new(cmd.clone(), epoch, Instant::now());
                    request.process = expected_process;
                    pending_hwbp.push(request);
                }
                Ok(false) => {}
                Err(e) => {
                    trace_diag!("[trace-cmd] apply failed (不自动重试): {e:#}");
                }
            }
            if let TraceCommand::DetachHwBp(addr) = cmd {
                pending_hwbp.retain(|request| {
                    !matches!(
                        &request.value,
                        TraceCommand::AttachHwBp { lib: None, offset, .. } if *offset == addr
                    )
                });
                // Symbolic waits keep their epoch. Once resolved, an older
                // request for this address is rejected by the cancellation ledger.
            }
        }
        let retry_now = Instant::now();
        if !stop_flag.load(Ordering::SeqCst) && !pending_hwbp.is_empty() {
            // 优先用事件流里捕获的目标 pid（已过 uid 过滤，最可靠）
            if hwbp_pid == 0 {
                let hint = hwbp_pid_hint.load(Ordering::SeqCst);
                if hint != 0 {
                    trace_diag!("[trace-cmd] 从事件流捕获目标 pid={hint}");
                    // 诊断：tracer 进程眼里这个 pid 的 status 长什么样
                    match fs::read_to_string(format!("/proc/{hint}/status")) {
                        Ok(s) => {
                            for line in s.lines() {
                                if line.starts_with("Name:") || line.starts_with("Uid:") || line.starts_with("Threads:")
                                {
                                    trace_diag!("[hwbp-resolve] /proc/{hint}/status: {line}");
                                }
                            }
                        }
                        Err(e) => {
                            trace_diag!("[hwbp-resolve] /proc/{hint}/status 读取失败: {e}");
                        }
                    }
                    hwbp_pid = hint;
                }
            }
            let mut still = Vec::new();
            for mut request in pending_hwbp.drain(..) {
                if stop_flag.load(Ordering::SeqCst) {
                    break;
                }
                if request.expired(retry_now) {
                    trace_diag!("[trace-cmd] 硬件断点等待超时(300s): {:?}", request.value);
                    continue;
                }
                if !request.ready(retry_now) {
                    still.push(request);
                    continue;
                }
                match apply_command(
                    request.value.clone(),
                    &mut ebpf,
                    &mut filter_map,
                    &mut hwbp_pid,
                    opts.uid,
                    &mut pending_resolve,
                    &mut hwbp,
                    request.epoch,
                    &mut request.process,
                    false,
                ) {
                    Ok(true) => {
                        request.defer(Instant::now());
                        still.push(request);
                    }
                    Ok(false) => {}
                    Err(e) => {
                        trace_diag!("[trace-cmd] hwbp attach failed (停止重试): {e:#}");
                    }
                }
            }
            pending_hwbp = still;
        }
        hwbp.cancellations
            .prune(pending_hwbp.iter().map(|request| request.epoch).min());
        if stop_flag.load(Ordering::SeqCst) {
            break;
        }
        let now = Instant::now();
        if now.duration_since(last_stats_at) >= Duration::from_secs(5) {
            let kernel = stats_map.as_ref().and_then(|map| {
                let mut values = [0u64; trace_stats::COUNT as usize];
                for (idx, value) in values.iter_mut().enumerate() {
                    match map.get(&(idx as u32), 0) {
                        Ok(per_cpu) => *value = per_cpu.iter().copied().sum(),
                        Err(e) => {
                            trace_diag!("[trace] TRACE_STATS read failed: {e}");
                            return None;
                        }
                    }
                }
                Some(values)
            });
            let current = counters.snapshot();
            print_stats(&current, &last_stats, now.duration_since(last_stats_at), kernel);
            last_stats = current;
            last_stats_at = now;
        }
        // 硬件断点按目标线程挂，新线程不继承：每 1s 扫 /proc/<pid>/task 补挂
        if !hwbp.is_empty() {
            hwbp_sweep_ticks += 1;
            if hwbp_sweep_ticks % 10 == 0 {
                hwbp.sweep(&mut ebpf);
            }
        }
        if armed_rx.try_recv().is_ok() {
            let mut f = filter_map.get(&0u32, 0).unwrap_or_else(|_| Filter::any());
            f.lib_armed = 1;
            if let Err(e) = filter_map.insert(0u32, f, 0) {
                trace_diag!("[trace] LIB_FILTER state update failed: {e}");
            }
        }
        // 延迟解析:so 名 → 全路径 attach(spawn 场景等库加载)。每 1s 试一次,90s 放弃。
        // 队列来源:启动 --trace-uprobe-lib + 动态 KT>brk(库未加载时入队重试)。
        if !pending_resolve.is_empty() {
            resolve_ticks += 1;
            if resolve_ticks % 10 == 0 {
                let mut still: Vec<(String, u64, u32)> = Vec::new();
                for (name, off, tries) in pending_resolve.drain(..) {
                    match try_resolve_attach(&mut ebpf, &name, off, opts.pid, opts.uid) {
                        Ok(true) => {}
                        Ok(false) => {
                            if tries >= 90 {
                                trace_diag!("[trace-cmd] uprobe 解析超时(90s):{name} 未出现在目标进程 maps");
                            } else {
                                still.push((name, off, tries + 1));
                            }
                        }
                        Err(e) => {
                            trace_diag!("[trace-cmd] uprobe 解析失败:{e}");
                        }
                    }
                }
                pending_resolve = still;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    pending_hwbp.clear();
    hwbp.clear();
    trace_diag!("[trace] hwbp stopped: active=0 pending=0");
    drop(ebpf);
    Ok(())
}

/// 应用一条动态指令:改 FILTER map(内核立即生效),或动态 attach uprobe/硬件断点。
/// 返回 Ok(true) 表示指令被延迟(如 spawn 早期目标进程尚未 specialize),调用方应稍后重试。
fn apply_command(
    cmd: TraceCommand,
    ebpf: &mut Ebpf,
    filter_map: &mut HashMap<aya::maps::MapData, u32, Filter>,
    uprobe_pid: &mut u32,
    uprobe_uid: u32,
    pending_resolve: &mut Vec<(String, u64, u32)>,
    hwbp: &mut HwBpManager,
    request_epoch: u64,
    expected_process: &mut Option<TaskIdentity>,
    explicit_request: bool,
) -> anyhow::Result<bool> {
    match cmd {
        TraceCommand::SetPid(p) => {
            let mut f = filter_map.get(&0u32, 0).ok().unwrap_or_else(Filter::any);
            f.pid = p;
            filter_map.insert(0u32, f, 0)?;
            trace_diag!("[trace-cmd] filter.pid = {p}");
        }
        TraceCommand::SetUid(u) => {
            let mut f = filter_map.get(&0u32, 0).ok().unwrap_or_else(Filter::any);
            f.uid = u;
            filter_map.insert(0u32, f, 0)?;
            trace_diag!("[trace-cmd] filter.uid = {u}");
        }
        TraceCommand::SetNr(n) => {
            let mut f = filter_map.get(&0u32, 0).ok().unwrap_or_else(Filter::any);
            f.nr = n;
            filter_map.insert(0u32, f, 0)?;
            let name = if n >= 0 {
                kernel_trace_common::syscall::nr_to_name(n as i64).unwrap_or("?")
            } else {
                "(任意)"
            };
            trace_diag!("[trace-cmd] filter.nr = {n} ({name})");
        }
        TraceCommand::ClearFilter => {
            let full_tname = filter_map.get(&0u32, 0)?.full_tname;
            let mut f = Filter::any();
            f.full_tname = full_tname;
            filter_map.insert(0u32, f, 0)?;
            trace_diag!("[trace-cmd] filter cleared (保留启动时的线程名排除设置)");
        }
        TraceCommand::AttachUprobe { lib, offset } => {
            // lib 可以是全路径或纯 so 名:名字先解析成路径(解析失败给提示)
            let resolved = if lib.starts_with('/') {
                lib.clone()
            } else {
                match resolve_lib_path(&lib, *uprobe_pid, uprobe_uid) {
                    Some(p) => p,
                    None => {
                        // 库还没加载:入待解析队列,reader 每 1s 自动重试(无需 JS 重发)
                        trace_diag!("[trace-cmd] {lib} 尚未加载,已入队等待自动 attach +0x{offset:x}");
                        pending_resolve.push((lib.clone(), offset, 0));
                        return Ok(false);
                    }
                }
            };
            use aya::programs::uprobe::UProbeScope;
            let prog: &mut UProbe = ebpf
                .program_mut("generic_uprobe")
                .ok_or_else(|| anyhow!("uprobe program missing"))?
                .try_into()?;
            // 重复 attach 会生成新 link,幂等加载无妨
            let _ = prog.load();
            // 动态 KT>brk 仍使用 AllProcesses，再由 FILTER 的 UID/PID 约束
            // 事件范围。Pixel/Android 上 OneProcess uprobe 与同一进程的
            // HWBP perf 事件组合时可能完全没有 BPF 入口；AllProcesses 是
            // 旧实现使用的兼容路径，低频组合回归已确认可进入。这里只记录
            // 实际 scope，便于每轮日志区分 attach 成功和内核事件是否进入。
            trace_diag!("[trace-cmd] uprobe scope=AllProcesses (FILTER uid={uprobe_uid})");
            let scope = UProbeScope::AllProcesses;
            prog.attach(offset, resolved.as_str(), scope)?;
            trace_diag!("[trace-cmd] uprobe attached: {resolved} +0x{offset:x}");
        }
        TraceCommand::AttachHwBp { kind, lib, offset, len } => {
            if !matches!(len, 1 | 2 | 4 | 8) {
                return Err(anyhow!("invalid hwbp length: {len}"));
            }
            if explicit_request {
                // Consume the explicit retry here, even if library resolution
                // must wait. Older queued requests never clear this pause.
                hwbp.automatic_attach_paused = false;
            }
            if *uprobe_pid == 0 {
                // spawn 模式：启动时目标进程不存在，按 uid 解析主进程（线程数最多者）
                match resolve_pid_by_uid(uprobe_uid) {
                    Some(p) => {
                        trace_diag!("[trace-cmd] spawn 模式按 uid={uprobe_uid} 解析到目标 pid={p}");
                        *uprobe_pid = p;
                    }
                    None => {
                        // spawn 极早期:子进程还没 specialize(uid 仍是 zygote 的 0),
                        // 延迟重试,等 uid 出现后再挂
                        trace_diag!("[trace-cmd] uid={uprobe_uid} 尚未出现对应进程,硬件断点延迟重试");
                        return Ok(true);
                    }
                }
            }
            let target_pid = *uprobe_pid;
            let process =
                read_task_identity(target_pid, target_pid).context("read hwbp target identity before maps")?;
            if expected_process.is_some_and(|expected| expected != process) {
                return Err(anyhow!(
                    "hwbp target identity changed while waiting; submit a new request"
                ));
            }
            *expected_process = Some(process);
            // lib+offset：解析目标进程 maps 换算绝对地址（spawn 后库加载完成的场景
            // 由调用方保证；解析失败给出明确提示）
            let addr = match lib.as_deref() {
                Some(name) => {
                    let Some(base) = lib_base_in_pid(target_pid, name).context("read hwbp library maps")? else {
                        return Ok(true);
                    };
                    let addr = base
                        .checked_add(offset)
                        .ok_or_else(|| anyhow!("hwbp address overflow"))?;
                    if kind != HW_BP_KIND_X && addr % len as u64 != 0 {
                        return Err(anyhow!("地址 0x{addr:x} 未按 len={len} 对齐（arm64 观察点要求）"));
                    }
                    addr
                }
                None => {
                    if kind != HW_BP_KIND_X && offset % len as u64 != 0 {
                        return Err(anyhow!("地址 0x{offset:x} 未按 len={len} 对齐（arm64 观察点要求）"));
                    }
                    offset
                }
            };
            if hwbp.cancellations.is_cancelled(addr, request_epoch) {
                trace_diag!("[trace-cmd] hwbp 旧请求已取消: 0x{addr:x}");
                return Ok(false);
            }
            let spec = HwBpSpec { kind, addr, len };
            let coverage = hwbp.attach(ebpf, spec, process, explicit_request)?;
            trace_diag!(
                "[trace-cmd] hwbp attached: {} {}+0x{offset:x} = 0x{addr:x} len={len} pid={target_pid} active={} target={} partial={}",
                kernel_trace_common::HwBpEvent::kind_name(kind),
                lib.as_deref().unwrap_or("abs"),
                coverage.active, coverage.target, coverage.active != coverage.target,
            );
        }
        TraceCommand::DetachHwBp(addr) => {
            let n = hwbp.detach(addr);
            trace_diag!("[trace-cmd] hwbp detached: 0x{addr:x} ({n} 个规格)");
        }
        TraceCommand::Pause(p) => {
            unsafe { libc::kill(p as i32, libc::SIGSTOP) };
            trace_diag!("[trace-cmd] SIGSTOP -> {p}");
        }
        TraceCommand::Cont(p) => {
            unsafe { libc::kill(p as i32, libc::SIGCONT) };
            trace_diag!("[trace-cmd] SIGCONT -> {p}");
        }
    }
    Ok(false)
}

// =====================================================================
// 硬件断点/观察点：slot 管理 + per-task attach + 线程补挂
// =====================================================================

/// Pixel/ARM64 常见硬件槽位默认值。不同内核或虚拟设备可以通过环境变量
/// 覆盖，便于做能力矩阵；实际 attach 失败仍以内核返回的 ENOSPC 为准。
const DEFAULT_MAX_HW_WATCHPOINTS: usize = 4;
const DEFAULT_MAX_HW_BREAKPOINTS: usize = 6;

fn configured_hwbp_limit(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| (1..=16).contains(value))
        .unwrap_or(default)
}

/// 解析 /sys/devices/system/cpu/online（如 "0-3,6,8-11"）。
fn online_cpus() -> Vec<u32> {
    let mut out = Vec::new();
    if let Ok(s) = fs::read_to_string("/sys/devices/system/cpu/online") {
        for part in s.trim().split(',') {
            if let Some((a, b)) = part.split_once('-') {
                if let (Ok(a), Ok(b)) = (a.parse::<u32>(), b.parse::<u32>()) {
                    out.extend(a..=b);
                }
            } else if let Ok(c) = part.parse::<u32>() {
                out.push(c);
            }
        }
    }
    if out.is_empty() {
        out.push(0);
    }
    out
}

struct HwBpAttachedEntry {
    spec: HwBpSpec,
    process: TaskIdentity,
    links: Vec<(HwBpTarget, HwBpLink)>,
    target_count: usize,
}

struct HwBpCoverage {
    active: usize,
    target: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HwBpTarget {
    Thread(TaskIdentity),
    Cpu(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HwBpScope {
    Threads,
    Main,
    SystemWide,
}

/// Both backends own their handles, including on partial startup and errors.
/// SET_BPF remains the default; neither backend is proven crash-free on the
/// affected device. Keep that observation separate from resource ownership.
enum HwBpLink {
    Aya(PerfEventLink),
    Fd(OwnedFd),
}

impl Drop for HwBpLink {
    fn drop(&mut self) {
        match self {
            Self::Fd(fd) => {
                // A failed disable must never prevent OwnedFd from closing.
                unsafe { libc::ioctl(fd.as_raw_fd(), PERF_EVENT_IOC_DISABLE_RAW as _, 0) };
            }
            Self::Aya(_link) => {} // PerfEventLink::drop detaches the owned link.
        }
    }
}

struct HwBpManager {
    entries: Vec<HwBpAttachedEntry>,
    /// 与 report worker 共享的规格表（事件打 kind 标用）
    specs: Arc<std::sync::Mutex<Vec<HwBpSpec>>>,
    scope: HwBpScope,
    sweep_enabled: bool,
    automatic_attach_paused: bool,
    cancellations: CancellationLedger,
    last_sweep_error: Option<Instant>,
}

impl HwBpManager {
    fn new(specs: Arc<std::sync::Mutex<Vec<HwBpSpec>>>) -> Self {
        let watch_limit = configured_hwbp_limit("KT_HWBP_MAX_WATCHPOINTS", DEFAULT_MAX_HW_WATCHPOINTS);
        let breakpoint_limit = configured_hwbp_limit("KT_HWBP_MAX_BREAKPOINTS", DEFAULT_MAX_HW_BREAKPOINTS);
        trace_diag!(
            "[trace] hwbp slot policy: watchpoints={} breakpoints={} (env override supported)",
            watch_limit,
            breakpoint_limit
        );
        HwBpManager {
            entries: Vec::new(),
            specs,
            scope: if std::env::var("KT_HWBP_SYSWIDE").ok().as_deref() == Some("1") {
                HwBpScope::SystemWide
            } else if std::env::var("KT_HWBP_SCOPE").ok().as_deref() == Some("main") {
                HwBpScope::Main
            } else {
                HwBpScope::Threads
            },
            sweep_enabled: std::env::var("KT_HWBP_SWEEP").ok().as_deref() != Some("0"),
            automatic_attach_paused: false,
            cancellations: CancellationLedger::default(),
            last_sweep_error: None,
        }
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn attach(
        &mut self,
        ebpf: &mut Ebpf,
        spec: HwBpSpec,
        process: TaskIdentity,
        explicit_request: bool,
    ) -> anyhow::Result<HwBpCoverage> {
        validate_hwbp_spec(spec)?;
        if self.automatic_attach_paused && !explicit_request {
            return Err(anyhow!(
                "hwbp automatic attach is paused after a resource/configuration error"
            ));
        }
        let pid = process.tid;
        if read_task_identity(pid, pid).context("verify hwbp process identity after maps")? != process {
            return Err(std::io::Error::from_raw_os_error(libc::ESRCH)).context("hwbp process identity changed");
        }
        if explicit_request {
            self.automatic_attach_paused = false;
        }
        if let Some(entry) = self.entries.iter().find(|e| e.spec == spec && e.process == process) {
            return Ok(HwBpCoverage {
                active: entry.links.len(),
                target: entry.target_count,
            });
        }
        if spec.kind == HW_BP_KIND_X {
            let n = self.entries.iter().filter(|e| e.spec.kind == HW_BP_KIND_X).count();
            let limit = configured_hwbp_limit("KT_HWBP_MAX_BREAKPOINTS", DEFAULT_MAX_HW_BREAKPOINTS);
            if n >= limit {
                return Err(anyhow!("执行断点槽位已满({limit})"));
            }
        } else {
            let n = self.entries.iter().filter(|e| e.spec.kind != HW_BP_KIND_X).count();
            let limit = configured_hwbp_limit("KT_HWBP_MAX_WATCHPOINTS", DEFAULT_MAX_HW_WATCHPOINTS);
            if n >= limit {
                return Err(anyhow!("观察点槽位已满({limit})，先 bpdel 释放"));
            }
        }
        let targets: Vec<_> = if self.scope == HwBpScope::SystemWide {
            online_cpus().into_iter().map(HwBpTarget::Cpu).collect()
        } else {
            list_tasks(pid, self.scope == HwBpScope::Main)
                .context("enumerate hwbp threads")?
                .into_iter()
                .map(HwBpTarget::Thread)
                .collect()
        };
        let total = targets.len();
        let mut links = Vec::new();
        let mut attempted = 0usize;
        let mut failed = 0usize;
        let mut last_err = None;
        // A fatal failure suspends automatic additions across all entries.
        for target in targets {
            attempted += 1;
            match hwbp_attach_target(ebpf, spec, process, target) {
                Ok(link) => {
                    links.push((target, link));
                }
                Err(e) => {
                    failed += 1;
                    let disappeared = hwbp_target_disappeared(&e);
                    trace_diag!("[trace] hwbp attach {target:?} 失败: {e:#}");
                    last_err = Some(e);
                    if !disappeared {
                        self.automatic_attach_paused = true;
                        break;
                    }
                }
            }
        }
        trace_diag!(
            "[trace] hwbp attach: active={} target={total} attempted={attempted} failed={failed} scope={:?} partial={} automatic_paused={}",
            links.len(), self.scope, links.len() != total, self.automatic_attach_paused
        );
        if links.is_empty() {
            return Err(last_err.unwrap_or_else(|| anyhow!("无可挂线程")));
        }
        let coverage = HwBpCoverage {
            active: links.len(),
            target: total,
        };
        self.entries.push(HwBpAttachedEntry {
            spec,
            process,
            links,
            target_count: total,
        });
        self.publish_specs();
        Ok(coverage)
    }

    /// Always reclaim ended/reused tasks, even when automatic additions are off.
    fn sweep(&mut self, ebpf: &mut Ebpf) {
        let mut kept = Vec::new();
        for mut entry in std::mem::take(&mut self.entries) {
            let pid = entry.process.tid;
            let current = match read_task_identity(pid, pid) {
                Ok(current) => current,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    self.sweep_error(&e);
                    kept.push(entry);
                    continue;
                }
            };
            if current != entry.process {
                trace_diag!("[trace] hwbp pid={pid} 身份已变化，释放旧会话断点");
                continue;
            }
            if self.scope == HwBpScope::SystemWide {
                kept.push(entry);
                continue;
            }
            let tasks = match list_tasks(pid, self.scope == HwBpScope::Main) {
                Ok(tasks) => tasks,
                Err(e) => {
                    self.sweep_error(&e);
                    kept.push(entry);
                    continue;
                }
            };
            entry.target_count = tasks.len();
            entry.links.retain(|(target, _)| match target {
                HwBpTarget::Thread(identity) => tasks.contains(identity),
                HwBpTarget::Cpu(_) => false,
            });
            if self.sweep_enabled && !self.automatic_attach_paused {
                for task in tasks {
                    let target = HwBpTarget::Thread(task);
                    if entry.links.iter().any(|(t, _)| *t == target) {
                        continue;
                    }
                    match hwbp_attach_target(ebpf, entry.spec, entry.process, target) {
                        Ok(link) => entry.links.push((target, link)),
                        Err(e) if hwbp_target_disappeared(&e) => {}
                        Err(e) => {
                            self.automatic_attach_paused = true;
                            trace_diag!("[trace] hwbp 自动补挂已暂停: {e:#}; 删除释放资源或明确重新下发后再尝试");
                            break;
                        }
                    }
                }
            }
            kept.push(entry);
        }
        self.entries = kept;
        self.publish_specs();
    }

    fn sweep_error(&mut self, error: &std::io::Error) {
        let now = Instant::now();
        if self
            .last_sweep_error
            .is_none_or(|last| now.duration_since(last) >= Duration::from_secs(30))
        {
            trace_diag!("[trace] hwbp 线程快照失败，保留现有句柄: {error}");
            self.last_sweep_error = Some(now);
        }
    }

    fn publish_specs(&self) {
        if let Ok(mut g) = self.specs.lock() {
            *g = self
                .entries
                .iter()
                .filter(|e| !e.links.is_empty())
                .map(|e| e.spec)
                .collect();
        }
    }

    fn detach(&mut self, addr: u64) -> usize {
        self.cancellations.cancel(addr);
        let before = self.entries.len();
        self.entries.retain(|e| e.spec.addr != addr);
        let removed = before - self.entries.len();
        if removed != 0 {
            self.automatic_attach_paused = false;
        }
        self.publish_specs();
        removed
    }

    fn clear(&mut self) {
        self.automatic_attach_paused = true;
        self.entries.clear();
        self.publish_specs();
    }
}

impl Drop for HwBpManager {
    fn drop(&mut self) {
        self.clear();
    }
}

fn validate_hwbp_spec(spec: HwBpSpec) -> anyhow::Result<()> {
    if !matches!(spec.kind, HW_BP_KIND_R | HW_BP_KIND_W | HW_BP_KIND_RW | HW_BP_KIND_X)
        || !matches!(spec.len, 1 | 2 | 4 | 8)
        || (spec.kind == HW_BP_KIND_X && spec.len != 4)
        || spec.addr % spec.len as u64 != 0
    {
        return Err(anyhow!("invalid hardware breakpoint specification: {spec:?}"));
    }
    Ok(())
}

fn hwbp_target_disappeared(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
        .any(|e| e.kind() == std::io::ErrorKind::NotFound || e.raw_os_error() == Some(libc::ESRCH))
}

fn hwbp_attach_target(
    ebpf: &mut Ebpf,
    spec: HwBpSpec,
    process: TaskIdentity,
    target: HwBpTarget,
) -> anyhow::Result<HwBpLink> {
    let check_identity = || -> std::io::Result<()> {
        if read_task_identity(process.tid, process.tid)? != process {
            return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
        }
        if let HwBpTarget::Thread(task) = target {
            if read_task_identity(process.tid, task.tid)? != task {
                return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
            }
        }
        Ok(())
    };
    check_identity().context("verify hwbp task before open")?;
    let link = match target {
        HwBpTarget::Thread(task) => hwbp_attach_one(ebpf, spec, task.tid)?,
        HwBpTarget::Cpu(cpu) => hwbp_attach_one_cpu(ebpf, spec, cpu)?,
    };
    // If a task ended or its numeric ID was reused during open, close the new
    // handle instead of registering it under the stale identity.
    check_identity().context("verify hwbp task after open")?;
    Ok(link)
}

fn hwbp_program(ebpf: &mut Ebpf) -> anyhow::Result<&mut AyaPerfEvent> {
    let prog: &mut AyaPerfEvent = ebpf
        .program_mut("hw_breakpoint")
        .ok_or_else(|| anyhow!("hw_breakpoint program missing"))?
        .try_into()?;
    if prog.fd().is_err() {
        prog.load().context("load hw_breakpoint program")?;
    }
    Ok(prog)
}

/// 对单个线程挂一个硬件断点 perf 事件。
/// 默认 raw open + SET_BPF；保留现有 Aya 后端选择。
fn hwbp_attach_one(ebpf: &mut Ebpf, spec: HwBpSpec, tid: u32) -> anyhow::Result<HwBpLink> {
    if std::env::var("KT_HWBP_AYA_LINK").ok().as_deref() == Some("1") {
        let link = hwbp_attach_one_aya(ebpf, spec, tid)?;
        return Ok(HwBpLink::Aya(link));
    }
    let fd = hwbp_open_raw_setbpf(ebpf, spec, tid as i32, -1)?;
    Ok(HwBpLink::Fd(fd))
}

fn hwbp_attach_one_aya(ebpf: &mut Ebpf, spec: HwBpSpec, tid: u32) -> anyhow::Result<PerfEventLink> {
    let prog = hwbp_program(ebpf)?;
    let config = PerfEventConfig::Breakpoint(match spec.kind {
        HW_BP_KIND_X => BreakpointConfig::Instruction { address: spec.addr },
        k => BreakpointConfig::Data {
            r#type: match k {
                HW_BP_KIND_R => PerfBreakpointType::Read,
                HW_BP_KIND_W => PerfBreakpointType::Write,
                _ => PerfBreakpointType::ReadWrite,
            },
            address: spec.addr,
            length: match spec.len {
                1 => PerfBreakpointLength::Len1,
                2 => PerfBreakpointLength::Len2,
                4 => PerfBreakpointLength::Len4,
                _ => PerfBreakpointLength::Len8,
            },
        },
    });
    // Period(1) = 每次命中采样一次；inherit=false：新线程由 sweep 补挂
    let link = prog.attach(
        config,
        PerfEventScope::OneProcess { pid: tid, cpu: None },
        SamplePolicy::Period(1),
        false,
    )?;
    Ok(prog.take_link(link)?)
}

/// uapi perf_event_attr（libc crate 未对 Android 暴露，自建 112B 布局）。
#[repr(C)]
struct PerfEventAttrRaw {
    type_: u32,
    size: u32,
    config: u64,
    sample_period: u64,
    sample_type: u64,
    read_format: u64,
    flags: u64,
    wakeup_events: u32,
    bp_type: u32,
    bp_addr: u64,
    bp_len: u64,
    branch_sample_type: u64,
    sample_regs_user: u64,
    sample_stack_user: u32,
    clockid: i32,
    sample_regs_intr: u64,
    aux_watermark: u32,
    sample_max_stack: u16,
    reserved_2: u16,
}

const PERF_TYPE_BREAKPOINT_RAW: u32 = 5;
const PERF_COUNT_SW_CPU_CLOCK_RAW: u64 = 0;
const PERF_SAMPLE_TID_RAW: u64 = 1 << 1;
const PERF_SAMPLE_ADDR_RAW: u64 = 1 << 3;
const PERF_FLAG_FD_CLOEXEC_RAW: u64 = 8;
// linux/hw_breakpoint.h
const HW_BP_R: u32 = 1;
const HW_BP_W: u32 = 2;
const HW_BP_X: u32 = 4;

fn hwbp_open_raw(spec: HwBpSpec, pid: i32, cpu: i32) -> anyhow::Result<OwnedFd> {
    let mut attr: PerfEventAttrRaw = unsafe { std::mem::zeroed() };
    attr.size = std::mem::size_of::<PerfEventAttrRaw>() as u32;
    attr.type_ = PERF_TYPE_BREAKPOINT_RAW;
    // Match the working stackplz perf setup.  The BPF context still carries
    // user_pt_regs and addr; ADDR|TID also makes the perf event's sample
    // contract explicit instead of relying on PERF_SAMPLE_RAW alone.
    attr.config = PERF_COUNT_SW_CPU_CLOCK_RAW;
    attr.sample_type = PERF_SAMPLE_TID_RAW | PERF_SAMPLE_ADDR_RAW;
    attr.bp_type = match spec.kind {
        HW_BP_KIND_X => HW_BP_X,
        HW_BP_KIND_R => HW_BP_R,
        HW_BP_KIND_W => HW_BP_W,
        _ => HW_BP_R | HW_BP_W,
    };
    attr.bp_addr = spec.addr;
    attr.bp_len = if spec.kind == HW_BP_KIND_X {
        4
    } else {
        match spec.len {
            1 => 1,
            2 => 2,
            4 => 4,
            _ => 8,
        }
    };
    attr.sample_period = 1;
    attr.wakeup_events = 1;
    attr.flags = 1; // disabled: configure ownership and BPF before activation.
                    // 隔离实验：KT_HWBP_PRECISE=2 时设 precise_ip=2（flags bit15-16），对齐 aya 行为。
    if std::env::var("KT_HWBP_PRECISE").ok().as_deref() == Some("2") {
        attr.flags |= 2 << 15;
    }
    let fd = unsafe { libc::syscall(libc::SYS_perf_event_open, &attr, pid, cpu, -1, PERF_FLAG_FD_CLOEXEC_RAW) } as i32;
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("perf_event_open(hwbp)");
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

const PERF_EVENT_IOC_ENABLE_RAW: u64 = 0x2400;
const PERF_EVENT_IOC_DISABLE_RAW: u64 = 0x2401;
const PERF_EVENT_IOC_SET_BPF_RAW: u64 = 0x4004_2408;

/// 默认 attach 路径：raw perf_event_open（precise_ip=0，与 stackplz 对齐）
/// + PERF_EVENT_IOC_SET_BPF + ENABLE。返回的 perf fd 由调用方持有，
/// OwnedFd 保证配置失败和会话停止也会关闭 fd。
fn hwbp_open_raw_setbpf(ebpf: &mut Ebpf, spec: HwBpSpec, pid: i32, cpu: i32) -> anyhow::Result<OwnedFd> {
    let prog = hwbp_program(ebpf)?;
    let prog_fd = prog.fd().context("get hw_breakpoint program fd")?;
    let prog_raw = prog_fd.as_fd().as_raw_fd();
    let fd = hwbp_open_raw(spec, pid, cpu)?;
    configure_fd(fd, |fd| {
        if unsafe { libc::ioctl(fd.as_raw_fd(), PERF_EVENT_IOC_SET_BPF_RAW as _, prog_raw) } != 0 {
            return Err(std::io::Error::last_os_error()).context("PERF_EVENT_IOC_SET_BPF");
        }
        if unsafe { libc::ioctl(fd.as_raw_fd(), PERF_EVENT_IOC_ENABLE_RAW as _, 0) } != 0 {
            return Err(std::io::Error::last_os_error()).context("PERF_EVENT_IOC_ENABLE");
        }
        Ok(())
    })
}

/// 系统级模式：对单个 CPU 挂全系统硬件断点（pid=-1,cpu=N），BPF 内按 uid/pid 过滤。
/// 与 stackplz 的默认模式一致；离线 CPU 由调用方跳过。
fn hwbp_attach_one_cpu(ebpf: &mut Ebpf, spec: HwBpSpec, cpu: u32) -> anyhow::Result<HwBpLink> {
    if std::env::var("KT_HWBP_AYA_LINK").ok().as_deref() == Some("1") {
        let link = hwbp_attach_one_cpu_aya(ebpf, spec, cpu)?;
        return Ok(HwBpLink::Aya(link));
    }
    let fd = hwbp_open_raw_setbpf(ebpf, spec, -1, cpu as i32)?;
    Ok(HwBpLink::Fd(fd))
}

fn hwbp_attach_one_cpu_aya(ebpf: &mut Ebpf, spec: HwBpSpec, cpu: u32) -> anyhow::Result<PerfEventLink> {
    let prog = hwbp_program(ebpf)?;
    let config = PerfEventConfig::Breakpoint(match spec.kind {
        HW_BP_KIND_X => BreakpointConfig::Instruction { address: spec.addr },
        k => BreakpointConfig::Data {
            r#type: match k {
                HW_BP_KIND_R => PerfBreakpointType::Read,
                HW_BP_KIND_W => PerfBreakpointType::Write,
                _ => PerfBreakpointType::ReadWrite,
            },
            address: spec.addr,
            length: match spec.len {
                1 => PerfBreakpointLength::Len1,
                2 => PerfBreakpointLength::Len2,
                4 => PerfBreakpointLength::Len4,
                _ => PerfBreakpointLength::Len8,
            },
        },
    });
    let link = prog.attach(
        config,
        PerfEventScope::AllProcessesOneCpu { cpu },
        SamplePolicy::Period(1),
        false,
    )?;
    Ok(prog.take_link(link)?)
}

/// spawn 模式下启动时目标 pid 未知，硬件断点首次下发时按 uid 解析。
/// 同 uid 可能有多个进程（app 主进程 + 少量子进程），选线程数最多者——
/// 主进程的线程数远大于 fork 子进程，是可靠的启发式。
fn resolve_pid_by_uid(uid: u32) -> Option<u32> {
    if uid == 0 {
        return None;
    }
    let mut best: Option<(u32, i64)> = None; // (pid, threads)
    let mut scanned = 0usize;
    let mut read_errors = 0usize;
    let mut uid_hits = 0usize;
    let mut max_pid = 0u32;
    let mut samples: Vec<(u32, u32, i64)> = Vec::new();
    let dir = match fs::read_dir("/proc") {
        Ok(d) => d,
        Err(e) => {
            trace_diag!("[hwbp-resolve] read_dir(/proc) 失败: {e}");
            return None;
        }
    };
    for ent in dir.flatten() {
        let Ok(pid) = ent.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        scanned += 1;
        if pid > max_pid {
            max_pid = pid;
        }
        let status = match fs::read_to_string(format!("/proc/{pid}/status")) {
            Ok(s) => s,
            Err(_) => {
                read_errors += 1;
                continue;
            }
        };
        let mut real_uid = None;
        let mut threads = 0i64;
        for line in status.lines() {
            if let Some(v) = line.strip_prefix("Uid:") {
                // Uid: real effective saved fs —— 第一个是 real uid
                real_uid = v.split_whitespace().next().and_then(|s| s.parse().ok());
            } else if let Some(v) = line.strip_prefix("Threads:") {
                threads = v.trim().parse().unwrap_or(0);
            }
        }
        if real_uid == Some(uid) {
            uid_hits += 1;
            if best.map_or(true, |(_, t)| threads > t) {
                best = Some((pid, threads));
            }
        } else if samples.len() < 5 && real_uid.map_or(false, |u| u >= 10000) {
            samples.push((pid, real_uid.unwrap_or(0), threads));
        }
    }
    if best.is_none() {
        let sample_str = samples
            .iter()
            .map(|(p, u, t)| format!("{p}:{u}({t}t)"))
            .collect::<Vec<_>>()
            .join(" ");
        trace_diag!(
            "[hwbp-resolve] uid={uid} 无匹配: scanned={scanned} max_pid={max_pid} read_err={read_errors} uid_hits={uid_hits} 样本={sample_str}"
        );
    }
    best.map(|(pid, _)| pid)
}

/// 观察点事件归属判定：数据观察点按 far 落窗匹配，执行断点按 pc 精确匹配。
fn match_hwbp_spec<'a>(specs: &'a [HwBpSpec], ev: &HwBpEvent) -> Option<&'a HwBpSpec> {
    specs.iter().find(|s| match s.kind {
        HW_BP_KIND_X => ev.pc == s.addr,
        _ => ev.addr >= s.addr && ev.addr < s.addr.wrapping_add(s.len as u64),
    })
}

// =====================================================================
// LIB_FILTER:目标库可执行区间 → BPF LIB_RANGES map
// =====================================================================

/// 每 1s 调用一次:扫目标进程 maps,把目标库的 r-xp 区间写进 BPF map。
///
/// - uid 模式:扫该 uid 全部进程(spawn 自动 uid 的主路径)
/// - pid 模式:扫主进程 + CHILD_PARENT_MAP 里的 fork 子进程
/// - cache 做历史合并:metasec 启动后期会把代码段匿名化(maps 里丢路径),
///   新扫描读不到名字时靠缓存里的旧区间续命(地址不变,只是名字没了)
/// 返回值:本次调用是否有至少一个进程写入了非空区间(用于 armed 判定)
fn refresh_lib_ranges(
    map: &mut HashMap<aya::maps::MapData, u32, LibRanges>,
    needle: &str,
    pid: u32,
    uid: u32,
    child_map: Option<&HashMap<aya::maps::MapData, u32, u32>>,
    cache: &mut std::collections::HashMap<u32, Vec<(u64, u64)>>,
) -> bool {
    let mut any_written = false;
    let mut pids: Vec<u32> = Vec::new();
    if pid != 0 {
        pids.push(pid);
        if let Some(cm) = child_map {
            for k in cm.keys().flatten() {
                if k != pid && !pids.contains(&k) {
                    pids.push(k);
                }
            }
        }
    } else if uid != 0 {
        pids = find_pids_by_uid(uid);
    }
    for p in pids {
        let fresh_named = argspec::read_lib_ranges_named(p, needle);
        // 名字窗口期可能极短(库加载后很快匿名化),赶上就喂给历史命名缓存,
        // 否则之后 lr/pc/栈帧只能显示 (anon)
        if !fresh_named.is_empty() {
            stackwalk::add_hist_mappings(p, &fresh_named);
        }
        let fresh: Vec<(u64, u64)> = fresh_named.into_iter().map(|(lo, hi, _)| (lo, hi)).collect();
        let entry = cache.entry(p).or_default();
        let was_empty = entry.is_empty();
        for r in fresh {
            if !entry.contains(&r) {
                entry.push(r);
            }
        }
        if entry.is_empty() {
            continue; // 库还没加载:保持无记录
        }
        entry.sort_unstable();
        entry.truncate(MAX_LIB_RANGES);
        let mut lr = LibRanges::zero();
        for (i, &(lo, hi)) in entry.iter().enumerate() {
            lr.ranges[i] = [lo, hi];
        }
        lr.count = entry.len() as u32;
        if map.insert(p, lr, 0).is_ok() {
            any_written = true;
            if was_empty {
                trace_diag!(
                    "[trace] LIB_FILTER 激活: pid={p} {} 区间 {} 段,首段 +0x{:x}",
                    needle,
                    entry.len(),
                    entry.first().map(|&(lo, _)| lo).unwrap_or(0)
                );
            }
        }
    }
    any_written
}

// =====================================================================
// so 名 → 全路径解析（/proc/<pid>/maps）
// =====================================================================

/// 在指定进程的 maps 里找名字含 name 的可执行映射全路径
fn find_lib_path_in_pid(pid: u32, name: &str) -> Option<String> {
    let maps = fs::read_to_string(format!("/proc/{}/maps", pid)).ok()?;
    for line in maps.lines() {
        // APK-contained shared objects are mapped r-xs on Android (the
        // filesystem-backed case is r-xp).  Both are executable code and
        // valid uprobe targets; requiring r-xp leaves Pixel 6 libraries
        // permanently stuck in the pending resolver.
        let executable = line
            .split_whitespace()
            .nth(1)
            .map(|perms| perms == "r-xp" || perms == "r-xs")
            .unwrap_or(false);
        if !line.contains(name) || !executable {
            continue;
        }
        // 路径在 inode 列之后
        if let Some(pos) = line.find('/') {
            return Some(line[pos..].trim().to_string());
        }
    }
    None
}

/// 库加载基址：maps 里第一条包含 name 的映射的起始地址。
/// 与 dlopen/so 偏移的惯用基准一致（第一个映射 = ELF 头，dynsym vaddr 相对它）。
fn lib_base_in_pid(pid: u32, name: &str) -> std::io::Result<Option<u64>> {
    let maps = fs::read_to_string(format!("/proc/{}/maps", pid))?;
    for line in maps.lines() {
        if !line.contains(name) {
            continue;
        }
        if let Some(hex) = line.split('-').next() {
            if let Ok(base) = u64::from_str_radix(hex, 16) {
                return Ok(Some(base));
            }
        }
    }
    Ok(None)
}

/// 扫 /proc 找所有属于 uid 的进程
fn find_pids_by_uid(uid: u32) -> Vec<u32> {
    let mut out = Vec::new();
    if let Ok(rd) = fs::read_dir("/proc") {
        for ent in rd.flatten() {
            let name = ent.file_name();
            let Some(s) = name.to_str() else { continue };
            let Ok(pid) = s.parse::<u32>() else { continue };
            if read_proc_uid(pid) == Some(uid) {
                out.push(pid);
            }
        }
    }
    out
}

/// 解析 so 名 → 全路径。pid != 0 只查该进程;否则按 uid 扫全部进程
fn resolve_lib_path(name: &str, pid: u32, uid: u32) -> Option<String> {
    if pid != 0 {
        return find_lib_path_in_pid(pid, name);
    }
    if uid != 0 {
        for p in find_pids_by_uid(uid) {
            if let Some(path) = find_lib_path_in_pid(p, name) {
                return Some(path);
            }
        }
    }
    None
}

/// 延迟解析 attach:库已加载 → attach 并返回 Ok(true);未加载 → Ok(false) 继续等
fn try_resolve_attach(ebpf: &mut Ebpf, name: &str, offset: u64, pid: u32, uid: u32) -> anyhow::Result<bool> {
    let Some(path) = resolve_lib_path(name, pid, uid) else {
        return Ok(false);
    };
    use aya::programs::uprobe::UProbeScope;
    let prog: &mut UProbe = ebpf
        .program_mut("generic_uprobe")
        .ok_or_else(|| anyhow!("uprobe program missing"))?
        .try_into()?;
    prog.load()?;
    let scope = if pid != 0 {
        UProbeScope::OneProcess(std::num::NonZeroU32::new(pid).unwrap())
    } else {
        UProbeScope::AllProcesses
    };
    prog.attach(offset, path.as_str(), scope)?;
    trace_diag!("[trace-cmd] uprobe 解析成功:{name} -> {path}");
    trace_diag!("[trace-cmd] uprobe attached: {path} +0x{offset:x}");
    Ok(true)
}

/// 把 31 GPR + sp + pc + pstate 展开为 Vec<(name, val)>,x30 命名 "lr"。
fn expand_regs_full(regs: &[u64; 31], sp: u64, pc: u64, pstate: u64) -> Vec<(String, u64)> {
    let mut out = Vec::with_capacity(34);
    for i in 0..31 {
        let name = if i == 30 {
            "lr".to_string()
        } else if i == 29 {
            "fp".to_string()
        } else {
            format!("x{}", i)
        };
        out.push((name, regs[i]));
    }
    out.push(("sp".to_string(), sp));
    out.push(("pc".to_string(), pc));
    out.push(("pstate".to_string(), pstate));
    out
}

/// 从 lr_off/pc_off("lib.so+0x.." 或 "0x..(anon)")提取行前缀用的 so 短名
fn so_tag_from(off: &Option<String>) -> String {
    off.as_deref()
        .filter(|s| !s.ends_with("(anon)"))
        .and_then(|s| {
            // 模块名本身可能含 '+'(如 libc++_shared.so):
            // 优先按 ".so+" 边界切,拿不到才退化为按第一个 '+' 切
            if let Some(idx) = s.find(".so+") {
                Some(&s[..idx + 3])
            } else {
                s.split('+').next()
            }
        })
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "anon".to_string())
}

/// uprobe 头部标签:地址没有模块名时,用堆栈中最近的命名帧兜底展示。
/// svc 来源单独按 LR 判断,不使用此展示兜底。
fn tag_with_stack_fallback(off: &Option<String>, stack: &Option<Vec<String>>) -> String {
    let t = so_tag_from(off);
    if t != "anon" {
        return t;
    }
    if let Some(frames) = stack {
        for f in frames {
            let ft = so_tag_from(&Some(f.clone()));
            if ft != "anon" {
                return ft;
            }
        }
    }
    t
}

/// Base reports consult only a previously published snapshot. They never
/// refresh maps, annotate all registers, or read stack/argument memory.
fn cached_module_offsets(
    maps: Option<&stackwalk::MapsSnapshot>,
    lr: u64,
    pc: u64,
) -> (Option<String>, Option<String>, Option<Vec<String>>) {
    match maps {
        Some(maps) => (maps.resolve_addr_named(lr), maps.resolve_addr_named(pc), None),
        None => (None, None, None),
    }
}

fn build_report_sys(
    ev: &SyscallEnterEvent,
    opts: &TraceOptions,
    skipped: Option<load::SkipReason>,
) -> Option<TraceReport> {
    // 用户态后置过滤(白名单/黑名单/UID 黑名单/分组/规则)
    if !opts.syscall_names.is_empty() && !opts.syscall_names.contains(&ev.nr) {
        return None;
    }
    if opts.no_syscall_names.contains(&ev.nr) {
        return None;
    }
    if !opts.uid_blacklist.is_empty() || !opts.process_groups.is_empty() {
        if let Some(uid) = procinfo::get(ev.pid).uid {
            if opts.uid_blacklist.contains(&uid)
                || (!opts.process_groups.is_empty() && !uid_matches_groups(uid, &opts.process_groups))
            {
                return None;
            }
        }
    }
    // lib_range: lr(x30) 落在指定 so 的 r-x 映射内 → 视为该 so 发起的 svc
    let lr = ev.regs[30];
    let lib_hit = match opts.lib_range.as_ref() {
        Some(needle) => argspec::lr_in_lib(ev.pid, lr, needle),
        None => false,
    };
    if opts.lib_only && opts.lib_range.is_some() && !lib_hit {
        return None;
    }
    let maps = if skipped.is_some() {
        stackwalk::cached_snapshot(ev.pid)
    } else {
        Some(stackwalk::snapshot(ev.pid))
    };
    // 参数语义解析:默认只对 lib 命中事件做(读 /proc/<pid>/mem 有开销);
    // 没设 lib_range 时对所有事件解码
    let (decoded_args, dump_blocks) = if skipped.is_none() && opts.decode_args && (opts.lib_range.is_none() || lib_hit)
    {
        match argspec::decode_args_with_options(ev.nr, ev.pid, &ev.regs, opts.dumphex) {
            Some((a, d)) => (Some(a), d),
            None => (None, Vec::new()),
        }
    } else {
        (None, Vec::new())
    };
    // regs 直接用 BPF 事件里的 31 GPR + sp/pc/pstate,不再读 /proc。
    // svc 事件全量输出 31 个寄存器,可解析出模块归属的值额外标注 offset
    let regs_vec = Some(expand_regs_full(&ev.regs, ev.sp, ev.pc, ev.pstate));
    // Even a budget-skipped report may use the last published maps snapshot.
    // Resolving offsets from that immutable cache is cheap and keeps the
    // compact/basic line useful without refreshing /proc or unwinding.
    let regs_off = maps.as_ref().and_then(|maps| {
        let mut v: Vec<(String, String)> = Vec::new();
        for (i, val) in ev.regs.iter().enumerate() {
            if let Some(s) = maps.resolve_addr_named(*val) {
                let name = if i == 30 {
                    "lr".to_string()
                } else if i == 29 {
                    "fp".to_string()
                } else {
                    format!("x{}", i)
                };
                v.push((name, s));
            }
        }
        for (name, val) in [("sp", ev.sp), ("pc", ev.pc)] {
            if let Some(s) = maps.resolve_addr_named(val) {
                v.push((name.to_string(), s));
            }
        }
        if v.is_empty() {
            None
        } else {
            Some(v)
        }
    });
    // lr 相对地址 + 用户态堆栈回溯(fp 链 + stackplz 风格栈扫描合并)
    // resolve_addr 内置历史命名缓存兜底(代码段匿名化场景),无需额外处理
    let should_stack = opts.stack_trace && (opts.lib_range.is_none() || lib_hit);
    let (lr_off, pc_off, stack) = if skipped.is_some() {
        cached_module_offsets(maps.as_ref(), lr, ev.pc)
    } else if let Some(maps) = maps.as_ref() {
        (
            // LR 决定 svc 来源，不能依赖是否开启堆栈，更不能用 PC/栈帧代替。
            maps.resolve_addr_named(lr),
            maps.resolve_addr(ev.pc),
            should_stack.then(|| maps.full_backtrace(ev.pid, ev.regs[29], lr, ev.sp, 12)),
        )
    } else {
        (None, None, None)
    };
    let mut report = TraceReport {
        detail_skipped: skipped.map(load::SkipReason::as_str),
        event_kind: "svc.enter",
        host_pid: ev.pid,
        ns_pid: procinfo::get(ev.pid).ns_pid,
        tid: ev.tid,
        timestamp_ns: ev.timestamp_ns,
        comm: ev.comm_str().to_string(),
        nr: Some(ev.nr),
        regs: regs_vec,
        kernel_stack: None,
        lib_hit,
        decoded_args,
        dump_blocks,
        so_tag: if lr_off.is_none() {
            "unresolved".into()
        } else {
            so_tag_from(&lr_off)
        },
        so_base: maps.as_ref().and_then(|m| m.resolve_base(lr)),
        lr_off,
        pc_off,
        regs_off,
        lr: ev.regs[30],
        pc: ev.pc,
        stack,
        bp_kind: None,
        bp_addr: None,
        instruction: None,
        instructions: None,
    };
    if skipped.is_none() && opts.unwind_stack {
        report.kernel_stack = read_kernel_stack(ev.pid);
    }
    if !opts.filter_rules.is_empty() {
        let regs_slice = report.regs.as_deref().unwrap_or(&[]);
        if !event_passes(&opts.filter_rules, &report.comm, regs_slice) {
            return None;
        }
    }
    Some(report)
}

fn build_report_uprobe(
    ev: &UprobeEvent,
    opts: &TraceOptions,
    skipped: Option<load::SkipReason>,
) -> Option<TraceReport> {
    if !opts.uid_blacklist.is_empty() || !opts.process_groups.is_empty() {
        if let Some(uid) = procinfo::get(ev.pid).uid {
            if opts.uid_blacklist.contains(&uid)
                || (!opts.process_groups.is_empty() && !uid_matches_groups(uid, &opts.process_groups))
            {
                return None;
            }
        }
    }
    let maps = if skipped.is_some() {
        stackwalk::cached_snapshot(ev.pid)
    } else {
        Some(stackwalk::snapshot(ev.pid))
    };
    let regs_vec = Some(expand_regs_full(&ev.regs, ev.sp, ev.pc, ev.pstate));
    // uprobe 命中:pc_off 即断点地址;lr_off 是调用方;fp 链+栈扫描合并回溯
    let (lr_off, pc_off, stack) = if skipped.is_some() {
        cached_module_offsets(maps.as_ref(), ev.regs[30], ev.pc)
    } else if let Some(maps) = maps.as_ref() {
        (
            maps.resolve_addr(ev.regs[30]),
            maps.resolve_addr(ev.pc),
            opts.stack_trace
                .then(|| maps.full_backtrace(ev.pid, ev.regs[29], ev.regs[30], ev.sp, 12)),
        )
    } else {
        (None, None, None)
    };
    let mut report = TraceReport {
        detail_skipped: skipped.map(load::SkipReason::as_str),
        event_kind: "uprobe.hit",
        host_pid: ev.pid,
        ns_pid: procinfo::get(ev.pid).ns_pid,
        tid: ev.tid,
        timestamp_ns: ev.timestamp_ns,
        comm: ev.comm_str().to_string(),
        nr: None,
        regs: regs_vec,
        kernel_stack: None,
        lib_hit: false,
        decoded_args: None,
        dump_blocks: Vec::new(),
        regs_off: maps.as_ref().and_then(|maps| {
            let mut v: Vec<(String, String)> = Vec::new();
            for (i, val) in ev.regs.iter().enumerate() {
                if let Some(s) = maps.resolve_addr_named(*val) {
                    let name = if i == 30 {
                        "lr".to_string()
                    } else if i == 29 {
                        "fp".to_string()
                    } else {
                        format!("x{}", i)
                    };
                    v.push((name, s));
                }
            }
            for (name, val) in [("sp", ev.sp), ("pc", ev.pc)] {
                if let Some(s) = maps.resolve_addr_named(val) {
                    v.push((name.to_string(), s));
                }
            }
            if v.is_empty() {
                None
            } else {
                Some(v)
            }
        }),
        so_tag: if skipped.is_some() && pc_off.is_none() {
            "unresolved".into()
        } else {
            tag_with_stack_fallback(&pc_off, &stack)
        },
        so_base: maps.as_ref().and_then(|m| m.resolve_base(ev.pc)),
        lr_off,
        pc_off,
        lr: ev.regs[30],
        pc: ev.pc,
        stack,
        bp_kind: None,
        bp_addr: None,
        instruction: None,
        instructions: None,
    };
    if skipped.is_none() && opts.unwind_stack {
        report.kernel_stack = read_kernel_stack(ev.pid);
    }
    if !opts.filter_rules.is_empty() {
        let regs_slice = report.regs.as_deref().unwrap_or(&[]);
        if !event_passes(&opts.filter_rules, &report.comm, regs_slice) {
            return None;
        }
    }
    Some(report)
}

/// 硬件断点/观察点命中报告。与 uprobe 同构：pc 即命中点，addr 是访问地址。
/// bp kind 由规格表回查（perf ctx 不携带断点编号）。
fn build_report_hwbp(
    ev: &HwBpEvent,
    opts: &TraceOptions,
    skipped: Option<load::SkipReason>,
    specs: &[HwBpSpec],
) -> Option<TraceReport> {
    if !opts.uid_blacklist.is_empty() || !opts.process_groups.is_empty() {
        if let Some(uid) = procinfo::get(ev.pid).uid {
            if opts.uid_blacklist.contains(&uid)
                || (!opts.process_groups.is_empty() && !uid_matches_groups(uid, &opts.process_groups))
            {
                return None;
            }
        }
    }
    let maps = if skipped.is_some() {
        stackwalk::cached_snapshot(ev.pid)
    } else {
        Some(stackwalk::snapshot(ev.pid))
    };
    let regs_vec = Some(expand_regs_full(&ev.regs, ev.sp, ev.pc, ev.pstate));
    // 命中点：观察点的 pc 是访问现场，执行断点的 pc 就是断点地址
    let (lr_off, pc_off, stack) = if skipped.is_some() {
        cached_module_offsets(maps.as_ref(), ev.regs[30], ev.pc)
    } else if let Some(maps) = maps.as_ref() {
        (
            maps.resolve_addr(ev.regs[30]),
            maps.resolve_addr(ev.pc),
            opts.stack_trace
                .then(|| maps.full_backtrace(ev.pid, ev.regs[29], ev.regs[30], ev.sp, 12)),
        )
    } else {
        (None, None, None)
    };
    let matched = match_hwbp_spec(specs, ev);
    // 以命中 PC 为起点一次读取 16 条 ARM64 指令；批量读取避免每条
    // 指令各打开一次 /proc/<pid>/mem，在高频观察点下只产生一次 I/O。
    let instructions = arm64_disasm::read_window(ev.pid, ev.pc, 16);
    let instruction = instructions.as_ref().and_then(|items| items.first().cloned());
    let mut report = TraceReport {
        detail_skipped: skipped.map(load::SkipReason::as_str),
        event_kind: "hwbp.hit",
        host_pid: ev.pid,
        ns_pid: procinfo::get(ev.pid).ns_pid,
        tid: ev.tid,
        timestamp_ns: ev.timestamp_ns,
        comm: ev.comm_str().to_string(),
        nr: None,
        regs: regs_vec,
        kernel_stack: None,
        lib_hit: false,
        decoded_args: None,
        dump_blocks: Vec::new(),
        regs_off: maps.as_ref().and_then(|maps| {
            let mut v: Vec<(String, String)> = Vec::new();
            for (i, val) in ev.regs.iter().enumerate() {
                if let Some(s) = maps.resolve_addr_named(*val) {
                    let name = if i == 30 {
                        "lr".to_string()
                    } else if i == 29 {
                        "fp".to_string()
                    } else {
                        format!("x{}", i)
                    };
                    v.push((name, s));
                }
            }
            for (name, val) in [("sp", ev.sp), ("pc", ev.pc), ("addr", ev.addr)] {
                if let Some(s) = maps.resolve_addr_named(val) {
                    v.push((name.to_string(), s));
                }
            }
            if v.is_empty() {
                None
            } else {
                Some(v)
            }
        }),
        so_tag: if skipped.is_some() && pc_off.is_none() {
            "unresolved".into()
        } else {
            tag_with_stack_fallback(&pc_off, &stack)
        },
        so_base: maps.as_ref().and_then(|m| m.resolve_base(ev.pc)),
        lr_off,
        pc_off,
        lr: ev.regs[30],
        pc: ev.pc,
        stack,
        bp_kind: matched.map(|s| s.kind),
        bp_addr: Some(if matched.is_some_and(|s| s.kind == HW_BP_KIND_X) {
            ev.pc
        } else {
            ev.addr
        }),
        instruction,
        instructions,
    };
    if skipped.is_none() && opts.unwind_stack {
        report.kernel_stack = read_kernel_stack(ev.pid);
    }
    if !opts.filter_rules.is_empty() {
        let regs_slice = report.regs.as_deref().unwrap_or(&[]);
        if !event_passes(&opts.filter_rules, &report.comm, regs_slice) {
            return None;
        }
    }
    Some(report)
}

/// 从 /proc/<pid>/status 读 Uid 字段(取第一个,real uid)。
fn read_proc_uid(pid: u32) -> Option<u32> {
    let path = format!("/proc/{}/status", pid);
    let content = fs::read_to_string(&path).ok()?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

// =====================================================================
// mini-itoa + JSON escape
// =====================================================================

fn push_u64(out: &mut String, mut n: u64) {
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    out.push_str(std::str::from_utf8(&buf[i..]).expect("decimal digits are ASCII"));
}

fn push_i64(out: &mut String, n: i64) {
    if n < 0 {
        out.push('-');
    }
    push_u64(out, n.unsigned_abs());
}

fn write_disasm_window(
    out: &mut String,
    pc: u64,
    pc_off: Option<&str>,
    instructions: &[InstructionInfo],
    separator: &str,
) {
    for (index, instruction) in instructions.iter().enumerate() {
        if index > 0 {
            out.push_str(separator);
        }
        out.push('#');
        push_u64(out, index as u64);
        out.push('@');
        push_hex(out, pc.saturating_add(index as u64 * 4));
        if let Some(pc_off) = pc_off {
            write_module_offset_annotation(out, pc_off, index as u64);
        }
        out.push('=');
        out.push_str(&instruction.asm);
    }
}

/// 在原始地址后写入模块相对位置。`pc_off` 的格式为 `module+0xoffset`，
/// 窗口内的 AArch64 指令按 4 字节递增；无法解析时保持只有原始地址。
fn write_module_offset_annotation(out: &mut String, module_offset: &str, index: u64) {
    let Some(marker) = module_offset.rfind("+0x") else {
        return;
    };
    let module = &module_offset[..marker];
    let digits = &module_offset[marker + 3..];
    let hex_len = digits.bytes().take_while(|byte| byte.is_ascii_hexdigit()).count();
    if module.is_empty() || hex_len == 0 {
        return;
    }
    let Ok(base_offset) = u64::from_str_radix(&digits[..hex_len], 16) else {
        return;
    };
    out.push('(');
    out.push_str(module);
    out.push_str("+0x");
    push_hex(out, base_offset.saturating_add(index.saturating_mul(4)));
    out.push(')');
}

fn push_hex(out: &mut String, mut n: u64) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [0u8; 16];
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = HEX[(n & 0xf) as usize];
        n >>= 4;
        if n == 0 {
            break;
        }
    }
    out.push_str(std::str::from_utf8(&buf[i..]).expect("hex digits are ASCII"));
}

fn push_hex_fixed_byte(out: &mut String, byte: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push(HEX[(byte >> 4) as usize] as char);
    out.push(HEX[(byte & 0xf) as usize] as char);
}

fn push_json_escaped(out: &mut String, value: &str) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut plain_start = 0;
    for (i, &byte) in value.as_bytes().iter().enumerate() {
        if byte >= 0x20 && byte != b'"' && byte != b'\\' {
            continue;
        }
        // Every split is at an ASCII character, hence a UTF-8 boundary.
        out.push_str(&value[plain_start..i]);
        match byte {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            _ => {
                out.push_str("\\u00");
                out.push(HEX[(byte >> 4) as usize] as char);
                out.push(HEX[(byte & 0xf) as usize] as char);
            }
        }
        plain_start = i + 1;
    }
    out.push_str(&value[plain_start..]);
}

fn push_joined(out: &mut String, values: &[String], separator: &str) {
    for (i, value) in values.iter().enumerate() {
        if i > 0 {
            out.push_str(separator);
        }
        out.push_str(value);
    }
}

fn report_reg_index(name: &str) -> Option<usize> {
    match name {
        "fp" => Some(29),
        "lr" => Some(30),
        "sp" => Some(31),
        "pc" => Some(32),
        "pstate" => Some(33),
        _ => match name.as_bytes() {
            [b'x', digit @ b'0'..=b'9'] => Some((digit - b'0') as usize),
            [b'x', tens @ b'1'..=b'2', units @ b'0'..=b'9'] => {
                let index = ((tens - b'0') * 10 + (units - b'0')) as usize;
                (index < 29).then_some(index)
            }
            _ => None,
        },
    }
}

/// 从寄存器偏移表中取出某个寄存器的模块标注。
///
/// 报告构建阶段使用固定的 AArch64 寄存器名称，但保留对外部构造报告中
/// 自定义名称的支持；反向查找与完整详情分支的“最后一次覆盖”语义一致。
fn report_reg_annotation<'a>(annotations: &'a [(String, String)], name: &str) -> Option<&'a str> {
    annotations
        .iter()
        .rev()
        .find(|(registered, _)| registered == name)
        .map(|(_, value)| value.as_str())
}

// 占位避免 lib.rs 编译 warning（BufRead 等未实际使用但保留用于未来 kallsyms/maps 解析）
#[allow(dead_code)]
fn _bufread_unused() {
    let _: Option<BufReader<&[u8]>> = None;
    let _: Option<&Path> = None;
    let _: Option<Box<dyn Read + Send>> = None;
}

// MAX_TID_BLACKLIST_COUNT re-export 给外部使用
pub use kernel_trace_common::MAX_TID_BLACKLIST_COUNT as _MAX_TID;
