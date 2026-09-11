//! kernel-trace standalone CLI — 验证 / 调试用。
//!
//! 与 stackplz 的 `stackplz stack` / `stackplz syscall` 用法对齐。
//! 真正的"单二进制 rustfrida"模式在 `rust_frida --mode=trace` 中。

use clap::Parser;
use kernel_trace::{parse_filter_list, parse_signal, KernelTracer, TraceOptions};
use kernel_trace_common::{parse_process_group, parse_syscall_list};
use std::thread;

#[derive(Debug, Parser)]
#[command(name = "kernel-trace", about = "eBPF syscall/uprobe tracer (rustfrida-embedded)")]
struct Opt {
    /// 跟踪这个 PID（0 = 不过滤）
    #[arg(short = 'p', long, default_value_t = 0)]
    pid: u32,

    /// 跟踪这个 UID（0 = 不过滤）
    #[arg(short = 'u', long, default_value_t = 0)]
    uid: u32,

    /// 只跟踪这个 syscall 号（-1 = 不过滤）
    #[arg(short = 'n', long, default_value = "-1")]
    nr: i32,

    /// TID 黑名单（逗号分隔）
    #[arg(short = 'b', long, value_delimiter = ',')]
    tid_blacklist: Vec<u32>,

    /// 关闭默认线程名黑名单（comm 仍最多 15 字节，显式过滤仍生效）
    #[arg(long)]
    full_tname: bool,

    /// 读 /proc/<pid>/syscall 抓 33 个 GPR
    #[arg(long)]
    show_regs: bool,

    /// 读 /proc/<pid>/stack 抓 kernel backtrace
    #[arg(long)]
    unwind_stack: bool,

    /// 单 reg 提取（x0..x30 / sp / pc / pstate）
    #[arg(long)]
    reg_name: Option<String>,

    /// 通用 uprobe：目标库绝对路径
    #[arg(short = 'l', long)]
    uprobe_lib: Option<String>,

    /// uprobe 偏移（与 --uprobe-lib 配对）
    #[arg(short = 'o', long)]
    uprobe_offset: Option<u64>,

    /// 是否挂 sys_enter tracepoint（默认开）
    #[arg(long, default_value_t = true)]
    enable_syscall: bool,

    // ===== stackplz 风格扩展 =====
    /// syscall 名白名单（逗号分隔，可含数字/名字/%file %net ...）
    #[arg(long = "syscall", value_name = "LIST")]
    syscall: Option<String>,

    /// syscall 名黑名单
    #[arg(long = "no-syscall", value_name = "LIST")]
    no_syscall: Option<String>,

    /// UID 黑名单
    #[arg(long = "no-uid", value_delimiter = ',')]
    no_uid: Vec<u32>,

    /// 进程分组（app/iso/root/system/shell/media/all）
    #[arg(long = "group", value_name = "GROUP")]
    group: Option<String>,

    /// 过滤规则（可多次使用）
    #[arg(short = 'f', long = "filter", value_name = "RULES")]
    filter: Vec<String>,

    /// 命中后给目标进程发信号
    #[arg(long = "kill", value_name = "SIGNAL")]
    kill: Option<String>,

    /// buffer 字段 hex+ASCII 输出
    #[arg(long)]
    dumphex: bool,

    /// ANSI 颜色
    #[arg(long)]
    color: bool,

    /// Disable the default detail budget/queue-age guard (may affect responsiveness)
    #[arg(long)]
    full_detail: bool,

    /// 硬件断点/观察点，格式 kind:addr[:len]，kind ∈ r/w/rw/x，len ∈ 1/2/4/8（缺省 8）。
    /// 例：--bp w:0x7f001234 --bp x:0x7f00abcd --bp rw:0x7f001230:4。需配合 -p <pid>。
    #[arg(long = "bp", value_name = "SPEC")]
    bp: Vec<String>,
}

fn main() -> anyhow::Result<()> {
    unsafe {
        let _ = libc::prctl(libc::PR_SET_NAME, b"ktracer\0".as_ptr(), 0, 0, 0);
    }
    env_logger::init();

    let opt = Opt::parse();

    let mut opts = TraceOptions::default();
    opts.pid = opt.pid;
    opts.uid = opt.uid;
    opts.nr = opt.nr;
    opts.tid_blacklist = opt.tid_blacklist;
    opts.full_tname = opt.full_tname;
    opts.show_regs = opt.show_regs;
    opts.unwind_stack = opt.unwind_stack;
    opts.reg_name = opt.reg_name.clone();
    opts.uprobe_lib = opt.uprobe_lib.clone();
    opts.uprobe_offset = opt.uprobe_offset.unwrap_or(0);
    opts.enable_syscall = opt.enable_syscall;
    opts.uid_blacklist = opt.no_uid.clone();
    opts.dumphex = opt.dumphex;
    opts.color = opt.color;
    opts.full_detail = opt.full_detail;

    if let Some(s) = &opt.syscall {
        opts.syscall_names = parse_syscall_list(s).map_err(anyhow::Error::msg)?;
    }
    if let Some(s) = &opt.no_syscall {
        opts.no_syscall_names = parse_syscall_list(s).map_err(anyhow::Error::msg)?;
    }
    if let Some(s) = &opt.group {
        opts.process_groups = parse_process_group(s).map_err(anyhow::Error::msg)?;
    }
    for f in &opt.filter {
        opts.filter_rules
            .extend(parse_filter_list(f).map_err(anyhow::Error::msg)?);
    }
    if let Some(s) = &opt.kill {
        opts.kill_signal = Some(parse_signal(s).map_err(anyhow::Error::msg)?);
    }
    for b in &opt.bp {
        opts.hw_breakpoints
            .push(kernel_trace_common::HwBpEvent::parse_spec(b).ok_or_else(|| {
                anyhow::anyhow!("无效的 --bp 规格 {b:?}（格式 kind:addr[:len]，kind ∈ r/w/rw/x，addr 需按 len 对齐）")
            })?);
    }

    let tracer = KernelTracer::start(opts)?;
    println!(
        "{{\"type\":\"tracer.ready\",\"mode\":\"kernel-trace\",\"show_regs\":{},\"unwind_stack\":{}}}",
        opt.show_regs, opt.unwind_stack
    );

    // stdin 动态指令：spawn 场景等库加载后再下发硬件断点
    //   w/r/rw/x libname.so+0xoff [len] | w/r/rw/x 0xADDR [len] | bpdel 0xADDR
    //   pid/uid/nr/any | brk lib off | pause/cont pid
    {
        let cmd_tx = tracer.command_tx();
        thread::spawn(move || {
            use std::io::BufRead;
            let stdin = std::io::stdin();
            for line in stdin.lock().lines() {
                let Ok(line) = line else { break };
                match kernel_trace::TraceCommand::parse(&line) {
                    Some(cmd) => {
                        if cmd_tx.send(cmd).is_err() {
                            break;
                        }
                    }
                    None => {
                        if !line.trim().is_empty() && !line.trim().starts_with('#') {
                            eprintln!("KT> 无法解析命令: {line}");
                        }
                    }
                }
            }
        });
    }

    let mut output = kernel_trace::sink::BufferedOutput::new(std::io::stdout());
    let mut line = String::with_capacity(2048);
    loop {
        match tracer.recv_timeout(output.wait_timeout()) {
            Ok(report) => {
                line.clear();
                report.write_jsonl(&mut line);
                line.push('\n');
                output.write_record(&line)?;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
        output.flush_due()?;
    }
    output.flush()?;

    Ok(())
}
