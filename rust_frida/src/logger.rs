use std::fs::OpenOptions;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

pub(crate) use crate::log_output::LogOutputStats;
use crate::log_output::{AsyncOutput, Source};

/// 全局 verbose 开关（由 --verbose 标志控制）
pub static VERBOSE: AtomicBool = AtomicBool::new(false);
static LOG_OUTPUT: OnceLock<AsyncOutput> = OnceLock::new();
static OUTPUT_INIT: Mutex<()> = Mutex::new(());
static SHUTDOWN_HEALTH_REPORTED: AtomicBool = AtomicBool::new(false);

pub fn is_verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

pub fn init_output_file(path: &str) -> std::io::Result<()> {
    let _initializing = OUTPUT_INIT.lock().unwrap_or_else(|poison| poison.into_inner());
    // Check before opening: a repeated init must never truncate either path.
    if LOG_OUTPUT.get().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "output file is already initialized",
        ));
    }
    let file = OpenOptions::new().create(true).write(true).truncate(true).open(path)?;
    let output = AsyncOutput::new(file)?;
    LOG_OUTPUT
        .set(output)
        .map_err(|_| io::Error::new(io::ErrorKind::AlreadyExists, "output file is already initialized"))?;
    #[cfg(unix)]
    {
        // Pure FFI keeps the independent host tests free of a libc dependency.
        // C atexit runs for std::process::exit too; abort/SIGKILL cannot flush.
        unsafe extern "C" {
            fn atexit(callback: extern "C" fn()) -> std::os::raw::c_int;
        }
        if unsafe { atexit(flush_at_exit) } != 0 {
            let _ = shutdown_output();
            return Err(io::Error::other("failed to register output shutdown handler"));
        }
    }
    Ok(())
}

#[cfg(unix)]
extern "C" fn flush_at_exit() {
    // Never unwind through a C exit hook. The writer performs bounded waits.
    let _ = std::panic::catch_unwind(|| {
        let _ = shutdown_output();
    });
}

pub fn has_output_file() -> bool {
    LOG_OUTPUT.get().is_some()
}

pub fn check_output() -> io::Result<()> {
    LOG_OUTPUT.get().map_or(Ok(()), AsyncOutput::check)
}

pub fn flush_output() -> io::Result<()> {
    LOG_OUTPUT.get().map_or(Ok(()), AsyncOutput::flush)
}

pub fn shutdown_output() -> io::Result<()> {
    let result = LOG_OUTPUT.get().map_or(Ok(()), AsyncOutput::shutdown);
    if let Some(output) = LOG_OUTPUT.get() {
        let stats = output.stats();
        let dropped = stats.host_dropped != 0 || stats.agent_dropped != 0 || stats.kernel_dropped != 0;
        let pending = stats.pending_records != 0 || stats.pending_bytes != 0 || stats.buffered_bytes != 0;
        // A sticky I/O error was already reported by the writer. A timeout or
        // rejected shutdown barrier still needs an explicit incomplete notice.
        let incomplete = result.is_err() && (stats.errors == 0 || pending);
        if (incomplete || dropped) && !SHUTDOWN_HEALTH_REPORTED.swap(true, Ordering::AcqRel) {
            if let Err(error) = &result {
                eprintln!(
                    "[output] 退出刷新未完成: {} | 待处理记录={} 待处理字节={} 缓冲字节={} | 丢弃 host={} agent={} kernel={}",
                    error, stats.pending_records, stats.pending_bytes, stats.buffered_bytes,
                    stats.host_dropped, stats.agent_dropped, stats.kernel_dropped,
                );
            } else {
                eprintln!(
                    "[output] 输出丢弃汇总: host={} agent={} kernel={} | 待处理记录={} 待处理字节={} 缓冲字节={}",
                    stats.host_dropped,
                    stats.agent_dropped,
                    stats.kernel_dropped,
                    stats.pending_records,
                    stats.pending_bytes,
                    stats.buffered_bytes,
                );
            }
        }
    }
    result
}

pub(crate) fn output_stats() -> LogOutputStats {
    LOG_OUTPUT
        .get()
        .map_or_else(LogOutputStats::default, AsyncOutput::stats)
}

fn complete_record(mut text: String) -> String {
    if !text.ends_with('\n') {
        text.push('\n');
    }
    text
}

pub fn write_kernel_record(record: &str) -> io::Result<()> {
    let output = LOG_OUTPUT
        .get()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "output file is not initialized"))?;
    let plain = strip_ansi(record);
    let mut text = String::with_capacity(plain.len() + 10);
    text.push_str("[kernel] ");
    text.push_str(&plain);
    output.enqueue(Source::Kernel, complete_record(text))
}

pub fn agent_line(session_id: u32, colored: &str, plain: &str) {
    if let Some(output) = LOG_OUTPUT.get() {
        let text = format!("[agent#{}] {}", session_id, strip_ansi(plain));
        let _ = output.enqueue(Source::Agent, complete_record(text));
    } else {
        println!("{}", colored);
    }
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\x1b' && chars.peek() == Some(&'[') {
            chars.next();
            for c in chars.by_ref() {
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(ch);
        }
    }
    out
}

pub fn write_log_line(line: &str) {
    if let Some(output) = LOG_OUTPUT.get() {
        let source = if line.starts_with("[agent]") || line.starts_with("[agent#") {
            Source::Agent
        } else {
            Source::Host
        };
        let _ = output.enqueue(source, complete_record(strip_ansi(line)));
    }
}

pub fn stdout_line(colored: &str, plain: &str) {
    if has_output_file() {
        write_log_line(plain);
    } else {
        println!("{}", colored);
    }
}

/// Ordinary unprefixed output follows the same destination as other host logs.
pub fn text_line(text: &str) {
    stdout_line(text, text);
}

/// Interactive help/status stays visible and is also copied into --output.
/// Input editing and terminal control sequences still belong to rustyline.
pub fn console_line(text: &str) {
    write_log_line(text);
    println!("{text}");
}

#[macro_export]
macro_rules! console_log {
    () => { $crate::logger::console_line("") };
    ($($arg:tt)*) => {{
        $crate::logger::console_line(&format!($($arg)*));
    }};
}

pub fn stderr_line(colored: &str, plain: &str) {
    write_log_line(plain);
    eprintln!("{}", colored);
}

/// ANSI 颜色常量
pub const RESET: &str = "\x1b[0m";
pub const BOLD: &str = "\x1b[1m";
pub const DIM: &str = "\x1b[2m";

pub const RED: &str = "\x1b[31m";
pub const GREEN: &str = "\x1b[32m";
pub const YELLOW: &str = "\x1b[33m";
pub const BLUE: &str = "\x1b[34m";
pub const MAGENTA: &str = "\x1b[35m";
pub const CYAN: &str = "\x1b[36m";

/// 256 色扩展常量（rustyline Highlighter 专用）
pub const GRAY: &str = "\x1b[38;5;245m";
pub const HIGHLIGHT_BG: &str = "\x1b[48;5;238m";
pub const HIGHLIGHT_FG: &str = "\x1b[38;5;255m";

/// [*] 蓝色前缀 - 通用信息
#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {{
        let msg = format!($($arg)*);
        $crate::logger::stdout_line(
            &format!("{}{} [*]{} {}", $crate::logger::BOLD, $crate::logger::BLUE, $crate::logger::RESET, msg),
            &format!("[*] {}", msg),
        );
    }};
}

/// [✓] 绿色前缀 - 成功操作
#[macro_export]
macro_rules! log_success {
    ($($arg:tt)*) => {{
        let msg = format!($($arg)*);
        $crate::logger::stdout_line(
            &format!("{}{} [✓]{} {}", $crate::logger::BOLD, $crate::logger::GREEN, $crate::logger::RESET, msg),
            &format!("[✓] {}", msg),
        );
    }};
}

/// [!] 黄色前缀 - 警告
#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {{
        let msg = format!($($arg)*);
        $crate::logger::stderr_line(
            &format!("{}{} [!]{} {}", $crate::logger::BOLD, $crate::logger::YELLOW, $crate::logger::RESET, msg),
            &format!("[!] {}", msg),
        );
    }};
}

/// [✗] 红色前缀 - 错误（输出到 stderr）
#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {{
        let msg = format!($($arg)*);
        $crate::logger::stderr_line(
            &format!("{}{} [✗]{} {}", $crate::logger::BOLD, $crate::logger::RED, $crate::logger::RESET, msg),
            &format!("[✗] {}", msg),
        );
    }};
}

/// [→] 青色前缀 - 步骤/详细信息
#[macro_export]
macro_rules! log_step {
    ($($arg:tt)*) => {{
        let msg = format!($($arg)*);
        $crate::logger::stdout_line(
            &format!("{}{} [→]{} {}", $crate::logger::BOLD, $crate::logger::CYAN, $crate::logger::RESET, msg),
            &format!("[→] {}", msg),
        );
    }};
}

/// 地址显示 - 带缩进的地址格式化
#[macro_export]
macro_rules! log_addr {
    ($label:expr, $addr:expr) => {{
        let plain = format!("     {}: 0x{:x}", $label, $addr);
        $crate::logger::stdout_line(
            &format!(
                "     {}: {}0x{:x}{}",
                $label,
                $crate::logger::DIM,
                $addr,
                $crate::logger::RESET
            ),
            &plain,
        );
    }};
}

/// [→] 仅 --verbose 时输出的详细步骤信息
#[macro_export]
macro_rules! log_verbose {
    ($($arg:tt)*) => {{
        if $crate::logger::is_verbose() {
            let msg = format!($($arg)*);
            $crate::logger::stdout_line(
                &format!("{}{} [→]{} {}", $crate::logger::BOLD, $crate::logger::CYAN, $crate::logger::RESET, msg),
                &format!("[→] {}", msg),
            );
        }
    }};
}

/// 地址显示 - 仅 --verbose 时输出
#[macro_export]
macro_rules! log_verbose_addr {
    ($label:expr, $addr:expr) => {{
        if $crate::logger::is_verbose() {
            let plain = format!("     {}: 0x{:x}", $label, $addr);
            $crate::logger::stdout_line(
                &format!(
                    "     {}: {}0x{:x}{}",
                    $label,
                    $crate::logger::DIM,
                    $addr,
                    $crate::logger::RESET
                ),
                &plain,
            );
        }
    }};
}

/// [agent] 紫色前缀 - 来自 agent 的消息
#[macro_export]
macro_rules! log_agent {
    ($($arg:tt)*) => {{
        let msg = format!($($arg)*);
        $crate::logger::stdout_line(
            &format!("{}{} [agent]{} {}", $crate::logger::BOLD, $crate::logger::MAGENTA, $crate::logger::RESET, msg),
            &format!("[agent] {}", msg),
        );
    }};
}

/// 打印 banner
pub fn print_banner() {
    let version = env!("CARGO_PKG_VERSION");
    stdout_line(
        &format!(
            "\n {BOLD}{CYAN}╔══════════════════════════════════════╗{RESET}\n \
             {BOLD}{CYAN}║{RESET}  {BOLD}      rustFrida v{version:<17} {RESET}{BOLD}{CYAN}║{RESET}\n \
             {BOLD}{CYAN}║{RESET}  {DIM}  ARM64 Dynamic Instrumentation    {RESET}{BOLD}{CYAN}║{RESET}\n \
             {BOLD}{CYAN}╚══════════════════════════════════════╝{RESET}\n"
        ),
        &format!(
            "\n ╔══════════════════════════════════════╗\n \
             ║        rustFrida v{version:<17} ║\n \
             ║    ARM64 Dynamic Instrumentation    ║\n \
             ╚══════════════════════════════════════╝\n"
        ),
    );
}
