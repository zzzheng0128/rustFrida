//! 目标进程和设备异常监控。
//!
//! 这层运行在 rustfrida 宿主进程中，不接管 ART 的 SIGSEGV 链。Android ART
//! 会把 SIGSEGV 用于隐式空指针检查和栈溢出检测，直接安装全局 handler 会把
//! 正常的 managed exception 误判成 native crash。这里通过 /proc、Agent socket
//! 状态和 boot id 做低开销轮询；出现异常时把最后一份现场写成 JSONL，便于
//! runner 在 adb 侧拉回并和 logcat/pstore 对照。

#![cfg(all(target_os = "android", target_arch = "aarch64"))]

use crate::{logger, session::Session};
use std::fs::OpenOptions;
use std::io::Write;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const POLL_INTERVAL: Duration = Duration::from_millis(100);
const MAX_PROC_FIELD: usize = 16 * 1024;
const MAX_COMMAND_OUTPUT: usize = 48 * 1024;

struct ProcObservation {
    state: char,
    start_time: Option<u64>,
    exit_code: Option<i64>,
    stat: String,
    status: String,
    cmdline: String,
    wchan: String,
    syscall: String,
    stack: String,
}

/// 可停止的异常监控线程。Drop 只停止线程，不会向目标进程发信号。
pub(crate) struct Monitor {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Monitor {
    pub(crate) fn start(pid: i32, session: Arc<Session>, output_hint: Option<&str>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = stop.clone();
        let report_path = report_path(pid, output_hint);
        logger::stderr_line(
            &format!("[异常监控] pid={}，现场输出: {}", pid, report_path),
            &format!("[异常监控] pid={}，现场输出: {}", pid, report_path),
        );
        let thread = thread::Builder::new()
            .name("rustfrida-anomaly".into())
            .spawn(move || monitor_loop(pid, session, report_path, stop_thread))
            .ok();
        Self { stop, thread }
    }

    pub(crate) fn stop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for Monitor {
    fn drop(&mut self) {
        self.stop();
    }
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn report_path(pid: i32, output_hint: Option<&str>) -> String {
    if let Ok(path) = std::env::var("RF_ANOMALY_OUTPUT") {
        if !path.trim().is_empty() {
            return path;
        }
    }
    if let Some(path) = output_hint.filter(|p| !p.trim().is_empty()) {
        return format!("{}.anomaly.jsonl", path);
    }
    format!("/data/local/tmp/rustfrida-anomaly-{}-{}.jsonl", pid, now_secs())
}

fn read_limited(path: &str) -> String {
    std::fs::read(path)
        .map(|bytes| String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_PROC_FIELD)]).into_owned())
        .unwrap_or_default()
}

fn read_boot_id() -> Option<String> {
    let value = read_limited("/proc/sys/kernel/random/boot_id");
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn read_uptime() -> Option<String> {
    let value = read_limited("/proc/uptime");
    let value = value.split_whitespace().next().unwrap_or("");
    (!value.is_empty()).then(|| value.to_string())
}

fn getprop(name: &str) -> Option<String> {
    let output = Command::new("getprop").arg(name).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!value.is_empty()).then_some(value)
}

fn command_tail(program: &str, args: &[&str]) -> String {
    let output = match Command::new(program).args(args).output() {
        Ok(output) if output.status.success() => output,
        _ => return String::new(),
    };
    let text = String::from_utf8_lossy(&output.stdout);
    if text.len() <= MAX_COMMAND_OUTPUT {
        return text.into_owned();
    }
    let start = text.len().saturating_sub(MAX_COMMAND_OUTPUT);
    // Avoid slicing in the middle of a UTF-8 codepoint.
    text.get(start..).unwrap_or(text.as_ref()).to_string()
}

fn parse_stat(pid: i32, stat: String) -> Option<(char, Option<u64>, Option<i64>)> {
    let (pid_text, remainder) = stat.split_once('(')?;
    if pid_text.trim().parse::<i32>().ok()? != pid {
        return None;
    }
    let (_, fields) = remainder.rsplit_once(')')?;
    let mut fields = fields.split_whitespace();
    let state = fields.next()?.chars().next()?;
    let fields: Vec<&str> = fields.collect();
    // After field 3 was consumed: field 22 (starttime) is index 18 and
    // field 52 (exit_code) is index 48.
    let start_time = fields.get(18).and_then(|s| s.parse::<u64>().ok());
    let exit_code = fields.get(48).and_then(|s| s.parse::<i64>().ok());
    Some((state, start_time, exit_code))
}

fn observe(pid: i32) -> Option<ProcObservation> {
    let base = format!("/proc/{}", pid);
    let stat = std::fs::read_to_string(format!("{}/stat", base)).ok()?;
    let (state, start_time, exit_code) = parse_stat(pid, stat.clone())?;
    Some(ProcObservation {
        state,
        start_time,
        // Keep this for zombies; for live processes it is normally absent or 0.
        exit_code: (state == 'Z').then_some(exit_code).flatten(),
        stat,
        status: read_limited(&format!("{}/status", base)),
        cmdline: read_limited(&format!("{}/cmdline", base)).replace('\0', " "),
        wchan: read_limited(&format!("{}/wchan", base)),
        syscall: read_limited(&format!("{}/syscall", base)),
        stack: read_limited(&format!("{}/stack", base)),
    })
}

fn expected_shutdown(session: &Session) -> bool {
    session.shutdown_requested.load(Ordering::Acquire) || crate::spawn::signal_received()
}

fn monitor_loop(pid: i32, session: Arc<Session>, path: String, stop: Arc<AtomicBool>) {
    let initial_boot = read_boot_id();
    let initial = observe(pid);
    let initial_start_time = initial.as_ref().and_then(|p| p.start_time);
    let mut last_observation = initial;
    let mut reported_agent_disconnect = false;
    let mut reported_process_exit = false;

    while !stop.load(Ordering::Acquire) {
        let current_boot = read_boot_id();
        if initial_boot.is_some() && current_boot.is_some() && initial_boot != current_boot {
            let expected = expected_shutdown(&session);
            write_report(
                &path,
                pid,
                &session,
                "device_reboot",
                expected,
                initial_start_time,
                last_observation.as_ref(),
                initial_boot.as_deref(),
                current_boot.as_deref(),
            );
            if !expected {
                log_anomaly(pid, "device_reboot", &path);
            }
            return;
        }

        let observation = observe(pid);
        if let Some(ref current) = observation {
            if let Some(expected_start) = initial_start_time {
                if current.start_time != Some(expected_start) {
                    write_report(
                        &path,
                        pid,
                        &session,
                        "pid_reused",
                        false,
                        initial_start_time,
                        Some(current),
                        initial_boot.as_deref(),
                        current_boot.as_deref(),
                    );
                    log_anomaly(pid, "pid_reused", &path);
                    return;
                }
            }

            if current.state == 'Z' || matches!(current.state, 'X' | 'x') {
                if !reported_process_exit {
                    let expected = expected_shutdown(session.as_ref()) || current.exit_code == Some(0);
                    let reason = if current.exit_code.map(|code| code & 0x7f != 0).unwrap_or(false) {
                        "target_signaled"
                    } else {
                        "target_exit"
                    };
                    write_report(
                        &path,
                        pid,
                        &session,
                        reason,
                        expected,
                        initial_start_time,
                        Some(current),
                        initial_boot.as_deref(),
                        current_boot.as_deref(),
                    );
                    if !expected {
                        log_anomaly(pid, reason, &path);
                    }
                    reported_process_exit = true;
                }
                return;
            }
            last_observation = observation;
        } else if !reported_process_exit {
            let expected = expected_shutdown(session.as_ref());
            write_report(
                &path,
                pid,
                &session,
                "target_gone",
                expected,
                initial_start_time,
                last_observation.as_ref(),
                initial_boot.as_deref(),
                current_boot.as_deref(),
            );
            if !expected {
                log_anomaly(pid, "target_gone", &path);
            }
            reported_process_exit = true;
            return;
        }

        if session.disconnected.load(Ordering::Acquire) && !reported_agent_disconnect {
            let expected = expected_shutdown(session.as_ref());
            write_report(
                &path,
                pid,
                &session,
                "agent_disconnect",
                expected,
                initial_start_time,
                last_observation.as_ref(),
                initial_boot.as_deref(),
                current_boot.as_deref(),
            );
            if !expected {
                log_anomaly(pid, "agent_disconnect", &path);
            }
            reported_agent_disconnect = true;
        }

        thread::sleep(POLL_INTERVAL);
    }
}

fn log_anomaly(pid: i32, reason: &str, path: &str) {
    let colored = format!(
        "\x1b[1m\x1b[31m [异常] \x1b[0mpid={} reason={}，现场: {}",
        pid, reason, path
    );
    let plain = format!("[异常] pid={} reason={}，现场: {}", pid, reason, path);
    logger::stderr_line(&colored, &plain);
}

fn push_json_str(out: &mut String, key: &str, value: &str) {
    out.push_str(",\"");
    out.push_str(key);
    out.push_str("\":");
    out.push_str(&json_string(value));
}

fn push_json_opt(out: &mut String, key: &str, value: Option<&str>) {
    match value {
        Some(value) => push_json_str(out, key, value),
        None => {
            out.push_str(",\"");
            out.push_str(key);
            out.push_str("\":null");
        }
    }
}

fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if (ch as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}

fn pstore_entries() -> String {
    let mut entries = Vec::new();
    if let Ok(read_dir) = std::fs::read_dir("/sys/fs/pstore") {
        for entry in read_dir.flatten() {
            entries.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    entries.sort();
    entries.join(",")
}

fn write_report(
    path: &str,
    pid: i32,
    session: &Session,
    reason: &str,
    expected: bool,
    initial_start_time: Option<u64>,
    observation: Option<&ProcObservation>,
    initial_boot: Option<&str>,
    current_boot: Option<&str>,
) {
    let label = session
        .label
        .lock()
        .map(|label| label.clone())
        .unwrap_or_else(|_| "?".to_string());
    let mut out = format!(
        "{{\"type\":\"rustfrida.anomaly\",\"schema\":1,\"ts_ms\":{},\"pid\":{},\"reason\":{},\"expected\":{},\"label\":{}",
        now_ms(),
        pid,
        json_string(reason),
        expected,
        json_string(&label),
    );
    push_json_opt(&mut out, "boot_id_before", initial_boot);
    push_json_opt(&mut out, "boot_id_after", current_boot);
    push_json_opt(&mut out, "bootreason", getprop("ro.boot.bootreason").as_deref());
    push_json_opt(&mut out, "uptime_sec", read_uptime().as_deref());
    push_json_opt(&mut out, "pstore_entries", Some(&pstore_entries()));
    if let Some(observation) = observation {
        out.push_str(&format!(
            ",\"state\":{},\"start_time\":{}",
            json_string(&observation.state.to_string()),
            observation
                .start_time
                .map_or_else(|| "null".to_string(), |v| v.to_string())
        ));
        match observation.exit_code {
            Some(code) => out.push_str(&format!(",\"exit_code\":{}", code)),
            None => out.push_str(",\"exit_code\":null"),
        }
        push_json_opt(&mut out, "proc_stat", Some(&observation.stat));
        push_json_opt(&mut out, "proc_status", Some(&observation.status));
        push_json_opt(&mut out, "cmdline", Some(&observation.cmdline));
        push_json_opt(&mut out, "wchan", Some(&observation.wchan));
        push_json_opt(&mut out, "syscall", Some(&observation.syscall));
        push_json_opt(&mut out, "stack", Some(&observation.stack));
    } else {
        push_json_opt(
            &mut out,
            "start_time",
            initial_start_time.map(|v| v.to_string()).as_deref(),
        );
    }
    // crash buffer 在 Android 上由 logcat 服务维护；这里只在异常点取最近窗口，
    // 避免每 100ms 运行一次外部命令影响 spawn 时序。
    push_json_opt(
        &mut out,
        "logcat_crash_tail",
        Some(&command_tail("logcat", &["-b", "crash", "-d", "-t", "80"])),
    );
    push_json_opt(&mut out, "dmesg_tail", Some(&command_tail("dmesg", &["-T"])));
    out.push_str("}\n");

    let write_result = (|| -> std::io::Result<()> {
        if let Some(parent) = std::path::Path::new(path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        file.write_all(out.as_bytes())?;
        file.flush()
    })();
    if let Err(error) = write_result {
        let message = format!("[异常监控] 写入现场失败 {}: {}", path, error);
        logger::stderr_line(&message, &message);
    }
}
