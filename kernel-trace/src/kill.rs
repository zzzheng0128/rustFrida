//! `--kill SIGNAL` 实现:命中事件时给目标进程发信号挂起,监听终端 `c` 回车恢复。
//!
//! 设计:
//! - `kill_signal: Option<i32>`(None 时不发信号)
//! - `KillController` 维护"被挂起的 PIDs",在收到事件时 kill(SIGSTOP),在 stdin 收到 `c\n` 时 kill(SIGCONT) 给所有 PIDs
//! - 监听线程独立运行,不阻塞 BPF reader

use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

/// 信号名 → libc::c_int 编号。
pub fn signal_from_name(s: &str) -> Option<i32> {
    Some(match s.to_ascii_uppercase().as_str() {
        "SIGSTOP" => 19,
        "SIGCONT" => 18,
        "SIGKILL" => 9,
        "SIGTERM" => 15,
        "SIGUSR1" => 10,
        "SIGUSR2" => 12,
        _ => return None,
    })
}

/// 信号名解析(支持 "STOP"/"STOP\n19" / "9" / "sigstop" 等),失败返回 Err。
pub fn parse_signal(s: &str) -> Result<i32, String> {
    let s = s.trim();
    if let Ok(n) = s.parse::<i32>() {
        if n > 0 && n < 64 {
            return Ok(n);
        }
        return Err(format!("signal number out of range: {n}"));
    }
    signal_from_name(s)
        .ok_or_else(|| format!("unknown signal: {s}; supported: SIGSTOP SIGCONT SIGKILL SIGTERM SIGUSR1 SIGUSR2"))
}

/// Kill 控制器:在命中事件时挂起目标进程,在 stdin 'c' 恢复。
#[derive(Clone)]
pub struct KillController {
    inner: Arc<Mutex<KillInner>>,
    stop_flag: Arc<AtomicBool>,
    handle: Arc<Mutex<Option<JoinHandle<()>>>>,
}

struct KillInner {
    signal: i32,
    killed_pids: std::collections::HashSet<u32>,
}

impl KillController {
    /// 新建控制器 + 启动 stdin 监听线程。
    pub fn new(signal: i32) -> Self {
        let inner = Arc::new(Mutex::new(KillInner {
            signal,
            killed_pids: std::collections::HashSet::new(),
        }));
        let stop_flag = Arc::new(AtomicBool::new(false));
        let inner_clone = inner.clone();
        let stop_flag_clone = stop_flag.clone();
        let handle = thread::Builder::new()
            .name("ktrace-kill-stdin".into())
            .spawn(move || {
                stdin_listener(inner_clone, stop_flag_clone);
            })
            .expect("spawn ktrace-kill-stdin");
        Self {
            inner,
            stop_flag,
            handle: Arc::new(Mutex::new(Some(handle))),
        }
    }

    /// 给目标 PID 发挂起信号。静默失败(权限不足、进程已退出等都忽略)。
    pub fn kill_target(&self, pid: u32) {
        let sig = {
            let g = self.inner.lock().unwrap();
            g.signal
        };
        // libc::kill 是 unsafe
        unsafe {
            libc::kill(pid as i32, sig);
        }
        let mut g = self.inner.lock().unwrap();
        g.killed_pids.insert(pid);
    }

    /// 主动给所有被挂起的进程发 SIGCONT 并清空记录。
    pub fn cont_all(&self) {
        let mut g = self.inner.lock().unwrap();
        for &pid in g.killed_pids.iter() {
            unsafe {
                libc::kill(pid as i32, libc::SIGCONT);
            }
        }
        g.killed_pids.clear();
    }

    /// 停掉监听线程(在 KernelTracer::stop 时调用)。
    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        // stdin 阻塞 read 不会主动醒;主动 wake 的方式是 cont_all 让用户输入 'c' 然后退出,
        // 或者由外部调 stop 时把 stdin 关掉。简单做法:detach 线程,daemon-like。
        let _ = self.handle.lock().unwrap().take();
    }
}

fn stdin_listener(inner: Arc<Mutex<KillInner>>, stop_flag: Arc<AtomicBool>) {
    let mut stdin = std::io::stdin();
    let mut buf = [0u8; 256];
    loop {
        if stop_flag.load(Ordering::SeqCst) {
            return;
        }
        // 阻塞读一行
        let n = match stdin.read(&mut buf) {
            Ok(0) => return, // EOF
            Ok(n) => n,
            Err(_) => return,
        };
        // 只看第一字节
        if n >= 1 && (buf[0] == b'c' || buf[0] == b'C') {
            let g = inner.lock().unwrap();
            let count = g.killed_pids.len();
            for &pid in g.killed_pids.iter() {
                unsafe {
                    libc::kill(pid as i32, libc::SIGCONT);
                }
            }
            drop(g);
            inner.lock().unwrap().killed_pids.clear();
            crate::emit_diagnostic(format_args!("\n[kill] SIGCONT sent to {count} pid(s)"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_signal_names() {
        assert_eq!(parse_signal("SIGSTOP").unwrap(), 19);
        assert_eq!(parse_signal("stop").unwrap(), 19);
        assert_eq!(parse_signal("19").unwrap(), 19);
        assert!(parse_signal("bogus").is_err());
    }
}
