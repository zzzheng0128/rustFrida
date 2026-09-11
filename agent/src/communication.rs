//! agent 端 socket 通信模块
//!
//! 日志消息 (FRAME_KIND_LOG_META) 通过非阻塞 socket 写发送，拿不到锁时直接丢弃，
//! 避免为日志保留后台线程影响自定义 linker 卸载。
//! 控制消息 (HELLO/COMPLETE/EVAL_OK/EVAL_ERR) 仍走同步路径（低频且需要保序）。

use std::io::{IoSlice, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use crate::agent_log::{encode_header, AgentLogMeta};

const FRAME_KIND_CMD: u8 = 1;
const FRAME_KIND_QBDI_HELPER: u8 = 2;

const FRAME_KIND_HELLO: u8 = 0x80;
const FRAME_KIND_LOG: u8 = 0x81;
const FRAME_KIND_COMPLETE: u8 = 0x82;
const FRAME_KIND_EVAL_OK: u8 = 0x83;
const FRAME_KIND_EVAL_ERR: u8 = 0x84;
const FRAME_KIND_RPC_OK: u8 = 0x85;
const FRAME_KIND_RPC_ERR: u8 = 0x86;
const FRAME_KIND_BYE: u8 = 0x87;

/// Write-half of the agent↔host socket, protected by Mutex to serialize messages.
/// 控制消息 (HELLO/COMPLETE/EVAL_OK/EVAL_ERR) 直接走此 stream。
pub static GLOBAL_STREAM: OnceLock<Mutex<UnixStream>> = OnceLock::new();
pub static GLOBAL_STREAM_FD: OnceLock<i32> = OnceLock::new();

// A signal handler can interrupt a normal log write on the same socket.  Keep
// the whole frame in one writev() call and let the handler reserve this flag;
// if a write is already in progress it drops the crash log instead of
// inserting bytes between another frame's header and payload.
static FRAME_WRITE_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

fn writev_frame_once(fd: i32, parts: &[IoSlice<'_>]) -> std::io::Result<usize> {
    if parts.is_empty() {
        return Ok(0);
    }
    let result = unsafe { libc::writev(fd, parts.as_ptr() as *const libc::iovec, parts.len() as i32) };
    if result < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(result as usize)
    }
}

fn write_frame_parts_once(fd: i32, parts: &[IoSlice<'_>]) -> std::io::Result<()> {
    let expected = parts.iter().map(|part| part.len()).sum::<usize>();
    if !FRAME_WRITE_IN_PROGRESS
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_ok()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "another frame write is in progress",
        ));
    }
    let result = writev_frame_once(fd, parts);
    FRAME_WRITE_IN_PROGRESS.store(false, Ordering::Release);
    match result? {
        written if written == expected => Ok(()),
        written => Err(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            format!("short frame write: {written}/{expected}"),
        )),
    }
}

/// Signal-safe variant used by the crash handler.  It deliberately does not
/// construct `std::io::Error` or retry: both can allocate or re-enter libc in
/// an async-signal context.
fn write_frame_parts_raw(fd: i32, parts: &[IoSlice<'_>]) {
    if !FRAME_WRITE_IN_PROGRESS
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_ok()
    {
        return;
    }
    unsafe {
        let _ = libc::writev(fd, parts.as_ptr() as *const libc::iovec, parts.len() as i32);
    }
    FRAME_WRITE_IN_PROGRESS.store(false, Ordering::Release);
}

fn write_frame(stream: &mut UnixStream, kind: u8, payload: &[u8]) -> std::io::Result<()> {
    let payload_len = (payload.len() as u32).to_le_bytes();
    let header = [kind, payload_len[0], payload_len[1], payload_len[2], payload_len[3]];
    write_frame_parts_once(stream.as_raw_fd(), &[IoSlice::new(&header), IoSlice::new(payload)])
}

/// Capture on the logging thread before waiting for any stream/cache lock.
fn capture_log_meta() -> AgentLogMeta {
    let pid = unsafe { libc::getpid() };
    let tid = unsafe { libc::gettid() };
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    let timestamp_ns = if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) } == 0
        && ts.tv_sec >= 0
        && (0..1_000_000_000).contains(&ts.tv_nsec)
    {
        (ts.tv_sec as u64)
            .checked_mul(1_000_000_000)
            .and_then(|seconds| seconds.checked_add(ts.tv_nsec as u64))
            .unwrap_or(0)
    } else {
        0
    };
    AgentLogMeta {
        pid: if pid > 0 { pid as u32 } else { 0 },
        tid: if tid > 0 { tid as u32 } else { 0 },
        timestamp_ns,
    }
}

fn write_log_frame(stream: &mut UnixStream, meta: AgentLogMeta, data: &[u8]) -> std::io::Result<()> {
    let header = encode_header(meta, data.len()).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "agent log frame exceeds u32 payload size",
        )
    })?;
    write_frame_parts_once(stream.as_raw_fd(), &[IoSlice::new(&header), IoSlice::new(data)])
}

pub(crate) fn read_frame(stream: &mut UnixStream) -> std::io::Result<(u8, Vec<u8>)> {
    let mut kind = [0u8; 1];
    stream.read_exact(&mut kind)?;
    let mut len = [0u8; 4];
    stream.read_exact(&mut len)?;
    let len = u32::from_le_bytes(len) as usize;
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload)?;
    Ok((kind[0], payload))
}

/// 保留调用点但不创建后台线程；agent 卸载前不能留下仍在执行 agent 代码的线程。
pub(crate) fn start_log_writer() {}

/// 非阻塞写日志：控制消息持锁或 socket 短时不可写时直接丢弃日志。
pub(crate) fn write_stream(data: &[u8]) {
    let meta = capture_log_meta();
    write_stream_with_meta(data, meta);
}

fn write_stream_with_meta(data: &[u8], meta: AgentLogMeta) {
    if let Some(m) = GLOBAL_STREAM.get() {
        let mut stream = match m.try_lock() {
            Ok(s) => s,
            Err(std::sync::TryLockError::WouldBlock) => return,
            Err(std::sync::TryLockError::Poisoned(e)) => e.into_inner(),
        };
        let _ = write_log_frame(&mut stream, meta, data);
    }
}

pub(crate) fn write_stream_sync(data: &[u8]) {
    let meta = capture_log_meta();
    write_stream_sync_with_meta(data, meta);
}

fn write_stream_sync_with_meta(data: &[u8], meta: AgentLogMeta) {
    if let Some(m) = GLOBAL_STREAM.get() {
        let _ = write_log_frame(&mut m.lock().unwrap_or_else(|e| e.into_inner()), meta, data);
    }
}

pub(crate) fn shutdown_log_writer() {}

/// 直接通过原始 fd 写 socket，供崩溃处理等场景使用。
/// 保留旧日志帧，不在异常上下文额外采样；host 将缺失元数据标为未知。
pub(crate) fn write_stream_raw(data: &[u8]) {
    if let Some(fd) = GLOBAL_STREAM_FD.get() {
        let mut header = [0u8; 5];
        header[0] = FRAME_KIND_LOG;
        header[1..].copy_from_slice(&(data.len() as u32).to_le_bytes());
        // Do not retry a short write from a signal handler: a second syscall
        // could interleave with another frame.  The host will discard a
        // partial frame, while a single writev keeps valid frames parseable.
        write_frame_parts_raw(*fd, &[IoSlice::new(&header), IoSlice::new(data)]);
    }
}

pub(crate) fn send_hello() {
    if let Some(m) = GLOBAL_STREAM.get() {
        let _ = write_frame(&mut m.lock().unwrap_or_else(|e| e.into_inner()), FRAME_KIND_HELLO, &[]);
    }
}

pub(crate) fn send_complete(text: &str) {
    if let Some(m) = GLOBAL_STREAM.get() {
        let _ = write_frame(
            &mut m.lock().unwrap_or_else(|e| e.into_inner()),
            FRAME_KIND_COMPLETE,
            text.as_bytes(),
        );
    }
}

pub(crate) fn send_eval_ok(text: &str) {
    if let Some(m) = GLOBAL_STREAM.get() {
        let _ = write_frame(
            &mut m.lock().unwrap_or_else(|e| e.into_inner()),
            FRAME_KIND_EVAL_OK,
            text.as_bytes(),
        );
    }
}

pub(crate) fn send_eval_err(text: &str) {
    if let Some(m) = GLOBAL_STREAM.get() {
        let _ = write_frame(
            &mut m.lock().unwrap_or_else(|e| e.into_inner()),
            FRAME_KIND_EVAL_ERR,
            text.as_bytes(),
        );
    }
}

pub(crate) fn send_rpc_ok(text: &str) {
    if let Some(m) = GLOBAL_STREAM.get() {
        let _ = write_frame(
            &mut m.lock().unwrap_or_else(|e| e.into_inner()),
            FRAME_KIND_RPC_OK,
            text.as_bytes(),
        );
    }
}

pub(crate) fn send_rpc_err(text: &str) {
    if let Some(m) = GLOBAL_STREAM.get() {
        let _ = write_frame(
            &mut m.lock().unwrap_or_else(|e| e.into_inner()),
            FRAME_KIND_RPC_ERR,
            text.as_bytes(),
        );
    }
}

pub(crate) fn send_bye() {
    if let Some(m) = GLOBAL_STREAM.get() {
        let _ = write_frame(&mut m.lock().unwrap_or_else(|e| e.into_inner()), FRAME_KIND_BYE, &[]);
    }
}

pub(crate) fn is_cmd_frame(kind: u8) -> bool {
    kind == FRAME_KIND_CMD
}

pub(crate) fn is_qbdi_helper_frame(kind: u8) -> bool {
    kind == FRAME_KIND_QBDI_HELPER
}

pub(crate) static CACHE_LOG: Mutex<Vec<(AgentLogMeta, String)>> = Mutex::new(Vec::new());

/// 日志函数：socket未连接时缓存，连接后走非阻塞 socket 写
/// 自动添加 [agent] 前缀
pub(crate) fn log_msg(msg: String) {
    let meta = capture_log_meta();
    let prefixed = format!("[agent] {}", msg);
    if GLOBAL_STREAM.get().is_some() {
        write_stream_with_meta(prefixed.as_bytes(), meta);
    } else {
        // Socket未连接，缓存日志
        if let Ok(mut cache) = CACHE_LOG.lock() {
            cache.push((meta, prefixed));
        }
    }
}

pub(crate) fn log_msg_sync(msg: String) {
    let meta = capture_log_meta();
    let prefixed = format!("[agent] {}", msg);
    if GLOBAL_STREAM.get().is_some() {
        write_stream_sync_with_meta(prefixed.as_bytes(), meta);
    } else if let Ok(mut cache) = CACHE_LOG.lock() {
        cache.push((meta, prefixed));
    }
}

/// 关闭 socket 写端。用 SHUT_WR 保留已排队的 LOG/BYE frame，避免 host 读到 reset。
pub(crate) fn shutdown_stream() {
    if let Some(m) = GLOBAL_STREAM.get() {
        let mut stream = m.lock().unwrap_or_else(|e| e.into_inner());
        let _ = stream.flush();
        let fd = stream.as_raw_fd();
        unsafe {
            libc::shutdown(fd, libc::SHUT_WR);
        }
    }
}

pub(crate) fn register_stream_fd(stream: &UnixStream) {
    let _ = GLOBAL_STREAM_FD.set(stream.as_raw_fd());
}

/// 刷新缓存的日志，在socket连接后调用
pub(crate) fn flush_cached_logs() {
    if GLOBAL_STREAM.get().is_some() {
        if let Ok(mut cache) = CACHE_LOG.lock() {
            drain_cached_logs(&mut cache, |meta, data| write_stream_with_meta(data, meta));
        }
    }
}

fn drain_cached_logs(cache: &mut Vec<(AgentLogMeta, String)>, mut send: impl FnMut(AgentLogMeta, &[u8])) {
    for (meta, msg) in cache.drain(..) {
        send(meta, msg.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_log::{decode_payload, FRAME_KIND_LOG_META};

    #[test]
    fn cached_logs_keep_original_metadata_and_order_when_flushed() {
        let first = AgentLogMeta {
            pid: 1,
            tid: 11,
            timestamp_ns: 100,
        };
        let second = AgentLogMeta {
            pid: 1,
            tid: 22,
            timestamp_ns: 200,
        };
        let mut cache = vec![(first, "[agent] first".into()), (second, "KT>sub svc".into())];
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        drain_cached_logs(&mut cache, |meta, data| {
            write_log_frame(&mut writer, meta, data).unwrap()
        });
        assert!(cache.is_empty());
        for (meta, message) in [(first, "[agent] first"), (second, "KT>sub svc")] {
            let (kind, payload) = read_frame(&mut reader).unwrap();
            assert_eq!(kind, FRAME_KIND_LOG_META);
            assert_eq!(decode_payload(&payload), Some((meta, message.as_bytes())));
        }
    }
}
