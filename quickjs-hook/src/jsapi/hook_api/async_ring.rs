//! 有界 MPSC lock-free 事件环：attach 模式 onEnter 的异步派发通道。
//!
//! 动机（scudo ↔ JS_ENGINE ABBA 死锁家族）：
//! 同步回调路径里 hooked 线程需要获取 JS 引擎锁；JS 线程在回调里
//! console.log/malloc 时又需要 scudo 分配器锁。若 hooked 线程恰好持 scudo 锁
//! 命中 hook（如 malloc 路径上的函数），双方互等 → 全进程冻结。
//!
//! 本模块让 hooked 线程只做一件事：把 (target, tid, HookContext 快照) 原子推入
//! ring，然后立即放行原函数。**永远不等 JS 引擎、永不分配内存**。JS 侧由专用
//! pump 线程批量出队执行回调。ring 满时丢弃并计数（压测/监控场景允许丢，不允许卡）。
//!
//! 正确性论证：异步路径上 hooked 线程不再接触任何互斥锁（仅一次 registry 读锁，
//! 持有者为安装/消费侧，持锁期间不取 JS 引擎、不分配），因此 ABBA 环在结构上
//! 不可能形成。

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::OnceLock;

use crate::ffi::hook as hook_ffi;

/// 事件字节数：8(target) + 4(tid) + 4(flags) + sizeof(HookContext)(352) = 368
pub const EVENT_BYTES: usize = 16 + 352;
/// ring 容量（2 的幂）。2048 × 368B ≈ 736KB，一次性预分配。
const CAPACITY: usize = 2048;

#[repr(C)]
struct Cell {
    seq: AtomicUsize,
    data: [u8; EVENT_BYTES],
}

struct Ring {
    cells: Vec<Cell>,
    head: AtomicUsize, // 生产者claim（多生产者 CAS）
    tail: AtomicUsize, // 单消费者推进
}

unsafe impl Sync for Ring {}

static RING: OnceLock<Ring> = OnceLock::new();
static ASYNC_ENABLED: AtomicBool = AtomicBool::new(false);
static PUSHED: AtomicU64 = AtomicU64::new(0);
static DROPPED: AtomicU64 = AtomicU64::new(0);
static DRAINED: AtomicU64 = AtomicU64::new(0);

/// 初始化 ring（在 JS/初始化线程调用，允许分配）。重复调用幂等。
pub fn init_ring() {
    let _ = RING.get_or_init(|| {
        let mut cells = Vec::with_capacity(CAPACITY);
        for i in 0..CAPACITY {
            cells.push(Cell {
                seq: AtomicUsize::new(i),
                data: [0u8; EVENT_BYTES],
            });
        }
        Ring {
            cells,
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
        }
    });
}

pub fn set_async_enabled(enabled: bool) {
    ASYNC_ENABLED.store(enabled, Ordering::Release);
}

pub fn async_enabled() -> bool {
    ASYNC_ENABLED.load(Ordering::Acquire)
}

/// (pushed, dropped, drained)
pub fn async_stats() -> (u64, u64, u64) {
    (
        PUSHED.load(Ordering::Relaxed),
        DROPPED.load(Ordering::Relaxed),
        DRAINED.load(Ordering::Relaxed),
    )
}

pub fn ring_pending() -> usize {
    match RING.get() {
        Some(r) => {
            let h = r.head.load(Ordering::Acquire);
            let t = r.tail.load(Ordering::Acquire);
            h.saturating_sub(t)
        }
        None => 0,
    }
}

/// 生产者：任意 hooked 线程调用。无分配、无互斥锁（一次 CAS + 一次序号等待）。
/// ctx 指向的 HookContext 内容被拷贝进事件。
/// 返回 true 表示事件已入队或被丢弃（调用方应直接放行原函数）；
/// 返回 false 表示 ring 未初始化（调用方应回退同步路径）。
pub fn push_event(target_addr: u64, tid: u32, ctx: *const hook_ffi::HookContext) -> bool {
    let ring = match RING.get() {
        Some(r) => r,
        None => return false,
    };
    debug_assert_eq!(std::mem::size_of::<hook_ffi::HookContext>(), 352);
    loop {
        let head = ring.head.load(Ordering::Acquire);
        let tail = ring.tail.load(Ordering::Acquire);
        if head.wrapping_sub(tail) >= CAPACITY {
            // 满：丢弃 + 计数。宁可丢事件不可卡 hooked 线程。
            DROPPED.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        if ring
            .head
            .compare_exchange_weak(head, head + 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            let idx = head % CAPACITY;
            let cell = &ring.cells[idx];
            // 等上一圈的该槽位被消费完（容量检查已保证不会真等，仅内存序兜底）
            while cell.seq.load(Ordering::Acquire) != head {
                std::hint::spin_loop();
            }
            unsafe {
                let dst = cell.data.as_ptr() as *mut u8;
                std::ptr::copy_nonoverlapping(target_addr.to_le_bytes().as_ptr(), dst, 8);
                std::ptr::copy_nonoverlapping(tid.to_le_bytes().as_ptr(), dst.add(8), 4);
                std::ptr::write_bytes(dst.add(12), 0, 4);
                std::ptr::copy_nonoverlapping(ctx as *const u8, dst.add(16), 352);
            }
            cell.seq.store(head + 1, Ordering::Release);
            PUSHED.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        std::hint::spin_loop();
    }
}

/// 消费者窥探队首事件头（不弹出）。用于在获取 JS 引擎前确认目标 hook 仍有效。
pub fn peek_header() -> Option<(u64, u32)> {
    let ring = RING.get()?;
    let tail = ring.tail.load(Ordering::Acquire);
    let head = ring.head.load(Ordering::Acquire);
    if tail == head {
        return None;
    }
    let cell = &ring.cells[tail % CAPACITY];
    if cell.seq.load(Ordering::Acquire) != tail + 1 {
        return None;
    }
    let d = &cell.data;
    let target = u64::from_le_bytes(d[0..8].try_into().unwrap());
    let tid = u32::from_le_bytes(d[8..12].try_into().unwrap());
    Some((target, tid))
}

/// 消费者（单线程，pump 专用）：弹出一个事件到 buf。
/// 返回 false 表示空或生产者写入中。
pub fn pop_event(buf: &mut [u8; EVENT_BYTES]) -> bool {
    let ring = match RING.get() {
        Some(r) => r,
        None => return false,
    };
    let tail = ring.tail.load(Ordering::Acquire);
    let head = ring.head.load(Ordering::Acquire);
    if tail == head {
        return false;
    }
    let idx = tail % CAPACITY;
    let cell = &ring.cells[idx];
    if cell.seq.load(Ordering::Acquire) != tail + 1 {
        return false; // 生产者写入中，下轮再来
    }
    buf.copy_from_slice(&cell.data);
    cell.seq.store(tail + CAPACITY, Ordering::Release);
    ring.tail.store(tail + 1, Ordering::Release);
    DRAINED.fetch_add(1, Ordering::Relaxed);
    true
}

/// 解析事件头部：返回 (target_addr, tid)
pub fn parse_header(buf: &[u8; EVENT_BYTES]) -> (u64, u32) {
    let target = u64::from_le_bytes(buf[0..8].try_into().unwrap());
    let tid = u32::from_le_bytes(buf[8..12].try_into().unwrap());
    (target, tid)
}

/// 从事件重建 HookContext（消费者栈上）。
/// # Safety
/// buf 必须是 pop_event 取出的事件。
pub unsafe fn hook_context_from_event(buf: &[u8; EVENT_BYTES]) -> hook_ffi::HookContext {
    let mut hctx: hook_ffi::HookContext = std::mem::zeroed();
    std::ptr::copy_nonoverlapping(
        buf[16..].as_ptr(),
        &mut hctx as *mut _ as *mut u8,
        std::mem::size_of::<hook_ffi::HookContext>(),
    );
    hctx
}
