//! 宿主执行的生命周期与线程期限；不依赖 QuickJS，可在宿主机验证并发协议。

use std::cell::Cell;
use std::marker::PhantomData;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

struct LifecycleState {
    shutting_down: bool,
    in_flight: usize,
}

pub(crate) struct EngineLifecycle {
    state: Mutex<LifecycleState>,
    idle: Condvar,
}

impl EngineLifecycle {
    pub(crate) const fn new() -> Self {
        Self {
            state: Mutex::new(LifecycleState {
                shutting_down: false,
                in_flight: 0,
            }),
            idle: Condvar::new(),
        }
    }

    /// 调用方持有 ENGINE；查闸门与登记在同一临界区内完成。
    pub(crate) fn try_enter(&self) -> Option<InFlightExecution<'_>> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.shutting_down {
            return None;
        }
        state.in_flight += 1;
        Some(InFlightExecution { lifecycle: self })
    }

    /// 调用方不得持有 ENGINE：挂起执行需要重新拿 ENGINE 才能退出。
    pub(crate) fn begin_shutdown(&self, timeout: Duration) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.shutting_down = true;
        let (state, _) = self
            .idle
            .wait_timeout_while(state, timeout, |s| s.in_flight != 0)
            .unwrap_or_else(|e| e.into_inner());
        state.in_flight == 0
    }

    pub(crate) fn reopen(&self) {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).shutting_down = false;
    }
}

pub(crate) struct InFlightExecution<'a> {
    lifecycle: &'a EngineLifecycle,
}

impl Drop for InFlightExecution<'_> {
    fn drop(&mut self) {
        let mut state = self.lifecycle.state.lock().unwrap_or_else(|e| e.into_inner());
        state.in_flight -= 1;
        if state.in_flight == 0 {
            self.lifecycle.idle.notify_all();
        }
    }
}

thread_local! {
    // 让锁不会改变本线程期限，其他线程的进入/退出也不会覆盖它。
    static DEADLINE: Cell<Option<Instant>> = const { Cell::new(None) };
}

pub(crate) struct JsExecutionDeadlineGuard {
    previous: Option<Instant>,
    // 退出必须发生在进入的线程，禁止把 TLS 恢复凭证移动到另一线程。
    _thread_bound: PhantomData<*mut ()>,
}

impl JsExecutionDeadlineGuard {
    pub(crate) fn begin(timeout_ms: u64) -> Self {
        Self::begin_at(Instant::now(), timeout_ms)
    }

    fn begin_at(now: Instant, timeout_ms: u64) -> Self {
        let requested = (timeout_ms != 0).then(|| now + Duration::from_millis(timeout_ms));
        let previous = DEADLINE.with(|cell| {
            let previous = cell.get();
            // 内层可以收紧期限，但不能延长或取消外层期限。
            let next = match (previous, requested) {
                (Some(outer), Some(inner)) => Some(outer.min(inner)),
                (outer, inner) => outer.or(inner),
            };
            cell.set(next);
            previous
        });
        Self {
            previous,
            _thread_bound: PhantomData,
        }
    }
}

impl Drop for JsExecutionDeadlineGuard {
    fn drop(&mut self) {
        DEADLINE.with(|cell| cell.set(self.previous));
    }
}

pub(crate) fn js_execution_deadline_expired() -> bool {
    // 无期限的普通回调不需要读时钟。
    DEADLINE.with(|cell| cell.get().is_some_and(|deadline| Instant::now() >= deadline))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{mpsc, Barrier};
    use std::thread;

    #[test]
    fn shutdown_keeps_suspended_execution_registered_and_rejects_new_entries() {
        let lifecycle = EngineLifecycle::new();
        let active = lifecycle.try_enter().unwrap();
        assert!(!lifecycle.begin_shutdown(Duration::ZERO));
        assert!(lifecycle.try_enter().is_none());
        drop(active);
        assert!(lifecycle.begin_shutdown(Duration::ZERO));
        assert!(lifecycle.try_enter().is_none());
        lifecycle.reopen();
        assert!(lifecycle.try_enter().is_some());
    }

    #[test]
    fn racing_entry_is_either_counted_or_rejected() {
        for _ in 0..32 {
            let lifecycle = EngineLifecycle::new();
            let start = Barrier::new(2);
            let (entered_tx, entered_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            thread::scope(|scope| {
                let lifecycle = &lifecycle;
                let start = &start;
                scope.spawn(move || {
                    start.wait();
                    let guard = lifecycle.try_enter();
                    entered_tx.send(guard.is_some()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                    drop(guard);
                });
                start.wait();
                let idle = lifecycle.begin_shutdown(Duration::ZERO);
                let entered = entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                assert_eq!(idle, !entered);
                release_tx.send(()).unwrap();
            });
            assert!(lifecycle.begin_shutdown(Duration::ZERO));
        }
    }

    #[test]
    fn nested_deadlines_cannot_extend_outer_budget_and_restore_on_exit() {
        let now = Instant::now();
        let outer = JsExecutionDeadlineGuard::begin_at(now, 100);
        {
            let _longer = JsExecutionDeadlineGuard::begin_at(now, 200);
            assert_eq!(DEADLINE.with(Cell::get), Some(now + Duration::from_millis(100)));
            let _disabled = JsExecutionDeadlineGuard::begin_at(now, 0);
            assert_eq!(DEADLINE.with(Cell::get), Some(now + Duration::from_millis(100)));
        }
        {
            let _shorter = JsExecutionDeadlineGuard::begin_at(now, 50);
            assert_eq!(DEADLINE.with(Cell::get), Some(now + Duration::from_millis(50)));
        }
        assert_eq!(DEADLINE.with(Cell::get), Some(now + Duration::from_millis(100)));
        drop(outer);
        assert_eq!(DEADLINE.with(Cell::get), None);
        assert!(!js_execution_deadline_expired());
    }

    #[test]
    fn expired_outer_deadline_stays_expired_in_nested_execution() {
        let past = Instant::now() - Duration::from_secs(1);
        let outer = JsExecutionDeadlineGuard::begin_at(past, 1);
        assert!(js_execution_deadline_expired());
        {
            let _inner = JsExecutionDeadlineGuard::begin(6_500);
            assert!(js_execution_deadline_expired());
        }
        drop(outer);
        assert!(!js_execution_deadline_expired());
    }

    #[test]
    fn deadlines_survive_non_lifo_cross_thread_exits() {
        let a = JsExecutionDeadlineGuard::begin(6_500);
        let a_deadline = DEADLINE.with(Cell::get);
        let (entered_tx, entered_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let b = thread::spawn(move || {
            assert_eq!(DEADLINE.with(Cell::get), None);
            let guard = JsExecutionDeadlineGuard::begin(10_000);
            let deadline = DEADLINE.with(Cell::get);
            entered_tx.send(()).unwrap();
            resume_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            assert_eq!(DEADLINE.with(Cell::get), deadline);
            drop(guard);
            assert_eq!(DEADLINE.with(Cell::get), None);
        });
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(DEADLINE.with(Cell::get), a_deadline);
        drop(a);
        resume_tx.send(()).unwrap();
        b.join().unwrap();
        assert_eq!(DEADLINE.with(Cell::get), None);
    }
}
