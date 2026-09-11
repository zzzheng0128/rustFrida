#!/usr/bin/env python3
"""Run the production executor queue helpers as host-only Rust regression tests.

Usage: python3 quickjs-hook/tests/test_executor_queue.py
Requires Python's standard library and rustc; does not use Cargo or JNI.
"""

from pathlib import Path
import re
import subprocess
import tempfile
import unittest


EXECUTOR_SOURCE = (
    Path(__file__).resolve().parents[1] / "src/jsapi/java/callback/executor.rs"
)


def extract_function(source: str, name: str) -> str:
    # These top-level helpers end with an unindented closing brace. Preserve
    # their actual source, so a production change is also tested here.
    pattern = (
        rf"^(?:pub(?:\([^)]*\))?\s+)?fn {re.escape(name)}\b.*?^}}"
    )
    match = re.search(pattern, source, re.MULTILINE | re.DOTALL)
    if match is None:
        raise ValueError(f"Cannot find production helper {name}")
    return match.group(0)


def extract_static(source: str, name: str) -> str:
    match = re.search(
        rf"^static {re.escape(name)}\b[^;]*;", source, re.MULTILINE
    )
    if match is None:
        raise ValueError(f"Cannot find production static {name}")
    return match.group(0)


RUST_TESTS = r"""
use std::sync::{mpsc, Arc, Barrier, Mutex, MutexGuard};
use std::sync::atomic::Ordering;
use std::time::Duration;

#[derive(Debug)]
struct ExecutorRequest {
    id: usize,
}

// Tests share production statics. This guard also makes running the generated
// test binary without --test-threads=1 safe.
static TEST_STATE: Mutex<()> = Mutex::new(());

fn fresh_queue() -> MutexGuard<'static, ()> {
    let guard = TEST_STATE.lock().unwrap_or_else(|error| error.into_inner());
    EXECUTOR_QUEUE.lock().unwrap().clear();
    reset_raw_clone_executor_abort();
    guard
}

fn request(id: usize) -> Arc<ExecutorRequest> {
    Arc::new(ExecutorRequest { id })
}

fn ids(requests: &[Arc<ExecutorRequest>]) -> Vec<usize> {
    requests.iter().map(|request| request.id).collect()
}

#[test]
fn shutdown_between_entry_precheck_and_admission_rejects_request() {
    let _state = fresh_queue();
    let (checked_tx, checked_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    let producer = std::thread::spawn(move || {
        // This is the allocation-saving precheck in enqueue_executor_task.
        assert!(!EXECUTOR_ABORTING.load(Ordering::Acquire));
        checked_tx.send(()).unwrap();
        resume_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        try_queue_executor_task(&request(1))
    });

    checked_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(take_executor_tasks_for_abort().is_empty());
    resume_tx.send(()).unwrap();
    assert!(!producer.join().unwrap());
    assert!(EXECUTOR_QUEUE.lock().unwrap().is_empty());
}

#[test]
fn shutdown_returns_all_queued_requests_for_cancellation() {
    let _state = fresh_queue();
    let first = request(10);
    let second = request(11);
    assert!(try_queue_executor_task(&first));
    assert!(try_queue_executor_task(&second));

    let pending = take_executor_tasks_for_abort();
    assert_eq!(ids(&pending), vec![10, 11]);
    assert!(Arc::ptr_eq(&pending[0], &first));
    assert!(Arc::ptr_eq(&pending[1], &second));
    assert!(EXECUTOR_ABORTING.load(Ordering::Acquire));
    assert!(EXECUTOR_QUEUE.lock().unwrap().is_empty());
    assert!(!try_queue_executor_task(&request(12)));
    assert!(take_executor_tasks_for_abort().is_empty());
}

#[test]
fn shutdown_rejects_pop_even_if_a_pending_item_exists() {
    let _state = fresh_queue();
    assert!(take_executor_tasks_for_abort().is_empty());
    // Test-only state injection isolates the dequeue guard from shutdown's
    // queue drain. Normal production admission cannot add this closed item.
    let pending = request(20);
    EXECUTOR_QUEUE.lock().unwrap().push_back(pending.clone());

    assert!(pop_executor_task().is_none());
    let cancelled = take_executor_tasks_for_abort();
    assert_eq!(ids(&cancelled), vec![20]);
    assert!(Arc::ptr_eq(&cancelled[0], &pending));
}

#[test]
fn request_popped_before_shutdown_remains_in_flight() {
    let _state = fresh_queue();
    let running = request(30);
    let queued = request(31);
    assert!(try_queue_executor_task(&running));
    assert!(try_queue_executor_task(&queued));
    let in_flight = pop_executor_task().unwrap();
    assert!(Arc::ptr_eq(&in_flight, &running));

    let pending = take_executor_tasks_for_abort();
    assert_eq!(ids(&pending), vec![31]);
    assert!(Arc::ptr_eq(&pending[0], &queued));
    assert_eq!(in_flight.id, 30);
    assert!(pop_executor_task().is_none());
}

#[test]
fn concurrent_producers_and_one_shutdown_account_for_every_accepted_request() {
    let _state = fresh_queue();
    const PRODUCERS: usize = 8;
    const ATTEMPTS: usize = 128;

    for _ in 0..16 {
        reset_raw_clone_executor_abort();
        let start = Arc::new(Barrier::new(PRODUCERS + 1));
        let producers: Vec<_> = (0..PRODUCERS).map(|producer| {
            let start = start.clone();
            std::thread::spawn(move || {
                let base = producer * (ATTEMPTS + 1);
                // Ensure the race includes accepted work even if shutdown
                // wins the queue lock immediately after the barrier.
                assert!(try_queue_executor_task(&request(base)));
                let mut accepted = vec![base];
                let mut rejected = 0;
                start.wait();
                for attempt in 1..=ATTEMPTS {
                    let id = base + attempt;
                    if try_queue_executor_task(&request(id)) {
                        accepted.push(id);
                    } else {
                        rejected += 1;
                    }
                    if attempt % 8 == 0 {
                        std::thread::yield_now();
                    }
                }
                (accepted, rejected)
            })
        }).collect();

        start.wait();
        // Exactly one shutdown races with this round's producers. There is
        // no consumer, so every accepted request must be in this snapshot.
        let pending = take_executor_tasks_for_abort();
        let mut accepted = Vec::new();
        let mut rejected = 0;
        for producer in producers {
            let (producer_accepted, producer_rejected) = producer.join().unwrap();
            accepted.extend(producer_accepted);
            rejected += producer_rejected;
        }
        let mut cancelled = ids(&pending);
        accepted.sort_unstable();
        cancelled.sort_unstable();
        assert_eq!(accepted, cancelled);
        assert!(accepted.windows(2).all(|pair| pair[0] != pair[1]));
        assert_eq!(accepted.len() + rejected, PRODUCERS * (ATTEMPTS + 1));
        assert!(EXECUTOR_QUEUE.lock().unwrap().is_empty());
        assert!(EXECUTOR_ABORTING.load(Ordering::Acquire));
    }
}
"""


class ExecutorQueueRegressionTests(unittest.TestCase):
    def test_production_queue_helpers(self) -> None:
        source = EXECUTOR_SOURCE.read_text(encoding="utf-8")
        items = [
            extract_static(source, "EXECUTOR_QUEUE"),
            extract_static(source, "EXECUTOR_ABORTING"),
        ]
        items.extend(
            extract_function(source, name)
            for name in (
                "try_queue_executor_task",
                "pop_executor_task",
                "take_executor_tasks_for_abort",
                "reset_raw_clone_executor_abort",
            )
        )
        with tempfile.TemporaryDirectory(prefix="executor-queue-test-") as directory:
            directory = Path(directory)
            rust_source = directory / "executor_queue_tests.rs"
            binary = directory / "executor_queue_tests"
            rust_source.write_text("\n\n".join(items) + RUST_TESTS, encoding="utf-8")
            compile_result = subprocess.run(
                ["rustc", "--edition=2021", "--test", str(rust_source), "-o", str(binary)],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(
                compile_result.returncode,
                0,
                compile_result.stdout + compile_result.stderr,
            )
            test_result = subprocess.run(
                [str(binary), "--test-threads=1"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(
                test_result.returncode, 0, test_result.stdout + test_result.stderr
            )
            print(test_result.stdout, end="")


if __name__ == "__main__":
    unittest.main()
