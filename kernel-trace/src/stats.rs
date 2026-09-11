//! Per-session pipeline counters. Live snapshots are approximate while workers run.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Default)]
pub struct EventStats {
    pub received: u64,
    pub invalid: u64,
    pub enqueued: u64,
    pub queue_dropped: u64,
    pub started: u64,
    pub completed: u64,
    pub filtered: u64,
    pub failed: u64,
    pub reports_enqueued: u64,
    pub reports_dropped: u64,
    /// Reports handed to recv/try_recv callers, not necessarily written to disk.
    pub delivered: u64,
    /// Built reports, counted before report queue admission (not delivery).
    pub full_detail: u64,
    pub basic_budget: u64,
    pub basic_queue_delay: u64,
    pub queue_wait_ns: u64,
    pub queue_wait_max_ns: u64,
    pub build_ns: u64,
    pub build_max_ns: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct QueueStats {
    /// Approximate live depth, including a sender's publication reservation.
    pub pending: usize,
    /// Reservation high-water mark, capped at capacity; includes rejected sends.
    pub high_water: usize,
    pub capacity: usize,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TraceStats {
    pub svc: EventStats,
    pub uprobe: EventStats,
    /// Hardware breakpoints share the probe queues but have separate totals.
    pub hwbp: EventStats,
    /// Syscall raw queue; probes have a separate lane.
    pub raw_queue: QueueStats,
    pub uprobe_raw_queue: QueueStats,
    /// Hardware breakpoint raw queue; isolated from uprobe bursts.
    pub hwbp_raw_queue: QueueStats,
    /// Syscall report queue; probes have separately reserved capacity.
    pub report_queue: QueueStats,
    pub uprobe_report_queue: QueueStats,
    pub active_workers: usize,
}

#[derive(Default)]
pub(crate) struct EventCounters {
    pub received: AtomicU64,
    pub invalid: AtomicU64,
    pub enqueued: AtomicU64,
    pub queue_dropped: AtomicU64,
    pub started: AtomicU64,
    pub completed: AtomicU64,
    pub filtered: AtomicU64,
    pub failed: AtomicU64,
    pub reports_enqueued: AtomicU64,
    pub reports_dropped: AtomicU64,
    pub delivered: AtomicU64,
    pub full_detail: AtomicU64,
    pub basic_budget: AtomicU64,
    pub basic_queue_delay: AtomicU64,
    queue_wait_ns: AtomicU64,
    queue_wait_max_ns: AtomicU64,
    build_ns: AtomicU64,
    build_max_ns: AtomicU64,
}

impl EventCounters {
    pub fn start(&self, wait: Duration) {
        self.started.fetch_add(1, Relaxed);
        let ns = nanos(wait);
        self.queue_wait_ns.fetch_add(ns, Relaxed);
        self.queue_wait_max_ns.fetch_max(ns, Relaxed);
    }

    pub fn finish(&self, elapsed: Duration) {
        let ns = nanos(elapsed);
        self.build_ns.fetch_add(ns, Relaxed);
        self.build_max_ns.fetch_max(ns, Relaxed);
        self.completed.fetch_add(1, Relaxed);
    }

    fn snapshot(&self) -> EventStats {
        EventStats {
            received: self.received.load(Relaxed),
            invalid: self.invalid.load(Relaxed),
            enqueued: self.enqueued.load(Relaxed),
            queue_dropped: self.queue_dropped.load(Relaxed),
            started: self.started.load(Relaxed),
            completed: self.completed.load(Relaxed),
            filtered: self.filtered.load(Relaxed),
            failed: self.failed.load(Relaxed),
            reports_enqueued: self.reports_enqueued.load(Relaxed),
            reports_dropped: self.reports_dropped.load(Relaxed),
            delivered: self.delivered.load(Relaxed),
            full_detail: self.full_detail.load(Relaxed),
            basic_budget: self.basic_budget.load(Relaxed),
            basic_queue_delay: self.basic_queue_delay.load(Relaxed),
            queue_wait_ns: self.queue_wait_ns.load(Relaxed),
            queue_wait_max_ns: self.queue_wait_max_ns.load(Relaxed),
            build_ns: self.build_ns.load(Relaxed),
            build_max_ns: self.build_max_ns.load(Relaxed),
        }
    }
}

fn nanos(duration: Duration) -> u64 {
    duration.as_nanos().min(u64::MAX as u128) as u64
}

pub(crate) struct QueueCounters {
    pending: AtomicUsize,
    high_water: AtomicUsize,
    capacity: usize,
}

impl QueueCounters {
    pub fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            pending: AtomicUsize::new(0),
            high_water: AtomicUsize::new(0),
            capacity,
        })
    }

    fn snapshot(&self) -> QueueStats {
        QueueStats {
            // A sender reserves a ticket before publishing, so live depth may
            // include an in-flight send. Do not present that as extra capacity.
            pending: self.pending.load(Relaxed).min(self.capacity),
            high_water: self.high_water.load(Relaxed),
            capacity: self.capacity,
        }
    }
}

/// Owns a depth ticket until dequeue, rejection, or channel destruction.
/// Reserving before publication prevents a fast receiver from underflowing it.
pub(crate) struct Queued<T> {
    value: Option<T>,
    queued_at: Instant,
    queue: Arc<QueueCounters>,
}

impl<T> Queued<T> {
    /// Reserve capacity before a caller performs an action associated with a
    /// report. Every sender using this queue must use the same ticket budget.
    pub fn try_new(value: T, queue: &Arc<QueueCounters>) -> Result<Self, T> {
        let previous = match queue.pending.fetch_update(Relaxed, Relaxed, |pending| {
            (pending < queue.capacity).then_some(pending + 1)
        }) {
            Ok(previous) => previous,
            Err(_) => return Err(value),
        };
        queue.high_water.fetch_max(previous + 1, Relaxed);
        Ok(Self {
            value: Some(value),
            queued_at: Instant::now(),
            queue: queue.clone(),
        })
    }

    pub fn value(&self) -> &T {
        self.value.as_ref().expect("queued value not yet consumed")
    }

    pub fn new(value: T, queue: &Arc<QueueCounters>) -> Self {
        let pending = queue.pending.fetch_add(1, Relaxed) + 1;
        queue.high_water.fetch_max(pending.min(queue.capacity), Relaxed);
        Self {
            value: Some(value),
            queued_at: Instant::now(),
            queue: queue.clone(),
        }
    }

    pub fn dequeue(mut self) -> (T, Duration) {
        let wait = self.queued_at.elapsed();
        let value = self.value.take().expect("queued value consumed once");
        (value, wait)
    }
}

impl<T> Drop for Queued<T> {
    fn drop(&mut self) {
        self.queue.pending.fetch_sub(1, Relaxed);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EventKind {
    Svc,
    Uprobe,
    HwBp,
}

pub(crate) struct PipelineCounters {
    pub svc: EventCounters,
    pub uprobe: EventCounters,
    pub hwbp: EventCounters,
    pub raw_queue: Arc<QueueCounters>,
    pub uprobe_raw_queue: Arc<QueueCounters>,
    pub hwbp_raw_queue: Arc<QueueCounters>,
    pub report_queue: Arc<QueueCounters>,
    pub uprobe_report_queue: Arc<QueueCounters>,
    pub active_workers: AtomicUsize,
}

impl PipelineCounters {
    pub fn new(
        raw_capacity: usize,
        uprobe_capacity: usize,
        hwbp_capacity: usize,
        report_capacity: usize,
        uprobe_report_capacity: usize,
    ) -> Arc<Self> {
        Arc::new(Self {
            svc: EventCounters::default(),
            uprobe: EventCounters::default(),
            hwbp: EventCounters::default(),
            raw_queue: QueueCounters::new(raw_capacity),
            uprobe_raw_queue: QueueCounters::new(uprobe_capacity),
            hwbp_raw_queue: QueueCounters::new(hwbp_capacity),
            report_queue: QueueCounters::new(report_capacity),
            uprobe_report_queue: QueueCounters::new(uprobe_report_capacity),
            active_workers: AtomicUsize::new(0),
        })
    }

    #[allow(dead_code)] // Compatibility adapter for existing two-lane callers.
    pub fn event(&self, syscall: bool) -> &EventCounters {
        self.event_kind(if syscall { EventKind::Svc } else { EventKind::Uprobe })
    }

    pub fn event_kind(&self, kind: EventKind) -> &EventCounters {
        match kind {
            EventKind::Svc => &self.svc,
            EventKind::Uprobe => &self.uprobe,
            EventKind::HwBp => &self.hwbp,
        }
    }

    pub fn snapshot(&self) -> TraceStats {
        TraceStats {
            svc: self.svc.snapshot(),
            uprobe: self.uprobe.snapshot(),
            hwbp: self.hwbp.snapshot(),
            raw_queue: self.raw_queue.snapshot(),
            uprobe_raw_queue: self.uprobe_raw_queue.snapshot(),
            hwbp_raw_queue: self.hwbp_raw_queue.snapshot(),
            report_queue: self.report_queue.snapshot(),
            uprobe_report_queue: self.uprobe_report_queue.snapshot(),
            active_workers: self.active_workers.load(Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn output_capacity_is_reserved_before_publication() {
        let q = QueueCounters::new(1);
        let (tx, rx) = mpsc::sync_channel(1);
        let first = Queued::try_new(1, &q).ok().unwrap();
        assert_eq!(Queued::try_new(2, &q).err(), Some(2));
        assert_eq!(*first.value(), 1);
        assert!(tx.try_send(first).is_ok());
        assert_eq!(Queued::try_new(3, &q).err(), Some(3));
        assert_eq!(rx.recv().unwrap().dequeue().0, 1);
        let next = Queued::try_new(4, &q).ok().unwrap();
        assert!(tx.try_send(next).is_ok());
        drop(rx);
        assert_eq!(q.snapshot().pending, 0);
    }

    #[test]
    fn tickets_are_released_on_receive_rejection_and_shutdown() {
        let q = QueueCounters::new(1);
        let (tx, rx) = mpsc::sync_channel(1);
        assert!(tx.try_send(Queued::new(1, &q)).is_ok());
        assert!(tx.try_send(Queued::new(2, &q)).is_err());
        assert_eq!(q.snapshot().pending, 1);
        assert_eq!(rx.recv().unwrap().dequeue().0, 1);
        assert_eq!(q.snapshot().pending, 0);
        assert!(tx.try_send(Queued::new(3, &q)).is_ok());
        drop(rx);
        assert_eq!(q.snapshot().pending, 0);
        assert!(tx.try_send(Queued::new(4, &q)).is_err());
        assert_eq!(q.snapshot().pending, 0);
    }

    #[test]
    fn fast_receiver_cannot_underflow_depth() {
        let q = QueueCounters::new(16);
        let (tx, rx) = mpsc::sync_channel::<Queued<usize>>(16);
        let worker = std::thread::spawn(move || {
            for expected in 0..10_000 {
                assert_eq!(rx.recv().unwrap().dequeue().0, expected);
            }
        });
        for value in 0..10_000 {
            assert!(tx.send(Queued::new(value, &q)).is_ok());
        }
        worker.join().unwrap();
        assert_eq!(q.snapshot().pending, 0);
        assert!(q.snapshot().high_water <= 16);
    }

    #[test]
    fn counters_isolate_event_types_and_sessions() {
        let a = PipelineCounters::new(16, 1, 1, 4, 1);
        let b = PipelineCounters::new(16, 1, 1, 4, 1);
        a.event(false).queue_dropped.fetch_add(7, Relaxed);
        a.event(true).start(Duration::from_millis(2));
        a.event(true).finish(Duration::from_micros(50));
        a.event_kind(EventKind::HwBp).received.fetch_add(11, Relaxed);
        a.event_kind(EventKind::HwBp).start(Duration::from_millis(3));
        a.event_kind(EventKind::HwBp).finish(Duration::from_micros(25));
        let s = a.snapshot();
        assert_eq!(s.uprobe.queue_dropped, 7);
        assert_eq!(s.svc.queue_dropped, 0);
        assert_eq!(s.svc.queue_wait_ns, 2_000_000);
        assert_eq!(s.svc.build_max_ns, 50_000);
        assert_eq!(s.svc.completed, 1);
        assert_eq!(s.hwbp.received, 11);
        assert_eq!(s.hwbp.queue_dropped, 0);
        assert_eq!(s.hwbp.queue_wait_ns, 3_000_000);
        assert_eq!(s.hwbp.build_max_ns, 25_000);
        assert_eq!(s.hwbp.completed, 1);
        assert_eq!(s.uprobe.received, 0);
        assert_eq!(s.uprobe.completed, 0);
        assert_eq!(b.snapshot().uprobe.queue_dropped, 0);
        assert_eq!(b.snapshot().hwbp.received, 0);
        assert_eq!(b.snapshot().hwbp.completed, 0);
    }
}
