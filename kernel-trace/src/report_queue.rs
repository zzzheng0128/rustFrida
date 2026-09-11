//! Two independently bounded report lanes with one coalescing wake notification.
//!
//! Probes normally have priority. After eight consecutive probes, an available
//! syscall is delivered first, so neither lane can starve the other. FIFO order
//! within each lane is preserved.

use std::cell::Cell;
use std::sync::mpsc;
use std::time::{Duration, Instant};

const MAX_CONSECUTIVE_UPROBES: usize = 8;

/// Both capacities must be positive: nonblocking sends cannot rendezvous with
/// this receiver, which waits on a separate notification channel.
pub(crate) fn channel<T>(svc_capacity: usize, uprobe_capacity: usize) -> (Sender<T>, Receiver<T>) {
    assert!(svc_capacity > 0, "syscall report capacity must be positive");
    assert!(uprobe_capacity > 0, "uprobe report capacity must be positive");
    let (svc_tx, svc_rx) = mpsc::sync_channel(svc_capacity);
    let (uprobe_tx, uprobe_rx) = mpsc::sync_channel(uprobe_capacity);
    let (wake_tx, wake_rx) = mpsc::sync_channel(1);
    (
        Sender {
            svc: svc_tx,
            uprobe: uprobe_tx,
            wake: wake_tx,
        },
        Receiver {
            svc: svc_rx,
            uprobe: uprobe_rx,
            wake: wake_rx,
            consecutive_uprobes: Cell::new(0),
        },
    )
}

pub(crate) struct Sender<T> {
    // Field drop order matters: the final wake sender must close after both
    // data senders, so a disconnected wake channel means no future data sends.
    svc: mpsc::SyncSender<T>,
    uprobe: mpsc::SyncSender<T>,
    wake: mpsc::SyncSender<()>,
}

impl<T> Clone for Sender<T> {
    fn clone(&self) -> Self {
        Self {
            svc: self.svc.clone(),
            uprobe: self.uprobe.clone(),
            wake: self.wake.clone(),
        }
    }
}

impl<T> Sender<T> {
    pub(crate) fn try_send(&self, syscall: bool, value: T) -> Result<(), mpsc::TrySendError<T>> {
        let sender = if syscall { &self.svc } else { &self.uprobe };
        sender.try_send(value)?;
        // Publish data before its notification. Full means a wake is already
        // pending; disconnected means the receiver has gone away after sending.
        let _ = self.wake.try_send(());
        Ok(())
    }
}

/// A single consumer; movable between threads, but not shared concurrently.
pub(crate) struct Receiver<T> {
    svc: mpsc::Receiver<T>,
    uprobe: mpsc::Receiver<T>,
    wake: mpsc::Receiver<()>,
    consecutive_uprobes: Cell<usize>,
}

impl<T> Receiver<T> {
    pub(crate) fn try_recv(&self) -> Result<T, mpsc::TryRecvError> {
        let syscall_first = self.consecutive_uprobes.get() >= MAX_CONSECUTIVE_UPROBES;
        let (first, second) = if syscall_first {
            (&self.svc, &self.uprobe)
        } else {
            (&self.uprobe, &self.svc)
        };
        let first_error = match first.try_recv() {
            Ok(value) => {
                self.record_delivery(syscall_first);
                return Ok(value);
            }
            Err(error) => error,
        };
        match second.try_recv() {
            Ok(value) => {
                self.record_delivery(!syscall_first);
                Ok(value)
            }
            Err(mpsc::TryRecvError::Disconnected) if first_error == mpsc::TryRecvError::Disconnected => {
                Err(mpsc::TryRecvError::Disconnected)
            }
            Err(_) => Err(mpsc::TryRecvError::Empty),
        }
    }

    pub(crate) fn recv(&self) -> Result<T, mpsc::RecvError> {
        loop {
            match self.try_recv() {
                Ok(value) => return Ok(value),
                Err(mpsc::TryRecvError::Disconnected) => return Err(mpsc::RecvError),
                Err(mpsc::TryRecvError::Empty) => {}
            }
            if self.wake.recv().is_err() {
                // The last sender may have published data after the empty
                // check and closed before this wait. Drain that tail first.
                return self.try_recv().map_err(|_| mpsc::RecvError);
            }
            // Notifications coalesce and can outlive data consumed by try_recv.
            // Recheck both lanes after every wake, including a stale one.
        }
    }

    pub(crate) fn recv_timeout(&self, timeout: Duration) -> Result<T, mpsc::RecvTimeoutError> {
        // A fixed deadline prevents stale wakes from restarting the timeout.
        // A duration beyond Instant's range is effectively an unbounded wait.
        let Some(deadline) = Instant::now().checked_add(timeout) else {
            return self.recv().map_err(|_| mpsc::RecvTimeoutError::Disconnected);
        };
        loop {
            match self.try_recv() {
                Ok(value) => return Ok(value),
                Err(mpsc::TryRecvError::Disconnected) => return Err(mpsc::RecvTimeoutError::Disconnected),
                Err(mpsc::TryRecvError::Empty) => {}
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(mpsc::RecvTimeoutError::Timeout);
            }
            match self.wake.recv_timeout(remaining) {
                Ok(()) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return self.try_recv().map_err(|_| mpsc::RecvTimeoutError::Disconnected);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    // Prefer an already-published item or completed disconnect
                    // over the notification timeout at this boundary.
                    return self.try_recv().map_err(|error| match error {
                        mpsc::TryRecvError::Empty => mpsc::RecvTimeoutError::Timeout,
                        mpsc::TryRecvError::Disconnected => mpsc::RecvTimeoutError::Disconnected,
                    });
                }
            }
        }
    }

    fn record_delivery(&self, syscall: bool) {
        self.consecutive_uprobes.set(if syscall {
            0
        } else {
            (self.consecutive_uprobes.get() + 1).min(MAX_CONSECUTIVE_UPROBES)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;

    #[test]
    fn full_syscall_lane_does_not_block_a_probe() {
        let (sender, receiver) = channel(1, 1);
        sender.try_send(true, "svc").unwrap();
        assert_eq!(
            sender.try_send(true, "overflow"),
            Err(mpsc::TrySendError::Full("overflow"))
        );
        sender.try_send(false, "probe").unwrap();
        assert_eq!(receiver.recv().unwrap(), "probe");
        assert_eq!(receiver.recv().unwrap(), "svc");
        assert_eq!(receiver.try_recv(), Err(mpsc::TryRecvError::Empty));
    }

    #[test]
    fn probe_priority_is_fair_and_preserves_each_lanes_fifo() {
        let (sender, receiver) = channel(3, 20);
        for index in 0..3 {
            sender.try_send(true, (true, index)).unwrap();
        }
        for index in 0..20 {
            sender.try_send(false, (false, index)).unwrap();
        }
        let mut expected = Vec::new();
        expected.extend((0..8).map(|index| (false, index)));
        expected.push((true, 0));
        expected.extend((8..16).map(|index| (false, index)));
        expected.push((true, 1));
        expected.extend((16..20).map(|index| (false, index)));
        expected.push((true, 2));
        for item in expected {
            assert_eq!(receiver.try_recv().unwrap(), item);
        }
    }

    #[test]
    fn absent_syscalls_do_not_stall_probes_and_late_syscalls_get_a_turn() {
        let (sender, receiver) = channel(1, 1);
        for index in 0..20 {
            sender.try_send(false, index).unwrap();
            assert_eq!(receiver.recv().unwrap(), index);
        }
        sender.try_send(false, 21).unwrap();
        sender.try_send(true, 22).unwrap();
        assert_eq!(receiver.recv().unwrap(), 22);
        assert_eq!(receiver.recv().unwrap(), 21);
    }

    #[test]
    fn buffered_tail_is_drained_before_disconnect() {
        let (sender, receiver) = channel(1, 1);
        sender.try_send(true, 1).unwrap();
        sender.try_send(false, 2).unwrap();
        drop(sender);
        assert_eq!(receiver.recv().unwrap(), 2);
        assert_eq!(receiver.recv_timeout(Duration::ZERO).unwrap(), 1);
        assert_eq!(receiver.recv(), Err(mpsc::RecvError));
        assert_eq!(
            receiver.recv_timeout(Duration::MAX),
            Err(mpsc::RecvTimeoutError::Disconnected)
        );
        assert_eq!(receiver.try_recv(), Err(mpsc::TryRecvError::Disconnected));
    }

    #[test]
    fn dropping_the_final_sender_wakes_a_waiter() {
        let (sender, receiver) = channel::<()>(1, 1);
        let last_sender = sender.clone();
        drop(sender);
        assert_eq!(
            receiver.recv_timeout(Duration::from_millis(1)),
            Err(mpsc::RecvTimeoutError::Timeout)
        );
        let ready = Arc::new(Barrier::new(2));
        let ready_reader = ready.clone();
        let (result_tx, result_rx) = mpsc::channel();
        let reader = thread::spawn(move || {
            ready_reader.wait();
            result_tx.send(receiver.recv()).unwrap();
        });
        ready.wait();
        drop(last_sender);
        assert_eq!(
            result_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            Err(mpsc::RecvError)
        );
        reader.join().unwrap();
    }

    #[test]
    fn dropping_receiver_disconnects_both_sending_lanes() {
        let (sender, receiver) = channel(1, 1);
        drop(receiver);
        assert_eq!(sender.try_send(true, 1), Err(mpsc::TrySendError::Disconnected(1)));
        assert_eq!(sender.try_send(false, 2), Err(mpsc::TrySendError::Disconnected(2)));
    }

    #[test]
    fn timeout_deadline_is_not_extended_by_stale_notifications() {
        let (sender, receiver) = channel::<()>(1, 1);
        let wake = sender.wake.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_notifier = stop.clone();
        let notifier = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(1);
            while !stop_notifier.load(Ordering::Relaxed) && Instant::now() < deadline {
                let _ = wake.try_send(());
                thread::sleep(Duration::from_millis(1));
            }
        });
        let started = Instant::now();
        let result = receiver.recv_timeout(Duration::from_millis(40));
        let elapsed = started.elapsed();
        stop.store(true, Ordering::Relaxed);
        notifier.join().unwrap();
        assert_eq!(result, Err(mpsc::RecvTimeoutError::Timeout));
        assert!(elapsed >= Duration::from_millis(40));
        assert!(
            elapsed < Duration::from_millis(250),
            "timeout was restarted: {elapsed:?}"
        );
    }

    #[test]
    fn stale_wake_followed_by_a_new_send_does_not_lose_the_new_wake() {
        let (sender, receiver) = channel(1, 1);
        sender.try_send(true, 1).unwrap();
        assert_eq!(receiver.try_recv().unwrap(), 1);
        // The first wake is still pending although its item was consumed.
        let producer = thread::spawn(move || {
            thread::sleep(Duration::from_millis(1));
            sender.try_send(false, 2).unwrap();
        });
        assert_eq!(receiver.recv_timeout(Duration::from_secs(1)).unwrap(), 2);
        producer.join().unwrap();
    }

    #[test]
    fn racing_senders_and_waits_deliver_every_successful_send() {
        const PRODUCERS: usize = 4;
        const PER_PRODUCER: usize = 500;
        let (sender, receiver) = channel(2, 3);
        let reader = thread::spawn(move || {
            let mut next_sequence = [0; PRODUCERS];
            for _ in 0..PRODUCERS * PER_PRODUCER {
                let (producer, sequence): (usize, usize) = receiver.recv_timeout(Duration::from_secs(2)).unwrap();
                assert_eq!(sequence, next_sequence[producer]);
                next_sequence[producer] += 1;
            }
            assert_eq!(next_sequence, [PER_PRODUCER; PRODUCERS]);
        });
        let mut producers = Vec::new();
        for producer in 0..PRODUCERS {
            let sender = sender.clone();
            producers.push(thread::spawn(move || {
                for sequence in 0..PER_PRODUCER {
                    let mut value = (producer, sequence);
                    loop {
                        match sender.try_send(producer % 2 == 0, value) {
                            Ok(()) => break,
                            Err(mpsc::TrySendError::Full(returned)) => {
                                value = returned;
                                thread::yield_now();
                            }
                            Err(error) => panic!("unexpected send failure: {error}"),
                        }
                    }
                }
            }));
        }
        drop(sender);
        for producer in producers {
            producer.join().unwrap();
        }
        reader.join().unwrap();
    }

    #[test]
    fn sender_clone_accepts_payloads_without_clone() {
        struct Payload;
        let (sender, receiver) = channel(1, 1);
        let other = sender.clone();
        assert!(other.try_send(true, Payload).is_ok());
        assert!(receiver.recv_timeout(Duration::ZERO).is_ok());
    }
}
