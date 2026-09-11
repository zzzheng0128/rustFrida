//! Admission control for optional, expensive event details.
//!
//! Credits represent aggregate worker wall time, not event count. Reserving an
//! estimated cost before starting work limits bursts; dropping the permit settles
//! its actual cost, including when the detail builder unwinds. A slow operation
//! can exceed its reservation because it cannot be preempted. Its resulting debt
//! must be repaid before more details are admitted.

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

const MAX_QUEUE_WAIT: Duration = Duration::from_millis(100);
const MIN_ESTIMATE_SECONDS: f64 = 0.000_1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SkipReason {
    Budget,
    QueueDelay,
}

impl SkipReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Budget => "budget",
            Self::QueueDelay => "queue_delay",
        }
    }
}

#[derive(Clone)]
pub(crate) struct LoadController {
    shared: Arc<Shared>,
}

struct Shared {
    clock: Arc<dyn Clock>,
    svc: Mutex<Bucket>,
    uprobe: Mutex<Bucket>,
}

pub(crate) struct DetailPermit {
    shared: Arc<Shared>,
    syscall: bool,
    started: Duration,
    reserved_seconds: f64,
}

trait Clock: Send + Sync {
    fn now(&self) -> Duration;
}

struct MonotonicClock(Instant);

impl Clock for MonotonicClock {
    fn now(&self) -> Duration {
        self.0.elapsed()
    }
}

impl LoadController {
    pub(crate) fn new() -> Self {
        Self::with_clock(Arc::new(MonotonicClock(Instant::now())))
    }

    fn with_clock(clock: Arc<dyn Clock>) -> Self {
        let now = clock.now();
        Self {
            shared: Arc::new(Shared {
                clock,
                // 200 ms/s with a 20 ms burst, starting at a 4 ms estimate.
                svc: Mutex::new(Bucket::new(now, 0.2, 0.020, 0.004, 2)),
                // Independent 50 ms/s allowance with a 10 ms burst.
                uprobe: Mutex::new(Bucket::new(now, 0.05, 0.010, 0.001, 1)),
            }),
        }
    }

    pub(crate) fn begin(&self, syscall: bool, queue_wait: Duration) -> Result<DetailPermit, SkipReason> {
        if queue_wait > MAX_QUEUE_WAIT {
            return Err(SkipReason::QueueDelay);
        }
        let now = self.shared.clock.now();
        let reserved_seconds = self.shared.bucket(syscall).reserve(now)?;
        Ok(DetailPermit {
            shared: Arc::clone(&self.shared),
            syscall,
            started: now,
            reserved_seconds,
        })
    }
}

impl Shared {
    fn bucket(&self, syscall: bool) -> MutexGuard<'_, Bucket> {
        let mutex = if syscall { &self.svc } else { &self.uprobe };
        // Detail work executes outside this lock. Recovering poison also keeps
        // a permit's destructor from panicking during an unrelated unwind.
        mutex.lock().unwrap_or_else(|poison| poison.into_inner())
    }
}

impl Drop for DetailPermit {
    fn drop(&mut self) {
        let now = self.shared.clock.now();
        let actual_seconds = now.saturating_sub(self.started).as_secs_f64();
        self.shared
            .bucket(self.syscall)
            .settle(now, self.reserved_seconds, actual_seconds);
    }
}

struct Bucket {
    last_refill: Duration,
    refill_per_second: f64,
    capacity_seconds: f64,
    credits_seconds: f64,
    estimate_seconds: f64,
    max_in_flight: usize,
    in_flight: usize,
}

impl Bucket {
    fn new(
        now: Duration,
        refill_per_second: f64,
        capacity_seconds: f64,
        estimate_seconds: f64,
        max_in_flight: usize,
    ) -> Self {
        Self {
            last_refill: now,
            refill_per_second,
            capacity_seconds,
            credits_seconds: capacity_seconds,
            estimate_seconds,
            max_in_flight,
            in_flight: 0,
        }
    }

    fn refill(&mut self, now: Duration) {
        let elapsed = now.saturating_sub(self.last_refill).as_secs_f64();
        self.last_refill = self.last_refill.max(now);
        self.credits_seconds = (self.credits_seconds + elapsed * self.refill_per_second).min(self.capacity_seconds);
    }

    fn reserve(&mut self, now: Duration) -> Result<f64, SkipReason> {
        self.refill(now);
        let reservation = self.estimate_seconds;
        if self.in_flight >= self.max_in_flight || self.credits_seconds < reservation {
            return Err(SkipReason::Budget);
        }
        self.credits_seconds -= reservation;
        self.in_flight += 1;
        Ok(reservation)
    }

    fn settle(&mut self, now: Duration, reservation: f64, actual: f64) {
        self.refill(now);
        self.credits_seconds = (self.credits_seconds + reservation - actual).min(self.capacity_seconds);
        self.in_flight = self.in_flight.saturating_sub(1);
        // Clip the estimate, not the actual charge: even an operation slower
        // than the entire burst allowance must eventually be eligible again.
        self.estimate_seconds =
            (self.estimate_seconds * 0.75 + actual * 0.25).clamp(MIN_ESTIMATE_SECONDS, self.capacity_seconds);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::Barrier;

    #[derive(Default)]
    struct ManualClock(AtomicU64);

    impl ManualClock {
        fn advance(&self, duration: Duration) {
            self.0.fetch_add(duration.as_nanos() as u64, Ordering::SeqCst);
        }
    }

    impl Clock for ManualClock {
        fn now(&self) -> Duration {
            Duration::from_nanos(self.0.load(Ordering::SeqCst))
        }
    }

    fn controller() -> (LoadController, Arc<ManualClock>) {
        let clock = Arc::new(ManualClock::default());
        (LoadController::with_clock(clock.clone()), clock)
    }

    #[test]
    fn sustained_work_obeys_each_budget_and_burst_allowance() {
        for (syscall, capacity, rate, cost) in [
            (true, 0.020, 0.2, Duration::from_millis(4)),
            (false, 0.010, 0.05, Duration::from_millis(1)),
        ] {
            let (load, clock) = controller();
            let mut total_work = Duration::ZERO;
            while clock.now() < Duration::from_secs(10) {
                if let Ok(permit) = load.begin(syscall, Duration::ZERO) {
                    clock.advance(cost);
                    total_work += cost;
                    drop(permit);
                    assert!(total_work.as_secs_f64() <= capacity + clock.now().as_secs_f64() * rate + 1e-9);
                } else {
                    clock.advance(Duration::from_millis(1));
                }
            }
            // The controller should use its allowance, not merely reject all
            // work and trivially satisfy the upper bound.
            assert!(total_work.as_secs_f64() > 10.0 * rate * 0.9);
        }
    }

    #[test]
    fn reservation_prevents_spending_the_same_credits_twice() {
        let mut bucket = Bucket::new(Duration::ZERO, 0.2, 0.020, 0.009, 8);
        assert!(bucket.reserve(Duration::ZERO).is_ok());
        assert!(bucket.reserve(Duration::ZERO).is_ok());
        assert_eq!(bucket.reserve(Duration::ZERO), Err(SkipReason::Budget));
        assert!((bucket.credits_seconds - 0.002).abs() < 1e-9);
    }

    #[test]
    fn concurrent_callers_cannot_accumulate_unlimited_details() {
        for (syscall, expected) in [(true, 2), (false, 1)] {
            let (load, _) = controller();
            let ready = Arc::new(Barrier::new(17));
            let release = Arc::new(Barrier::new(17));
            let admitted = Arc::new(AtomicUsize::new(0));
            let mut threads = Vec::new();
            for _ in 0..16 {
                let load = load.clone();
                let ready = ready.clone();
                let release = release.clone();
                let admitted = admitted.clone();
                threads.push(std::thread::spawn(move || {
                    let permit = load.begin(syscall, Duration::ZERO);
                    if permit.is_ok() {
                        admitted.fetch_add(1, Ordering::SeqCst);
                    }
                    ready.wait();
                    release.wait();
                    drop(permit);
                }));
            }
            ready.wait();
            assert_eq!(admitted.load(Ordering::SeqCst), expected);
            release.wait();
            for thread in threads {
                thread.join().unwrap();
            }
        }
    }

    #[test]
    fn in_flight_limit_survives_refill_during_a_stalled_operation() {
        let (load, clock) = controller();
        let permit = load.begin(false, Duration::ZERO).unwrap();
        clock.advance(Duration::from_secs(10));
        assert!(matches!(load.begin(false, Duration::ZERO), Err(SkipReason::Budget)));
        drop(permit);
    }

    #[test]
    fn old_events_skip_without_spending_credits() {
        let (load, _) = controller();
        let before = load.shared.bucket(true).credits_seconds;
        assert!(matches!(
            load.begin(true, MAX_QUEUE_WAIT + Duration::from_nanos(1)),
            Err(SkipReason::QueueDelay)
        ));
        assert_eq!(load.shared.bucket(true).credits_seconds, before);
        assert!(load.begin(true, MAX_QUEUE_WAIT).is_ok());
        assert_eq!(SkipReason::QueueDelay.as_str(), "queue_delay");
        assert_eq!(SkipReason::Budget.as_str(), "budget");
    }

    #[test]
    fn slow_work_is_charged_and_recovers_after_debt_is_repaid() {
        let (load, clock) = controller();
        let permit = load.begin(true, Duration::ZERO).unwrap();
        clock.advance(Duration::from_millis(200));
        drop(permit);
        assert!(load.shared.bucket(true).credits_seconds < 0.0);
        assert!(matches!(load.begin(true, Duration::ZERO), Err(SkipReason::Budget)));
        // A costly syscall detail does not consume the independent uprobe
        // allowance, including while the syscall bucket is in debt.
        assert!(load.begin(false, Duration::ZERO).is_ok());
        clock.advance(Duration::from_secs(2));
        assert!(load.begin(true, Duration::ZERO).is_ok());
    }

    #[test]
    fn panic_releases_the_permit_and_charges_elapsed_work() {
        let (load, clock) = controller();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _permit = load.begin(false, Duration::ZERO).unwrap();
            clock.advance(Duration::from_millis(100));
            panic!("synthetic detail builder failure");
        }));
        assert!(result.is_err());
        let bucket = load.shared.bucket(false);
        assert_eq!(bucket.in_flight, 0);
        assert!(bucket.credits_seconds < 0.0);
        drop(bucket);
        clock.advance(Duration::from_secs(3));
        assert!(load.begin(false, Duration::ZERO).is_ok());
    }

    #[test]
    fn an_idle_period_cannot_accumulate_more_than_one_burst() {
        let (load, clock) = controller();
        clock.advance(Duration::from_secs(3600));
        let permit = load.begin(true, Duration::ZERO).unwrap();
        let bucket = load.shared.bucket(true);
        assert!((bucket.credits_seconds + permit.reserved_seconds - 0.020).abs() < 1e-9);
    }
}
