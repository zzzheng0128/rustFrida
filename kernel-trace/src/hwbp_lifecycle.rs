//! Resource ownership and retry state, independent of perf and BPF APIs.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::os::fd::OwnedFd;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TaskIdentity {
    pub tid: u32,
    pub start_time: u64,
}

fn parse_task_identity(tid: u32, stat: &str) -> io::Result<TaskIdentity> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid task stat identity");
    // comm (field 2) may contain both spaces and parentheses. Fields after its
    // final ')' start at field 3; starttime is field 22, hence index 19.
    let open = stat.find('(').ok_or_else(invalid)?;
    let close = stat.rfind(')').filter(|close| *close > open).ok_or_else(invalid)?;
    let recorded_tid: u32 = stat[..open].trim().parse().map_err(|_| invalid())?;
    if recorded_tid != tid {
        return Err(invalid());
    }
    let start_time = stat[close + 1..]
        .split_whitespace()
        .nth(19)
        .ok_or_else(invalid)?
        .parse()
        .map_err(|_| invalid())?;
    Ok(TaskIdentity { tid, start_time })
}

pub(crate) fn read_task_identity(pid: u32, tid: u32) -> io::Result<TaskIdentity> {
    let stat = fs::read_to_string(format!("/proc/{pid}/task/{tid}/stat"))?;
    parse_task_identity(tid, &stat)
}

fn collect_task_identities(
    pid: u32,
    main_only: bool,
    tids: impl IntoIterator<Item = u32>,
    mut read: impl FnMut(u32) -> io::Result<TaskIdentity>,
) -> io::Result<Vec<TaskIdentity>> {
    let mut tasks = Vec::new();
    for tid in tids {
        if main_only && tid != pid {
            continue;
        }
        match read(tid) {
            Ok(task) => tasks.push(task),
            // Threads may exit between enumeration and stat reads. Other
            // errors do not prove disappearance and must not form a snapshot.
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    tasks.sort_unstable_by_key(|task| task.tid);
    Ok(tasks)
}

pub(crate) fn list_tasks(pid: u32, main_only: bool) -> io::Result<Vec<TaskIdentity>> {
    let entries = fs::read_dir(format!("/proc/{pid}/task"))?;
    let mut tids = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if let Some(tid) = entry.file_name().to_str().and_then(|name| name.parse().ok()) {
            tids.push(tid);
        }
    }
    collect_task_identities(pid, main_only, tids, |tid| read_task_identity(pid, tid))
}

/// Keeps deletions until requests queued before them have resolved or expired.
/// The request epoch is assigned once on admission, including symbolic requests
/// whose absolute address is not yet known.
#[derive(Default)]
pub(crate) struct CancellationLedger {
    epoch: u64,
    cancelled: HashMap<u64, u64>,
}

impl CancellationLedger {
    pub(crate) fn current(&self) -> u64 {
        self.epoch
    }

    pub(crate) fn cancel(&mut self, addr: u64) {
        self.epoch = self.epoch.checked_add(1).expect("cancellation epoch exhausted");
        self.cancelled.insert(addr, self.epoch);
    }

    pub(crate) fn is_cancelled(&self, addr: u64, epoch: u64) -> bool {
        self.cancelled.get(&addr).is_some_and(|cancelled| *cancelled > epoch)
    }

    pub(crate) fn prune(&mut self, oldest_pending: Option<u64>) {
        match oldest_pending {
            Some(oldest) => self.cancelled.retain(|_, epoch| *epoch > oldest),
            None => self.cancelled.clear(),
        }
    }
}

const INITIAL_RETRY_DELAY: Duration = Duration::from_secs(1);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(30);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(300);

pub(crate) struct PendingRequest<T> {
    pub value: T,
    pub epoch: u64,
    pub process: Option<TaskIdentity>,
    retry_at: Instant,
    retry_delay: Duration,
    deadline: Instant,
}

impl<T> PendingRequest<T> {
    pub(crate) fn new(value: T, epoch: u64, now: Instant) -> Self {
        Self {
            value,
            epoch,
            process: None,
            retry_at: now + INITIAL_RETRY_DELAY,
            retry_delay: INITIAL_RETRY_DELAY,
            deadline: now + REQUEST_TIMEOUT,
        }
    }

    pub(crate) fn ready(&self, now: Instant) -> bool {
        now >= self.retry_at && !self.expired(now)
    }

    pub(crate) fn expired(&self, now: Instant) -> bool {
        now >= self.deadline
    }

    pub(crate) fn defer(&mut self, now: Instant) {
        self.retry_delay = (self.retry_delay * 2).min(MAX_RETRY_DELAY);
        self.retry_at = now + self.retry_delay;
    }
}

/// Ownership is acquired before configuration so every error or panic closes
/// the descriptor. Successful configuration transfers the same ownership out.
pub(crate) fn configure_fd<E>(fd: OwnedFd, configure: impl FnOnce(&OwnedFd) -> Result<(), E>) -> Result<OwnedFd, E> {
    configure(&fd)?;
    Ok(fd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::unix::net::UnixStream;

    fn stat(tid: u32, comm: &str, start_time: &str) -> String {
        let mut fields = vec!["S".to_owned()];
        fields.extend((4..=21).map(|field| field.to_string()));
        fields.push(start_time.to_owned());
        fields.push("999".to_owned());
        format!("{tid} ({comm}) {}\n", fields.join(" "))
    }

    #[test]
    fn task_identity_uses_starttime_after_complete_comm() {
        let text = stat(42, "worker ) (disk io)", "123456789");
        assert_eq!(
            parse_task_identity(42, &text).unwrap(),
            TaskIdentity {
                tid: 42,
                start_time: 123456789
            },
        );
        let replacement = parse_task_identity(42, &stat(42, "worker", "123456790")).unwrap();
        assert_ne!(parse_task_identity(42, &text).unwrap(), replacement);
    }

    #[test]
    fn malformed_or_mismatched_stat_does_not_produce_an_identity() {
        for text in [
            "42 worker S 0".to_owned(),
            "42 (worker) S 0".to_owned(),
            stat(42, "worker", "not-a-number"),
            stat(41, "worker", "123"),
        ] {
            assert_eq!(
                parse_task_identity(42, &text).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn main_scope_uses_pid_not_first_or_smallest_tid() {
        let mut reads = Vec::new();
        let tasks = collect_task_identities(42, true, [7, 99, 42], |tid| {
            reads.push(tid);
            Ok(TaskIdentity { tid, start_time: 1 })
        })
        .unwrap();
        assert_eq!(reads, [42]);
        assert_eq!(tasks, [TaskIdentity { tid: 42, start_time: 1 }]);
    }

    #[test]
    fn exited_tasks_are_skipped_but_other_read_errors_abort_snapshot() {
        let tasks = collect_task_identities(42, false, [99, 7, 42], |tid| {
            if tid == 7 {
                Err(io::Error::from(io::ErrorKind::NotFound))
            } else {
                Ok(TaskIdentity { tid, start_time: 1 })
            }
        })
        .unwrap();
        assert_eq!(tasks.iter().map(|task| task.tid).collect::<Vec<_>>(), [42, 99]);

        for kind in [
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::Interrupted,
            io::ErrorKind::InvalidData,
        ] {
            let result = collect_task_identities(42, false, [42, 99], |tid| {
                if tid == 99 {
                    Err(io::Error::from(kind))
                } else {
                    Ok(TaskIdentity { tid, start_time: 1 })
                }
            });
            assert_eq!(result.unwrap_err().kind(), kind);
        }
    }

    #[test]
    fn deletion_cancels_old_symbolic_resolution_but_allows_new_request() {
        let mut ledger = CancellationLedger::default();
        let old_epoch = ledger.current();
        ledger.cancel(0x1000);
        assert!(ledger.is_cancelled(0x1000, old_epoch));
        assert!(!ledger.is_cancelled(0x2000, old_epoch));
        let new_epoch = ledger.current();
        assert!(!ledger.is_cancelled(0x1000, new_epoch));
        ledger.cancel(0x1000);
        assert!(ledger.is_cancelled(0x1000, new_epoch));
    }

    #[test]
    fn ledger_pruning_preserves_only_deletions_needed_by_pending_requests() {
        let mut ledger = CancellationLedger::default();
        ledger.cancel(0x1000);
        let oldest_pending = ledger.current();
        ledger.cancel(0x2000);
        ledger.prune(Some(oldest_pending));
        assert!(!ledger.cancelled.contains_key(&0x1000));
        assert!(ledger.is_cancelled(0x2000, oldest_pending));
        let epoch = ledger.current();
        ledger.prune(None);
        assert!(ledger.cancelled.is_empty());
        assert_eq!(ledger.current(), epoch);
        ledger.cancel(0x3000);
        assert!(ledger.is_cancelled(0x3000, epoch));
    }

    #[test]
    fn pending_retry_backoff_is_bounded_and_does_not_extend_deadline() {
        let start = Instant::now();
        let mut pending = PendingRequest::new("request", 7, start);
        assert_eq!(pending.value, "request");
        assert_eq!(pending.epoch, 7);
        assert!(!pending.ready(start));
        let mut attempt = start + Duration::from_secs(1);
        assert!(pending.ready(attempt));
        for delay in [2, 4, 8, 16, 30, 30] {
            pending.defer(attempt);
            assert!(!pending.ready(attempt + Duration::from_secs(delay) - Duration::from_nanos(1)));
            attempt += Duration::from_secs(delay);
            assert!(pending.ready(attempt));
        }
        pending.defer(start + Duration::from_secs(299));
        assert!(!pending.expired(start + Duration::from_secs(299)));
        assert!(pending.expired(start + Duration::from_secs(300)));
        assert!(!pending.ready(start + Duration::from_secs(330)));
    }

    fn socket_pair() -> (OwnedFd, UnixStream) {
        let (stream, peer) = UnixStream::pair().unwrap();
        peer.set_nonblocking(true).unwrap();
        (stream.into(), peer)
    }

    fn assert_peer_open(peer: &mut UnixStream) {
        assert_eq!(peer.read(&mut [0u8]).unwrap_err().kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn successful_configuration_keeps_fd_until_owner_drops() {
        let (fd, mut peer) = socket_pair();
        let owned = configure_fd(fd, |fd| fd.try_clone().map(drop)).unwrap();
        assert_peer_open(&mut peer);
        drop(owned);
        assert_eq!(peer.read(&mut [0u8]).unwrap(), 0);
    }

    #[test]
    fn failed_configuration_closes_fd_immediately() {
        let (fd, mut peer) = socket_pair();
        assert_peer_open(&mut peer);
        let result = configure_fd(fd, |_| Err::<(), _>("configuration failed"));
        assert_eq!(result.unwrap_err(), "configuration failed");
        assert_eq!(peer.read(&mut [0u8]).unwrap(), 0);
    }

    #[test]
    fn panicking_configuration_also_closes_fd() {
        let (fd, mut peer) = socket_pair();
        let result = std::panic::catch_unwind(|| {
            let _ = configure_fd::<()>(fd, |_| panic!("configuration panic"));
        });
        assert!(result.is_err());
        assert_eq!(peer.read(&mut [0u8]).unwrap(), 0);
    }
}
