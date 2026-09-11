//! Host adapter for freshly extracted production manager code. The adapter
//! controls task snapshots and attach results; it never loads or attaches BPF.
#![allow(dead_code)]

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hwbp_lifecycle::{CancellationLedger, TaskIdentity};

// Error context formatting and kernel error generation are outside this
// fixture's contract. Preserve io::Error/errno for manager branching tests.
mod anyhow {
    pub type Result<T> = std::io::Result<T>;
}
macro_rules! anyhow {
    ($($arg:tt)*) => { std::io::Error::other(format!($($arg)*)) };
}
trait Context<T> {
    fn context(self, message: &str) -> io::Result<T>;
}
impl<T> Context<T> for io::Result<T> {
    fn context(self, _message: &str) -> io::Result<T> {
        self
    }
}
macro_rules! trace_diag {
    ($($arg:tt)*) => { let _ = format_args!($($arg)*); };
}

const HW_BP_KIND_X: u32 = 4;
const HW_BP_KIND_W: u32 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HwBpSpec {
    kind: u32,
    addr: u64,
    len: u32,
}

struct Ebpf;

struct PerfEventLink {
    _fd: OwnedFd,
    drops: Rc<Cell<usize>>,
}

impl Drop for PerfEventLink {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() + 1);
    }
}

mod libc {
    pub const ESRCH: i32 = 3;
    pub const ENOSPC: i32 = 28;

    // Deliberately no FFI: production Drop still runs, then OwnedFd closes the
    // socket descriptor without issuing any ioctl to the host kernel.
    pub unsafe fn ioctl(_fd: i32, _request: u64, _argument: i32) -> i32 {
        super::STATE.with(|state| state.borrow_mut().disabled += 1);
        0
    }
}

struct FakeState {
    process: TaskIdentity,
    process_error: Option<io::ErrorKind>,
    tasks: Vec<TaskIdentity>,
    list_error: Option<io::ErrorKind>,
    list_scopes: Vec<bool>,
    cpus: Vec<u32>,
    outcomes: VecDeque<Option<i32>>,
    attempts: Vec<(HwBpSpec, HwBpTarget)>,
    peers: Vec<UnixStream>,
    use_aya: bool,
    aya_drops: Rc<Cell<usize>>,
    disabled: usize,
}

impl Default for FakeState {
    fn default() -> Self {
        Self {
            process: task(42, 100),
            process_error: None,
            tasks: vec![task(42, 100), task(43, 101), task(44, 102)],
            list_error: None,
            list_scopes: Vec::new(),
            cpus: vec![0, 1, 2],
            outcomes: VecDeque::new(),
            attempts: Vec::new(),
            peers: Vec::new(),
            use_aya: false,
            aya_drops: Rc::new(Cell::new(0)),
            disabled: 0,
        }
    }
}

thread_local! {
    static STATE: RefCell<FakeState> = RefCell::new(FakeState::default());
}

fn task(tid: u32, start_time: u64) -> TaskIdentity {
    TaskIdentity { tid, start_time }
}

fn read_task_identity(pid: u32, tid: u32) -> io::Result<TaskIdentity> {
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(pid, state.process.tid, "fixture queried unexpected process");
        if tid == pid {
            if let Some(error) = state.process_error {
                return Err(io::Error::from(error));
            }
            return Ok(state.process);
        }
        state
            .tasks
            .iter()
            .copied()
            .find(|task| task.tid == tid)
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
    })
}

fn list_tasks(pid: u32, main_only: bool) -> io::Result<Vec<TaskIdentity>> {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        assert_eq!(pid, state.process.tid);
        state.list_scopes.push(main_only);
        if let Some(error) = state.list_error {
            return Err(io::Error::from(error));
        }
        Ok(state
            .tasks
            .iter()
            .copied()
            .filter(|task| !main_only || task.tid == pid)
            .collect())
    })
}

fn online_cpus() -> Vec<u32> {
    STATE.with(|state| state.borrow().cpus.clone())
}

fn validate_hwbp_spec(_spec: HwBpSpec) -> io::Result<()> {
    Ok(())
}

fn hwbp_target_disappeared(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::NotFound || error.raw_os_error() == Some(libc::ESRCH)
}

fn hwbp_attach_target(
    _ebpf: &mut Ebpf,
    spec: HwBpSpec,
    process: TaskIdentity,
    target: HwBpTarget,
) -> io::Result<HwBpLink> {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        assert_eq!(process, state.process, "stale process passed to attach");
        state.attempts.push((spec, target));
        if let Some(Some(errno)) = state.outcomes.pop_front() {
            return Err(io::Error::from_raw_os_error(errno));
        }
        let (owned, peer) = UnixStream::pair()?;
        peer.set_nonblocking(true)?;
        state.peers.push(peer);
        Ok(if state.use_aya {
            HwBpLink::Aya(PerfEventLink {
                _fd: owned.into(),
                drops: state.aya_drops.clone(),
            })
        } else {
            HwBpLink::Fd(owned.into())
        })
    })
}

include!(env!("KTRACE_HWBP_MANAGER_SOURCE"));

#[cfg(test)]
mod hwbp_manager_fixture_tests {
    use super::*;

    fn reset() {
        STATE.with(|state| *state.borrow_mut() = FakeState::default());
    }

    fn manager(scope: HwBpScope) -> HwBpManager {
        let mut manager = HwBpManager::new(Arc::new(Mutex::new(Vec::new())));
        // Avoid mutating environment shared by concurrently running tests.
        manager.scope = scope;
        manager.sweep_enabled = true;
        manager
    }

    fn spec(addr: u64) -> HwBpSpec {
        HwBpSpec {
            kind: HW_BP_KIND_X,
            addr,
            len: 4,
        }
    }

    fn process() -> TaskIdentity {
        STATE.with(|state| state.borrow().process)
    }

    fn attempts() -> usize {
        STATE.with(|state| state.borrow().attempts.len())
    }

    fn assert_peer(index: usize, closed: bool) {
        STATE.with(|state| {
            let result = state.borrow_mut().peers[index].read(&mut [0u8]);
            if closed {
                assert_eq!(result.unwrap(), 0, "peer {index} should have reached EOF");
            } else {
                assert_eq!(
                    result.unwrap_err().kind(),
                    io::ErrorKind::WouldBlock,
                    "peer {index} should remain owned"
                );
            }
        });
    }

    fn assert_all_closed() {
        let count = STATE.with(|state| state.borrow().peers.len());
        for index in 0..count {
            assert_peer(index, true);
        }
    }

    #[test]
    fn enospc_blocks_another_automatic_request_and_sweep_until_explicit_request() {
        reset();
        STATE.with(|state| state.borrow_mut().outcomes = [None, Some(libc::ENOSPC)].into());
        let mut manager = manager(HwBpScope::Threads);
        let coverage = manager.attach(&mut Ebpf, spec(0x1000), process(), true).unwrap();
        assert_eq!((coverage.active, coverage.target), (1, 3));
        assert!(manager.automatic_attach_paused);
        assert_eq!(attempts(), 2);

        assert!(manager.attach(&mut Ebpf, spec(0x2000), process(), false).is_err());
        // A pending duplicate must not bypass the pause through the manager's
        // already-present-spec shortcut either.
        assert!(manager.attach(&mut Ebpf, spec(0x1000), process(), false).is_err());
        manager.sweep(&mut Ebpf);
        assert_eq!(attempts(), 2, "automatic work must not open after ENOSPC");
        assert!(manager.automatic_attach_paused);

        let coverage = manager.attach(&mut Ebpf, spec(0x2000), process(), true).unwrap();
        assert_eq!((coverage.active, coverage.target), (3, 3));
        assert!(!manager.automatic_attach_paused);
        assert_eq!(attempts(), 5);
        drop(manager);
        assert_all_closed();
    }

    #[test]
    fn manager_drop_releases_raw_and_aya_owned_handles() {
        for use_aya in [false, true] {
            reset();
            STATE.with(|state| state.borrow_mut().use_aya = use_aya);
            let mut manager = manager(HwBpScope::Threads);
            manager.attach(&mut Ebpf, spec(0x1000), process(), true).unwrap();
            let published = manager.specs.clone();
            for index in 0..3 {
                assert_peer(index, false);
            }
            drop(manager);
            assert_all_closed();
            assert!(published.lock().unwrap().is_empty());
            STATE.with(|state| {
                let state = state.borrow();
                assert_eq!(state.disabled, if use_aya { 0 } else { 3 });
                assert_eq!(state.aya_drops.get(), if use_aya { 3 } else { 0 });
            });
        }
    }

    #[test]
    fn paused_sweep_releases_dead_and_reused_tids_without_reopening() {
        reset();
        let mut manager = manager(HwBpScope::Threads);
        manager.attach(&mut Ebpf, spec(0x1000), process(), true).unwrap();
        manager.automatic_attach_paused = true;
        STATE.with(|state| state.borrow_mut().tasks = vec![task(42, 100), task(43, 999)]);
        manager.sweep(&mut Ebpf);
        assert_eq!(attempts(), 3);
        assert_eq!(manager.entries[0].links.len(), 1);
        assert_eq!(manager.entries[0].target_count, 2);
        assert_peer(0, false);
        assert_peer(1, true);
        assert_peer(2, true);
        drop(manager);
        assert_all_closed();
    }

    #[test]
    fn permission_denied_snapshots_preserve_existing_handles() {
        reset();
        let mut manager = manager(HwBpScope::Threads);
        manager.attach(&mut Ebpf, spec(0x1000), process(), true).unwrap();
        STATE.with(|state| state.borrow_mut().list_error = Some(io::ErrorKind::PermissionDenied));
        manager.sweep(&mut Ebpf);
        assert_eq!(manager.entries[0].links.len(), 3);
        STATE.with(|state| state.borrow_mut().process_error = Some(io::ErrorKind::PermissionDenied));
        manager.sweep(&mut Ebpf);
        assert_eq!(manager.entries[0].links.len(), 3);
        assert_eq!(attempts(), 3);
        for index in 0..3 {
            assert_peer(index, false);
        }
        drop(manager);
        assert_all_closed();
    }

    #[test]
    fn reused_process_releases_session_instead_of_attaching_old_addresses() {
        reset();
        let mut manager = manager(HwBpScope::Threads);
        manager.attach(&mut Ebpf, spec(0x1000), process(), true).unwrap();
        let original = process();
        STATE.with(|state| state.borrow_mut().process.start_time += 1);
        assert!(manager.attach(&mut Ebpf, spec(0x2000), original, true).is_err());
        manager.sweep(&mut Ebpf);
        assert!(manager.is_empty());
        assert_eq!(attempts(), 3);
        assert_all_closed();
    }

    #[test]
    fn main_scope_is_preserved_during_later_sweeps() {
        reset();
        STATE.with(|state| state.borrow_mut().tasks = vec![task(7, 99), task(42, 100), task(99, 101)]);
        let mut manager = manager(HwBpScope::Main);
        let coverage = manager.attach(&mut Ebpf, spec(0x1000), process(), true).unwrap();
        assert_eq!((coverage.active, coverage.target), (1, 1));
        STATE.with(|state| state.borrow_mut().tasks.push(task(101, 102)));
        manager.sweep(&mut Ebpf);
        assert_eq!(attempts(), 1);
        assert_eq!(manager.entries[0].links[0].0, HwBpTarget::Thread(task(42, 100)));
        STATE.with(|state| assert!(state.borrow().list_scopes.iter().all(|main| *main)));
        drop(manager);
        assert_all_closed();
    }

    #[test]
    fn repeated_systemwide_request_reports_existing_partial_coverage() {
        reset();
        STATE.with(|state| state.borrow_mut().outcomes = [None, Some(libc::ENOSPC)].into());
        let mut manager = manager(HwBpScope::SystemWide);
        let coverage = manager.attach(&mut Ebpf, spec(0x1000), process(), true).unwrap();
        assert_eq!((coverage.active, coverage.target), (1, 3));
        let repeated = manager.attach(&mut Ebpf, spec(0x1000), process(), true).unwrap();
        assert_eq!((repeated.active, repeated.target), (1, 3));
        manager.sweep(&mut Ebpf);
        assert_eq!(
            attempts(),
            2,
            "systemwide retries must not claim unperformed CPU attachment"
        );
        drop(manager);
        assert_all_closed();
    }

    #[test]
    fn detach_closes_only_matching_address_and_records_cancellation() {
        reset();
        let mut manager = manager(HwBpScope::Threads);
        let epoch = manager.cancellations.current();
        manager.attach(&mut Ebpf, spec(0x1000), process(), true).unwrap();
        manager.attach(&mut Ebpf, spec(0x2000), process(), true).unwrap();
        assert_eq!(manager.detach(0x1000), 1);
        assert!(manager.cancellations.is_cancelled(0x1000, epoch));
        assert!(!manager.cancellations.is_cancelled(0x2000, epoch));
        for index in 0..6 {
            assert_peer(index, index < 3);
        }
        assert_eq!(*manager.specs.lock().unwrap(), vec![spec(0x2000)]);
        drop(manager);
        assert_all_closed();
    }
}
