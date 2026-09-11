//! Host-only fixture driven by reservation_paths.py; no kernel helpers execute.
//! Maps/helpers are deterministic stubs. Probe bodies, passes_filter, PtRegs,
//! common event structs, and default thread filtering come from current source.
#![allow(dead_code, unused_attributes)]

use std::cell::RefCell;
use std::ffi::c_void;
use std::mem::{size_of, MaybeUninit};
use std::ops::{Deref, DerefMut};

include!(env!("KTRACE_PROBE_FUNCTIONS"));

const PID: u32 = 2718;
const TID: u32 = 2818;
const UID: u32 = 10123;
const GID: u32 = 50123;
const NR: i64 = 63;
const TIMESTAMP: u64 = 0x0123_4567_89ab_cdef;
const POISON: u8 = 0xa5;
// Synthetic code intervals only; no process mapping is inspected or created.
const APP_CODE: (u64, u64) = (0x1000_0000, 0x1000_1000);
const SYSTEM_CODE: (u64, u64) = (0x2000_0000, 0x2000_1000);

#[derive(Default)]
struct RingState {
    full: bool,
    reserve_calls: usize,
    outstanding: usize,
    submits: usize,
    discards: usize,
    abandoned: usize,
    records: Vec<Vec<u8>>,
}

struct State {
    filter: Filter,
    descendant: bool,
    root_marks: Vec<u32>,
    lib_ranges: Vec<(u64, u64)>,
    comm: Result<[u8; TASK_COMM_LEN], i64>,
    read_calls: usize,
    fail_read: Option<usize>,
    stats: [u64; trace_stats::COUNT as usize],
    rings: [RingState; 3],
}

impl Default for State {
    fn default() -> Self {
        let mut filter = Filter::any();
        // Different UID/GID also exercises the low-32-bit helper interpretation.
        filter.uid = UID;
        filter.pid = PID;
        Self {
            filter,
            descendant: false,
            root_marks: Vec::new(),
            lib_ranges: vec![APP_CODE],
            comm: Ok(comm("fixture-main")),
            read_calls: 0,
            fail_read: None,
            stats: [0; trace_stats::COUNT as usize],
            rings: Default::default(),
        }
    }
}

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
}

fn state<R>(f: impl FnOnce(&mut State) -> R) -> R {
    STATE.with(|s| f(&mut s.borrow_mut()))
}

fn reset() {
    state(|s| *s = State::default());
}

fn comm(name: &str) -> [u8; TASK_COMM_LEN] {
    let mut bytes = [0; TASK_COMM_LEN];
    assert!(name.len() < TASK_COMM_LEN);
    bytes[..name.len()].copy_from_slice(name.as_bytes());
    bytes
}

fn bpf_get_current_pid_tgid() -> u64 {
    (u64::from(PID) << 32) | u64::from(TID)
}

fn bpf_get_current_uid_gid() -> u64 {
    (u64::from(GID) << 32) | u64::from(UID)
}

fn bpf_get_current_comm() -> Result<[u8; TASK_COMM_LEN], i64> {
    state(|s| s.comm)
}

unsafe fn bpf_ktime_get_ns() -> u64 {
    TIMESTAMP
}

unsafe fn bpf_probe_read_kernel<T: Copy>(pointer: *const T) -> Result<T, i64> {
    let fail = state(|s| {
        s.read_calls += 1;
        s.fail_read == Some(s.read_calls)
    });
    if fail {
        Err(-14)
    } else {
        Ok(pointer.read())
    }
}

fn load_filter() -> Filter {
    state(|s| s.filter)
}

fn is_tracked_descendant(_pid: u32) -> bool {
    state(|s| s.descendant)
}

fn mark_tracked_root(pid: u32) {
    state(|s| s.root_marks.push(pid));
}

fn lr_in_lib_ranges(pid: u32, lr: u64) -> bool {
    assert_eq!(pid, PID);
    state(|s| s.lib_ranges.iter().any(|&(lo, hi)| lr >= lo && lr < hi))
}

fn bump_stat(index: u32) {
    state(|s| s.stats[index as usize] += 1);
}

struct RawTracePointContext(*mut c_void);
impl RawTracePointContext {
    fn as_ptr(&self) -> *mut c_void {
        self.0
    }
}

struct ProbeContext(*mut c_void);
impl ProbeContext {
    fn as_ptr(&self) -> *mut c_void {
        self.0
    }
}

struct PerfEventContext {
    ctx: *mut PerfEventData,
}

struct RingBuf(usize);
static SYSCALL_EVENTS: RingBuf = RingBuf(0);
static UPROBE_EVENTS: RingBuf = RingBuf(1);
static HWBP_EVENTS: RingBuf = RingBuf(2);

impl RingBuf {
    fn reserve<T: 'static>(&self, flags: u64) -> Option<RingBufEntry<T>> {
        assert_eq!(flags, 0);
        if state(|s| {
            let ring = &mut s.rings[self.0];
            ring.reserve_calls += 1;
            if ring.full {
                true
            } else {
                assert_eq!(ring.outstanding, 0, "previous reservation leaked");
                ring.outstanding += 1;
                false
            }
        }) {
            return None;
        }
        let mut value = Box::new(MaybeUninit::<T>::uninit());
        // Define every allocation byte as poison before the real writes. This
        // permits inspecting incomplete output without reading uninitialized Rust
        // memory; equality with an independently serialized record detects it.
        unsafe {
            value.as_mut_ptr().cast::<u8>().write_bytes(POISON, size_of::<T>());
        }
        Some(RingBufEntry {
            ring: self.0,
            value,
            released: false,
        })
    }
}

struct RingBufEntry<T> {
    ring: usize,
    value: Box<MaybeUninit<T>>,
    released: bool,
}

// Match Aya's MaybeUninit deref API, including as_mut_ptr method resolution.
impl<T> Deref for RingBufEntry<T> {
    type Target = MaybeUninit<T>;
    fn deref(&self) -> &Self::Target {
        &self.value
    }
}
impl<T> DerefMut for RingBufEntry<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.value
    }
}

impl<T> RingBufEntry<T> {
    fn discard(mut self, flags: u64) {
        assert_eq!(flags, 0);
        state(|s| {
            let ring = &mut s.rings[self.ring];
            ring.discards += 1;
            ring.outstanding -= 1;
        });
        self.released = true;
    }

    fn submit(mut self, flags: u64) {
        assert_eq!(flags, 0);
        let bytes = unsafe { std::slice::from_raw_parts(self.value.as_ptr().cast::<u8>(), size_of::<T>()) }.to_vec();
        state(|s| {
            let ring = &mut s.rings[self.ring];
            ring.records.push(bytes);
            ring.submits += 1;
            ring.outstanding -= 1;
        });
        self.released = true;
    }
}

impl<T> Drop for RingBufEntry<T> {
    fn drop(&mut self) {
        if !self.released {
            // Free the host box, but leave the logical reservation outstanding.
            // An ordinary Rust drop must never masquerade as eBPF discard.
            state(|s| s.rings[self.ring].abandoned += 1);
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Probe {
    Syscall,
    Uprobe,
}

impl Probe {
    fn ring(self) -> usize {
        match self {
            Self::Syscall => 0,
            Self::Uprobe => 1,
        }
    }

    fn run(self) -> Result<u32, u32> {
        self.run_with_regs(&registers())
    }

    fn run_with_regs(self, regs: &PtRegs) -> Result<u32, u32> {
        match self {
            Self::Syscall => {
                // syscallno intentionally differs: nr must come from args[1].
                let args = [regs as *const PtRegs as u64, NR as u64];
                let context = RawTracePointContext(args.as_ptr() as *mut c_void);
                try_raw_sys_sys_enter(&context)
            }
            Self::Uprobe => {
                let context = ProbeContext(regs as *const PtRegs as *mut c_void);
                try_generic_uprobe(&context)
            }
        }
    }
}

fn registers() -> PtRegs {
    PtRegs {
        regs: std::array::from_fn(|index| {
            if index == 30 {
                APP_CODE.0 + 0x100
            } else {
                0x1020_3040_5000_0000 + index as u64 * 0x0101_0101
            }
        }),
        sp: 0x2131_4151_6171_8191,
        pc: SYSTEM_CODE.0 + 0x200,
        pstate: 0x4353_6373_8393_a3b3,
        orig_x0: 0xdead_beef,
        syscallno: 999,
        unused2: 0xfeed_face,
    }
}

fn run_hwbp() -> Result<u32, u32> {
    let regs = registers();
    let mut data = PerfEventData {
        regs: UserRegs {
            regs: regs.regs,
            sp: regs.sp,
            pc: regs.pc,
            pstate: regs.pstate,
        },
        sample_period: 1,
        addr: 0x3000_0080,
    };
    try_hw_breakpoint(&PerfEventContext { ctx: &mut data })
}

#[test]
fn hwbp_entry_count_includes_uid_and_pid_rejections() {
    for (uid_mismatch, rejected) in [
        (true, trace_stats::HWBP_UID_FILTERED),
        (false, trace_stats::HWBP_PID_FILTERED),
    ] {
        reset();
        state(|s| {
            if uid_mismatch {
                s.filter.uid += 1;
            } else {
                s.filter.pid += 1;
            }
        });
        assert_eq!(run_hwbp(), Ok(0));
        state(|s| {
            assert_eq!(s.stats[trace_stats::HWBP_ENTERED as usize], 1);
            assert_eq!(s.stats[rejected as usize], 1);
            assert_eq!(s.stats[trace_stats::HWBP_SUBMITTED as usize], 0);
            assert_eq!(s.stats[trace_stats::HWBP_RING_DROPPED as usize], 0);
            assert_eq!(s.rings[2].reserve_calls, 0);
        });
    }
}

#[test]
fn hwbp_success_and_ring_full_have_distinct_counters() {
    for full in [false, true] {
        reset();
        state(|s| s.rings[2].full = full);
        assert_eq!(run_hwbp(), Ok(0));
        state(|s| {
            assert_eq!(s.stats[trace_stats::HWBP_ENTERED as usize], 1);
            assert_eq!(s.stats[trace_stats::HWBP_SUBMITTED as usize], u64::from(!full));
            assert_eq!(s.stats[trace_stats::HWBP_RING_DROPPED as usize], u64::from(full));
            assert_eq!(s.stats[trace_stats::HWBP_UID_FILTERED as usize], 0);
            assert_eq!(s.stats[trace_stats::HWBP_PID_FILTERED as usize], 0);
            let ring = &s.rings[2];
            assert_eq!(ring.outstanding, 0);
            assert_eq!(ring.abandoned, 0);
            assert_eq!(ring.records.len(), usize::from(!full));
            assert_eq!(s.rings[0].reserve_calls + s.rings[1].reserve_calls, 0);
            if !full {
                let mut expected = Vec::new();
                expected.extend(PID.to_ne_bytes());
                expected.extend(TID.to_ne_bytes());
                expected.extend(TIMESTAMP.to_ne_bytes());
                expected.extend(comm("fixture-main"));
                expected.extend(0x3000_0080u64.to_ne_bytes());
                let regs = registers();
                for value in regs.regs.into_iter().chain([regs.sp, regs.pc, regs.pstate]) {
                    expected.extend(value.to_ne_bytes());
                }
                assert_eq!(ring.records[0], expected);
            }
        });
    }
}

fn expected(probe: Probe, name: [u8; TASK_COMM_LEN]) -> Vec<u8> {
    expected_with_regs(probe, name, &registers())
}

fn expected_with_regs(probe: Probe, name: [u8; TASK_COMM_LEN], regs: &PtRegs) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend(PID.to_ne_bytes());
    bytes.extend(TID.to_ne_bytes());
    bytes.extend(TIMESTAMP.to_ne_bytes());
    bytes.extend(name);
    if matches!(probe, Probe::Syscall) {
        bytes.extend(NR.to_ne_bytes());
    }
    for value in regs.regs.into_iter().chain([regs.sp, regs.pc, regs.pstate]) {
        bytes.extend(value.to_ne_bytes());
    }
    bytes
}

fn assert_ring(probe: Probe, reserve: usize, submit: usize, discard: usize) {
    state(|s| {
        let ring = &s.rings[probe.ring()];
        assert_eq!(ring.reserve_calls, reserve, "{probe:?} reserve count");
        assert_eq!(ring.submits, submit, "{probe:?} submit count");
        assert_eq!(ring.discards, discard, "{probe:?} discard count");
        assert_eq!(ring.records.len(), submit);
        assert_eq!(ring.outstanding, 0, "{probe:?} leaked reservation");
        assert_eq!(ring.abandoned, 0, "{probe:?} unconsumed reservation");
        assert_eq!(s.rings[1 - probe.ring()].reserve_calls, 0, "wrong ring used");
    });
}

#[test]
fn success_initializes_every_abi_byte_and_all_registers() {
    assert_eq!(size_of::<SyscallEnterEvent>(), 312);
    assert_eq!(size_of::<UprobeEvent>(), 304);
    for probe in [Probe::Syscall, Probe::Uprobe] {
        reset();
        assert_eq!(probe.run(), Ok(0));
        assert_ring(probe, 1, 1, 0);
        state(|s| {
            assert_eq!(s.rings[probe.ring()].records[0], expected(probe, comm("fixture-main")));
            let mut stats = [0; trace_stats::COUNT as usize];
            stats[2 + probe.ring()] = 1;
            assert_eq!(s.stats, stats);
            assert_eq!(s.read_calls, if matches!(probe, Probe::Syscall) { 36 } else { 34 });
            assert_eq!(s.root_marks, [PID]);
        });
    }
}

#[test]
fn ring_full_has_no_reservation_to_discard_or_register_reads() {
    for probe in [Probe::Syscall, Probe::Uprobe] {
        reset();
        state(|s| s.rings[probe.ring()].full = true);
        assert_eq!(probe.run(), Ok(0));
        assert_ring(probe, 1, 0, 0);
        state(|s| {
            let mut stats = [0; trace_stats::COUNT as usize];
            stats[probe.ring()] = 1;
            assert_eq!(s.stats, stats);
            assert_eq!(s.read_calls, if matches!(probe, Probe::Syscall) { 2 } else { 0 });
        });
    }
}

#[test]
fn syscall_each_of_34_fill_read_failures_discards_once() {
    for read in 3..=36 {
        reset();
        state(|s| s.fail_read = Some(read));
        let error = match read {
            3..=33 => 3,
            34 => 4,
            35 => 5,
            36 => 6,
            _ => unreachable!(),
        };
        assert_eq!(Probe::Syscall.run(), Err(error), "read #{read}");
        assert_ring(Probe::Syscall, 1, 0, 1);
        state(|s| {
            assert_eq!(s.stats, [0; trace_stats::COUNT as usize]);
            assert_eq!(s.read_calls, read);
        });
    }
}

#[test]
fn uprobe_each_of_34_fill_read_failures_discards_once() {
    for read in 1..=34 {
        reset();
        state(|s| s.fail_read = Some(read));
        let error = match read {
            1..=31 => 10,
            32 => 11,
            33 => 12,
            34 => 13,
            _ => unreachable!(),
        };
        assert_eq!(Probe::Uprobe.run(), Err(error), "read #{read}");
        assert_ring(Probe::Uprobe, 1, 0, 1);
        state(|s| {
            assert_eq!(s.stats, [0; trace_stats::COUNT as usize]);
            assert_eq!(s.read_calls, read);
        });
    }
}

#[test]
fn syscall_front_reads_fail_before_reserving() {
    for read in 1..=3 {
        reset();
        state(|s| {
            s.fail_read = Some(read);
            s.filter.lib_only = 1;
        });
        assert_eq!(Probe::Syscall.run(), Err([1, 2, 7][read - 1]));
        assert_ring(Probe::Syscall, 0, 0, 0);
        state(|s| {
            assert_eq!(s.stats, [0; trace_stats::COUNT as usize]);
            assert_eq!(s.read_calls, read);
        });
    }
}

#[test]
fn explicit_uid_pid_tid_and_nr_filters_do_not_reserve() {
    for probe in [Probe::Syscall, Probe::Uprobe] {
        for selector in 0..3 {
            reset();
            state(|s| match selector {
                0 => s.filter.uid = UID + 1,
                1 => s.filter.pid = PID + 1,
                2 => {
                    assert!(s.filter.add_tid_blacklist(TID));
                }
                _ => unreachable!(),
            });
            assert_eq!(probe.run(), Ok(0));
            assert_ring(probe, 0, 0, 0);
            state(|s| assert_eq!(s.stats, [0; trace_stats::COUNT as usize]));
        }
    }
    reset();
    state(|s| s.filter.nr = NR as i32 + 1);
    assert_eq!(Probe::Syscall.run(), Ok(0));
    assert_ring(Probe::Syscall, 0, 0, 0);
    state(|s| assert_eq!(s.stats, [0; trace_stats::COUNT as usize]));
}

#[test]
fn default_thread_exclusion_precedes_reservation_and_has_separate_stats() {
    for probe in [Probe::Syscall, Probe::Uprobe] {
        reset();
        state(|s| s.comm = Ok(comm("RenderThread")));
        assert_eq!(probe.run(), Ok(0));
        assert_ring(probe, 0, 0, 0);
        state(|s| {
            let mut stats = [0; trace_stats::COUNT as usize];
            stats[4 + probe.ring()] = 1;
            assert_eq!(s.stats, stats);
        });

        reset();
        state(|s| {
            s.comm = Ok(comm("RenderThread"));
            s.filter.full_tname = 1;
        });
        assert_eq!(probe.run(), Ok(0));
        assert_ring(probe, 1, 1, 0);
        state(|s| assert_eq!(s.rings[probe.ring()].records[0], expected(probe, comm("RenderThread"))));
    }
}

#[test]
fn syscall_library_miss_never_reserves_and_hit_preserves_fields() {
    for hit in [false, true] {
        reset();
        state(|s| {
            s.filter.lib_only = 1;
            if !hit {
                s.lib_ranges.clear();
            }
        });
        assert_eq!(Probe::Syscall.run(), Ok(0));
        assert_ring(Probe::Syscall, usize::from(hit), usize::from(hit), 0);
        state(|s| {
            assert_eq!(s.read_calls, if hit { 37 } else { 3 });
            if hit {
                assert_eq!(s.rings[0].records[0], expected(Probe::Syscall, comm("fixture-main")));
            } else {
                assert_eq!(s.stats, [0; trace_stats::COUNT as usize]);
            }
        });
    }
}

#[test]
fn read_admission_uses_app_lr_even_when_pc_is_in_system_code() {
    // All four cases use the same nr=63 (read), filter, and App-only interval.
    // Only the captured LR/PC values change. The interval stub compares the
    // value actually passed by the extracted production probe, so selecting PC
    // instead of LR would reverse the two mixed cases and fail this test.
    for (label, lr_range, pc_range, admitted) in [
        ("App LR / system PC", APP_CODE, SYSTEM_CODE, true),
        ("system LR / App PC", SYSTEM_CODE, APP_CODE, false),
        ("App LR / App PC", APP_CODE, APP_CODE, true),
        ("system LR / system PC", SYSTEM_CODE, SYSTEM_CODE, false),
    ] {
        reset();
        state(|s| {
            s.filter.lib_only = 1;
            s.filter.nr = NR as i32;
            assert_eq!(s.lib_ranges, [APP_CODE]);
        });
        let mut regs = registers();
        regs.regs[30] = lr_range.0 + 0x100;
        regs.pc = pc_range.0 + 0x200;
        assert_eq!(Probe::Syscall.run_with_regs(&regs), Ok(0), "{label}");
        assert_ring(Probe::Syscall, usize::from(admitted), usize::from(admitted), 0);
        state(|s| {
            let mut stats = [0; trace_stats::COUNT as usize];
            stats[2] = u64::from(admitted);
            assert_eq!(s.stats, stats, "{label}");
            assert_eq!(s.read_calls, if admitted { 37 } else { 3 }, "{label}");
            if admitted {
                assert_eq!(
                    s.rings[0].records[0],
                    expected_with_regs(Probe::Syscall, comm("fixture-main"), &regs),
                    "{label} must preserve nr, LR, PC and every other field",
                );
            }
        });
    }
}

#[test]
fn comm_helper_failure_still_initializes_comm_to_zero() {
    for probe in [Probe::Syscall, Probe::Uprobe] {
        reset();
        state(|s| s.comm = Err(-14));
        assert_eq!(probe.run(), Ok(0));
        assert_ring(probe, 1, 1, 0);
        state(|s| assert_eq!(s.rings[probe.ring()].records[0], expected(probe, [0; TASK_COMM_LEN])));
    }
}
