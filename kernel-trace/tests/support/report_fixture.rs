// Included by run_report_fixture.py after extraction of the production builder,
// report/options types, shared event ABI, helpers and library path matcher.
// All addresses below refer only to synthetic mappings; none are dereferenced.

use std::cell::RefCell;

const APP_PATH: &str = "/data/app/org.example.fixture/lib/arm64/libfixture.so";
const SYSTEM_PATH: &str = "/apex/com.android.runtime/lib64/bionic/libc.so";
const APP_LR: u64 = 0x1040;
const SYSTEM_PC: u64 = 0x9008;

#[derive(Default, Clone)]
struct FixtureState {
    cached: bool,
    deny_details: bool,
    snapshots: usize,
    cached_snapshots: usize,
    backtraces: usize,
    kernel_stacks: usize,
    named_lookups: Vec<u64>,
    library_queries: Vec<(u32, u64, String)>,
    decode_flags: Vec<bool>,
}

thread_local! {
    static FIXTURE: RefCell<FixtureState> = RefCell::new(FixtureState::default());
}

fn fixture_path(address: u64) -> Option<(&'static str, u64)> {
    match address {
        0x1000..=0x1fff => Some((APP_PATH, 0x1000)),
        0x9000..=0x9fff => Some((SYSTEM_PATH, 0x9000)),
        _ => None,
    }
}

mod procinfo {
    pub struct ProcInfo {
        pub ns_pid: Option<u32>,
        pub uid: Option<u32>,
    }
    pub fn get(pid: u32) -> ProcInfo {
        assert_eq!(pid, 1234);
        ProcInfo { ns_pid: Some(12), uid: Some(10001) }
    }
}

mod argspec {
    pub fn lr_in_lib(pid: u32, lr: u64, needle: &str) -> bool {
        super::FIXTURE.with(|state| state.borrow_mut().library_queries.push((pid, lr, needle.into())));
        super::fixture_path(lr)
            .is_some_and(|(path, _)| super::lib_path_matches(path, needle))
    }

    pub fn decode_args(_: i64, _: u32, _: &[u64; 31]) -> Option<(Vec<String>, Vec<String>)> {
        panic!("builder used the legacy decoder without passing opts.dumphex")
    }

    pub fn decode_args_with_options(
        nr: i64, pid: u32, _: &[u64; 31], dumphex: bool,
    ) -> Option<(Vec<String>, Vec<String>)> {
        assert_eq!((nr, pid), (64, 1234));
        super::FIXTURE.with(|state| {
            let mut state = state.borrow_mut();
            assert!(!state.deny_details, "basic report decoded arguments");
            state.decode_flags.push(dumphex);
        });
        Some((vec!["owned-fixture-buffer".into()],
              if dumphex { vec!["owned-fixture-hexdump".into()] } else { Vec::new() }))
    }
}

mod stackwalk {
    pub struct MapsSnapshot;

    pub fn snapshot(pid: u32) -> MapsSnapshot {
        assert_eq!(pid, 1234);
        super::FIXTURE.with(|state| {
            let mut state = state.borrow_mut();
            assert!(!state.deny_details, "basic report refreshed maps");
            state.snapshots += 1;
        });
        MapsSnapshot
    }

    pub fn cached_snapshot(pid: u32) -> Option<MapsSnapshot> {
        assert_eq!(pid, 1234);
        super::FIXTURE.with(|state| {
            let mut state = state.borrow_mut();
            state.cached_snapshots += 1;
            state.cached.then_some(MapsSnapshot)
        })
    }

    impl MapsSnapshot {
        pub fn resolve_addr_named(&self, address: u64) -> Option<String> {
            super::FIXTURE.with(|state| state.borrow_mut().named_lookups.push(address));
            super::fixture_path(address).map(|(path, base)| {
                format!("{}+0x{:x}", path.rsplit('/').next().unwrap(), address - base)
            })
        }

        pub fn resolve_addr(&self, address: u64) -> Option<String> {
            self.resolve_addr_named(address).or_else(|| Some(format!("0x{address:x}(anon)")))
        }

        pub fn resolve_base(&self, address: u64) -> Option<u64> {
            super::fixture_path(address).map(|(_, base)| base)
        }

        pub fn full_backtrace(&self, pid: u32, _: u64, _: u64, _: u64, _: usize) -> Vec<String> {
            assert_eq!(pid, 1234);
            super::FIXTURE.with(|state| {
                let mut state = state.borrow_mut();
                assert!(!state.deny_details, "basic report read stack memory");
                state.backtraces += 1;
            });
            vec!["libc.so+0x20".into(), "libfixture.so+0x80".into()]
        }
    }
}

fn read_kernel_stack(pid: u32) -> Option<String> {
    assert_eq!(pid, 1234);
    FIXTURE.with(|state| {
        let mut state = state.borrow_mut();
        assert!(!state.deny_details, "basic report read kernel stack");
        state.kernel_stacks += 1;
    });
    Some("owned-fixture-kernel-stack".into())
}

#[cfg(test)]
mod report_fixture_tests {
    use super::*;

    fn reset(cached: bool, deny_details: bool) {
        FIXTURE.with(|state| *state.borrow_mut() = FixtureState { cached, deny_details, ..Default::default() });
    }

    fn state() -> FixtureState {
        FIXTURE.with(|state| state.borrow().clone())
    }

    fn event() -> SyscallEnterEvent {
        let mut comm = [0; TASK_COMM_LEN];
        comm[..7].copy_from_slice(b"fixture");
        let mut regs = std::array::from_fn(|index| 0x5000 + index as u64);
        regs[30] = APP_LR;
        SyscallEnterEvent { pid: 1234, tid: 1235, timestamp_ns: 987654321,
            comm, nr: 64, regs, sp: 0x6000, pc: SYSTEM_PC, pstate: 0x60000000 }
    }

    fn options() -> TraceOptions {
        TraceOptions { lib_range: Some("org.example.fixture".into()), lib_only: true, ..Default::default() }
    }

    #[test]
    fn system_pc_and_application_lr_keeps_application_source() {
        reset(true, false);
        let report = build_report_sys(&event(), &options(), None).unwrap();
        assert!(report.lib_hit);
        assert_eq!(report.so_tag, "libfixture.so");
        assert_eq!(report.lr_off.as_deref(), Some("libfixture.so+0x40"));
        assert_eq!(report.pc_off.as_deref(), Some("libc.so+0x8"));
        assert_eq!(report.so_base, Some(0x1000));
        assert_eq!(state().library_queries, [(1234, APP_LR, "org.example.fixture".into())]);
    }

    #[test]
    fn application_pc_does_not_replace_system_lr_in_library_filter() {
        reset(true, false);
        let mut event = event();
        event.regs[30] = SYSTEM_PC;
        event.pc = APP_LR;
        assert!(build_report_sys(&event, &options(), None).is_none());
        assert_eq!(state().snapshots, 0);
        assert_eq!(state().library_queries[0].1, SYSTEM_PC);
    }

    #[test]
    fn disabling_stack_keeps_module_offsets_without_backtrace_reads() {
        reset(true, false);
        let mut opts = options();
        opts.stack_trace = false;
        let report = build_report_sys(&event(), &opts, None).unwrap();
        assert_eq!(report.so_tag, "libfixture.so");
        assert_eq!(report.lr_off.as_deref(), Some("libfixture.so+0x40"));
        assert_eq!(report.pc_off.as_deref(), Some("libc.so+0x8"));
        assert!(report.stack.is_none());
        assert_eq!((state().backtraces, state().kernel_stacks), (0, 0));
    }

    #[test]
    fn unknown_lr_does_not_borrow_source_from_pc_or_named_stack_frames() {
        reset(true, false);
        let mut event = event();
        event.regs[30] = 0x7000;
        let report = build_report_sys(&event, &TraceOptions::default(), None).unwrap();
        assert_eq!(report.so_tag, "unresolved");
        assert!(report.lr_off.is_none());
        assert_eq!(report.pc_off.as_deref(), Some("libc.so+0x8"));
        assert_eq!(report.stack.as_ref().unwrap()[0], "libc.so+0x20");
        assert_eq!(state().backtraces, 1);
    }

    #[test]
    fn basic_keeps_raw_fields_and_only_reads_cached_lr_pc_labels() {
        for cached in [false, true] {
            for reason in [load::SkipReason::Budget, load::SkipReason::QueueDelay] {
                reset(cached, true);
                let mut opts = options();
                opts.decode_args = true;
                opts.dumphex = true;
                opts.unwind_stack = true;
                let event = event();
                let report = build_report_sys(&event, &opts, Some(reason)).unwrap();
                assert_eq!((report.host_pid, report.tid, report.timestamp_ns),
                           (event.pid, event.tid, event.timestamp_ns));
                assert_eq!(report.nr, Some(event.nr));
                assert_eq!((report.lr, report.pc), (event.regs[30], event.pc));
                assert_eq!(report.detail_skipped, Some(reason.as_str()));
                let expected_names = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
                    "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x19",
                    "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "fp", "lr",
                    "sp", "pc", "pstate"];
                let regs = report.regs.as_ref().unwrap();
                assert_eq!(regs.len(), expected_names.len());
                let tail = [event.sp, event.pc, event.pstate];
                for ((actual, name), value) in regs.iter().zip(expected_names).zip(event.regs.iter().chain(tail.iter())) {
                    assert_eq!(actual.0, name);
                    assert_eq!(actual.1, *value);
                }
                assert!(report.regs_off.is_none() && report.stack.is_none() && report.kernel_stack.is_none());
                assert!(report.decoded_args.is_none() && report.dump_blocks.is_empty());
                let state = state();
                assert_eq!((state.snapshots, state.backtraces, state.kernel_stacks), (0, 0, 0));
                assert!(state.decode_flags.is_empty());
                assert_eq!(state.cached_snapshots, 1);
                if cached {
                    assert_eq!(report.so_tag, "libfixture.so");
                    assert_eq!(state.named_lookups, [APP_LR, SYSTEM_PC]);
                } else {
                    assert_eq!(report.so_tag, "unresolved");
                    assert!(state.named_lookups.is_empty());
                }
            }
        }
    }

    #[test]
    fn syscall_numbers_are_kept_in_full_and_basic_reports() {
        // These register records are constructed without running a traced workload.
        for nr in [56, 270] {
            for skipped in [None, Some(load::SkipReason::Budget), Some(load::SkipReason::QueueDelay)] {
                reset(true, skipped.is_some());
                let mut event = event();
                event.nr = nr;
                event.regs[8] = nr as u64;
                let report = build_report_sys(&event, &options(), skipped).unwrap();
                assert_eq!(report.nr, Some(nr));
                assert_eq!(report.so_tag, "libfixture.so");
                assert_eq!(report.detail_skipped, skipped.map(load::SkipReason::as_str));
            }
        }
    }

    #[test]
    fn dumphex_false_and_true_reach_the_actual_decoder_call_site() {
        for dumphex in [false, true] {
            reset(true, false);
            let mut opts = options();
            opts.stack_trace = false;
            opts.decode_args = true;
            opts.dumphex = dumphex;
            let report = build_report_sys(&event(), &opts, None).unwrap();
            assert_eq!(state().decode_flags, [dumphex]);
            assert_eq!(report.dump_blocks.len(), usize::from(dumphex));
            assert!(report.decoded_args.is_some());
        }
    }

    #[test]
    fn hwbp_reports_serialize_execution_pc_and_data_access_address() {
        for kind in [HW_BP_KIND_X, HW_BP_KIND_R, HW_BP_KIND_W, HW_BP_KIND_RW] {
            for skipped in [None, Some(load::SkipReason::Budget), Some(load::SkipReason::QueueDelay)] {
                reset(true, skipped.is_some());
                let source = event();
                let mut comm = [0; TASK_COMM_LEN];
                let escaped_comm = b"fi\"xt\\ure\n";
                comm[..escaped_comm.len()].copy_from_slice(escaped_comm);
                let event = HwBpEvent {
                    pid: source.pid, tid: source.tid, timestamp_ns: source.timestamp_ns,
                    comm, regs: source.regs, sp: source.sp, pc: source.pc, pstate: source.pstate,
                    // Execution events deliberately carry an unrelated raw addr;
                    // watchpoints access a byte inside the watched window.
                    addr: if kind == HW_BP_KIND_X { 0xdeadbeef } else { 0x1083 },
                };
                let spec = HwBpSpec {
                    kind,
                    addr: if kind == HW_BP_KIND_X { SYSTEM_PC } else { 0x1080 },
                    len: if kind == HW_BP_KIND_X { 4 } else { 8 },
                };
                let report = build_report_hwbp(&event, &TraceOptions::default(), skipped, &[spec]).unwrap();
                assert_eq!(report.bp_kind, Some(kind));
                assert_eq!(report.bp_addr, Some(if kind == HW_BP_KIND_X { SYSTEM_PC } else { event.addr }));
                assert_eq!(report.pc, SYSTEM_PC);
                assert_eq!(report.detail_skipped, skipped.map(load::SkipReason::as_str));
                if skipped.is_some() {
                    assert_eq!((state().snapshots, state().backtraces, state().kernel_stacks), (0, 0, 0));
                }
                // Python independently parses the actual serializer output,
                // including escaped comm and the nested callback schema.
                println!("\nREPORT_FIXTURE_JSON {}", report.to_jsonl());
            }
        }
    }
}
