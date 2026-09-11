#!/usr/bin/env python3
"""Run actual syscall/HWBP report builders against owned, in-memory host fixtures.

From any directory:
    python3 /path/to/repo/kernel-trace/tests/run_report_fixture.py

Requires Python 3 and rustc; no Cargo dependencies, BPF, device, target process,
or /proc access. The temporary harness contains freshly extracted production
code, not a second implementation of the builder. Only maps/process metadata,
argument decoding and stack reads are replaced by the fixture's observable
stubs. Files under the temporary directory are removed after the run.
"""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile


def between(source, start, end):
    if source.count(start) != 1:
        raise ValueError(f"expected one source marker: {start!r}")
    first = source.index(start)
    return source[first:source.index(end, first + len(start))]


def harness_source(root):
    lib = (root / "kernel-trace/src/lib.rs").read_text()
    common = (root / "kernel-trace-common/src/lib.rs").read_text()
    argspec = (root / "kernel-trace/src/argspec.rs").read_text()

    # Keep the repr(C) event definition and actual comm normalization together.
    event_marker = common.index("pub struct SyscallEnterEvent {")
    event_start = common.rindex("#[repr(C)]", 0, event_marker)
    event = common[event_start:common.index("/// 用户态 uprobe", event_marker)]
    hwbp_marker = common.index("pub struct HwBpEvent {")
    hwbp_start = common.rindex("#[repr(C)]", 0, hwbp_marker)
    hwbp_event = common[hwbp_start:common.index("/// 共享过滤器", hwbp_marker)]
    hwbp_spec = between(common, "#[derive(Debug, Clone, Copy, PartialEq, Eq)]\npub struct HwBpSpec", "// =====================================================================")
    hwbp_constants = "\n".join(line for line in common.splitlines() if line.startswith("pub const HW_BP_KIND_"))
    hwbp_kind_name = between(common, "pub fn kind_name(", "    /// 解析")
    comm = between(common, "fn trim_comm(", '#[cfg(feature = "user")]')
    constant = next(line for line in common.splitlines() if line.startswith("pub const TASK_COMM_LEN:"))
    options_and_report = between(lib, "#[derive(Clone, Debug)]\npub struct TraceOptions", "impl TraceReport {")
    helpers_and_builder = between(lib, "fn expand_regs_full(", "fn build_report_uprobe(")
    hwbp_builder = between(lib, "fn build_report_hwbp(", "/// 从 /proc/<pid>/status 读 Uid")
    hwbp_matcher = between(lib, "fn match_hwbp_spec<'a>(", "// =====================================================================")
    report_impl = between(lib, "impl TraceReport {", "// =====================================================================\n// 取证")
    serialization_helpers = between(lib, "fn push_u64(", "// 占位避免")
    matcher = between(argspec, "pub fn lib_path_matches(", "/// 读 pid 进程 maps")

    lines = ["#![allow(dead_code)]"]
    for module, path in [
        ("load", "kernel-trace/src/load.rs"),
        ("filter", "kernel-trace/src/filter.rs"),
        ("groups", "kernel-trace-common/src/groups.rs"),
        ("syscall_table_aarch64", "kernel-trace-common/src/syscall_table_aarch64.rs"),
    ]:
        lines.append(f"#[path={json.dumps(str(root / path), ensure_ascii=False)}] mod {module};")
    syscall_path = json.dumps(str(root / "kernel-trace-common/src/syscall.rs"), ensure_ascii=False)
    lines += [
        "use filter::{FilterRule, event_passes};",
        "use groups::uid_matches_groups;",
        constant, event, comm, hwbp_constants, hwbp_event, hwbp_spec,
        "impl SyscallEnterEvent { fn comm_str(&self) -> &str { trim_comm(&self.comm) } }",
        "impl HwBpEvent { fn comm_str(&self) -> &str { trim_comm(&self.comm) } " + hwbp_kind_name + " }",
        f"mod kernel_trace_common {{ pub use super::HwBpEvent; #[path={syscall_path}] pub mod syscall; }}",
        options_and_report, helpers_and_builder, matcher, hwbp_matcher,
        hwbp_builder, report_impl, serialization_helpers,
        f"include!({json.dumps(str(root / 'kernel-trace/tests/support/report_fixture.rs'), ensure_ascii=False)});",
    ]
    return "\n".join(lines), hashlib.sha256(lib.encode()).hexdigest()[:16]


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--rustc", default="rustc", help="host rustc executable")
    arguments = parser.parse_args()
    rustc = shutil.which(arguments.rustc)
    if not rustc:
        parser.error(f"rustc not found: {arguments.rustc}")
    root = Path(__file__).resolve().parents[2]
    source, revision = harness_source(root)
    with tempfile.TemporaryDirectory(prefix="kernel-trace-report-fixture-") as folder:
        source_path = Path(folder) / "report_fixture.rs"
        binary = Path(folder) / "report_fixture_tests"
        source_path.write_text(source)
        print(f"Testing actual syscall/HWBP reports; lib.rs sha256={revision}", flush=True)
        subprocess.run([rustc, "--edition=2021", "--test", str(source_path), "-o", str(binary)], check=True)
        # Other modules' unit tests are compiled, but this runner executes only
        # these builder fixtures; kernel-trace/tests/host.rs covers those modules.
        result = subprocess.run(
            [str(binary), "report_fixture_tests::", "--nocapture", "--test-threads=1"],
            text=True, capture_output=True,
        )
        # Keep successful output readable; retain the complete serializer output
        # in memory for independent JSON validation below.
        print("\n".join(line for line in result.stdout.splitlines()
                        if line and not line.startswith("REPORT_FIXTURE_JSON ")), flush=True)
        if result.stderr:
            print(result.stderr, end="")
        result.check_returncode()
        rows = [json.loads(line.removeprefix("REPORT_FIXTURE_JSON "))
                for line in result.stdout.splitlines() if line.startswith("REPORT_FIXTURE_JSON ")]
        assert len(rows) == 12, f"expected 12 HWBP JSON fixtures, got {len(rows)}"
        for row in rows:
            assert row["type"] == "hwbp.hit"
            assert row["pid"] == 1234 and row["tid"] == 1235
            assert row["comm"] == 'fi"xt\\ure\n'
            assert row["pc"] == "0x9008"
            assert row["bp"]["addr"] == ("0x9008" if row["bp"]["kind"] == "x" else "0x1083")
            assert "addr" not in row, "address belongs in the nested bp object"
        print(f"Validated {len(rows)} serialized HWBP records with Python's JSON parser.")


if __name__ == "__main__":
    main()
