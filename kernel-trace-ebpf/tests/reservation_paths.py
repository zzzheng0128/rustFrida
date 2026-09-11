#!/usr/bin/env python3
"""Exercise the real probe bodies with offline host helper/ring stubs.

Run from any directory: python3 kernel-trace-ebpf/tests/reservation_paths.py
Requires only Python 3 and host rustc; does not use Cargo, Aya linking, a device,
network access, or /proc. Production functions are extracted afresh on each run,
not copied into the fixture. This tests control flow and emitted ABI bytes, not
the BPF verifier, generated stack depth, kernel ring behavior, or concurrency.
"""

import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile


def item(source, prefix):
    # Rustfmt-style top-level items: only the final closing brace is in column 0.
    # Fail on layout changes rather than silently substituting a stale fixture.
    pattern = r"(?ms)^" + re.escape(prefix) + r"\b[^\n]*\{\n.*?^\}"
    matches = re.findall(pattern, source)
    if len(matches) != 1:
        raise RuntimeError(f"expected one source item starting with {prefix!r}")
    return matches[0]


def main():
    tests = Path(__file__).resolve().parent
    root = tests.parent.parent
    source = (tests.parent / "src/main.rs").read_text()
    generated = [
        '#[path = "' + (root / "kernel-trace-common/src/lib.rs").as_posix() + '"]',
        "mod common;",
        "use common::{trace_stats, Filter, HwBpEvent, SyscallEnterEvent, UprobeEvent, MAX_TID_BLACKLIST_COUNT};",
        "use common::thread_names::should_filter_thread;",
        "pub use common::TASK_COMM_LEN;",
        "#[repr(C)]\n#[derive(Clone, Copy)]\n" + item(source, "pub struct PtRegs"),
        "#[repr(C)]\n" + item(source, "pub struct UserRegs"),
        "#[repr(C)]\n" + item(source, "pub struct PerfEventData"),
    ]
    for name in ("passes_filter", "try_raw_sys_sys_enter", "try_generic_uprobe", "try_hw_breakpoint"):
        generated.append(item(source, "fn " + name))

    with tempfile.TemporaryDirectory(prefix="ktrace-reservation-") as temporary:
        temporary = Path(temporary)
        extracted = temporary / "actual_probe_functions.rs"
        extracted.write_text("\n\n".join(generated) + "\n")
        binary = temporary / "reservation-host-tests"
        env = os.environ.copy()
        env["KTRACE_PROBE_FUNCTIONS"] = str(extracted)
        print("main.rs sha256=" + hashlib.sha256(source.encode()).hexdigest(), flush=True)
        subprocess.run(
            ["rustc", "--edition=2021", "--test", str(tests / "reservation_paths_host.rs"),
             "-o", str(binary)],
            env=env, check=True,
        )
        subprocess.run([str(binary), "--test-threads=1"], check=True)


if __name__ == "__main__":
    main()
