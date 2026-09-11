#!/usr/bin/env python3
"""Test the current hardware-breakpoint manager with synthetic host resources.

Extracts the actual manager on every run. Task discovery, perf attachment, BPF,
and ioctl are replaced by in-memory stubs; successful handles own UnixStream
descriptors so deletion and shutdown exercise real fd closure. No Cargo, /proc,
device, network, or actual perf/BPF operation is used.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


def manager_source(root):
    source = (root / "kernel-trace/src/lib.rs").read_text()
    begin = "struct HwBpAttachedEntry {"
    end = "fn validate_hwbp_spec("
    if source.count(begin) != 1 or source.count(end) != 1:
        raise RuntimeError("hardware-breakpoint manager source markers changed")
    start = source.index(begin)
    manager = source[start:source.index(end, start)]
    constants = []
    for name in ("DEFAULT_MAX_HW_WATCHPOINTS", "DEFAULT_MAX_HW_BREAKPOINTS", "PERF_EVENT_IOC_DISABLE_RAW"):
        matches = re.findall(r"(?m)^const " + name + r": [^\n]+;", source)
        if len(matches) != 1:
            raise RuntimeError(f"expected one production constant: {name}")
        constants.extend(matches)
    limit_start = source.index("fn configured_hwbp_limit(")
    configured_limit = source[limit_start:source.index("\n/// 解析 /sys/devices/system/cpu/online", limit_start)]
    lifecycle = root / "kernel-trace/src/hwbp_lifecycle.rs"
    extracted = [
        f"#[path = {json.dumps(str(lifecycle))}] mod hwbp_lifecycle;",
        *constants,
        configured_limit,
        manager,
    ]
    return "\n\n".join(extracted), hashlib.sha256(source.encode()).hexdigest()


def main():
    root = Path(__file__).resolve().parents[2]
    source, revision = manager_source(root)
    with tempfile.TemporaryDirectory(prefix="ktrace-hwbp-manager-") as folder:
        directory = Path(folder)
        extracted = directory / "actual_manager.rs"
        extracted.write_text(source)
        binary = directory / "manager_tests"
        env = os.environ.copy()
        # These tests cover manager ownership and pause behavior using the
        # production default limits, regardless of the caller's device setup.
        env.pop("KT_HWBP_MAX_BREAKPOINTS", None)
        env.pop("KT_HWBP_MAX_WATCHPOINTS", None)
        env["KTRACE_HWBP_MANAGER_SOURCE"] = str(extracted)
        print("Testing actual HwBpManager; lib.rs sha256=" + revision, flush=True)
        subprocess.run(
            ["rustc", "--edition=2021", "--test",
             str(root / "kernel-trace/tests/support/hwbp_manager_fixture.rs"),
             "-o", str(binary)],
            env=env, check=True,
        )
        subprocess.run([str(binary), "hwbp_manager_fixture_tests::"], env=env, check=True)


if __name__ == "__main__":
    main()
