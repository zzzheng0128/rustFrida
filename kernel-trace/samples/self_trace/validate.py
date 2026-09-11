#!/usr/bin/env python3
"""Validate copied self_trace artifacts offline; never contacts a device."""

import argparse
from collections import Counter
import json
from pathlib import Path
import sys

EXPECTED_READS = 6400
EXPECTED_LIBRARIES = {
    "libktrace_sample_a.so": 3200,
    "libktrace_sample_b.so": 3200,
}


def validate(directory: Path, require_library_counts: bool = False) -> dict:
    pid_text = (directory / "sample.pid").read_text(encoding="utf-8").strip()
    if not pid_text.isdecimal() or int(pid_text) <= 0:
        raise ValueError("sample.pid must contain a positive decimal PID")
    pid = int(pid_text)
    if (directory / "sample.exit").read_text(encoding="utf-8").strip() != "0":
        raise ValueError("sample did not exit successfully")
    sample_log = (directory / "sample.log").read_text(encoding="utf-8").splitlines()
    for expected in [
        f"sample pid={pid} ready",
        f"sample pid={pid} done: 6400 reads, 3200 per library",
        "sample completed: 6400 reads, 3200 per library",
    ]:
        if expected not in sample_log:
            raise ValueError(f"missing sample handshake: {expected}")

    total_records = 0
    reads = 0
    decoded_reads = 0
    libraries = Counter()
    details = Counter()
    with (directory / "events.jsonl").open(encoding="utf-8") as events:
        for number, line in enumerate(events, 1):
            if not line.endswith("\n"):
                raise ValueError(f"line {number}: incomplete JSONL record (missing newline)")
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"line {number}: invalid JSON: {error.msg}") from error
            if not isinstance(record, dict):
                raise ValueError(f"line {number}: record must be a JSON object")
            if type(record.get("pid")) is not int or record["pid"] != pid:
                raise ValueError(f"line {number}: record PID differs from sample PID {pid}")
            total_records += 1
            if record.get("type") != "svc.enter" or record.get("nr") != 63:
                continue
            regs = record.get("regs")
            if not isinstance(regs, dict):
                raise ValueError(f"line {number}: read record is missing raw registers")
            try:
                fd = int(regs["x0"], 0)
                size = int(regs["x2"], 0)
            except (KeyError, TypeError, ValueError) as error:
                raise ValueError(f"line {number}: malformed raw fd/count register") from error
            if fd < 0 or size != 64:
                raise ValueError(f"line {number}: expected a 64-byte read from a valid descriptor")
            if "args" in record:
                args = record["args"]
                if not isinstance(args, list) or f"fd={fd}" not in args or "count=64" not in args:
                    raise ValueError(f"line {number}: decoded fd/count differs from raw registers")
                decoded_reads += 1
            label = record.get("so", "unresolved")
            detail = record.get("detail", "unknown")
            if not isinstance(label, str) or not isinstance(detail, str):
                raise ValueError(f"line {number}: malformed library/detail label")
            reads += 1
            libraries[label] += 1
            details[detail] += 1

    if reads != EXPECTED_READS:
        raise ValueError(f"expected {EXPECTED_READS} sample read records, found {reads}")
    if require_library_counts and dict(libraries) != EXPECTED_LIBRARIES:
        raise ValueError(f"expected 3200 reads per sample library, found {dict(libraries)}")
    return {
        "pid": pid,
        "total_records": total_records,
        "read_records": reads,
        "decoded_read_records": decoded_reads,
        "read_details": dict(details),
        "read_libraries": dict(libraries),
        "library_counts_checked": require_library_counts,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="copied self_trace run directory")
    parser.add_argument("--require-library-counts", action="store_true")
    args = parser.parse_args()
    try:
        summary = validate(args.directory, args.require_library_counts)
    except (OSError, UnicodeError, ValueError) as error:
        print(f"self_trace validation failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
