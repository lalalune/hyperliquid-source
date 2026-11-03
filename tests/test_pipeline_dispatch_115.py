"""Tests for node #115's pipeline dispatcher at 0x5f88550.

Each case is a target-grounded expectation read off the verbatim
disassembly in research/work-items/RE-001-pipeline-dispatch-115/.
Run from the repository root: python3 tests/test_pipeline_dispatch_115.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from pipeline_dispatch_115 import dispatch  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-001-pipeline-dispatch-115"
MASK64 = (1 << 64) - 1


def check(name, actual, expected):
    if actual != expected:
        raise AssertionError("%s: got %r, want %r" % (name, actual, expected))


def run(flag_value, field_0x10, arg="ARG"):
    """Run dispatch with recording oracles; return (result, calls)."""
    calls = []

    def scan(obj):
        calls.append(("scan", obj))

    def prologue(obj, obj_delta, arg2, arg3):
        calls.append(("prologue", obj_delta, arg2, arg3))
        return "PROLOGUE-RESULT"

    result = dispatch({0x10: field_0x10}, arg, flag_value, scan, prologue)
    return result, calls


def main():
    count = 0

    # Flag byte zero: prologue only, exact arguments, return passes through.
    result, calls = run(0, 0x1000)
    check("flag 0 result", result, "PROLOGUE-RESULT")
    check("flag 0 calls", len(calls), 1)
    check("flag 0 prologue delta", calls[0][1], 0x40)
    check("flag 0 prologue arg2", calls[0][2], 0x1000 + 0x368)
    check("flag 0 prologue arg3", calls[0][3], "ARG")
    count += 5

    # Flag byte one: scan first, then prologue, in that order.
    result, calls = run(1, 0x1000)
    check("flag 1 result", result, "PROLOGUE-RESULT")
    check("flag 1 calls", [c[0] for c in calls], ["scan", "prologue"])
    check("flag 1 prologue arg2", calls[1][2], 0x1000 + 0x368)
    count += 3

    # Any nonzero flag byte scans, including 0xFF.
    _, calls = run(0xFF, 0)
    check("flag 0xFF calls", [c[0] for c in calls], ["scan", "prologue"])
    count += 1

    # Only the low byte participates: edx 0x100 has dl 0, so no scan.
    _, calls = run(0x100, 0x2000)
    check("flag 0x100 calls", [c[0] for c in calls], ["prologue"])
    check("flag 0x100 arg2", calls[0][2], 0x2000 + 0x368)
    count += 2

    # edx 0x101 has dl 1, so the scan runs.
    _, calls = run(0x101, 0)
    check("flag 0x101 calls", [c[0] for c in calls], ["scan", "prologue"])
    count += 1

    # Wrapping 64-bit arg2 derivation.
    _, calls = run(0, MASK64)
    check("arg2 wraps at 2**64", calls[0][2], 0x367)
    _, calls = run(0, MASK64 - 0x368 + 1)
    check("arg2 wraps to zero", calls[0][2], 0)
    _, calls = run(0, 0)
    check("arg2 from zero field", calls[0][2], 0x368)
    count += 3

    # The scan's return value is discarded; the prologue's is returned.
    def scan_value(obj):
        return "SCAN-RESULT"

    def prologue_value(obj, obj_delta, arg2, arg3):
        return "P-VALUE"

    check("scan return discarded",
          dispatch({0x10: 5}, "A", 1, scan_value, prologue_value),
          "P-VALUE")
    count += 1

    # Missing field guard.
    try:
        dispatch({}, "A", 0, scan_value, prologue_value)
    except ValueError:
        count += 1
    else:
        raise AssertionError("missing field 0x10 did not raise")

    # Packet checks: semantic records only, digest-bound, census exact.
    records = json.loads((PACKET / "records.json").read_text())
    check("records digest",
          records["artifact_sha256"],
          "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
    check("records task", records["task"], "RE-001")
    check("records node", records["node"], 115)
    check("records dispatcher calls",
          records["census"]["dispatcher_0x5f88550"]["direct_calls"],
          ["0x5f956ab", "0x5f973b5", "0x5fa01f1", "0x5fa600e"])
    check("records dispatcher jumps",
          records["census"]["dispatcher_0x5f88550"]["tail_jumps"], [])
    if "endbr64" in json.dumps(records):
        raise AssertionError("records carry instruction-level detail")
    count += 6

    print("%d checks pass" % count)


if __name__ == "__main__":
    main()
