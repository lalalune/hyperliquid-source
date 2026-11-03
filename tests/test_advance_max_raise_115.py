"""Tests for node #115's twin field-raise leaves at 0x5f6f400 and
0x5f6f430.

Each case is a target-grounded expectation read off the verbatim
disassembly in research/work-items/RE-001-advance-max-field-raise-115/.
Run from the repository root: python3 tests/test_advance_max_raise_115.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from advance_max_raise_115 import (  # noqa: E402
    advance_past, max_store, shared_caller_sequence)

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-001-advance-max-field-raise-115"
MASK64 = (1 << 64) - 1


def check(name, actual, expected):
    if actual != expected:
        raise AssertionError("%s: got %r, want %r" % (name, actual, expected))


def main():
    count = 0

    # Advance leaf: strictly smaller value leaves the field unchanged.
    obj = {0xD8: 100, 0xE0: 7}
    advance_past(obj, 99)
    check("advance smaller unchanged", obj[0xD8], 100)
    check("advance leaves other field alone", obj[0xE0], 7)
    count += 1

    # Advance leaf: equality advances to current + 1 (branch on >=).
    obj = {0xD8: 100}
    advance_past(obj, 100)
    check("advance equality", obj[0xD8], 101)
    count += 1

    # Advance leaf: larger value stores value + 1.
    obj = {0xD8: 100}
    advance_past(obj, 500)
    check("advance larger", obj[0xD8], 501)
    count += 1

    # Advance leaf: maximum value wraps the +1 to zero.
    obj = {0xD8: 0}
    advance_past(obj, MASK64)
    check("advance wrap to zero", obj[0xD8], 0)
    count += 1

    # Advance leaf: unsigned comparison, not signed: a huge value
    # advances past a small current, and a small value never advances
    # past a huge current even though it is larger when read signed.
    obj = {0xD8: 5}
    advance_past(obj, 1 << 63)
    check("advance unsigned huge", obj[0xD8], (1 << 63) + 1)
    obj = {0xD8: 1 << 63}
    advance_past(obj, 5)
    check("advance unsigned small unchanged", obj[0xD8], 1 << 63)
    count += 1

    # Advance leaf: missing field raises instead of inventing state.
    try:
        advance_past({}, 1)
        raise AssertionError("advance missing field did not raise")
    except ValueError:
        count += 1

    # Max leaf: smaller value leaves the field unchanged.
    obj = {0xD8: 3, 0xE0: 100}
    max_store(obj, 99)
    check("max smaller unchanged", obj[0xE0], 100)
    check("max leaves other field alone", obj[0xD8], 3)
    count += 1

    # Max leaf: equality leaves the field unchanged (branch on <).
    obj = {0xE0: 100}
    max_store(obj, 100)
    check("max equality unchanged", obj[0xE0], 100)
    count += 1

    # Max leaf: larger value stores exactly the value, no +1.
    obj = {0xE0: 100}
    max_store(obj, 101)
    check("max larger exact", obj[0xE0], 101)
    count += 1

    # Max leaf: unsigned comparison at the sign boundary.
    obj = {0xE0: 1 << 63}
    max_store(obj, 5)
    check("max unsigned small unchanged", obj[0xE0], 1 << 63)
    obj = {0xE0: 5}
    max_store(obj, 1 << 63)
    check("max unsigned huge", obj[0xE0], 1 << 63)
    count += 1

    # Max leaf: missing field raises instead of inventing state.
    try:
        max_store({}, 1)
        raise AssertionError("max missing field did not raise")
    except ValueError:
        count += 1

    # Shared caller sequence: max, then advance, then advance, in
    # order, on the same object. Second advance sees the first
    # advance's result.
    obj = {0xD8: 10, 0xE0: 20}
    shared_caller_sequence(obj, 30, 15, 12)
    check("shared max applied", obj[0xE0], 30)
    check("shared advances chained", obj[0xD8], 16)
    count += 1

    # Shared caller sequence with descending advances: the second
    # advance is a no-op once the first has raised the field past it.
    obj = {0xD8: 10, 0xE0: 20}
    shared_caller_sequence(obj, 5, 50, 40)
    check("shared max below unchanged", obj[0xE0], 20)
    check("shared descending second no-op", obj[0xD8], 51)
    count += 1

    # Packet checks: records bind the digest and both censuses.
    records = json.loads((PACKET / "records.json").read_text())
    check("records digest", records["artifact_sha256"],
          "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
    check("records advance census",
          records["census"]["advance_0x5f6f400"]["direct_calls"],
          ["0x5e6987d", "0x5e6b3ac", "0x5e82edc", "0x5f9dfc1",
           "0x5f9dfd1"])
    check("records max census",
          records["census"]["max_0x5f6f430"]["direct_calls"],
          ["0x5f9846d", "0x5f9dfb1"])
    check("records advance field", records["advance"]["field"], "obj+0xd8")
    check("records max field", records["max"]["field"], "obj+0xe0")
    count += 1

    print("%d model checks passed" % count)


if __name__ == "__main__":
    main()
