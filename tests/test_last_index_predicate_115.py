"""Tests for node #115's last-index predicate at 0x5f6afa0.

Each case is a target-grounded expectation read off the verbatim
disassembly in research/work-items/RE-001-last-index-predicate-115/.
Run from the repository root: python3 tests/test_last_index_predicate_115.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from last_index_predicate_115 import (  # noqa: E402
    last_index_predicate, predicate_from_obj)

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-001-last-index-predicate-115"


def check(name, actual, expected):
    if actual != expected:
        raise AssertionError("%s: got %r, want %r" % (name, actual, expected))


def main():
    # Link byte zero: returns 0 at once, count never read.
    check("zero link byte", last_index_predicate(0, 5, 1, 6), 0)
    check("zero link byte, last index", last_index_predicate(0, 5, 0, 6), 0)
    # Gate: index <= 0 and flag zero returns 0 at once.
    check("index zero, flag zero", last_index_predicate(1, 0, 0, 1), 0)
    check("index negative, flag zero",
          last_index_predicate(1, -3, 0, -2), 0)
    # Flag nonzero rescues a non-positive index.
    check("flag rescues index zero",
          last_index_predicate(1, 0, 0xFF, 1), 1)
    check("flag upper bits ignored",
          last_index_predicate(1, 0, 0x100, 1), 0)
    # Last-index test.
    check("last index hit", last_index_predicate(1, 5, 0, 6), 1)
    check("last index miss", last_index_predicate(1, 4, 0, 6), 0)
    check("beyond last index", last_index_predicate(1, 6, 0, 6), 0)
    check("count one, index zero, flag set",
          last_index_predicate(1, 0, 1, 1), 1)
    # 32-bit wrap: count 0 minus one wraps to the pattern of -1.
    check("wrap count zero index minus one flag set",
          last_index_predicate(1, -1, 1, 0), 1)
    check("wrap count zero index minus one flag zero",
          last_index_predicate(1, -1, 0, 0), 0)
    # Negative count: count -5 minus one is -6; index -6 with flag set.
    check("negative count wrap",
          last_index_predicate(1, -6, 1, -5), 1)
    # Object mapping helper and its guards.
    check("from obj hit",
          predicate_from_obj({"link_byte": 1, "count": 6}, 5, 0), 1)
    for missing in ({"count": 6}, {"link_byte": 1}):
        try:
            predicate_from_obj(missing, 5, 0)
        except KeyError:
            pass
        else:
            raise AssertionError("missing field not rejected: %r" % missing)
    # Packet checks: semantic records carry the census and no
    # instruction-level detail.
    records = json.loads((PACKET / "records.json").read_text())
    check("records census",
          records["census"]["predicate_0x5f6afa0"]["direct_calls"],
          ["0x5f6b0e9", "0x5f73880", "0x5f92bce", "0x5f9a0e4"])
    check("records call sites", len(records["call_sites"]), 4)
    if "endbr64" in json.dumps(records):
        raise AssertionError("records carry instruction-level detail")
    print("OK: 19 checks passed")


if __name__ == "__main__":
    main()
