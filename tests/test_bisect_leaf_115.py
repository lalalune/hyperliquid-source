"""Tests for the node #115 bisect leaf (tools/bisect_leaf_115.py).

Run directly: python3 tests/test_bisect_leaf_115.py
(pytest is not installed on this VM; the file runs its checks under
plain python3 via the __main__ runner below, as in the recent RE-001
packets.)
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from bisect_leaf_115 import bisect_leaf, BisectLeafError  # noqa: E402

U64 = (1 << 64) - 1
CALL_SITES = [
    "0x5f463fe", "0x5f4a482", "0x5f4ad3a", "0x5f4bcb1", "0x5f50795",
    "0x5f52f32", "0x5f709d5", "0x5f71073", "0x5f711ea", "0x5f71211",
    "0x5f71238", "0x5f7126e", "0x5f71312", "0x5f7f456",
]


def check(name, got, want):
    assert got == want, "%s: got %r, want %r" % (name, got, want)
    print("ok:", name)


def expect_error(name, fn):
    try:
        fn()
    except BisectLeafError:
        print("ok:", name)
        return
    raise AssertionError("%s: expected BisectLeafError" % name)


def test_empty():
    check("empty array returns begin", bisect_leaf([], 42), 0)


def test_single():
    check("single equal", bisect_leaf([10], 10), 0)
    check("single above", bisect_leaf([10], 5), 0)
    check("single below", bisect_leaf([10], 11), 1)


def test_middle_and_edges():
    keys = [3, 7, 7, 12, 20]
    check("first of equal run", bisect_leaf(keys, 7), 1)
    check("between keys", bisect_leaf(keys, 8), 3)
    check("below all", bisect_leaf(keys, 0), 0)
    check("above all", bisect_leaf(keys, 21), 5)
    check("exact last", bisect_leaf(keys, 20), 4)


def test_unsigned_order():
    # Signed readings would put both keys below 5; unsigned, both are
    # above it, so the lower bound is index 0.
    keys = [0x8000000000000000, U64]
    check("unsigned high-bit keys", bisect_leaf(keys, 5), 0)
    check("unsigned max target below all",
          bisect_leaf([0x8000000000000000], U64), 1)
    check("unsigned max target equal", bisect_leaf([U64], U64), 0)


def test_partial_span():
    # A byte span of 8 is not a whole record; the native loop still
    # reads the first record and steps past it when its key is below.
    check("partial span key above", bisect_leaf([10], 5, byte_span=8), 0)
    check("partial span key below", bisect_leaf([10], 11, byte_span=8), 1)
    check("non-positive span returns begin without reading",
          bisect_leaf([10], 11, byte_span=0), 0)
    check("negative span returns begin",
          bisect_leaf([10], 11, byte_span=(1 << 64) - 16), 0)


def test_guards():
    expect_error("target out of range",
                 lambda: bisect_leaf([10], 1 << 64))
    expect_error("key out of range",
                 lambda: bisect_leaf([1 << 64], 5))
    # Span claims 3 records but only 1 is supplied; the loop's second
    # probe would read past the supplied records.
    expect_error("mid past supplied records",
                 lambda: bisect_leaf([10], 11, byte_span=48))
    expect_error("empty records with positive partial span",
                 lambda: bisect_leaf([], 5, byte_span=8))


def test_packet_records():
    here = os.path.dirname(os.path.abspath(__file__))
    packet = os.path.join(
        here, "..", "research", "work-items", "RE-001-bisect-leaf-115",
        "records.json")
    records = json.load(open(packet))
    check("packet window start",
          records["windows"]["bisect"]["start"], "0x5f6bba0")
    check("packet window end",
          records["windows"]["bisect"]["end"], "0x5f6bc0a")
    check("packet census call sites",
          records["census"]["bisect"]["direct_calls"], CALL_SITES)
    check("packet census tail jumps",
          records["census"]["bisect"]["tail_jumps"], [])
    check("packet census qwords",
          records["census"]["bisect"]["qword_file_offsets"], [])
    check("packet census relocations",
          records["census"]["bisect"]["relative_reloc_offsets"], [])


def main():
    test_empty()
    test_single()
    test_middle_and_edges()
    test_unsigned_order()
    test_partial_span()
    test_guards()
    test_packet_records()
    print("ALL MODEL TESTS PASSED")


if __name__ == "__main__":
    main()
