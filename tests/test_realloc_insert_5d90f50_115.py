"""Tests for tools/realloc_insert_5d90f50_115.py (RE-001, node #115).

Runs under plain python3 via the __main__ runner below because pytest
is not installed on this VM. Run from the clone root:
  python3 tests/test_realloc_insert_5d90f50_115.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from realloc_insert_5d90f50_115 import (  # noqa: E402
    LengthError, ReallocInsertError,
    allocation_bytes, insert_grow, new_capacity_for_size)

CHECKS = []


def check(name, cond):
    CHECKS.append((name, bool(cond)))
    if not cond:
        raise AssertionError("failed: " + name)


def test_empty_insert():
    elems, cap, freed = insert_grow([], 0, 0x1122334455667788)
    check("empty -> single element", elems == [0x1122334455667788])
    check("empty -> capacity 1", cap == 1)
    check("empty null begin -> no free", freed is False)
    check("empty alloc bytes 8", allocation_bytes(cap) == 8)


def test_empty_allocated_begin_freed():
    _, _, freed = insert_grow([], 0, 7, old_begin_null=False)
    check("empty allocated begin -> freed", freed is True)


def test_append_middle_front():
    elems, cap, freed = insert_grow([10, 20, 30], 3, 40)
    check("append contents", elems == [10, 20, 30, 40])
    check("append capacity 6", cap == 6)
    check("nonempty -> old buffer freed", freed is True)
    elems, cap, _ = insert_grow([10, 20, 30, 40], 1, 99)
    check("middle contents", elems == [10, 99, 20, 30, 40])
    check("middle capacity 8", cap == 8)
    elems, cap, _ = insert_grow([10, 20], 0, 5)
    check("front contents", elems == [5, 10, 20])
    check("front capacity 4", cap == 4)


def test_capacity_arithmetic():
    check("cap size 0 -> 1", new_capacity_for_size(0) == 1)
    check("cap size 1 -> 2", new_capacity_for_size(1) == 2)
    check("cap size 3 -> 6", new_capacity_for_size(3) == 6)
    check("cap size 2**59-1 -> 2**60-2",
          new_capacity_for_size(2 ** 59 - 1) == 2 ** 60 - 2)
    check("cap size 2**59 -> maximum (capped)",
          new_capacity_for_size(2 ** 59) == 0x0FFFFFFFFFFFFFFF)
    check("cap size 2**63 -> maximum (wrap arm, same result)",
          new_capacity_for_size(2 ** 63) == 0x0FFFFFFFFFFFFFFF)
    try:
        new_capacity_for_size(0x0FFFFFFFFFFFFFFF)
        check("maximum size raises LengthError", False)
    except LengthError:
        check("maximum size raises LengthError", True)


def test_qword_truncation_and_guards():
    elems, _, _ = insert_grow([1], 1, 2 ** 64 + 5)
    check("value truncated to one qword", elems == [1, 5])
    for bad in (-1, 2):
        try:
            insert_grow([1], bad, 0)
            check("out-of-range index %d raises" % bad, False)
        except ReallocInsertError:
            check("out-of-range index %d raises" % bad, True)


def test_packet_records():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(
        root, "research", "work-items",
        "RE-001-realloc-insert-5d90f50-115", "records.json")
    rec = json.load(open(path))
    calls = rec["census"]["grow"]["direct_calls"]
    check("census has 8 direct calls", len(calls) == 8)
    check("census includes transfer call site 0x5f13e8c",
          "0x5f13e8c" in calls)
    check("census includes sibling-caller site 0x5d911ca",
          "0x5d911ca" in calls)
    check("no tail jumps", rec["census"]["grow"]["tail_jumps"] == [])
    check("no stored qwords",
          rec["census"]["grow"]["qword_file_offsets"] == [])
    check("window start", rec["windows"]["grow"]["start"] == "0x5d90f50")
    check("window size 389", rec["windows"]["grow"]["size_bytes"] == 389)
    check("twin recorded", rec["twin_copy"]["address"] == "0x5d9ee20")
    check("twin byte diff 15", rec["twin_copy"]["body_byte_differences"] == 15)
    check("caller census 3 direct calls",
          len(rec["census"]["caller"]["direct_calls"]) == 3)
    check("caller census 1 tail jump",
          rec["census"]["caller"]["tail_jumps"] == ["0x5f1435f"])
    check("caller window start",
          rec["windows"]["caller"]["start"] == "0x5f13e00")


def main():
    test_empty_insert()
    test_empty_allocated_begin_freed()
    test_append_middle_front()
    test_capacity_arithmetic()
    test_qword_truncation_and_guards()
    test_packet_records()
    print("%d checks passed" % len(CHECKS))


if __name__ == "__main__":
    main()
