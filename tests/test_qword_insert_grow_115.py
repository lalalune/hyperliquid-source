"""Tests for tools/qword_insert_grow_115.py (RE-001, node #115).

Runs under plain python3 via the __main__ runner below because pytest
is not installed on this VM. Run from the clone root:
  python3 tests/test_qword_insert_grow_115.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from qword_insert_grow_115 import (  # noqa: E402
    LengthError, QwordInsertGrowError,
    allocation_bytes, append_group_element, insert_grow,
    new_capacity_for_size)

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
        except QwordInsertGrowError:
            check("out-of-range index %d raises" % bad, True)


def test_packet_census():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(
        root, "research", "work-items", "RE-001-qword-insert-grow-115",
        "records.json")
    rec = json.load(open(path))
    calls = rec["census"]["grow"]["direct_calls"]
    check("census has 26 direct calls", len(calls) == 26)
    check("census includes append call site 0x5f780ad",
          "0x5f780ad" in calls)
    check("census includes site 0x5d9f0c0", "0x5d9f0c0" in calls)
    check("no tail jumps", rec["census"]["grow"]["tail_jumps"] == [])
    check("no stored qwords",
          rec["census"]["grow"]["qword_file_offsets"] == [])
    check("window start", rec["windows"]["grow"]["start"] == "0x5d9ee20")
    check("capacity rule empty -> 1",
          "1 element" in rec["capacity_rule"]["empty_container"])


def test_group_append_caller():
    groups = [[10, 20], [30]]
    caps = [4, 1]
    refs = {}
    arm, cap = append_group_element(groups, caps, 0, 99, refs)
    check("caller inplace arm", arm == "inplace")
    check("caller inplace contents", groups[0] == [10, 20, 99])
    check("caller inplace capacity unchanged", cap == 4)
    check("caller inplace refcount bump", refs[99] == 1)
    arm, cap = append_group_element(groups, caps, 1, 77, refs)
    check("caller grow arm", arm == "grow")
    check("caller grow contents", groups[1] == [30, 77])
    check("caller grow capacity 2", cap == 2)
    check("caller grow refcount bump", refs[77] == 1)
    arm, cap = append_group_element(groups, caps, 1, 77, refs)
    check("caller second append grows again (capacity 2 full)", arm == "grow")
    check("caller second grow contents", groups[1] == [30, 77, 77])
    check("caller second grow capacity 4", cap == 4)
    check("caller refcount bumps on both arms", refs[77] == 2)
    groups = [[]]
    caps = [0]
    refs = {}
    arm, cap = append_group_element(groups, caps, 0, 5, refs)
    check("caller empty group grow arm", arm == "grow")
    check("caller empty group contents", groups[0] == [5])
    check("caller empty group capacity 1", cap == 1)
    try:
        append_group_element(groups, caps, 3, 1, refs)
        check("caller bad group index raises", False)
    except QwordInsertGrowError:
        check("caller bad group index raises", True)
    rec_caps = None
    import json as _json
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    rec = _json.load(open(os.path.join(
        root, "research", "work-items", "RE-001-qword-insert-grow-115",
        "records.json")))
    check("caller census 3 direct calls",
          len(rec["census"]["caller"]["direct_calls"]) == 3)
    check("caller census 1 tail jump",
          rec["census"]["caller"]["tail_jumps"] == ["0x5f45dcd"])
    check("caller window start",
          rec["windows"]["caller"]["start"] == "0x5f78060")


def main():
    test_empty_insert()
    test_empty_allocated_begin_freed()
    test_append_middle_front()
    test_capacity_arithmetic()
    test_qword_truncation_and_guards()
    test_packet_census()
    test_group_append_caller()
    print("%d checks passed" % len(CHECKS))


if __name__ == "__main__":
    main()
