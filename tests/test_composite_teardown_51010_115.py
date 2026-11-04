"""Tests for the node #115 composite teardown model (0x5d51010).

Target-grounded expectations: the seven phases in order, the
SSO rule in both arrays, the backwards first walk and the
forwards second walk, the vacuous post-reset re-walk, the
buffer and pointer-vector delete sizes, the head-count
zeroing, the end reset preceding the pointer null check, and
the input guards. Run from the repository root:

    python3 tests/test_composite_teardown_51010_115.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from composite_teardown_51010_115 import (
    DELETE_CALLEE, DESTROY_CALLEE, ELEMENT_STRIDE,
    MEMBER_DELETE_SIZE, CompositeObject, StringField,
    teardown_composite)

CHECKS = []


def check(name, condition):
    if not condition:
        raise AssertionError("failed: %s" % name)
    CHECKS.append(name)


def test_constants():
    check("destroy callee", DESTROY_CALLEE == 0x5D8D820)
    check("member delete size", MEMBER_DELETE_SIZE == 0x290)
    check("element stride", ELEMENT_STRIDE == 0x30)
    check("delete callee", DELETE_CALLEE == 0x63F0D80)


def test_empty_object():
    obj = CompositeObject()
    events = teardown_composite(obj)
    check("empty object only records the vacuous re-walk",
          events == [("rewalk_vacuous",)])
    check("empty head count stays zero", obj.head_count == 0)
    check("empty second end reset recorded", obj.second_end_reset is True)


def test_member_phase():
    obj = CompositeObject(member="m1")
    events = teardown_composite(obj)
    check("member destroy precedes its delete",
          events[:2] == [("destroy", "m1"), ("delete", "m1", 0x290)])
    check("member slot value untouched", obj.member == "m1")


def test_first_array_backwards():
    obj = CompositeObject(first=[
        StringField("a", 3), StringField("b", 0, inline=True),
        StringField("c", 7)])
    events = teardown_composite(obj)
    deletes = [e for e in events if e[0] == "delete"]
    check("first array walked backwards, inline skipped",
          deletes == [("delete", "c", 8), ("delete", "a", 4)])
    check("first count ends at zero", obj.first_count == 0)


def test_second_array_forwards_and_buffer():
    obj = CompositeObject(
        second=[StringField("x", 1), StringField("y", 2, inline=True),
                StringField("z", 0)],
        second_buffer_size=0x300)
    events = teardown_composite(obj)
    check("second array forwards with cap + 1, inline skipped",
          [e for e in events if e[0] == "delete"] ==
          [("delete", "x", 2), ("delete", "z", 1),
           ("delete", "second_buffer", 0x300)])
    check("second end reset recorded", obj.second_end_reset is True)


def test_rewalk_deletes_nothing_twice():
    obj = CompositeObject(second=[StringField("only", 5)])
    events = teardown_composite(obj)
    check("second string deleted exactly once despite the re-walk",
          events.count(("delete", "only", 6)) == 1)
    check("re-walk recorded vacuous",
          ("rewalk_vacuous",) in events)


def test_head_count_and_pointer_vector():
    obj = CompositeObject(head_count=9, ptr_begin="p",
                          ptr_end="q", ptr_cap_size=0x40)
    events = teardown_composite(obj)
    check("head count zeroed", obj.head_count == 0)
    check("pointer end reset before the tail delete",
          events == [("rewalk_vacuous",), ("zero", "head_count"),
                     ("reset", "ptr_end"), ("tail_delete", "p", 0x40)])
    check("pointer end now equals begin", obj.ptr_end == "p")


def test_pointer_null_begin_resets_end():
    obj = CompositeObject(ptr_begin=None, ptr_end="q")
    events = teardown_composite(obj)
    check("null begin still resets the end, no delete",
          events == [("rewalk_vacuous",), ("reset", "ptr_end")])
    check("pointer end reset to null", obj.ptr_end is None)


def test_full_order():
    obj = CompositeObject(
        member="m", first=[StringField("f1", 1)],
        second=[StringField("s1", 2)], second_buffer_size=0x90,
        head_count=1, ptr_begin="p", ptr_end="p",
        ptr_cap_size=0x18)
    events = teardown_composite(obj)
    check("full phase order",
          events == [("destroy", "m"), ("delete", "m", 0x290),
                     ("delete", "f1", 2), ("delete", "s1", 3),
                     ("rewalk_vacuous",),
                     ("delete", "second_buffer", 0x90),
                     ("zero", "head_count"),
                     ("tail_delete", "p", 0x18)])


def test_guards():
    try:
        teardown_composite(None)
        check("null object raises", False)
    except ValueError:
        check("null object raises", True)
    obj = CompositeObject(first=[StringField("a", 1)])
    obj.first_count = 3
    try:
        teardown_composite(obj)
        check("count mismatch raises", False)
    except ValueError:
        check("count mismatch raises", True)


def main():
    test_constants()
    test_empty_object()
    test_member_phase()
    test_first_array_backwards()
    test_second_array_forwards_and_buffer()
    test_rewalk_deletes_nothing_twice()
    test_head_count_and_pointer_vector()
    test_pointer_null_begin_resets_end()
    test_full_order()
    test_guards()
    print("%d checks pass" % len(CHECKS))


if __name__ == "__main__":
    main()
