"""Tests for the node #115 destructor chain model (0x5d519d0).

Target-grounded expectations: the destructor call first, the
index-ordered pointer-vector walk with its index-8 chunk
switch, destroy-then-delete pairs with size 0xd20, null
skips, the post-loop zeroing, end reset and buffer delete
in order, the teardown tail jump last, and the input
guards. Run from the repository root:

    python3 tests/test_destructor_chain_519d0_115.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from destructor_chain_519d0_115 import (
    DELETE_CALLEE, DESTROY_CALLEE, DESTRUCTOR_CALLEE,
    ELEMENT_DELETE_SIZE, FIRST_CHUNK_LIMIT, TEARDOWN_CALLEE,
    CompositeObject, destroy_chain)

CHECKS = []


def check(name, condition):
    if not condition:
        raise AssertionError("failed: %s" % name)
    CHECKS.append(name)


def test_constants():
    check("destructor callee", DESTRUCTOR_CALLEE == 0x5D50DE0)
    check("destroy callee", DESTROY_CALLEE == 0x5F10D40)
    check("element delete size", ELEMENT_DELETE_SIZE == 0xD20)
    check("teardown callee", TEARDOWN_CALLEE == 0x5D51010)
    check("delete callee", DELETE_CALLEE == 0x63F0D80)
    check("first chunk limit", FIRST_CHUNK_LIMIT == 8)


def test_empty_object():
    obj = CompositeObject()
    events = destroy_chain(obj)
    check("empty object is destructor call then tail only",
          events == [("destructor_call",), ("tail",)])


def test_destructor_first_and_tail_last():
    obj = CompositeObject(first_chunk=["a"], first_count=1,
                          second_begin="buf", second_end="buf",
                          second_cap_size=0x40)
    events = destroy_chain(obj)
    check("destructor call first, tail last",
          events[0] == ("destructor_call",)
          and events[-1] == ("tail",))
    check("element destroy precedes its delete",
          events[1:3] == [("destroy", "a"), ("delete", "a", 0xD20)])
    check("first count zeroed", obj.first_count == 0)
    check("buffer deleted with cap size",
          ("delete", "second_buffer", 0x40) in events)


def test_chunk_switch_at_index_eight():
    obj = CompositeObject(
        first_chunk=["f%d" % i for i in range(8)], first_count=8,
        second_chunk=["s0", "s1"], second_begin="buf",
        second_end="end", second_cap_size=0x80)
    events = destroy_chain(obj)
    deletes = [e for e in events if e[0] == "delete"
               and e[1] != "second_buffer"]
    check("first chunk then second chunk, in index order",
          [e[1] for e in events if e[0] == "destroy"] ==
          ["f%d" % i for i in range(8)] + ["s0", "s1"])
    check("every element deleted with size 0xd20",
          all(size == 0xD20 for _tag, _ident, size in deletes))
    check("end reset precedes the buffer delete",
          events.index(("reset", "second_end"))
          < events.index(("delete", "second_buffer", 0x80)))


def test_null_elements_skipped():
    obj = CompositeObject(first_chunk=["a", None, "c"], first_count=3)
    events = destroy_chain(obj)
    check("null element skipped, others kept in order",
          events == [("destructor_call",),
                     ("destroy", "a"), ("delete", "a", 0xD20),
                     ("destroy", "c"), ("delete", "c", 0xD20),
                     ("zero", "first_count"), ("tail",)])


def test_index_rule_is_literal():
    # total = 0 + 2 = 2, so indices 0 and 1 both read the
    # first chunk; the second chunk is never visited on
    # this entry path, exactly as the binary's index rule
    # (not its counts) decides.
    obj = CompositeObject(first_chunk=["a", "b"], first_count=0,
                          second_chunk=["s0", "s1"])
    events = destroy_chain(obj)
    check("low first count leaves the second chunk unvisited",
          [e[1] for e in events if e[0] == "destroy"] == ["a", "b"])


def test_zero_count_path_skips_loop():
    obj = CompositeObject(second_begin="buf", second_end="buf",
                          second_cap_size=0x10)
    events = destroy_chain(obj)
    check("zero total skips the loop but still deletes the buffer",
          events == [("destructor_call",),
                     ("delete", "second_buffer", 0x10), ("tail",)])


def test_null_begin_deletes_nothing():
    obj = CompositeObject(first_chunk=["a"], first_count=1)
    events = destroy_chain(obj)
    check("null begin means no buffer delete",
          events == [("destructor_call",),
                     ("destroy", "a"), ("delete", "a", 0xD20),
                     ("zero", "first_count"), ("tail",)])
    check("null begin with null end needs no reset",
          ("reset", "second_end") not in events)


def test_end_reset_with_null_begin():
    obj = CompositeObject(second_begin=None, second_end="q")
    events = destroy_chain(obj)
    check("null begin with non-null end resets the end, no delete",
          events == [("destructor_call",), ("reset", "second_end"),
                     ("tail",)])
    check("second end reset to null", obj.second_end is None)


def test_full_order():
    obj = CompositeObject(
        first_chunk=["f0", "f1"], first_count=2,
        second_chunk=[], second_begin="buf", second_end="other",
        second_cap_size=0x30)
    events = destroy_chain(obj)
    check("full phase order",
          events == [("destructor_call",),
                     ("destroy", "f0"), ("delete", "f0", 0xD20),
                     ("destroy", "f1"), ("delete", "f1", 0xD20),
                     ("zero", "first_count"),
                     ("reset", "second_end"),
                     ("delete", "second_buffer", 0x30),
                     ("tail",)])


def test_guards():
    try:
        destroy_chain(None)
        check("null object raises", False)
    except ValueError:
        check("null object raises", True)
    obj = CompositeObject(first_chunk=["a"], first_count=-1)
    try:
        destroy_chain(obj)
        check("negative first count raises", False)
    except ValueError:
        check("negative first count raises", True)
    obj = CompositeObject(
        first_chunk=["f%d" % i for i in range(8)], first_count=9)
    try:
        destroy_chain(obj)
        check("second-chunk walk past the chunk raises", False)
    except ValueError:
        check("second-chunk walk past the chunk raises", True)
    obj = CompositeObject(first_chunk=["a"], first_count=9,
                          second_chunk=["s0"])
    try:
        destroy_chain(obj)
        check("first-chunk overrun raises", False)
    except ValueError:
        check("first-chunk overrun raises", True)


def main():
    test_constants()
    test_empty_object()
    test_destructor_first_and_tail_last()
    test_chunk_switch_at_index_eight()
    test_null_elements_skipped()
    test_index_rule_is_literal()
    test_zero_count_path_skips_loop()
    test_null_begin_deletes_nothing()
    test_end_reset_with_null_begin()
    test_full_order()
    test_guards()
    print("%d checks pass" % len(CHECKS))


if __name__ == "__main__":
    main()
