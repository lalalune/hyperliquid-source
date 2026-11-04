"""Tests for the node #115 composite destructor model
(tools/composite_destructor_50de0_115.py, RE-001 work item
RE-001-composite-destructor-50de0-115). Each check counts; the run
prints "<n> checks pass" on success.

Expectations are target-grounded: the four phases in order, the
sentinel-filtered virtual calls, the backwards first-chunk string
disposal, the forwards second-chunk string disposal, the pointer
destroy-then-delete pairs, and the container-state resets -- all
read from the whole-function excerpt in the packet.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from composite_destructor_50de0_115 import (
    CompositeObject,
    Element,
    SENTINEL_SLOT,
    destroy_composite,
)

CHECKS = [0]


def check(condition, label):
    assert condition, label
    CHECKS[0] += 1


def expect_raises(fn, label):
    try:
        fn()
    except (ValueError, TypeError):
        CHECKS[0] += 1
    else:
        raise AssertionError(label)


def main():
    # Empty object: no calls, no deletes, only the resets.
    check(destroy_composite(CompositeObject("empty")) == [
        ("reset_elem_count", 0), ("reset_elem_end",),
        ("clear_ptr_count", 0), ("reset_ptr_end",),
    ], "empty object only resets state")

    # Phase 1 alone: sentinel entry skipped, live entry called.
    elem = Element("e0", ("inline", "s0", None), [
        ("live-obj", 0x5d49000), ("skip-obj", SENTINEL_SLOT)])
    check(destroy_composite(CompositeObject(
        "p1", elem_first=[elem], elem_first_count=1)) == [
        ("virtual_call", "e0", "live-obj"),
        ("reset_elem_count", 0), ("reset_elem_end",),
        ("clear_ptr_count", 0), ("reset_ptr_end",),
    ], "sentinel skipped, live entry called once")

    # Phase 2 order: first-chunk strings freed last-to-first,
    # heap only, size capacity + 1; inline strings skipped.
    elems = [
        Element("a", ("heap", "pa", 4)),
        Element("b", ("inline", "pb", None)),
        Element("c", ("heap", "pc", 0)),
    ]
    check(destroy_composite(CompositeObject(
        "p2", elem_first=elems, elem_first_count=3)) == [
        ("delete_string", "pc", 1), ("delete_string", "pa", 5),
        ("reset_elem_count", 0), ("reset_elem_end",),
        ("clear_ptr_count", 0), ("reset_ptr_end",),
    ], "first-chunk strings backwards, heap only, cap + 1")

    # Phase 3 order: second-chunk strings freed forwards.
    second = [
        Element("d", ("heap", "pd", 9)),
        Element("e", ("inline", "pe", None)),
        Element("f", ("heap", "pf", 2)),
    ]
    check(destroy_composite(CompositeObject(
        "p3", elem_first=[Element("g", ("inline", "pg", None))] * 8,
        elem_first_count=8, elem_second=second)) == [
        ("reset_elem_count", 0),
        ("delete_string", "pd", 10), ("delete_string", "pf", 3),
        ("reset_elem_end",),
        ("clear_ptr_count", 0), ("reset_ptr_end",),
    ], "second-chunk strings forwards, heap only")

    # Phase 1 spans chunks: elements 0..7 from the first chunk,
    # element 8 from the second chunk at index 0.
    first = [Element("f%d" % i, ("inline", "s%d" % i, None),
                     [("o%d" % i, 0x5d49000 + i)]) for i in range(8)]
    second_elem = Element("s8", ("inline", "s8", None),
                          [("o8", 0x5d49008)])
    events = destroy_composite(CompositeObject(
        "span", elem_first=first, elem_first_count=8,
        elem_second=[second_elem]))
    calls = [e for e in events if e[0] == "virtual_call"]
    check(calls == [("virtual_call", "f%d" % i, "o%d" % i)
                    for i in range(8)]
          + [("virtual_call", "s8", "o8")],
          "walk spans chunks at index 8")

    # Phase 4: null pointers skipped; each live pointer destroyed
    # then deleted with size 0x290, in order.
    check(destroy_composite(CompositeObject(
        "p4", ptr_first=["p0", None, "p2"],
        ptr_first_count=3)) == [
        ("reset_elem_count", 0), ("reset_elem_end",),
        ("destroy", "p0"), ("delete_pointer", "p0", 0x290),
        ("destroy", "p2"), ("delete_pointer", "p2", 0x290),
        ("clear_ptr_count", 0), ("reset_ptr_end",),
    ], "pointer destroy-then-delete pairs, null skipped")

    # Phase 4 spans chunks: pointer 8 from the second chunk.
    ptr_first = ["q%d" % i for i in range(8)]
    events = destroy_composite(CompositeObject(
        "pspan", ptr_first=ptr_first, ptr_first_count=8,
        ptr_second=["q8"]))
    pairs = [e for e in events if e[0] in ("destroy", "delete_pointer")]
    check(pairs == [item for q in ptr_first + ["q8"] for item in
                    (("destroy", q), ("delete_pointer", q, 0x290))],
          "pointer walk spans chunks at index 8")

    # Full order: phase 1 calls, then phase 2, then phase 3,
    # then phase 4, then the resets.
    # Well-formed object: the first chunk holds both walked
    # elements (the walk total is len(second) + first_count, so
    # a second chunk would extend the walk past this chunk).
    obj = CompositeObject(
        "full",
        elem_first=[Element("a", ("heap", "pa", 3),
                            [("oa", 0x5d49000)]),
                    Element("b", ("heap", "pb", 7))],
        elem_first_count=2,
        ptr_first=["r0"], ptr_first_count=1)
    check(destroy_composite(obj) == [
        ("virtual_call", "a", "oa"),
        ("delete_string", "pb", 8), ("delete_string", "pa", 4),
        ("reset_elem_count", 0), ("reset_elem_end",),
        ("destroy", "r0"), ("delete_pointer", "r0", 0x290),
        ("clear_ptr_count", 0), ("reset_ptr_end",),
    ], "phases in order on a well-formed object")

    # Input guards: bad kinds, negative counts, wrong types,
    # and walks past a provided chunk all raise.
    expect_raises(lambda: Element("bad", ("heap", "p", -1)),
                  "negative heap capacity rejected")
    expect_raises(lambda: Element("bad", ("other", "p", None)),
                  "unknown string kind rejected")
    expect_raises(lambda: Element("bad", ("heap", "p", 1),
                                  [("o", "not-an-int")]),
                  "non-integer slot rejected")
    expect_raises(lambda: CompositeObject("bad", ptr_first=[42]),
                  "non-string pointer token rejected")
    expect_raises(lambda: CompositeObject("bad", elem_first_count=-1),
                  "negative first count rejected")
    expect_raises(lambda: destroy_composite(CompositeObject(
        "bad", elem_first=[Element("x", ("inline", "s", None))],
        elem_first_count=1, elem_second=[
            Element("y", ("inline", "t", None))])),
        "element walk past first chunk rejected")
    expect_raises(lambda: destroy_composite(CompositeObject(
        "bad", ptr_first=["a"] * 8, ptr_first_count=9,
        ptr_second=[])),
        "pointer walk past second chunk rejected")
    expect_raises(lambda: destroy_composite("not-an-object"),
                  "non-object input rejected")

    print("%d checks pass" % CHECKS[0])


if __name__ == "__main__":
    main()
