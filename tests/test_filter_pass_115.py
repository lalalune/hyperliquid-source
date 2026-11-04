"""Tests for the node #115 filter pass model (tools/filter_pass_115.py).

Run from the clone root with plain python3 (pytest is not installed on
this VM, so the file carries its own __main__ runner):
  python3 tests/test_filter_pass_115.py

The predicate is an oracle stub in every test: the model takes the
predicate's decision as an input, exactly as the native loop consults
the later-group predicate 0x5f6d600, whose own semantics are pinned by
the RE-001 later-group predicate item, not by this one.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from filter_pass_115 import (  # noqa: E402
    Element, LengthError_, PassObject, filter_pass)

PACKET = os.path.join(
    os.path.dirname(__file__), "..", "research", "work-items",
    "RE-001-filter-pass-115", "records.json")


def _obj(cursor, inline, heap, elements):
    return PassObject(cursor, inline, heap, elements)


def _elements(base, values):
    out = {}
    for idx, val in enumerate(values):
        out[(base, idx)] = Element(val, 0x100 + idx, 0x200 + idx,
                                   0x300 + idx, 0x400 + idx)
    return out


def test_empty_total_calls_nothing():
    seen = []
    obj = _obj(0, [(0, "b")] * 8, [], {})
    filter_pass(obj, lambda o, rsi, rdx, i, r8: seen.append((i, r8)) or True)
    assert seen == []
    assert obj.scan_records == []


def test_zero_limit_calls_nothing():
    seen = []
    obj = _obj(1, [(0, "b")] + [(0, "x")] * 7, [], {})
    filter_pass(obj, lambda o, rsi, rdx, i, r8: seen.append((i, r8)) or True)
    assert seen == []
    assert obj.scan_records == []


def test_group0_mixed_and_r8_sequence():
    seen = []
    obj = _obj(1, [(3, "g0")] + [(0, "x")] * 7, [],
               _elements("g0", [10, 20, 30]))

    def pred(o, rsi, rdx, i, r8):
        seen.append((i, r8))
        return r8 != 1  # skip elements 0 and 2, append element 1

    filter_pass(obj, pred)
    assert seen == [(0, 0), (0, 1), (0, 2)]
    assert obj.scan_records == [(0, 20)]


def test_nonzero_group_r8_always_minus_one():
    seen = []
    obj = _obj(2, [(0, "g0"), (2, "g1")] + [(0, "x")] * 6, [],
               _elements("g1", [7, 8]))

    def pred(o, rsi, rdx, i, r8):
        seen.append((i, r8))
        return False

    filter_pass(obj, pred)
    assert seen == [(1, -1), (1, -1)]
    assert obj.scan_records == [(1, 7), (1, 8)]


def test_cursor_bounds_the_groups():
    # cursor 5 with no heap: only groups 0..4 run, even though inline
    # slots 5..7 hold limits; the native total is cursor + heap count.
    seen = []
    obj = _obj(5, [(1, "a"), (1, "b"), (1, "c"), (1, "d"), (1, "e"),
                   (9, "f"), (9, "g"), (9, "h")],
               [], _elements("a", [1]) | _elements("b", [2])
               | _elements("c", [3]) | _elements("d", [4])
               | _elements("e", [5]))

    def pred(o, rsi, rdx, i, r8):
        seen.append(i)
        return False

    filter_pass(obj, pred)
    assert seen == [0, 1, 2, 3, 4]
    assert obj.scan_records == [(0, 1), (1, 2), (2, 3), (3, 4), (4, 5)]


def test_heap_group_slot():
    seen = []
    obj = _obj(8, [(0, "x")] * 8, [(1, "h0")], _elements("h0", [42]))

    def pred(o, rsi, rdx, i, r8):
        seen.append((i, r8))
        return False

    filter_pass(obj, pred)
    assert seen == [(8, -1)]
    assert obj.scan_records == [(8, 42)]


def test_struct_fields_and_wrap():
    got = []
    el = Element(99, 0x100, 0, 0x300, 8)
    obj = _obj(1, [(1, "g0")] + [(0, "x")] * 7, [], {("g0", 0): el})

    def pred(o, rsi, rdx, i, r8):
        got.append((rsi, rdx))
        return True

    filter_pass(obj, pred)
    # rsi = (f30, f38 - 8 wrapping); rdx = (f40, f48 - 8 wrapping).
    assert got == [((0x100, (1 << 64) - 8), (0x300, 0))]


def test_scan_inline_then_heap_growth():
    obj = _obj(1, [(10, "g0")] + [(0, "x")] * 7, [],
               _elements("g0", list(range(100, 110))))
    filter_pass(obj, lambda o, rsi, rdx, i, r8: False)
    assert obj.scan_inline == [(0, v) for v in range(100, 108)]
    assert obj.scan_heap == [(0, 108), (0, 109)]
    assert obj.scan_heap_capacity == 2
    assert obj.scan_records == [(0, v) for v in range(100, 110)]


def test_heap_growth_capacities():
    obj = _obj(1, [(20, "g0")] + [(0, "x")] * 7, [],
               _elements("g0", list(range(20))))
    filter_pass(obj, lambda o, rsi, rdx, i, r8: False)
    assert len(obj.scan_inline) == 8
    assert len(obj.scan_heap) == 12
    assert obj.scan_heap_capacity == 16
    assert obj.scan_records == [(0, v) for v in range(20)]


def test_r12_resets_per_group():
    seen = []
    obj = _obj(2, [(2, "g0"), (2, "g1")] + [(0, "x")] * 6, [],
               _elements("g0", [1, 2]) | _elements("g1", [3, 4]))

    def pred(o, rsi, rdx, i, r8):
        seen.append((i, r8))
        return True

    filter_pass(obj, pred)
    assert seen == [(0, 0), (0, 1), (1, -1), (1, -1)]


def test_missing_element_guard():
    obj = _obj(1, [(2, "g0")] + [(0, "x")] * 7, [],
               _elements("g0", [1]))
    try:
        filter_pass(obj, lambda o, rsi, rdx, i, r8: True)
    except ValueError:
        return
    raise AssertionError("expected ValueError for a missing element")


def test_grow_at_maximum_raises():
    # Exercise the maximum arm directly: with the module maximum
    # patched to 0, an empty heap already sits at the maximum, so
    # growing must raise instead of allocating.
    import filter_pass_115 as m
    from filter_pass_115 import _grow_scan_heap
    obj = _obj(0, [(0, "x")] * 8, [], {})
    old = m.MAX_RECORDS
    try:
        m.MAX_RECORDS = 0
        try:
            _grow_scan_heap(obj)
        except LengthError_:
            return
        raise AssertionError("expected LengthError_ at the maximum")
    finally:
        m.MAX_RECORDS = old


def test_packet_records_match_census():
    records = json.load(open(PACKET))
    assert records["windows"]["pass"]["start"] == "0x5f6d700"
    assert records["windows"]["pass"]["stop"] == "0x5f6da47"
    assert records["census"]["pass"]["direct_calls"] == ["0x5f88533"]
    assert records["census"]["pass"]["tail_jumps"] == []
    assert records["census"]["predicate"]["direct_calls"] == [
        "0x5da51be", "0x5f6d7e1"]


TESTS = [v for k, v in sorted(globals().items())
         if k.startswith("test_")]


def main():
    failed = []
    for test in TESTS:
        try:
            test()
        except Exception as exc:  # noqa: BLE001 - report and continue
            failed.append((test.__name__, exc))
    if failed:
        for name, exc in failed:
            print("FAIL %s: %r" % (name, exc))
        return 1
    print("%d model checks pass" % len(TESTS))
    return 0


if __name__ == "__main__":
    sys.exit(main())
