"""Tests for tools/later_group_predicate_115.py (node #115 predicate 0x5f6d600).

Run with pytest when available, or directly: python3 this file.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from later_group_predicate_115 import LaterGroupPredicate


def pred(count, entries, group, elem_index=0, selector=None):
    return LaterGroupPredicate(count, entries, group, elem_index,
                               selector or (lambda g: 0))


def test_group0_non_last_returns_one():
    # Entry 0 spans 3 eight-byte elements: last index 2.
    assert pred(3, [(0x1000, 0x1018), (0, 0), (0, 0)], 0, 0).run() == 1
    assert pred(3, [(0x1000, 0x1018), (0, 0), (0, 0)], 0, 1).run() == 1


def test_group0_last_count_one_returns_zero():
    assert pred(1, [(0x1000, 0x1018)], 0, 2).run() == 0


def test_group0_last_all_later_empty_returns_zero():
    entries = [(0x1000, 0x1018), (0x2000, 0x2000), (0x3000, 0x3000)]
    assert pred(3, entries, 0, 2).run() == 0


def test_group0_last_later_nonempty_returns_one():
    entries = [(0x1000, 0x1018), (0x2000, 0x2000), (0x3000, 0x3010)]
    assert pred(3, entries, 0, 2).run() == 1


def test_group0_last_begin_past_end_is_nonempty():
    # Equality is the test: begin != end counts, even past-end.
    entries = [(0x1000, 0x1018), (0x2010, 0x2000)]
    assert pred(2, entries, 0, 2).run() == 1


def test_group0_last_32bit_wrap():
    # (end - begin) >> 3 == 2**32: low 32 bits are 0, so last == 0xffffffff.
    entries = [(0, 1 << 35), (0, 0)]
    assert pred(2, entries, 0, 0xFFFFFFFF).run() == 0
    assert pred(2, entries, 0, 0).run() == 1


def test_nonzero_group_no_later_groups_returns_zero():
    calls = []
    p = pred(3, [(0, 0)] * 3, 2, 0,
             lambda g: calls.append(g) or 1)
    assert p.run() == 0
    assert calls == []


def test_nonzero_group_empty_later_skipped():
    calls = []
    entries = [(0, 0), (0, 0), (0x2000, 0x2000), (0x3000, 0x3010)]
    p = pred(4, entries, 1, 0, lambda g: calls.append(g) or 0)
    assert p.run() == 0
    assert calls == [3]


def test_nonzero_group_selector_hit_returns_one_at_first_hit():
    calls = []
    entries = [(0, 0), (0, 0), (0x2000, 0x2010), (0x3000, 0x3010)]

    def sel(g):
        calls.append(g)
        return 1 if g == 3 else 0

    p = pred(4, entries, 1, 0, sel)
    assert p.run() == 1
    assert calls == [2, 3]


def test_nonzero_group_selector_hit_stops_scan():
    calls = []
    entries = [(0, 0), (0, 0), (0x2000, 0x2010), (0x3000, 0x3010)]

    def sel(g):
        calls.append(g)
        return 1

    assert pred(4, entries, 1, 0, sel).run() == 1
    assert calls == [2]


def test_nonzero_group_r8_ignored():
    entries = [(0, 0), (0, 0), (0x2000, 0x2000)]
    assert pred(3, entries, 1, 999).run() == 0
    assert pred(3, entries, 2, 999).run() == 0


def test_guards():
    for bad in (pred(3, [(0x1000, 0x1008)], 0, 0),
                pred(3, [(0x1000, 0x1008), (0, 0)], 0, 0)):
        # group-0 last arm scanning past a too-short entry list
        try:
            bad.run()
        except ValueError:
            pass
        else:
            raise AssertionError("expected ValueError")
    try:
        LaterGroupPredicate(3, [(0, 0)], -1, 0, lambda g: 0)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for negative group")


def test_packet_records_match_model_windows():
    here = os.path.dirname(os.path.abspath(__file__))
    rec = json.load(open(os.path.join(
        here, "..", "research", "work-items",
        "RE-001-later-group-predicate-115", "records.json")))
    assert rec["windows"]["predicate"]["start"] == "0x5f6d600"
    assert rec["windows"]["predicate"]["stop"] == "0x5f6d6f4"
    assert rec["windows"]["selector"]["start"] == "0x5f6c2a0"
    assert rec["census"]["predicate"]["direct_calls"] == [
        "0x5da51be", "0x5f6d7e1"]
    assert rec["census"]["selector"]["direct_calls"] == [
        "0x5df1739", "0x5df186a", "0x5ebd196", "0x5f6d67e"]


TESTS = [v for k, v in sorted(globals().items())
         if k.startswith("test_")]

if __name__ == "__main__":
    for fn in TESTS:
        fn()
    print("%d model checks pass" % len(TESTS))
