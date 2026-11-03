"""Tests for the node #115 threshold store (tools/threshold_store_115.py).

Runs under pytest when available, and under plain python3 via the
``__main__`` runner below (pytest is not installed on this VM).
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from threshold_store_115 import (  # noqa: E402
    SENTINEL, ThresholdStoreError, collection, make_element, make_obj,
    recompute, set_threshold,
)

PACKET = os.path.join(
    os.path.dirname(__file__), "..", "research", "work-items",
    "RE-001-threshold-store-115")


def rec(value, flag=0, first=0):
    return (first, make_element(flag, value))


def test_fast_path_store_below_min():
    obj = make_obj(f28=100, f30=90, coll_size=2,
                   coll_inline=[rec(1), rec(2)], coll_heap=[],
                   coll_heap_capacity=0)
    set_threshold(obj, 50)
    assert obj["f30"] == 50
    assert obj["f28"] == 100
    assert obj["coll_size"] == 2
    assert collection(obj) == [rec(1), rec(2)]


def test_fast_path_store_equal_to_min():
    obj = make_obj(f28=100, f30=90)
    set_threshold(obj, 100)
    assert obj["f30"] == 100
    assert obj["f28"] == 100
    assert obj["coll_size"] == 0


def test_recompute_collects_below_and_sets_min():
    obj = make_obj(f28=10, f30=100,
                   scan_inline=[rec(5), rec(25), rec(30)],
                   scan_extra=3)
    set_threshold(obj, 20)
    assert obj["f30"] == 20
    assert collection(obj) == [rec(5)]
    assert obj["f28"] == 25


def test_recompute_uses_new_threshold_not_old():
    # With the old threshold 100, value 50 would be collected; with the
    # new threshold 20 it is a minimum candidate instead.
    obj = make_obj(f28=10, f30=100,
                   scan_inline=[rec(5), rec(50), rec(80)],
                   scan_extra=3)
    set_threshold(obj, 20)
    assert collection(obj) == [rec(5)]
    assert obj["f28"] == 50


def test_recompute_sentinel_when_no_candidate():
    obj = make_obj(f28=10, f30=100,
                   scan_inline=[rec(5), rec(9)],
                   scan_extra=2)
    set_threshold(obj, 20)
    assert collection(obj) == [rec(5), rec(9)]
    assert obj["f28"] == SENTINEL


def test_zero_value_skipped():
    obj = make_obj(f28=10, f30=100,
                   scan_inline=[rec(0), rec(7), rec(30)],
                   scan_extra=3)
    set_threshold(obj, 20)
    assert collection(obj) == [rec(7)]
    assert obj["f28"] == 30


def test_flagged_element_skipped():
    obj = make_obj(f28=10, f30=100,
                   scan_inline=[rec(3, flag=1), rec(40, flag=2), rec(30)],
                   scan_extra=3)
    set_threshold(obj, 20)
    assert collection(obj) == []
    assert obj["f28"] == 30


def test_value_equal_to_threshold_is_min_not_collected():
    obj = make_obj(f28=10, f30=100,
                   scan_inline=[rec(20), rec(21)],
                   scan_extra=2)
    set_threshold(obj, 20)
    assert collection(obj) == []
    assert obj["f28"] == 20


def test_recompute_clears_previous_collection():
    obj = make_obj(f28=10, f30=100, coll_size=3,
                   coll_inline=[rec(1), rec(2), rec(3)],
                   coll_heap=[rec(4)], coll_heap_capacity=4,
                   scan_inline=[rec(9)],
                   scan_extra=1)
    set_threshold(obj, 20)
    assert collection(obj) == [rec(9)]
    assert obj["coll_heap_capacity"] == 4  # capacity retained
    assert obj["f28"] == SENTINEL


def test_scan_inline_heap_mix():
    obj = make_obj(f28=10, f30=100,
                   scan_inline=[rec(i) for i in (1, 2, 3, 4, 5, 6, 7, 8)],
                   scan_heap=[rec(9), rec(50)],
                   scan_extra=8)
    set_threshold(obj, 20)
    assert collection(obj) == [rec(i) for i in range(1, 10)]
    assert obj["f28"] == 50


def test_collection_growth_past_inline():
    # 12 below-threshold records: 8 inline, then heap growth 1, 2, 4.
    obj = make_obj(f28=10, f30=100,
                   scan_inline=[rec(i) for i in range(1, 9)],
                   scan_heap=[rec(i) for i in range(9, 13)],
                   scan_extra=8)
    set_threshold(obj, 20)
    assert collection(obj) == [rec(i) for i in range(1, 13)]
    assert obj["coll_heap"] == [rec(i) for i in range(9, 13)]
    assert obj["coll_heap_capacity"] == 4
    assert obj["coll_size"] == 12


def test_heap_append_without_growth_when_capacity_remains():
    obj = make_obj(f28=10, f30=100, coll_heap_capacity=4,
                   scan_inline=[rec(i) for i in range(1, 9)],
                   scan_heap=[rec(9)],
                   scan_extra=8)
    # Capacity is retained across the recompute's heap clear.
    set_threshold(obj, 20)
    assert obj["coll_heap_capacity"] == 4
    assert obj["coll_heap"] == [rec(9)]


def test_unsigned_ordering():
    big = (1 << 64) - 1
    obj = make_obj(f28=big, f30=0)
    set_threshold(obj, 5)  # 2**64-1 is not < 5 unsigned: fast path
    assert obj["f28"] == big
    obj = make_obj(f28=10, f30=0,
                   scan_inline=[rec(big), rec(7)],
                   scan_extra=2)
    set_threshold(obj, 20)
    assert collection(obj) == [rec(7)]
    # big is a minimum candidate, but the sentinel 0x00ffffffffffffff
    # is smaller than 2**64-1, so the minimum stays at the sentinel.
    assert obj["f28"] == SENTINEL


def test_missing_element_guard():
    obj = make_obj(f28=10, f30=100,
                   scan_inline=[(0, None)],
                   scan_extra=1)
    try:
        set_threshold(obj, 20)
    except ThresholdStoreError:
        pass
    else:
        raise AssertionError("expected ThresholdStoreError")


def test_short_scan_array_guard():
    obj = make_obj(f28=10, f30=100,
                   scan_inline=[rec(1)],
                   scan_extra=3)
    try:
        set_threshold(obj, 20)
    except ThresholdStoreError:
        pass
    else:
        raise AssertionError("expected ThresholdStoreError")


def test_packet_files_present():
    for name in ("README.md", "records.json", "MANIFEST.sha256",
                 "verify.py", "export_excerpts.py", "census.py",
                 "frames.txt", "relocations.txt",
                 os.path.join("excerpts", "setter.txt"),
                 os.path.join("excerpts", "recompute.txt")):
        assert os.path.isfile(os.path.join(PACKET, name)), name
    records = json.load(open(os.path.join(PACKET, "records.json")))
    assert records["windows"]["setter"]["start"] == "0x5f6c270"
    assert records["windows"]["recompute"]["start"] == "0x5f6bfe0"


if __name__ == "__main__":
    tests = [(k, v) for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    for name, fn in tests:
        fn()
        print("ok:", name)
    print("ALL %d TESTS PASSED" % len(tests))
