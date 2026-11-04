"""Tests for the node #115 two-list aggregate 0x5f13130 model.

Run under plain python3 (pytest is not installed on this VM):
    python3 tests/test_two_list_aggregate_115.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "tools"))

from two_list_aggregate_115 import (
    Payload,
    aggregate,
    element_terms,
    refresh,
    threshold_check,
)

MASK = (1 << 64) - 1


def test_empty_lists():
    assert aggregate([], []) == 0
    # Distinguished object ignored when the second list is empty.
    assert aggregate([], [], Payload(9, 9, 9)) == 0


def test_first_list_only():
    nodes = [Payload(1, 2, 3), Payload(10, 20, 30), Payload(0, 0, 7)]
    assert aggregate(nodes, []) == 6 + 60 + 7


def test_element_terms_order():
    # Slot results first, then the direct qword; the sum is the same
    # either way, but the recorded order pins the window's reads.
    assert element_terms(Payload(5, 6, 7)) == 18


def test_both_lists_with_distinguished_subtraction():
    list1 = [Payload(1, 1, 1)]
    list2 = [Payload(2, 2, 2), Payload(3, 3, 3)]
    distinguished = Payload(4, 4, 4)
    assert aggregate(list1, list2, distinguished) == 3 + 15 - 12


def test_distinguished_ignored_when_second_list_empty():
    list1 = [Payload(1, 2, 3)]
    assert aggregate(list1, [], Payload(100, 100, 100)) == 6


def test_missing_distinguished_raises():
    try:
        aggregate([], [Payload(1, 1, 1)])
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for missing distinguished")


def test_wrapping_arithmetic():
    big = Payload((1 << 63), (1 << 63), 5)
    assert aggregate([big], []) == 5  # 2**64 wraps to 0, plus 5
    assert aggregate([Payload(10, 0, 0)], [Payload(1, 0, 0)],
                     Payload(20, 0, 0)) == (11 - 20) & MASK


def test_threshold_positive_arm():
    # base + total >= limit (unsigned) decides.
    assert threshold_check(100, 0, 0, 0, 40, 60) is True  # exact tie
    assert threshold_check(100, 0, 0, 0, 40, 59) is False
    assert threshold_check(100, 0, 0, 0, 0, 200) is True


def test_threshold_fallback_arm():
    # limit <= 0: seed <= 0 -> False; else field sum > seed.
    assert threshold_check(0, 0, 999, 999, 0, 0) is False
    assert threshold_check(-5, 10, 4, 5, 0, 0) is False  # 9 <= 10
    assert threshold_check(-5, 10, 4, 7, 0, 0) is True  # 11 > 10


def test_refresh_consumer():
    assert refresh(123, True) == {"cached_total": 123,
                                  "list2_nonempty": True}
    assert refresh(0, False) == {"cached_total": 0,
                                 "list2_nonempty": False}


def test_end_to_end_aggregate_then_refresh():
    total = aggregate([Payload(2, 3, 4)], [Payload(1, 1, 1)],
                      Payload(0, 0, 1))
    assert total == 9 + 3 - 1
    assert refresh(total, True)["cached_total"] == 11
    assert threshold_check(11, 0, 0, 0, 0, total) is True


def test_packet_records_digest():
    here = os.path.dirname(os.path.abspath(__file__))
    packet = os.path.join(here, "..", "research", "work-items",
                          "RE-001-two-list-aggregate-115", "records.json")
    records = json.load(open(packet))
    assert records["artifact_sha256"] == (
        "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
    assert records["windows"]["main"]["start"] == "0x5f13130"
    assert records["windows"]["main"]["end"] == "0x5f13231"
    assert records["windows"]["main"]["size_bytes"] == 257
    assert records["census"]["main"]["direct_calls"] == [
        "0x5f1327b", "0x5f1345c"]


TESTS = [v for k, v in sorted(globals().items())
         if k.startswith("test_")]

if __name__ == "__main__":
    for fn in TESTS:
        fn()
        print("PASS", fn.__name__)
    print("ALL %d TESTS PASSED" % len(TESTS))
