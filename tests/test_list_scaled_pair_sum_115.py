"""Tests for the node #115 list scaled-pair sum 0x5f13090 model.

Run under plain python3 (pytest is not installed on this VM):
    python3 tests/test_list_scaled_pair_sum_115.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "tools"))

from list_scaled_pair_sum_115 import (
    CALLEE,
    ListHeader,
    ListNode,
    list_scaled_pair_sum,
)

MASK = (1 << 64) - 1


def _chain(payloads):
    """Build a header-terminated chain from a payload list."""
    header = ListHeader()
    node = None
    for payload in reversed(payloads):
        node = ListNode(payload, node if node is not None else header)
    header.first = node if node is not None else header
    return header


def _by_payload(table):
    def pair_total(payload, arg1, arg2):
        return table[payload]
    return pair_total


def test_empty_list_returns_zero():
    header = ListHeader()
    assert list_scaled_pair_sum(header, _by_payload({}), 1, 2) == (0, 0)


def test_single_node():
    header = _chain(["a"])
    table = {"a": (60, 20)}
    assert list_scaled_pair_sum(header, _by_payload(table), 7, 9) == (60, 20)


def test_multiple_nodes_sum_both_components():
    header = _chain(["a", "b", "c"])
    table = {"a": (60, 20), "b": (90, 30), "c": (5, 5)}
    assert list_scaled_pair_sum(header, _by_payload(table), 0, 0) == (155, 55)


def test_pass_through_args_forwarded_unchanged():
    seen = []

    def pair_total(payload, arg1, arg2):
        seen.append((payload, arg1, arg2))
        return (1, 1)

    header = _chain(["x", "y"])
    assert list_scaled_pair_sum(header, pair_total, 123, 456) == (2, 2)
    assert seen == [("x", 123, 456), ("y", 123, 456)]


def test_calls_follow_list_order():
    order = []

    def pair_total(payload, arg1, arg2):
        order.append(payload)
        return (0, 0)

    header = _chain(["first", "second", "third"])
    list_scaled_pair_sum(header, pair_total, 0, 0)
    assert order == ["first", "second", "third"]


def test_zero_contributions_add_nothing():
    header = _chain(["a", "b"])
    table = {"a": (0, 0), "b": (10, 4)}
    assert list_scaled_pair_sum(header, _by_payload(table), 0, 0) == (10, 4)


def test_wrapping_sums_on_both_components():
    header = _chain(["a", "b"])
    table = {"a": (MASK, MASK - 1), "b": (5, 7)}
    assert list_scaled_pair_sum(header, _by_payload(table), 0, 0) == (4, 5)


def test_missing_terminator_raises():
    header = ListHeader()
    dangling = ListNode("a", None)
    header.first = dangling
    try:
        list_scaled_pair_sum(header, _by_payload({"a": (1, 1)}), 0, 0)
    except ValueError:
        return
    raise AssertionError("expected ValueError for a non-terminating chain")


def test_callee_address():
    assert CALLEE == 0x5F09A50


def test_packet_records_present():
    import json

    here = os.path.dirname(os.path.abspath(__file__))
    packet = os.path.join(here, "..", "research", "work-items",
                          "RE-001-list-scaled-pair-sum-115")
    with open(os.path.join(packet, "records.json")) as fh:
        records = json.load(fh)
    assert records["window"] == "0x5f13090"
    assert records["callee"]["address"] == "0x5f09a50"
    assert records["census"]["main"]["direct_calls"] == [
        "0x5d64291", "0x5d646f2", "0x5d64a7c"]
    with open(os.path.join(packet, "main-5f13090.objdump.txt")) as fh:
        excerpt = fh.read()
    assert "5f13090" in excerpt and "5f130fd" in excerpt
    assert "5f09a50" in excerpt


def _run():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_")]
    for test in tests:
        test()
        print("ok", test.__name__)
    print("all", len(tests), "tests passed")


if __name__ == "__main__":
    _run()
