"""Tests for the node #115 unmatched-node minimum scan 0x5f134b0 model.

Run under plain python3 (pytest is not installed on this VM):
    python3 tests/test_min_scan_115.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "tools"))

from min_scan_115 import (
    ChainEntry,
    HashBucket,
    HashQuery,
    KeyRecord,
    LinearQuery,
    caller_min,
    scan,
)


def test_empty_list_returns_zero():
    assert scan([], None) == 0
    assert scan([], LinearQuery(None)) == 0


def test_null_query_counts_every_node():
    nodes = [KeyRecord(9, 1), KeyRecord(4, 2), KeyRecord(7, 3)]
    assert scan(nodes, None) == 4


def test_zero_results_are_skipped():
    # A zero callee result leaves the running minimum untouched, so
    # the result is the minimum over the nonzero results, not 0.
    assert scan([KeyRecord(0, 1), KeyRecord(5, 2)], None) == 5
    assert scan([KeyRecord(0, 1), KeyRecord(0, 2)], None) == 0


def test_linear_match_skips_matched_node():
    node_a = KeyRecord(2, 1)
    node_b = KeyRecord(8, 2)
    query = LinearQuery(ChainEntry(node_b, ChainEntry(node_a)))
    # Both matched: nothing is counted.
    assert scan([node_a, node_b], query) == 0
    # Only node_b matched: node_a's value counts.
    query2 = LinearQuery(ChainEntry(node_b))
    assert scan([node_a, node_b], query2) == 2


def test_linear_chain_exhausted_counts():
    node = KeyRecord(6, 1)
    other = KeyRecord(1, 9)
    query = LinearQuery(ChainEntry(other))
    assert scan([node], query) == 6


def test_hash_direct_hit_skips():
    node = KeyRecord(3, 6)  # 6 % 4 == 2
    buckets = [None, None, HashBucket(ChainEntry(node)), None]
    assert scan([node], HashQuery(4, buckets)) == 0


def test_hash_empty_bucket_counts():
    node = KeyRecord(3, 6)
    buckets = [None, None, None, None]
    assert scan([node], HashQuery(4, buckets)) == 3


def test_hash_chain_hit_skips():
    node = KeyRecord(3, 10)  # 10 % 4 == 2
    first = KeyRecord(0, 6)  # 6 % 4 == 2, same bucket
    buckets = [None, None,
               HashBucket(ChainEntry(first, ChainEntry(node))), None]
    assert scan([node], HashQuery(4, buckets)) == 0


def test_hash_wrong_bucket_entry_ends_as_no_match():
    node = KeyRecord(3, 10)  # bucket 2
    first = KeyRecord(0, 6)  # 6 % 4 == 2, same bucket, not the node
    stray = KeyRecord(0, 5)  # 5 % 4 == 1, foreign bucket
    buckets = [None, None,
               HashBucket(ChainEntry(
                   first, ChainEntry(stray, ChainEntry(node)))), None]
    # The window stops at the foreign-bucket entry before ever
    # reaching the node, so the node counts.
    assert scan([node], HashQuery(4, buckets)) == 3


def test_hash_zero_divisor_raises():
    node = KeyRecord(3, 6)
    try:
        scan([node], HashQuery(0, []))
    except ValueError:
        return
    raise AssertionError("expected a fault for divisor 0")


def test_hash_null_head_raises():
    node = KeyRecord(3, 6)
    buckets = [None, None, HashBucket(None), None]
    try:
        scan([node], HashQuery(4, buckets))
    except ValueError:
        return
    raise AssertionError("expected a fault for a null bucket head")


def test_caller_flag_zero_returns_field():
    assert caller_min(False, 42, [KeyRecord(1, 1)], 7) == 42


def test_caller_scan_candidate_wins():
    # Scan 5 < field 9; value 7 is above the candidate, so 5 wins.
    assert caller_min(True, 9, [KeyRecord(5, 1)], 7) == 5


def test_caller_value_wins_when_smallest():
    assert caller_min(True, 9, [KeyRecord(5, 1)], 3) == 3


def test_caller_zero_value_leaves_candidate():
    assert caller_min(True, 9, [KeyRecord(5, 1)], 0) == 5


def test_caller_scan_zero_falls_back_to_field():
    # Scan 0 (all values zero) -> candidate is the field; value 7 wins.
    assert caller_min(True, 9, [KeyRecord(0, 1)], 7) == 7
    assert caller_min(True, 9, [KeyRecord(0, 1)], 0) == 9


def test_packet_records_digest():
    here = os.path.dirname(os.path.abspath(__file__))
    packet = os.path.join(here, "..", "research", "work-items",
                          "RE-001-min-scan-115", "records.json")
    records = json.load(open(packet))
    assert records["artifact_sha256"] == (
        "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
    assert records["windows"]["main"]["start"] == "0x5f134b0"
    assert records["windows"]["main"]["end"] == "0x5f135c1"
    assert records["windows"]["main"]["size_bytes"] == 273
    assert records["census"]["main"]["direct_calls"] == [
        "0x5d8bd5c", "0x5e4bfca", "0x5e4c2d5"]


TESTS = [v for k, v in sorted(globals().items())
         if k.startswith("test_")]

if __name__ == "__main__":
    for fn in TESTS:
        fn()
        print("PASS", fn.__name__)
    print("ALL %d TESTS PASSED" % len(TESTS))
