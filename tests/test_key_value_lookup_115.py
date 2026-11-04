"""Tests for tools/key_value_lookup_115.py: node #115's key lookup
0x5d8cf70 and second-stage value lookup 0x5d8ce90 (RE-001).

Run from the repository root:
    python3 tests/test_key_value_lookup_115.py
Prints "checks pass" on success, else raises.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from key_value_lookup_115 import lookup, lookup_id, value_lookup

CHECKS = []


def check(name, actual, expected):
    if actual != expected:
        raise AssertionError("%s: got %r, want %r" % (name, actual, expected))
    CHECKS.append(name)


def check_raises(name, fn):
    try:
        fn()
    except ValueError:
        CHECKS.append(name)
        return
    raise AssertionError("%s: expected ValueError" % name)


def key_node(key, node_id, stored_hash, nxt=None):
    return {"next": nxt, "key": key, "id": node_id, "hash": stored_hash}


def value_node(node_id, value, nxt=None):
    return {"next": nxt, "id": node_id, "value": value}


def base_map(**overrides):
    m = {
        "count": 3,
        "small_head": None,
        "bucket_count": 4,
        "buckets": [None, None, None, None],
        "value_flag": 0,
        "value_head": None,
        "value_bucket_count": 4,
        "value_buckets": [None, None, None, None],
    }
    m.update(overrides)
    return m


def main():
    # Small path: linear scan, order matters.
    n3 = key_node(b"plum", 30, 0)
    n2 = key_node(b"pear", 20, 0, n3)
    n1 = key_node(b"apple", 10, 0, n2)
    m = base_map(small_head=n1)
    check("small hit first", lookup_id(m, b"apple", 0), 10)
    check("small hit later", lookup_id(m, b"pear", 0), 20)
    check("small hit last", lookup_id(m, b"plum", 0), 30)
    check("small miss", lookup_id(m, b"fig", 0), None)
    check("small same-length mismatch", lookup_id(m, b"applx", 0), None)
    check("small empty head", lookup_id(base_map(), b"apple", 0), None)

    # Small path, empty key: first length-zero node wins, no memcmp.
    e2 = key_node(b"", 22, 0)
    e1 = key_node(b"kiwi", 21, 0, e2)
    m = base_map(small_head=e1)
    check("small empty key", lookup_id(m, b"", 0), 22)
    check("small empty key miss",
          lookup_id(base_map(small_head=key_node(b"kiwi", 21, 0)), b"", 0), None)

    # Hash path: bucket index = hash % count; segment rule.
    # hash 13 % 4 = 1. Nodes in bucket 1: hash 13 (match), then
    # hash 9 (9 % 4 = 1, same segment, different hash), then a
    # node with hash 10 (10 % 4 = 2, segment ends).
    seg_end = key_node(b"apple", 99, 10)
    other = key_node(b"apple", 98, 9, seg_end)
    hit = key_node(b"apple", 42, 13, other)
    m = base_map(count=21, buckets=[None, {"next": hit}, None, None])
    check("hash hit first", lookup_id(m, b"apple", 13), 42)
    # Same key bytes but a different supplied hash: no node has it.
    check("hash mismatch", lookup_id(m, b"apple", 14), None)
    # Hash matches a later node in the same segment.
    later = key_node(b"apple", 55, 9, seg_end)
    first = key_node(b"berry", 44, 13, later)
    m = base_map(count=21, buckets=[None, {"next": first}, None, None])
    check("hash hit later", lookup_id(m, b"apple", 9), 55)
    # The segment ends before a node whose stored hash equals the
    # sought hash but sits past a foreign-bucket node: the scan
    # advances from a same-bucket node (hash 13) to a foreign one
    # (hash 10, bucket 2) and stops there, never reaching the
    # matching node behind it.
    past = key_node(b"apple", 77, 9)
    foreign = key_node(b"berry", 66, 10, past)
    first_seg = key_node(b"berry", 44, 13, foreign)
    m = base_map(count=21, buckets=[None, {"next": first_seg}, None, None])
    check("hash segment end", lookup_id(m, b"apple", 9), None)
    # Empty bucket slot and empty-key hash hit (no memcmp).
    check("hash empty slot", lookup_id(base_map(count=21), b"apple", 13), None)
    ehit = key_node(b"", 33, 13)
    m = base_map(count=21, buckets=[None, {"next": ehit}, None, None])
    check("hash empty key", lookup_id(m, b"", 13), 33)
    # Hash matches but the length differs: not a match.
    lhit = key_node(b"apples", 44, 13)
    m = base_map(count=21, buckets=[None, {"next": lhit}, None, None])
    check("hash length mismatch", lookup_id(m, b"apple", 13), None)
    # Threshold: count exactly 20 stays on the small path even
    # when a bucket entry exists.
    m = base_map(count=20, small_head=n1,
                 buckets=[None, {"next": hit}, None, None])
    check("threshold 20 small", lookup_id(m, b"pear", 13), 20)

    # Value lookup, small path.
    v3 = value_node(30, 0x7000)
    v2 = value_node(20, 0x6000, v3)
    v1 = value_node(10, 0x5000, v2)
    m = base_map(value_head=v1)
    check("value small hit", value_lookup(m, 20), 0x6000)
    check("value small miss", value_lookup(m, 99), 0)
    check("value small empty", value_lookup(base_map(), 10), 0)
    vz = value_node(10, 0)
    check("value small zero value", value_lookup(base_map(value_head=vz), 10), 0)

    # Value lookup, bucketed path: id 21 % 4 = 1.
    vend = value_node(21, 0x9000)
    vother = value_node(25, 0x8000, vend)  # 25 % 4 = 1, same segment
    vfirst = value_node(17, 0x7000, vother)  # 17 % 4 = 1
    m = base_map(value_flag=1,
                 value_buckets=[None, {"next": vfirst}, None, None])
    check("value bucketed hit later", value_lookup(m, 25), 0x8000)
    check("value bucketed hit last", value_lookup(m, 21), 0x9000)
    check("value bucketed miss", value_lookup(m, 29), 0)
    check("value bucketed empty slot", value_lookup(base_map(value_flag=1), 21), 0)
    # Segment ends before a matching id past a foreign-bucket node:
    # advancing from a same-bucket node (id 17, bucket 1) to a
    # foreign one (id 22, bucket 2) stops the scan, never
    # reaching the matching node behind it.
    past_v = value_node(21, 0x9000)
    foreign_v = value_node(22, 0x8000, past_v)  # 22 % 4 = 2
    first_v = value_node(17, 0x7000, foreign_v)  # 17 % 4 = 1
    m = base_map(value_flag=1,
                 value_buckets=[None, {"next": first_v}, None, None])
    check("value bucketed segment end", value_lookup(m, 21), 0)

    # End to end: key -> id -> value; a miss returns 0 without
    # consulting the value side at all.
    m = base_map(small_head=n1, value_head=v1)
    check("end to end small", lookup(m, b"pear", 0), 0x6000)
    check("end to end miss", lookup(m, b"fig", 0), 0)
    m = base_map(count=21, buckets=[None, {"next": hit}, None, None],
                 value_flag=1,
                 value_buckets=[None, {"next": value_node(42, 0xABCD)}, None, None])
    # 42 % 4 = 2, so put the value node in bucket 2 instead.
    m["value_buckets"] = [None, None, {"next": value_node(42, 0xABCD)}, None]
    check("end to end hash+bucketed", lookup(m, b"apple", 13), 0xABCD)

    # Guards: missing fields and degenerate bucket counts raise.
    check_raises("guard missing count", lambda: lookup_id({}, b"a", 0))
    check_raises("guard hash zero buckets",
                 lambda: lookup_id(base_map(count=21, bucket_count=0), b"a", 1))
    check_raises("guard value zero buckets",
                 lambda: value_lookup(base_map(value_flag=1, value_bucket_count=0), 1))
    check_raises("guard null first hash node",
                 lambda: lookup_id(base_map(count=21, buckets=[{"next": None}, None, None, None]), b"a", 0))
    check_raises("guard missing value flag",
                 lambda: value_lookup({"value_head": None}, 1))

    print("%d checks pass" % len(CHECKS))


if __name__ == "__main__":
    main()
