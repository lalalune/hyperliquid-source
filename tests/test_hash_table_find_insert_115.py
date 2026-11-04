"""Tests for the node #115 hash-table find-or-insert model.

Run under plain python3 (pytest is not installed on this VM):
    python3 tests/test_hash_table_find_insert_115.py

Hash values are injected: the window's hash call (0x61c34a0, seed
0x18d) is cited by contract in the packet, so the tests pin the
table mechanics for given hash codes, not the hash itself.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from hash_table_find_insert_115 import (  # noqa: E402
    HEAD, Table, find_or_insert)


def no_rehash(bucket_count, element_count, insertions):
    return False, bucket_count


def insert(table, key, hash_code, need=no_rehash, rehash=None):
    node, inserted = find_or_insert(table, key, hash_code, need, rehash)
    assert inserted
    return node


def lookup(table, key, hash_code):
    node, inserted = find_or_insert(table, key, hash_code, no_rehash)
    assert not inserted
    return node


def test_insert_into_empty_table_then_hit():
    table = Table(4)
    node = insert(table, b"alpha", 5)
    assert table.size == 1
    assert table.head is node
    assert table.buckets[1] is HEAD
    assert node.value == 0
    assert node.next is None
    found = lookup(table, b"alpha", 5)
    assert found is node
    assert table.size == 1  # a hit never increments the count


def test_value_slot_identity():
    table = Table(4)
    node = insert(table, b"alpha", 5)
    node.value = 42  # the caller writes through the returned address
    assert lookup(table, b"alpha", 5).value == 42


def test_same_bucket_second_insert_splices_after_head_marker():
    table = Table(4)
    first = insert(table, b"a", 5)   # bucket 1
    second = insert(table, b"b", 9)  # bucket 1, occupied slot
    assert table.head is second
    assert second.next is first
    assert table.buckets[1] is HEAD
    assert lookup(table, b"a", 5) is first
    assert lookup(table, b"b", 9) is second


def test_hash_collision_walks_past_on_key_mismatch():
    table = Table(4)
    first = insert(table, b"alpha", 5)
    second = insert(table, b"beta", 5)  # same hash, different key
    assert second.next is first  # spliced after the head marker
    assert lookup(table, b"alpha", 5) is first
    assert lookup(table, b"beta", 5) is second


def test_length_mismatch_is_not_a_hit():
    table = Table(4)
    first = insert(table, b"alpha", 5)
    # Same hash, key is a prefix: the length check rejects it first.
    second = insert(table, b"alph", 5)
    assert second is not first
    assert lookup(table, b"alpha", 5) is first
    assert lookup(table, b"alph", 5) is second


def test_full_64bit_hash_compare():
    table = Table(4)
    first = insert(table, b"alpha", 0x100000005)
    # The lookup hash is zero-extended to 0x5; the stored qword
    # 0x100000005 does not equal it, so this is a miss, not a hit.
    second = insert(table, b"alpha", 5)
    assert second is not first
    assert lookup(table, b"alpha", 0x100000005) is first
    assert lookup(table, b"alpha", 5) is second


def test_run_ends_at_next_node_of_another_bucket():
    table = Table(4)
    x = insert(table, b"x", 6)  # bucket 2
    y = insert(table, b"y", 5)  # bucket 1, empty slot, old head x
    assert table.head is y
    assert y.next is x
    assert table.buckets[2] is y  # old head's bucket slot rewritten
    assert table.buckets[1] is HEAD
    # Unknown bucket-1 key: walk y (miss), then x belongs to bucket
    # 2, so the run ends. The splice still goes after the bucket's
    # before-node (the head field), not after y: the new node
    # becomes the list head, and bucket 2's run (after y) is intact.
    new = insert(table, b"z", 9)  # bucket 1
    assert table.nodes_in_order() == [new, y, x]
    assert table.buckets[2] is y
    assert table.buckets[1] is HEAD
    assert lookup(table, b"z", 9) is new
    assert lookup(table, b"y", 5) is y
    assert lookup(table, b"x", 6) is x


def test_run_ends_at_null_next():
    table = Table(4)
    a = insert(table, b"a", 5)
    b = insert(table, b"b", 9)
    assert table.nodes_in_order() == [b, a]
    c = insert(table, b"c", 13)  # bucket 1, walks b, a, then null
    # The splice goes after the bucket's before-node (the head
    # field), so c becomes the new list head, ahead of b and a.
    assert table.nodes_in_order() == [c, b, a]
    assert c.next is b
    assert lookup(table, b"c", 13) is c


def test_empty_slot_same_bucket_old_head():
    # After a rebuild, the head node can sit in a bucket whose slot
    # is empty; inserting into that empty slot must rewrite the old
    # head's bucket slot first, then the new slot to the head field.
    table = Table(4)
    a = insert(table, b"a", 5)  # bucket 1
    calls = {"n": 0}

    def once(bucket_count, element_count, insertions):
        calls["n"] += 1
        if calls["n"] == 1:
            return True, 8
        return False, bucket_count

    b = insert(table, b"b", 9, need=once)  # bucket 1 under count 8
    # Rehash moved a to bucket 5; b's empty slot is bucket 1.
    assert table.buckets[5] is b
    assert table.buckets[1] is HEAD
    assert table.nodes_in_order() == [b, a]
    assert lookup(table, b"a", 5) is a
    assert lookup(table, b"b", 9) is b


def test_rehash_call_receives_saved_field_and_new_count():
    table = Table(4, field_0x28="saved-marker")
    insert(table, b"a", 5)
    insert(table, b"b", 6)
    seen = {}

    def recording_rehash(t, new_count, saved):
        seen["new_count"] = new_count
        seen["saved"] = saved
        from hash_table_find_insert_115 import _reference_rehash
        _reference_rehash(t, new_count)

    def need_once(bucket_count, element_count, insertions):
        return True, 8

    insert(table, b"c", 9, need=need_once, rehash=recording_rehash)
    assert seen == {"new_count": 8, "saved": "saved-marker"}
    assert lookup(table, b"a", 5).key == b"a"
    assert lookup(table, b"b", 6).key == b"b"
    assert lookup(table, b"c", 9).key == b"c"
    assert table.size == 3


def test_zero_bucket_count_faults_on_division():
    table = Table(0)
    try:
        find_or_insert(table, b"a", 5, no_rehash)
    except ZeroDivisionError:
        pass
    else:
        raise AssertionError("expected a division fault on count 0")


def test_packet_checks():
    here = os.path.dirname(__file__)
    packet = os.path.join(here, "..", "research", "work-items",
                          "RE-001-hash-find-insert-115", "records.json")
    records = json.load(open(packet))
    assert records["window"]["start"] == "0x5f0e660"
    assert records["window"]["end"] == "0x5f0e85f"
    assert records["window"]["artifact_sha256"] == (
        "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
    assert records["census"]["direct_calls"] == ["0x5f0f052"]
    assert records["lsda"]["address"] == "0x414ab0"
    sites = [c["site"] for c in records["in_window_calls"]]
    assert "0x5f0e7e0" in sites  # the rehash callee call
    assert "0x5f0e695" in sites  # the hash call


def _run_all():
    fns = [(n, f) for n, f in sorted(globals().items())
           if n.startswith("test_") and callable(f)]
    for name, fn in fns:
        fn()
        print("ok", name)
    print("all %d tests passed" % len(fns))


if __name__ == "__main__":
    _run_all()
