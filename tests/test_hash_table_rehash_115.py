"""Tests for the node #115 hash-table rehash (0x5f0e520).

RE-001 work item; packet research/work-items/RE-001-hash-rehash-115/.
Runs under pytest when installed, and under plain python3 via the
__main__ runner below (pytest is not installed on the analysis VM).

Hand-computed expectations below follow the window instruction by
instruction: bucket = hash % new_count; an occupied bucket splices
the node after the slot's before-node; an empty bucket makes the
node the new list head, stores the HEAD sentinel in the slot, and —
only when the node has a successor — rewrites the most recently
started bucket's slot (initially bucket 0) to the node, then updates
that index. The occupied path never updates the index.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from hash_table_rehash_115 import (  # noqa: E402
    HEAD, BadAlloc, BadArrayNewLength, Node, Table, rehash)


def chain(head):
    out = []
    cur = head
    while cur is not None:
        out.append(cur.hash_code)
        cur = cur.next
    return out


def table_of(hashes, count=4, embedded=False):
    nodes = [Node(h) for h in hashes]
    for a, b in zip(nodes, nodes[1:]):
        a.next = b
    return Table([None] * count, count, nodes[0] if nodes else None,
                 embedded=embedded), nodes


def test_single_bucket_path_reverses_list():
    table, nodes = table_of([5, 9, 2])
    result = rehash(table, 1)
    assert result == {"freed_old_array": True, "bucket_count": 1,
                      "embedded": True}
    assert table.buckets == [HEAD]
    assert table.bucket_count == 1
    assert table.embedded is True
    # Every node lands in bucket 0; occupied splices after HEAD, so
    # the head order is the reverse of the arrival order.
    assert chain(table.head) == [2, 9, 5]


def test_distinct_buckets_and_prev_slot_rewrite():
    table, nodes = table_of([10, 19, 3])
    rehash(table, 8)
    # N1 (10 % 8 = 2): empty bucket, becomes head, slot[2] = HEAD,
    # no successor yet so no rewrite. N2 (19 % 8 = 3): empty bucket,
    # becomes head, slot[3] = HEAD, successor N1 exists so the most
    # recently started slot (2) is rewritten to N2. N3 (3 % 8 = 3):
    # occupied bucket, spliced after HEAD, becomes head.
    assert chain(table.head) == [3, 19, 10]
    assert table.buckets[2] is nodes[1]
    assert table.buckets[3] is HEAD
    assert all(s is None for i, s in enumerate(table.buckets)
               if i not in (2, 3))


def test_colliding_bucket_keeps_head_splice_order():
    table, nodes = table_of([8, 16, 24])
    rehash(table, 8)
    assert chain(table.head) == [24, 16, 8]
    assert table.buckets[0] is HEAD
    assert all(s is None for s in table.buckets[1:])


def test_empty_table_installs_empty_buckets():
    table, _ = table_of([])
    result = rehash(table, 5)
    assert result["freed_old_array"] is True
    assert table.buckets == [None] * 5
    assert table.bucket_count == 5
    assert table.head is None


def test_count_zero_empty_table_installs_zero_buckets():
    table, _ = table_of([])
    rehash(table, 0)
    assert table.buckets == []
    assert table.bucket_count == 0
    assert table.head is None


def test_count_zero_nonempty_table_faults_on_first_div():
    table, _ = table_of([7, 8])
    try:
        rehash(table, 0)
    except ZeroDivisionError:
        pass
    else:
        raise AssertionError("expected ZeroDivisionError")
    # The detach (head field zeroed) happens before the loop, and the
    # install happens after it, so the fault leaves the head detached
    # and the old buckets still installed.
    assert table.head is None
    assert table.bucket_count == 4


def test_count_guards():
    for count in (1 << 60, (1 << 61) - 1):
        table, _ = table_of([1])
        try:
            rehash(table, count)
        except BadAlloc:
            pass
        else:
            raise AssertionError("expected BadAlloc for %d" % count)
    for count in (1 << 61, (1 << 61) + 5, 1 << 62):
        table, _ = table_of([1])
        try:
            rehash(table, count)
        except BadArrayNewLength:
            pass
        else:
            raise AssertionError(
                "expected BadArrayNewLength for %d" % count)


def test_embedded_old_array_is_not_freed():
    table, _ = table_of([4], count=1, embedded=True)
    result = rehash(table, 4)
    assert result["freed_old_array"] is False
    assert table.embedded is False
    assert chain(table.head) == [4]
    assert table.buckets[0] is HEAD


def test_heap_old_array_is_freed():
    table, _ = table_of([4], count=1, embedded=False)
    result = rehash(table, 4)
    assert result["freed_old_array"] is True


def test_prev_index_not_updated_on_occupied_path():
    # Buckets: N1 -> bucket 1 (empty, prev becomes 1), N2 -> bucket
    # 1 again (occupied, prev stays 1), N3 -> bucket 2 (empty, has a
    # successor, so slot[1] — not slot[2] — is rewritten to N3).
    table, nodes = table_of([9, 17, 10])
    rehash(table, 8)
    assert chain(table.head) == [10, 17, 9]
    assert table.buckets[1] is nodes[2]
    assert table.buckets[2] is HEAD


def test_packet_checks():
    here = os.path.dirname(__file__)
    packet = os.path.join(here, "..", "research", "work-items",
                          "RE-001-hash-rehash-115", "records.json")
    records = json.load(open(packet))
    assert records["window"]["start"] == "0x5f0e520"
    assert records["window"]["end"] == "0x5f0e65d"
    assert records["window"]["artifact_sha256"] == (
        "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
    assert records["census"]["direct_calls"] == ["0x5f0e7e0"]
    assert records["lsda"]["address"] == "0x414a94"


def _run_all():
    fns = [(n, f) for n, f in sorted(globals().items())
           if n.startswith("test_") and callable(f)]
    for name, fn in fns:
        fn()
        print("ok", name)
    print("all %d tests passed" % len(fns))


if __name__ == "__main__":
    _run_all()
