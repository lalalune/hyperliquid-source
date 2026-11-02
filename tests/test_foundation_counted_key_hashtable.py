"""Tests for tools/foundation_counted_key_hashtable.py (node #94
0x5160dd0 counted-key increment-or-insert, its 0x5160c10
find-or-insert callee and the 0x5160ad0 rehash callee).

Run with unittest (no pytest on this VM):

    python3 -m unittest tests.test_foundation_counted_key_hashtable -v

Policies are supplied by the tests: never_rehash pins the
no-rehash arms, and recording policies pin the call contract.
The binary's prime policy table is not claimed here.
"""

import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools"))

from foundation_counted_key_hashtable import (  # noqa: E402
    SENTINEL,
    BadAlloc,
    BadArrayNewLength,
    CountedKeyTable,
    FakeMutex,
    HashTable,
    InconsistentTable,
    LockError,
    Node,
    increment_or_insert,
)

PACKET = REPO / "research" / "work-items" / "RE-001-counted-key-hashtable-94"
# Relative on purpose: objdump prints the binary path in its header,
# so the stored excerpts only regenerate byte-for-byte when the
# binary is named by the same relative path from the repo root.
BINARY = "work/hl-node-94.bin"


def never_rehash(bucket_count, element_count, n):
    assert n == 1
    return (False, bucket_count)


def rehash_to(target):
    calls = []

    def policy(bucket_count, element_count, n):
        calls.append((bucket_count, element_count, n))
        return (True, target)

    policy.calls = calls
    return policy


def table_with(keys, count=8):
    """A table whose chain holds keys in order, bucket entries
    consistent with key % count. Segments here are single nodes
    except where the test states a collision."""
    table = HashTable()
    table.count = count
    table.buckets = [None] * count
    table.single_slot = False
    nodes = [Node(k, 0) for k in keys]
    for i, node in enumerate(nodes):
        node.next = nodes[i + 1] if i + 1 < len(nodes) else None
    table.head = nodes[0] if nodes else None
    prev = SENTINEL
    for node in nodes:
        bucket = node.key % count
        if table.buckets[bucket] is None:
            table.buckets[bucket] = prev
        prev = node
    table.element_count = len(nodes)
    return table, nodes


class FindOrInsertTest(unittest.TestCase):
    def test_found_first_node_returns_existing_slot(self):
        table, nodes = table_with([10, 25, 41], count=8)
        # 10%8=2, 25%8=1, 41%8=1: 25 and 41 share bucket 1; chain
        # order is 10, 25, 41, so bucket 1's segment is 25 then 41.
        found = table.find_or_insert(25, never_rehash)
        self.assertIs(found, nodes[1])
        self.assertEqual(table.element_count, 3)

    def test_found_later_node_after_segment_walk(self):
        table, nodes = table_with([10, 25, 41], count=8)
        found = table.find_or_insert(41, never_rehash)
        self.assertIs(found, nodes[2])
        self.assertEqual(table.element_count, 3)

    def test_miss_at_chain_end_and_segment_end(self):
        table, _ = table_with([10, 25, 41], count=8)
        # 50%8=2 shares bucket 2 with 10 but is not present: the
        # walk reaches the chain end (41's bucket differs) and
        # misses.
        node = table.find_or_insert(50, never_rehash)
        self.assertEqual(node.key, 50)
        self.assertEqual(node.value, 0)
        self.assertEqual(table.element_count, 4)

    def test_miss_never_written_bucket(self):
        table, _ = table_with([10], count=8)
        node = table.find_or_insert(7, never_rehash)
        self.assertEqual(node.key, 7)
        # 7%8=7 was never written: head path, entry is sentinel.
        self.assertIs(table.buckets[7], SENTINEL)
        self.assertIs(table.head, node)

    def test_insert_after_before_node_keeps_entry(self):
        table, nodes = table_with([10, 25], count=8)
        # 33%8=1 joins bucket 1 after its before-node (node 10):
        # the entry is unchanged, the new node sits between 10 and
        # 25, and the head does not move.
        node = table.find_or_insert(33, never_rehash)
        self.assertIs(table.head, nodes[0])
        self.assertIs(nodes[0].next, node)
        self.assertIs(node.next, nodes[1])
        self.assertIs(table.buckets[1], nodes[0])

    def test_head_insert_repoints_old_head_bucket(self):
        table2, _ = table_with([25], count=8)
        # 25%8=1, entry SENTINEL, head 25. Insert 3 (bucket 3,
        # never written) through the head path: the old head 25's
        # bucket entry is repointed at the new node, and bucket 3's
        # entry becomes the sentinel.
        fresh = table2.find_or_insert(3, never_rehash)
        self.assertIs(table2.head, fresh)
        self.assertIs(table2.buckets[1], fresh)
        self.assertIs(table2.buckets[3], SENTINEL)

    def test_bucket_count_zero_is_inconsistent(self):
        table = HashTable()
        table.count = 0
        with self.assertRaises(InconsistentTable):
            table.find_or_insert(5, never_rehash)


class RehashTest(unittest.TestCase):
    def test_single_bucket_arm_skips_overflow_checks(self):
        table, _ = table_with([10, 25, 41], count=8)
        table.rehash_aux(1, table.next_resize)
        self.assertEqual(table.count, 1)
        self.assertTrue(table.single_slot)
        self.assertTrue(table.freed_old)
        # Single bucket: every migration takes the empty-then-
        # nonempty path, so the chain reverses (each later node
        # prepends after the sentinel).
        keys = []
        node = table.head
        while node is not None:
            keys.append(node.key)
            node = node.next
        self.assertEqual(keys, [41, 25, 10])
        self.assertIs(table.buckets[0], SENTINEL)

    def test_migration_keeps_all_nodes(self):
        table = HashTable()
        table.count = 4
        table.buckets = [None] * 4
        table.single_slot = False
        nodes = [Node(5), Node(9), Node(13), Node(6)]
        for i, node in enumerate(nodes):
            node.next = nodes[i + 1] if i + 1 < len(nodes) else None
        table.head = nodes[0]
        table.element_count = 4
        table.rehash_aux(8, 0)
        keys = []
        node = table.head
        while node is not None:
            keys.append(node.key)
            node = node.next
        self.assertEqual(sorted(keys), [5, 6, 9, 13])
        self.assertIsNotNone(table.buckets[5])
        self.assertEqual(table.count, 8)
        self.assertEqual(table.element_count, 4)

    def test_overflow_arms(self):
        table = HashTable()
        with self.assertRaises(BadAlloc):
            table.rehash_aux(1 << 60, 0)
        with self.assertRaises(BadArrayNewLength):
            table.rehash_aux(1 << 61, 0)

    def test_alloc_failure_restores_next_resize(self):
        table, _ = table_with([10], count=8)
        table.next_resize = 77
        with self.assertRaises(BadAlloc):
            table.rehash_aux(16, 77, force_alloc_failure=True)
        self.assertEqual(table.next_resize, 77)
        self.assertEqual(table.count, 8)  # table untouched

    def test_insert_rehash_call_contract_and_bucket_recompute(self):
        table, _ = table_with([10], count=8)
        policy = rehash_to(16)
        node = table.find_or_insert(26, policy)
        self.assertEqual(policy.calls, [(8, 1, 1)])
        self.assertEqual(table.count, 16)
        self.assertEqual(node.key, 26)
        self.assertEqual(table.element_count, 2)

    def test_insert_rehash_failure_frees_node_and_propagates(self):
        table, _ = table_with([10], count=8)

        def failing_aux(new_count, saved):
            raise BadAlloc("boom")

        with self.assertRaises(BadAlloc):
            table.find_or_insert(26, rehash_to(16),
                                 rehash_aux=failing_aux)
        self.assertEqual(len(table.freed_nodes), 1)
        self.assertEqual(table.freed_nodes[0].key, 26)
        self.assertEqual(table.element_count, 1)


class WrapperTest(unittest.TestCase):
    def test_found_increments_and_unlocks(self):
        outer = CountedKeyTable()
        outer.table, _ = table_with([10, 25], count=8)
        kind, node = increment_or_insert(outer, 25, never_rehash)
        self.assertEqual(kind, "found")
        self.assertEqual(node.value, 1)
        self.assertEqual(outer.mutex.unlock_calls, 1)

    def test_found_increments_by_one_from_existing(self):
        outer = CountedKeyTable()
        table, nodes = table_with([10, 25], count=8)
        outer.table = table
        nodes[1].value = 41
        kind, node = increment_or_insert(outer, 25, never_rehash)
        self.assertEqual(kind, "found")
        self.assertEqual(node.value, 42)

    def test_value_wraps_mod_2_to_64(self):
        outer = CountedKeyTable()
        table, nodes = table_with([10], count=8)
        outer.table = table
        nodes[0].value = (1 << 64) - 1
        _, node = increment_or_insert(outer, 10, never_rehash)
        self.assertEqual(node.value, 0)

    def test_miss_inserts_with_count_one(self):
        outer = CountedKeyTable()
        kind, node = increment_or_insert(outer, 7, never_rehash)
        self.assertEqual(kind, "inserted")
        self.assertEqual(node.value, 1)
        self.assertEqual(outer.table.element_count, 1)
        self.assertEqual(outer.mutex.unlock_calls, 1)

    def test_count_zero_linear_walk(self):
        outer = CountedKeyTable()
        # Inconsistent-but-observable fixture: count 0 with a live
        # head. The binary walks the chain linearly in that case.
        table = HashTable()
        node = Node(9, 5)
        table.head = node
        table.element_count = 0
        outer.table = table
        kind, found = increment_or_insert(outer, 9, never_rehash)
        self.assertEqual(kind, "found")
        self.assertEqual(found.value, 6)

    def test_count_zero_empty_head_inserts(self):
        outer = CountedKeyTable()
        outer.table.element_count = 0
        kind, node = increment_or_insert(outer, 3, never_rehash)
        self.assertEqual(kind, "inserted")
        self.assertEqual(node.value, 1)

    def test_lock_failure_throws_without_unlock(self):
        outer = CountedKeyTable(FakeMutex(lock_result=1))
        with self.assertRaises(LockError):
            increment_or_insert(outer, 3, never_rehash)
        self.assertEqual(outer.mutex.unlock_calls, 0)

    def test_unlocks_on_rehash_exception(self):
        outer = CountedKeyTable()
        outer.table, _ = table_with([10], count=8)

        def failing_aux(new_count, saved):
            raise BadAlloc("boom")

        with self.assertRaises(BadAlloc):
            increment_or_insert(outer, 26, rehash_to(16),
                                rehash_aux=failing_aux)
        self.assertEqual(outer.mutex.unlock_calls, 1)

    def test_end_to_end_sequence(self):
        outer = CountedKeyTable()
        for key, expected in [(5, 1), (5, 2), (9, 1), (5, 3),
                              (13, 1)]:
            kind, node = increment_or_insert(outer, key, never_rehash)
            self.assertEqual(node.value, expected)
        self.assertEqual(outer.table.element_count, 3)


class PacketTest(unittest.TestCase):
    def test_packet_verify_passes(self):
        result = subprocess.run(
            [sys.executable, str(PACKET / "verify.py"),
             "--binary", BINARY],
            capture_output=True, text=True, cwd=str(REPO))
        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)
        self.assertIn("ALL CHECKS PASSED", result.stdout)

    def test_packet_records_are_semantic_only(self):
        records = json.loads((PACKET / "records.json").read_text())
        self.assertEqual(records["task_id"], "RE-001")
        self.assertNotIn("instructions", records)
        self.assertNotIn("mnemonic", (PACKET / "records.json").read_text())
        self.assertEqual(records["window"]["start"], "0x5160dd0")
        self.assertEqual(records["window"]["end"], "0x5160ebd")

    def test_packet_excerpts_regenerate(self):
        result = subprocess.run(
            [sys.executable, str(PACKET / "export_excerpts.py"),
             "--binary", BINARY, "--out", "/tmp/ckh-excerpts"],
            capture_output=True, text=True, cwd=str(REPO))
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in ("window.objdump.txt", "insert.objdump.txt",
                     "rehash.objdump.txt", "cleanup.objdump.txt",
                     "caller-site-1.objdump.txt",
                     "caller-site-2.objdump.txt"):
            self.assertEqual(
                (Path("/tmp/ckh-excerpts") / name).read_text(),
                (PACKET / name).read_text())

    def test_self_check_samples_match_real_binary(self):
        blob = (REPO / BINARY).read_bytes()
        # Three instructions sampled from the raw excerpts, checked
        # byte-for-byte against the real binary (the pre-submit
        # self-check): window endbr64, insert call in the wrapper,
        # rehash call in the insert function.
        self.assertEqual(
            blob[0x5160dd0 - 0x1000:0x5160dd0 - 0x1000 + 4],
            bytes.fromhex("f30f1efa"))
        self.assertEqual(blob[0x5160e99 - 0x1000], 0xE8)
        self.assertEqual(blob[0x5160d3e - 0x1000], 0xE8)


if __name__ == "__main__":
    unittest.main()
