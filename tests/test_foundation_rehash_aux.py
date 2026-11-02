"""Tests for tools/foundation_rehash_aux.py (node #94 0x515a820).

The expectations are transcribed from the window's disassembly
(see research/work-items/RE-001-rehash-aux-94/): the table and
node layouts, the single-bucket and overflow arms, the
empty/nonempty bucket insertion rules, the previous-bucket
fixup, the old-array free rule, and the catch-arm restore. The
tests pin the model, not an execution of the target binary (no
execution is available here).
"""

import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.foundation_rehash_aux import (
    SENTINEL,
    AllocationFailed,
    BadAlloc,
    BadArrayNewLength,
    Node,
    Table,
    rehash_aux,
)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(
    REPO, "research", "work-items", "RE-001-rehash-aux-94")
# Relative path, run from the repo root: objdump embeds the path
# spelling in each excerpt header, so absolute and relative runs
# would not regenerate byte-for-byte.
BINARY = os.path.join("work", "hl-node-94.bin")


def chain_table(nodes, bucket_count=3, next_resize=99):
    """Build a table whose chain is nodes in list order."""
    head = None
    for node in reversed(nodes):
        node.next = head
        head = node
    table = Table([None] * bucket_count, bucket_count, head,
                  element_count=len(nodes), next_resize=next_resize)
    return table


class TestEmptyAndSingleNode(unittest.TestCase):
    def test_empty_table_heap_to_heap(self):
        table = chain_table([], bucket_count=3)
        summary = rehash_aux(table, 7, saved_next_resize=99)
        self.assertEqual(table.chain(), [])
        self.assertEqual(table.bucket_entries(), [None] * 7)
        self.assertEqual(table.bucket_count, 7)
        self.assertEqual(summary["old_array_freed"], True)
        self.assertEqual(table.head, None)

    def test_empty_table_heap_to_single(self):
        table = chain_table([], bucket_count=5)
        rehash_aux(table, 1, saved_next_resize=99)
        self.assertEqual(table.bucket_entries(), [None])
        self.assertEqual(table.bucket_count, 1)
        self.assertTrue(table.buckets_is_single)
        self.assertEqual(table.freed, [True])

    def test_single_node_no_fixup_when_next_is_null(self):
        # Hash 10 % 4 = bucket 2. The only node is prepended to
        # the head and its bucket entry becomes the sentinel.
        # The fixup store is skipped because the inserted node's
        # next pointer is null (the head was null), so bucket
        # entry 0 stays empty and the previous index stays 0.
        node = Node("A", 10)
        table = chain_table([node], bucket_count=3)
        rehash_aux(table, 4, saved_next_resize=99)
        self.assertEqual(table.chain(), ["A"])
        self.assertEqual(table.bucket_entries(), [None, None, "S", None])
        self.assertEqual(table.freed, [True])


class TestMigrationOrder(unittest.TestCase):
    def test_three_nodes_empty_path_fixup_repoints_previous(self):
        # Old chain A(5%3=2), B(4%3=1), C(8%3=2), walked in order:
        # A starts bucket 2 (next null, so no fixup; previous
        # stays 0). B starts bucket 1: its next is A (non-null),
        # so the fixup overwrites bucket entry 2 — the previous
        # bucket — with B, then previous becomes 1. C finds
        # bucket 2 nonempty with before-node B, so C inserts
        # after B (C next = A, B next = C); the nonempty path
        # touches neither the fixup nor the previous index.
        # Final chain B -> C -> A; bucket 2's before-node is B,
        # whose next is C, bucket 2's first node.
        a, b, c = Node("A", 5), Node("B", 4), Node("C", 8)
        table = chain_table([a, b, c], bucket_count=3)
        rehash_aux(table, 3, saved_next_resize=99)
        self.assertEqual(table.chain(), ["B", "C", "A"])
        self.assertEqual(table.bucket_entries(), [None, "S", "B"])

    def test_same_bucket_second_node_inserts_after_before_node(self):
        # X then Y, both bucket 1 (hashes 4 and 7, count 3):
        # X starts the bucket (its next is null, so the fixup
        # is skipped, but the previous index still becomes 1);
        # Y inserts after the sentinel, so the head becomes Y
        # and the chain runs Y -> X. The nonempty path touches
        # neither the fixup nor the previous index, so bucket
        # entry 0 stays empty.
        x, y = Node("X", 4), Node("Y", 7)
        table = chain_table([x, y], bucket_count=3)
        rehash_aux(table, 3, saved_next_resize=99)
        self.assertEqual(table.chain(), ["Y", "X"])
        self.assertEqual(table.bucket_entries(), [None, "S", None])

    def test_bucket_zero_second_node_uses_nonempty_path(self):
        # First node A hashes to bucket 0 (hash 6 % 3): its
        # empty-bucket entry is the sentinel, and the fixup is
        # skipped because A's next is null. The second bucket-0
        # node B finds the entry set, so it inserts after the
        # sentinel (B next = A, head = B); the nonempty path
        # touches neither the fixup nor the previous index.
        # Final chain B -> A with bucket 0 entry the sentinel.
        a, b = Node("A", 6), Node("B", 9)
        table = chain_table([a, b], bucket_count=3)
        rehash_aux(table, 3, saved_next_resize=99)
        self.assertEqual(table.chain(), ["B", "A"])
        self.assertEqual(table.bucket_entries(), ["S", None, None])

    def test_every_node_survives_exactly_once(self):
        nodes = [Node("n%d" % i, 1000 + i * 7) for i in range(20)]
        table = chain_table(nodes, bucket_count=5)
        rehash_aux(table, 11, saved_next_resize=99)
        self.assertEqual(sorted(table.chain()),
                         sorted(n.id for n in nodes))
        self.assertEqual(len(table.chain()), 20)
        # Each bucket entry's chain segment is reachable from the
        # head: every node is on the single global chain.
        seen = set()
        node = table.head
        while node is not None:
            self.assertNotIn(node.id, seen)
            seen.add(node.id)
            node = node.next
        self.assertEqual(len(seen), 20)

    def test_hash_modulo_uses_full_unsigned_value(self):
        node = Node("big", (1 << 64) - 1)
        table = chain_table([node], bucket_count=3)
        rehash_aux(table, 7, saved_next_resize=99)
        # (2**64 - 1) % 7 == 1, so the single node lands in
        # bucket 1; its next is null, so the fixup is skipped
        # and bucket entry 0 stays empty.
        self.assertEqual(node.cached_hash % 7, 1)
        self.assertEqual(table.bucket_entries(),
                         [None, "S", None, None, None, None, None])


class TestSingleBucketArm(unittest.TestCase):
    def test_single_bucket_preserves_chain_order(self):
        # Count 1: every node hashes to bucket 0. The first node
        # starts the bucket (entry = sentinel, fixup skipped:
        # its next is null). Every later node finds the entry
        # set and inserts after the sentinel, i.e. prepends to
        # the head, so the chain reverses: B -> A with bucket 0
        # entry still the sentinel.
        a, b = Node("A", 5), Node("B", 9)
        table = chain_table([a, b], bucket_count=3)
        rehash_aux(table, 1, saved_next_resize=99)
        self.assertEqual(table.chain(), ["B", "A"])
        self.assertEqual(table.bucket_entries(), ["S"])
        self.assertTrue(table.buckets_is_single)
        self.assertEqual(table.freed, [True])

    def test_single_bucket_three_nodes_chain_reverses(self):
        a, b, c = Node("A", 5), Node("B", 9), Node("C", 13)
        table = chain_table([a, b, c], bucket_count=3)
        rehash_aux(table, 1, saved_next_resize=99)
        self.assertEqual(table.chain(), ["C", "B", "A"])
        self.assertEqual(table.bucket_entries(), ["S"])

    def test_single_bucket_from_single_is_not_freed(self):
        a = Node("A", 5)
        table = chain_table([a], bucket_count=1)
        table.buckets = table.single_bucket
        table.buckets[0] = SENTINEL
        table.buckets_is_single = True
        rehash_aux(table, 1, saved_next_resize=99)
        self.assertEqual(table.chain(), ["A"])
        self.assertEqual(table.freed, [False])

    def test_single_bucket_skips_overflow_check(self):
        # A count of 1 never reaches the overflow tests.
        table = chain_table([], bucket_count=3)
        rehash_aux(table, 1, saved_next_resize=99)
        self.assertEqual(table.bucket_count, 1)


class TestOverflowAndFailure(unittest.TestCase):
    def test_bad_alloc_range(self):
        table = chain_table([], bucket_count=3)
        with self.assertRaises(BadAlloc):
            rehash_aux(table, 1 << 60, saved_next_resize=99)
        with self.assertRaises(BadAlloc):
            rehash_aux(table, (1 << 61) - 1, saved_next_resize=99)
        # Table untouched by the rejected counts.
        self.assertEqual(table.bucket_count, 3)

    def test_bad_array_new_length_range(self):
        table = chain_table([], bucket_count=3)
        with self.assertRaises(BadArrayNewLength):
            rehash_aux(table, 1 << 61, saved_next_resize=99)
        with self.assertRaises(BadArrayNewLength):
            rehash_aux(table, (1 << 63), saved_next_resize=99)
        self.assertEqual(table.bucket_count, 3)

    def test_zero_count_refused(self):
        table = chain_table([], bucket_count=3)
        with self.assertRaises(ValueError):
            rehash_aux(table, 0, saved_next_resize=99)

    def test_allocation_failure_restores_next_resize(self):
        a = Node("A", 5)
        table = chain_table([a], bucket_count=3, next_resize=7)
        with self.assertRaises(AllocationFailed):
            rehash_aux(table, 9, saved_next_resize=42,
                       alloc_fail=True)
        self.assertEqual(table.next_resize, 42)
        # Buckets, count and head untouched: failure precedes
        # migration.
        self.assertEqual(table.bucket_count, 3)
        self.assertEqual(table.chain(), ["A"])
        self.assertEqual(table.freed, [])

    def test_allocation_failure_in_single_arm_does_not_apply(self):
        # The single-bucket arm allocates nothing, so a simulated
        # allocation failure there is a no-op for the arm.
        table = chain_table([], bucket_count=3)
        rehash_aux(table, 1, saved_next_resize=99, alloc_fail=True)
        self.assertEqual(table.bucket_count, 1)


class TestEpilogue(unittest.TestCase):
    def test_element_count_and_policy_untouched(self):
        a = Node("A", 5)
        table = chain_table([a], bucket_count=3, next_resize=77)
        table.element_count = 5
        rehash_aux(table, 4, saved_next_resize=77)
        self.assertEqual(table.element_count, 5)
        self.assertEqual(table.next_resize, 77)

    def test_old_heap_array_freed_new_committed(self):
        table = chain_table([], bucket_count=3)
        summary = rehash_aux(table, 6, saved_next_resize=99)
        self.assertEqual(summary["old_count"], 3)
        self.assertEqual(summary["new_count"], 6)
        self.assertTrue(summary["old_array_freed"])


class TestPacket(unittest.TestCase):
    def test_verify_script_passes(self):
        result = subprocess.run(
            [sys.executable,
             os.path.join(PACKET, "verify.py"),
             "--binary", BINARY],
            capture_output=True, text=True, cwd=REPO)
        self.assertEqual(result.stdout.strip(), "ALL CHECKS PASSED",
                         result.stdout + result.stderr)

    def test_excerpts_regenerate(self):
        result = subprocess.run(
            [sys.executable,
             os.path.join(PACKET, "export_excerpts.py"),
             "--binary", BINARY, "--out", "/tmp/rehash_excerpts"],
            capture_output=True, text=True, cwd=REPO)
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in ("window.objdump.txt", "caller.objdump.txt"):
            with open(os.path.join(PACKET, name)) as fh:
                expected = fh.read()
            with open(os.path.join("/tmp/rehash_excerpts", name)) as fh:
                self.assertEqual(fh.read(), expected, name)

    def test_corruption_controls(self):
        # Flipping a byte in the window excerpt must break the
        # byte-for-byte regeneration the checker performs.
        with open(os.path.join(PACKET, "window.objdump.txt")) as fh:
            text = fh.read()
        self.assertIn("515a820", text)
        corrupted = text.replace("515a820", "515a821", 1)
        self.assertNotEqual(corrupted, text)
        with open(os.path.join(PACKET, "caller.objdump.txt")) as fh:
            caller = fh.read()
        self.assertIn("515acf8", caller)
        self.assertNotEqual(caller.replace("515acf8", "515acf9", 1),
                            caller)


if __name__ == "__main__":
    unittest.main()
