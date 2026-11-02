"""Tests for tools/foundation_range_ctor.py (node #94 0x515a960).

The expectations are transcribed from the window's disassembly
(see research/work-items/RE-001-range-ctor-94/): the table and node
layouts, the single-bucket and overflow arms, the linear scan with
its empty-key arm, the hash path with its bucket-segment walk, the
empty/nonempty bucket insertion rules, and the need-rehash/rehash
call contract. The tests pin the model, not an execution of the
target binary (no execution is available here). Library callees
are injected stubs; the rehash stub below rebuilds bucket entries
by chain order for test purposes only and is not a claim about the
rehash auxiliary's own rule (see PR #1751 for that packet).
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.foundation_range_ctor import (
    HASH_SEED,
    LINEAR_LIMIT,
    BadAlloc,
    BadArrayNewLength,
    Element,
    Node,
    Table,
    _bucket_walk,
    _insert,
    range_ctor,
)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(
    REPO, "research", "work-items", "RE-001-range-ctor-94")
# Relative path, run from the repo root: objdump embeds the path
# spelling in each excerpt header, so absolute and relative runs
# would not regenerate byte-for-byte.
BINARY = os.path.join("work", "hl-node-94.bin")

PAYLOAD = bytes(range(0x48))


def hash_map(mapping):
    def hash_bytes(key, seed):
        assert seed == HASH_SEED
        return mapping[bytes(key)]
    return hash_bytes


def sum_hash(key, seed):
    assert seed == HASH_SEED
    return sum(key)


def need_no_rehash(bucket_count, element_count, n_ins):
    assert n_ins == 1
    return (False, 0)


def rehash_stub(table, new_count, saved_next_resize):
    """Test-only rebuild: bucket entries by first chain occurrence."""
    rehash_stub.calls.append((new_count, saved_next_resize))
    table.bucket_count = new_count
    table.buckets = {}
    prev = table.sentinel
    node = table.head
    while node is not None:
        bucket = node.cached_hash % new_count
        if bucket not in table.buckets:
            table.buckets[bucket] = prev
        prev = node
        node = node.next


rehash_stub.calls = []


def chain_table(nodes, bucket_count, entries):
    """Build a table with the given chain and bucket entries.

    ``entries`` maps a bucket index to a before-node: the table's
    sentinel or one of ``nodes``. The sentinel's next pointer is
    the chain head.
    """
    table = Table()
    table.bucket_count = bucket_count
    head = None
    for node in reversed(nodes):
        node.next = head
        head = node
    table.set_head(head)
    table.element_count = len(nodes)
    for bucket, before in entries.items():
        table.buckets[bucket] = before
    return table


class TestInit(unittest.TestCase):
    def test_skip_alloc_when_count_covers_hint(self):
        seen = []
        table = range_ctor([], 0, lambda hint: (seen.append(hint), 1)[1],
                           sum_hash, need_no_rehash)
        self.assertEqual(seen, [0])
        self.assertEqual(table.bucket_count, 1)
        self.assertEqual(table.buckets, {})
        self.assertEqual(table.element_count, 0)

    def test_alloc_for_larger_hint(self):
        table = range_ctor([], 5, lambda hint: 7,
                           sum_hash, need_no_rehash)
        self.assertEqual(table.bucket_count, 7)

    def test_overflow_bad_alloc(self):
        for count in (1 << 60, (1 << 61) - 1):
            with self.assertRaises(BadAlloc):
                range_ctor([], 0, lambda hint, c=count: c,
                           sum_hash, need_no_rehash)

    def test_overflow_bad_array_new_length(self):
        for count in (1 << 61, 1 << 62):
            with self.assertRaises(BadArrayNewLength):
                range_ctor([], 0, lambda hint, c=count: c,
                           sum_hash, need_no_rehash)

    def test_alloc_boundary_below_limit(self):
        table = range_ctor([], 0, lambda hint: (1 << 60) - 1,
                           sum_hash, need_no_rehash)
        self.assertEqual(table.bucket_count, (1 << 60) - 1)


class TestLinearScan(unittest.TestCase):
    def test_duplicate_nonempty_key_skipped(self):
        mapping = {b"a": 0, b"b": 1}
        table = range_ctor(
            [Element(b"a", PAYLOAD), Element(b"b", PAYLOAD),
             Element(b"a", PAYLOAD)],
            0, lambda hint: 7, hash_map(mapping), need_no_rehash)
        self.assertEqual(table.element_count, 2)
        self.assertEqual(table.chain_keys(), [b"b", b"a"])

    def test_duplicate_empty_key_skipped(self):
        mapping = {b"": 0, b"x": 1}
        table = range_ctor(
            [Element(b"", PAYLOAD), Element(b"x", PAYLOAD),
             Element(b"", PAYLOAD)],
            0, lambda hint: 7, hash_map(mapping), need_no_rehash)
        self.assertEqual(table.element_count, 2)
        self.assertEqual(table.chain_keys(), [b"x", b""])

    def test_empty_key_does_not_match_nonempty(self):
        # The empty-key arm walks while a node's length is nonzero,
        # so a nonempty node is never an empty-key match.
        mapping = {b"ab": 0, b"": 1}
        table = range_ctor(
            [Element(b"ab", PAYLOAD), Element(b"", PAYLOAD)],
            0, lambda hint: 7, hash_map(mapping), need_no_rehash)
        self.assertEqual(table.element_count, 2)

    def test_direct_insert_below_limit_ignores_bucket(self):
        # Same hash, different keys, count below the limit: the
        # linear scan misses, the hash path inserts directly
        # without a bucket walk, so both keys land.
        mapping = {b"a": 5, b"b": 5}
        table = range_ctor(
            [Element(b"a", PAYLOAD), Element(b"b", PAYLOAD)],
            0, lambda hint: 7, hash_map(mapping), need_no_rehash)
        self.assertEqual(table.element_count, 2)


class TestBucketWalk(unittest.TestCase):
    def _walk_table(self):
        # Chain: k2 (bucket 3) -> k1 (bucket 5); bucket 3's entry
        # is the sentinel, so the walk starts at k2.
        k1 = Node(b"k1", PAYLOAD, 5)
        k2 = Node(b"k2", PAYLOAD, 3)
        table = chain_table([k2, k1], 53, {3: None})
        table.buckets[3] = table.sentinel
        return table, k1, k2

    def test_first_node_match(self):
        table, _, _ = self._walk_table()
        self.assertTrue(_bucket_walk(table, b"k2", 3, 3))

    def test_empty_key_match(self):
        node = Node(b"", PAYLOAD, 3)
        table = chain_table([node], 53, {3: None})
        table.buckets[3] = table.sentinel
        self.assertTrue(_bucket_walk(table, b"", 3, 3))

    def test_key_mismatch_then_segment_end(self):
        # k2's key differs, and the next node k1 hashes to bucket
        # 5, not 3: the segment ended, so the record inserts.
        table, _, _ = self._walk_table()
        self.assertFalse(_bucket_walk(table, b"zz", 3, 3))

    def test_hash_mismatch_then_chain_end(self):
        k1 = Node(b"k1", PAYLOAD, 3)
        k2 = Node(b"k2", PAYLOAD, 3)
        table = chain_table([k2, k1], 53, {3: None})
        table.buckets[3] = table.sentinel
        self.assertFalse(_bucket_walk(table, b"zz", 9, 3))

    def test_empty_bucket_entry(self):
        table = Table()
        table.bucket_count = 53
        self.assertFalse(_bucket_walk(table, b"a", 3, 3))

    def test_later_node_match(self):
        k1 = Node(b"k1", PAYLOAD, 3)
        k2 = Node(b"k2", PAYLOAD, 3)
        table = chain_table([k2, k1], 53, {3: None})
        table.buckets[3] = table.sentinel
        self.assertTrue(_bucket_walk(table, b"k1", 3, 3))


class TestInsert(unittest.TestCase):
    def test_empty_bucket_no_head(self):
        table = Table()
        table.bucket_count = 7
        _insert(table, Element(b"a", PAYLOAD), 0, 0,
                need_no_rehash, None)
        self.assertIs(table.buckets[0], table.sentinel)
        self.assertEqual(table.chain_keys(), [b"a"])
        self.assertEqual(table.element_count, 1)

    def test_empty_bucket_repoints_old_head(self):
        # k1 in bucket 3, then k2 in bucket 5: k1's bucket entry is
        # repointed at k2, and bucket 5's entry is the sentinel.
        mapping = {b"k1": 3, b"k2": 5}
        table = range_ctor(
            [Element(b"k1", PAYLOAD), Element(b"k2", PAYLOAD)],
            0, lambda hint: 7, hash_map(mapping), need_no_rehash)
        self.assertEqual(table.chain_keys(), [b"k2", b"k1"])
        self.assertEqual(table.buckets[3].key, b"k2")
        self.assertIs(table.buckets[5], table.sentinel)

    def test_nonempty_bucket_insert_after_before_node(self):
        # k1 then k2 in the same bucket: k2 links after the
        # sentinel, before k1.
        mapping = {b"k1": 3, b"k2": 3}
        table = range_ctor(
            [Element(b"k1", PAYLOAD), Element(b"k2", PAYLOAD)],
            0, lambda hint: 7, hash_map(mapping), need_no_rehash)
        self.assertEqual(table.chain_keys(), [b"k2", b"k1"])
        self.assertIs(table.buckets[3], table.sentinel)

    def test_key_storage(self):
        short = Element(b"x" * 15, PAYLOAD)
        long = Element(b"x" * 16, PAYLOAD)
        table = range_ctor([short, long], 0, lambda hint: 7,
                           sum_hash, need_no_rehash)
        by_key = {node.key: node for node in
                  [table.head, table.head.next]}
        self.assertEqual(by_key[b"x" * 15].storage, "sso")
        self.assertEqual(by_key[b"x" * 16].storage, "heap")

    def test_payload_copied_verbatim(self):
        payload = bytes([0xAB] * 0x48)
        table = range_ctor([Element(b"a", payload)], 0,
                           lambda hint: 7, sum_hash, need_no_rehash)
        self.assertEqual(table.head.payload, payload)


class TestRehashContract(unittest.TestCase):
    def test_rehash_called_with_saved_slot_and_recomputed_bucket(self):
        rehash_stub.calls = []
        calls = []

        def need(bucket_count, element_count, n_ins):
            calls.append((bucket_count, element_count, n_ins))
            return (True, 11)

        mapping = {b"a": 20}
        table = range_ctor([Element(b"a", PAYLOAD)], 0,
                           lambda hint: 7, hash_map(mapping),
                           need, rehash_stub)
        self.assertEqual(calls, [(7, 0, 1)])
        self.assertEqual(rehash_stub.calls, [(11, 0)])
        self.assertEqual(table.bucket_count, 11)
        self.assertEqual(table.element_count, 1)
        # Bucket 20 % 11 == 9: the node linked into bucket 9.
        self.assertIs(table.buckets[9], table.sentinel)

    def test_no_rehash_call_when_not_needed(self):
        def boom(table, new_count, saved):
            raise AssertionError("rehash must not be called")

        table = range_ctor([Element(b"a", PAYLOAD)], 0,
                           lambda hint: 7, sum_hash,
                           need_no_rehash, boom)
        self.assertEqual(table.element_count, 1)


class TestEndToEnd(unittest.TestCase):
    def test_range_crossing_linear_limit_with_duplicates(self):
        keys = [("k%02d" % i).encode() for i in range(25)]
        mapping = {key: i for i, key in enumerate(keys)}
        elements = [Element(key, PAYLOAD) for key in keys]
        elements.append(Element(keys[3], PAYLOAD))
        elements.append(Element(b"new", PAYLOAD))
        mapping[b"new"] = 99
        table = range_ctor(elements, 0, lambda hint: 53,
                           hash_map(mapping), need_no_rehash)
        # 25 unique + 1 duplicate skipped + 1 new = 26 nodes.
        self.assertEqual(table.element_count, 26)
        self.assertEqual(sorted(table.chain_keys()),
                         sorted(keys + [b"new"]))
        self.assertEqual(table.chain_keys().count(keys[3]), 1)

    def test_empty_range(self):
        table = range_ctor([], 0, lambda hint: 7,
                           sum_hash, need_no_rehash)
        self.assertEqual(table.element_count, 0)
        self.assertEqual(table.chain_keys(), [])


class TestPacket(unittest.TestCase):
    def test_verify_passes(self):
        result = subprocess.run(
            [sys.executable, os.path.join(PACKET, "verify.py"),
             "--binary", BINARY],
            capture_output=True, text=True, cwd=REPO)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ALL CHECKS PASSED", result.stdout)

    def test_excerpt_regeneration(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [sys.executable,
                 os.path.join(PACKET, "export_excerpts.py"),
                 "--binary", BINARY, "--out", tmp],
                capture_output=True, text=True, cwd=REPO)
            self.assertEqual(result.returncode, 0, result.stderr)
            for name in ("window.objdump.txt", "caller.objdump.txt"):
                with open(os.path.join(PACKET, name), "rb") as fh:
                    want = fh.read()
                with open(os.path.join(tmp, name), "rb") as fh:
                    got = fh.read()
                self.assertEqual(got, want, name)

    def test_records_are_semantic_only(self):
        with open(os.path.join(PACKET, "records.json")) as fh:
            records = json.load(fh)

        def walk(value):
            if isinstance(value, dict):
                for key in value:
                    self.assertNotIn(key, ("mnemonics", "instructions",
                                           "operands", "bytes"))
                    walk(value[key])
            elif isinstance(value, list):
                for item in value:
                    walk(item)

        walk(records)
        self.assertEqual(records["window"]["start"], "0x515a960")
        self.assertEqual(records["window"]["end"], "0x515ae14")

    def test_verify_rejects_tampered_excerpt(self):
        with tempfile.TemporaryDirectory() as tmp:
            packet = os.path.join(tmp, "packet")
            shutil.copytree(PACKET, packet)
            with open(os.path.join(packet, "window.objdump.txt"),
                      "ab") as fh:
                fh.write(b"tamper\n")
            result = subprocess.run(
                [sys.executable, os.path.join(packet, "verify.py"),
                 "--binary", BINARY, "--packet-dir", packet],
                capture_output=True, text=True, cwd=REPO)
            self.assertNotEqual(result.returncode, 0)

    def test_verify_rejects_tampered_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            packet = os.path.join(tmp, "packet")
            shutil.copytree(PACKET, packet)
            with open(os.path.join(packet, "MANIFEST.sha256"),
                      "a") as fh:
                fh.write("0" * 64 + "  records.json\n")
            result = subprocess.run(
                [sys.executable, os.path.join(packet, "verify.py"),
                 "--binary", BINARY, "--packet-dir", packet],
                capture_output=True, text=True, cwd=REPO)
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
