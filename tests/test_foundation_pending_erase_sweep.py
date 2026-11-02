"""Tests for the node #94 pending-key erase sweep model.

Run from the repository root with unittest (no pytest on this VM):

    python3 -m unittest tests.test_foundation_pending_erase_sweep -v
"""

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from foundation_pending_erase_sweep import (
    SENTINEL,
    HashNode,
    SweepTable,
    caller_min,
    sweep,
)

REPO = Path(__file__).resolve().parents[1]
PACKET = REPO / "research" / "work-items" / "RE-001-pending-erase-sweep-94"
BINARY = REPO / "work" / "hl-node-94.bin"


def chain(*specs):
    """Build a chain from (key, value) pairs, head first."""
    head = None
    for key, value in reversed(specs):
        head = HashNode(key, value, head)
    return head


def nodes_of(table):
    out = []
    cur = table.before_begin_next
    while cur is not None:
        out.append((cur.key, cur.value))
        cur = cur.next
    return out


class TestSweep(unittest.TestCase):
    def test_empty_vector_returns_zero(self):
        table = SweepTable([], None, 0)
        pending = []
        self.assertEqual(sweep(pending, table), 0)
        self.assertEqual(pending, [])

    def test_chain_path_single_erase(self):
        # Count 0 selects the chain lookup, but removal still
        # divides by the bucket count, so the fixture carries a
        # consistent bucket array (bucket 3 holds SENTINEL, the
        # node being the chain head).
        node = chain((10, 5))
        buckets = [None] * 7
        buckets[3] = SENTINEL
        table = SweepTable(buckets, node, 0)
        pending = [(10, 5)]
        self.assertEqual(sweep(pending, table), 0)
        self.assertEqual(pending, [])
        self.assertIsNone(table.before_begin_next)
        self.assertIsNone(table.buckets[3])
        # The delete path decrements +0x58 unconditionally, so a
        # chain-path erase drives the count from 0 to -1.
        self.assertEqual(table.count, -1)

    def test_chain_path_empty_bails_with_key(self):
        table = SweepTable([], None, 0)
        pending = [(10, 5)]
        self.assertEqual(sweep(pending, table), 10)
        self.assertEqual(pending, [(10, 5)])

    def test_chain_then_bucket_crossover(self):
        # Chain A(10) -> B(20), bucket_count 7. A is the chain
        # head, so bucket 3 (10 % 7) holds SENTINEL; B's bucket
        # is 6 (20 % 7). The chain-path erase of A repoints
        # bucket 6 to SENTINEL and clears bucket 3; the second
        # element then takes the bucket path (count is -1).
        head = chain((10, 5), (20, 5))
        buckets = [None] * 7
        buckets[3] = SENTINEL
        table = SweepTable(buckets, head, 0)
        pending = [(10, 5), (20, 5)]
        self.assertEqual(sweep(pending, table), 0)
        self.assertEqual(pending, [])
        self.assertIsNone(table.before_begin_next)
        self.assertIsNone(table.buckets[3])
        self.assertIsNone(table.buckets[6])
        self.assertEqual(table.count, -2)

    def test_bucket_first_in_bucket_same_bucket(self):
        head = chain((10, 5), (17, 5))
        buckets = [None] * 7
        buckets[3] = SENTINEL
        table = SweepTable(buckets, head, 2)
        pending = [(10, 5)]
        self.assertEqual(sweep(pending, table), 0)
        self.assertEqual(nodes_of(table), [(17, 5)])
        self.assertIs(table.buckets[3], SENTINEL)
        self.assertEqual(table.count, 1)

    def test_bucket_first_in_bucket_different_bucket_sentinel(self):
        head = chain((10, 5), (20, 5))
        buckets = [None] * 7
        buckets[3] = SENTINEL
        table = SweepTable(buckets, head, 2)
        pending = [(10, 0)]
        self.assertEqual(sweep(pending, table), 0)
        self.assertEqual(nodes_of(table), [(20, 5)])
        self.assertIsNone(table.buckets[3])
        self.assertIs(table.buckets[6], SENTINEL)
        self.assertIs(table.before_begin_next, head.next)
        self.assertEqual(table.count, 1)

    def test_bucket_nonfirst_different_bucket_repoint(self):
        head = chain((10, 5), (17, 5), (20, 5))
        a, b, c = head, head.next, head.next.next
        buckets = [None] * 7
        buckets[3] = SENTINEL
        buckets[6] = b
        table = SweepTable(buckets, head, 3)
        pending = [(17, 0)]
        self.assertEqual(sweep(pending, table), 0)
        self.assertEqual(nodes_of(table), [(10, 5), (20, 5)])
        self.assertIs(table.buckets[6], a)
        self.assertIs(a.next, c)
        self.assertEqual(table.count, 2)

    def test_guard_bails_and_keeps_node(self):
        node = chain((10, 3))
        buckets = [None] * 7
        buckets[3] = SENTINEL
        table = SweepTable(buckets, node, 1)
        pending = [(10, 5)]
        self.assertEqual(sweep(pending, table), 10)
        self.assertEqual(pending, [(10, 5)])
        self.assertEqual(nodes_of(table), [(10, 3)])
        self.assertEqual(table.count, 1)

    def test_guard_boundary_equal_value_erases(self):
        node = chain((10, 5))
        buckets = [None] * 7
        buckets[3] = SENTINEL
        table = SweepTable(buckets, node, 1)
        pending = [(10, 5)]
        self.assertEqual(sweep(pending, table), 0)
        self.assertEqual(pending, [])

    def test_not_found_bails_after_partial_progress(self):
        node = chain((10, 5))
        buckets = [None] * 7
        buckets[3] = SENTINEL
        table = SweepTable(buckets, node, 1)
        pending = [(10, 0), (99, 0)]
        self.assertEqual(sweep(pending, table), 99)
        self.assertEqual(pending, [(99, 0)])
        self.assertEqual(table.count, 0)

    def test_duplicate_key_second_bails(self):
        node = chain((10, 5))
        buckets = [None] * 7
        buckets[3] = SENTINEL
        table = SweepTable(buckets, node, 1)
        pending = [(10, 0), (10, 0)]
        self.assertEqual(sweep(pending, table), 10)
        self.assertEqual(pending, [(10, 0)])

    def test_caller_min_combination(self):
        self.assertEqual(caller_min(50, 0, 0), 50)
        self.assertEqual(caller_min(50, 30, 0), 30)
        self.assertEqual(caller_min(50, 0, 20), 20)
        self.assertEqual(caller_min(50, 30, 20), 20)
        self.assertEqual(caller_min(50, 60, 40), 40)


class TestPacket(unittest.TestCase):
    def test_verify_passes(self):
        # objdump embeds the binary path in its header, so the
        # canonical spelling is the repo-relative path from the
        # repository root, as in the packet README.
        result = subprocess.run(
            [sys.executable, str(PACKET / "verify.py"),
             "--binary", "work/hl-node-94.bin"],
            capture_output=True, text=True, cwd=str(REPO))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ALL CHECKS PASSED", result.stdout)

    def test_excerpts_regenerate(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [sys.executable, str(PACKET / "export_excerpts.py"),
                 "--binary", "work/hl-node-94.bin", "--out", tmp],
                capture_output=True, text=True, cwd=str(REPO))
            self.assertEqual(result.returncode, 0, result.stderr)
            for name in ("window.objdump.txt", "cleanup.objdump.txt",
                         "caller-twin.objdump.txt", "caller-site3.objdump.txt"):
                self.assertEqual(
                    (PACKET / name).read_bytes(),
                    (Path(tmp) / name).read_bytes(), name)

    def test_records_match_model(self):
        records = json.loads((PACKET / "records.json").read_text())
        self.assertEqual(records["task_id"], "RE-001")
        self.assertEqual(records["window"]["start"], "0x5160560")
        self.assertEqual(records["window"]["end"], "0x5160783")
        self.assertEqual(records["window"]["size_bytes"], 547)
        self.assertEqual(len(records["callers"]), 3)
        self.assertEqual(
            [c["site"] for c in records["callers"]],
            ["0x50abaf2", "0x50b0722", "0x50ec61e"])

    def test_records_semantic_only(self):
        text = (PACKET / "records.json").read_text()
        self.assertNotIn("mnemonic", text)
        self.assertNotIn("instructions", text)

    def test_sampled_instructions_byte_for_byte(self):
        fresh = subprocess.run(
            ["objdump", "-d", "--start-address=0x5160560",
             "--stop-address=0x5160783", str(BINARY)],
            capture_output=True, text=True, cwd=str(REPO)).stdout
        excerpt = (PACKET / "window.objdump.txt").read_text()
        for addr in ("5160560", "516057c", "5160649"):
            fresh_line = [l for l in fresh.splitlines()
                          if l.strip().startswith(addr + ":")]
            excerpt_line = [l for l in excerpt.splitlines()
                            if l.strip().startswith(addr + ":")]
            self.assertEqual(len(fresh_line), 1, addr)
            self.assertEqual(fresh_line, excerpt_line, addr)

    def test_corruption_control_tampered_excerpt(self):
        stored = (PACKET / "window.objdump.txt").read_bytes()
        tampered = stored.replace(b"endbr64", b"endbr65", 1)
        self.assertNotEqual(stored, tampered)
        fresh = subprocess.run(
            ["objdump", "-d", "--start-address=0x5160560",
             "--stop-address=0x5160783", "work/hl-node-94.bin"],
            capture_output=True, text=True, cwd=str(REPO)).stdout.encode()
        self.assertEqual(fresh, stored)
        self.assertNotEqual(fresh, tampered)

    def test_corruption_control_manifest(self):
        manifest = {}
        for line in (PACKET / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split(None, 1)
            manifest[name.lstrip("*")] = digest
        actual = hashlib.sha256(
            (PACKET / "records.json").read_bytes()).hexdigest()
        self.assertEqual(manifest["records.json"], actual)
        tampered = hashlib.sha256(
            (PACKET / "records.json").read_bytes() + b" ").hexdigest()
        self.assertNotEqual(manifest["records.json"], tampered)


if __name__ == "__main__":
    unittest.main()
