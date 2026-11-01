#!/usr/bin/env python3
"""Tests for node #94's 0x68-byte tree-node teardown 0x514cd00 (RE-001).

Covers the destroy_list order (children before parents, siblings in
+0x10 order), the per-node disposal order (string 2, string 1, node),
the heap/SSO string rules (capacity + 1, or nothing), a chain deeper
than the six-link unrolling in the bytes, the 0x514d010 wrapper
equivalence, and the evidence packet: its verify script, excerpt
regeneration, and corruption controls.
"""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from foundation_tree_teardown_68 import (  # noqa: E402
    NODE_SIZE,
    destroy_container_list,
    destroy_tree,
    make_node,
)

REPO = Path(__file__).resolve().parents[1]
PACKET = REPO / "research" / "work-items" / "RE-001-tree-teardown-68-94"
BINARY = REPO / "work" / "hl-node-94.bin"


def str2_sizes(events):
    """The string-2 freed sizes in disposal order (None for SSO)."""
    return [size for kind, size in events if kind == "string2"]


class NullAndSingleTests(unittest.TestCase):
    def test_null_head_frees_nothing(self):
        self.assertEqual(destroy_tree(None), [])

    def test_single_sso_node(self):
        node = make_node()
        self.assertEqual(
            destroy_tree(node),
            [("string2", None), ("string1", None), ("node", NODE_SIZE)])
        self.assertEqual(NODE_SIZE, 0x68)

    def test_single_heap_node_sizes(self):
        node = make_node(str1_heap=True, str1_capacity=5,
                         str2_heap=True, str2_capacity=10)
        self.assertEqual(
            destroy_tree(node),
            [("string2", 11), ("string1", 6), ("node", 0x68)])

    def test_mixed_heap_and_sso_strings(self):
        node = make_node(str1_heap=False, str2_heap=True, str2_capacity=0)
        self.assertEqual(
            destroy_tree(node),
            [("string2", 1), ("string1", None), ("node", 0x68)])


class OrderTests(unittest.TestCase):
    def test_child_before_parent(self):
        child = make_node(str2_heap=True, str2_capacity=100)
        parent = make_node(child=child, str2_heap=True, str2_capacity=200)
        self.assertEqual(str2_sizes(destroy_tree(parent)), [101, 201])

    def test_siblings_in_order(self):
        first = make_node(str2_heap=True, str2_capacity=10)
        second = make_node(str2_heap=True, str2_capacity=20)
        first["sibling"] = second
        self.assertEqual(str2_sizes(destroy_tree(first)), [11, 21])

    def test_mixed_child_plus_sibling_tree(self):
        # H: child C, sibling S; C: sibling D. Binary order: C, D, H, S.
        c = make_node(str2_heap=True, str2_capacity=30)
        d = make_node(str2_heap=True, str2_capacity=40)
        c["sibling"] = d
        s = make_node(str2_heap=True, str2_capacity=60)
        h = make_node(child=c, sibling=s, str2_heap=True, str2_capacity=50)
        self.assertEqual(str2_sizes(destroy_tree(h)), [31, 41, 51, 61])

    def test_deep_chain_beyond_unrolling(self):
        # Ten levels through +0x18 links: deepest first.
        head = None
        for i in range(10):
            head = make_node(child=head, str2_heap=True, str2_capacity=i)
        # head is level 0 (capacity 9); deepest is capacity 0.
        self.assertEqual(str2_sizes(destroy_tree(head)),
                         [1, 2, 3, 4, 5, 6, 7, 8, 9, 10])

    def test_wrapper_equivalence(self):
        c = make_node(str2_heap=True, str2_capacity=30)
        s = make_node(str2_heap=True, str2_capacity=60)
        h = make_node(child=c, sibling=s, str2_heap=True, str2_capacity=50)
        self.assertEqual(destroy_container_list(h), destroy_tree(h))

    def test_node_count_matches_nodes(self):
        nodes = [make_node(str2_heap=True, str2_capacity=i) for i in range(4)]
        for prev, nxt in zip(nodes, nodes[1:]):
            prev["sibling"] = nxt
        events = destroy_tree(nodes[0])
        self.assertEqual(sum(1 for kind, _ in events if kind == "node"), 4)
        self.assertEqual(len(events), 12)


class PacketTests(unittest.TestCase):
    def test_verify_script_passes(self):
        result = subprocess.run(
            [sys.executable, str(PACKET / "verify.py"), "--binary", str(BINARY)],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ALL CHECKS PASSED", result.stdout)

    def test_records_callers(self):
        records = json.loads((PACKET / "records.json").read_text())
        sites = {caller["site"] for caller in records["callers"]}
        self.assertEqual(sites, {"0x514d027", "0x5150b34"})
        self.assertEqual(records["node_layout"]["total_size"], "0x68")

    def test_excerpt_regeneration(self):
        with tempfile.TemporaryDirectory() as tmp:
            outdir = Path(tmp)
            result = subprocess.run(
                [sys.executable, str(PACKET / "export_excerpts.py"),
                 "--out", str(outdir)],
                capture_output=True, text=True, cwd=str(REPO))
            self.assertEqual(result.returncode, 0, result.stderr)
            for name in ("window.objdump.txt", "wrapper.objdump.txt",
                         "cleanup.objdump.txt", "plt.objdump.txt"):
                self.assertEqual((outdir / name).read_text(),
                                 (PACKET / name).read_text(), name)

    def test_corruption_controls(self):
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "packet"
            shutil.copytree(PACKET, copy)
            # Tampered function SHA must fail verification.
            records = json.loads((copy / "records.json").read_text())
            records["functions"][0]["sha256"] = "0" * 64
            (copy / "records.json").write_text(json.dumps(records))
            result = subprocess.run(
                [sys.executable, str(copy / "verify.py"),
                 "--binary", str(BINARY)], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            # Tampered excerpt must fail verification.
            shutil.copytree(PACKET, copy, dirs_exist_ok=True)
            window = (copy / "window.objdump.txt").read_text()
            (copy / "window.objdump.txt").write_text(window + "tampered\n")
            result = subprocess.run(
                [sys.executable, str(copy / "verify.py"),
                 "--binary", str(BINARY)], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
