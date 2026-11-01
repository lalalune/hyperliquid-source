#!/usr/bin/env python3
"""Tests for RE-001 recursive chain teardown (function 0x514bf60, node #94).

Run from the repository root:

    python3 tests/test_foundation_recursive_teardown.py

The binary path defaults to the canonical captured artifact; pass
``--binary`` to point at another copy of node #94, or set
``HL_NODE94_BIN``.  All expectations are read from the bytes: a
null input logs nothing; each node disposes its +0x40 string, then
its +0x20 string, then itself with size 0x60; a heap string deletes
with size capacity + 1 (mod 2**64) while an inline string deletes
nothing; a node's child subtree is torn down before the node
itself; and the next sibling is saved before disposal, so siblings
follow in chain order.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tools.foundation_recursive_teardown import (  # noqa: E402
    NODE_SIZE, Node, StringField, check_packet, teardown)

PACKET_DIR = os.path.join(
    os.path.dirname(__file__), "..", "research", "work-items",
    "RE-001-recursive-teardown-94")
DEFAULT_BINARY = os.path.join("artifacts", "node", "94", "hl-node")
BINARY = os.environ.get("HL_NODE94_BIN", DEFAULT_BINARY)


def heap(pointer, capacity):
    return StringField(pointer, heap=True, capacity=capacity)


def inline(pointer):
    return StringField(pointer, heap=False, capacity=0)


class TeardownTests(unittest.TestCase):
    def test_null_input_logs_nothing(self):
        self.assertEqual(teardown(None), [])

    def test_single_inline_node_deletes_only_itself(self):
        node = Node("a", string1=inline("p1"), string2=inline("p2"))
        self.assertEqual(teardown(node), [("node", "a", 0x60)])

    def test_single_heap_node_disposal_order_and_sizes(self):
        node = Node("a", string1=heap("s1", 10), string2=heap("s2", 4))
        # Bytes dispose the +0x40 string before the +0x20 string.
        self.assertEqual(teardown(node), [
            ("string", "s2", 5),
            ("string", "s1", 11),
            ("node", "a", 0x60),
        ])

    def test_mixed_strings_skip_inline_only(self):
        node = Node("a", string1=inline("p1"), string2=heap("s2", 0))
        self.assertEqual(teardown(node), [
            ("string", "s2", 1),
            ("node", "a", 0x60),
        ])

    def test_sibling_chain_follows_saved_next_order(self):
        c = Node("c")
        b = Node("b", next_sibling=c)
        a = Node("a", next_sibling=b)
        self.assertEqual(teardown(a), [
            ("node", "a", 0x60),
            ("node", "b", 0x60),
            ("node", "c", 0x60),
        ])

    def test_child_subtree_before_own_disposal(self):
        child = Node("kid", string2=heap("ks", 7))
        node = Node("a", child=child, string1=heap("s1", 1))
        self.assertEqual(teardown(node), [
            ("string", "ks", 8),
            ("node", "kid", 0x60),
            ("string", "s1", 2),
            ("node", "a", 0x60),
        ])

    def test_nested_child_and_sibling_combo(self):
        # Sibling b carries a child; a's own disposal must not disturb
        # the walk: order is a, then b's child subtree, then b.
        kid = Node("kid")
        b = Node("b", child=kid)
        a = Node("a", next_sibling=b)
        self.assertEqual(teardown(a), [
            ("node", "a", 0x60),
            ("node", "kid", 0x60),
            ("node", "b", 0x60),
        ])

    def test_capacity_plus_one_wraps_at_64_bits(self):
        node = Node("a", string2=heap("s2", (1 << 64) - 1))
        self.assertEqual(teardown(node), [
            ("string", "s2", 0),
            ("node", "a", 0x60),
        ])

    def test_node_size_is_0x60(self):
        self.assertEqual(NODE_SIZE, 0x60)


class PacketTests(unittest.TestCase):
    def test_packet_checks_pass(self):
        self.assertEqual(check_packet(PACKET_DIR, BINARY), [])

    def test_packet_verify_script_passes(self):
        result = subprocess.run(
            [sys.executable,
             os.path.join(PACKET_DIR, "verify.py"),
             "--binary", BINARY],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ALL CHECKS PASSED", result.stdout)

    def test_corruption_of_records_is_caught(self):
        with tempfile.TemporaryDirectory() as tmp:
            copy = os.path.join(tmp, "packet")
            shutil.copytree(PACKET_DIR, copy)
            path = os.path.join(copy, "records.json")
            with open(path) as f:
                rec = json.load(f)
            rec["function"]["sha256"] = "0" * 64
            with open(path, "w") as f:
                json.dump(rec, f)
            self.assertNotEqual(check_packet(copy, BINARY), [])

    def test_corruption_of_excerpt_is_caught(self):
        with tempfile.TemporaryDirectory() as tmp:
            copy = os.path.join(tmp, "packet")
            shutil.copytree(PACKET_DIR, copy)
            path = os.path.join(copy, "window.objdump.txt")
            with open(path) as f:
                text = f.read()
            # Flip one byte of the first instruction's encoding.
            text = text.replace("48 85 ff", "48 85 fe", 1)
            with open(path, "w") as f:
                f.write(text)
            self.assertNotEqual(check_packet(copy, BINARY), [])

    def test_excerpt_regeneration_is_byte_identical(self):
        with tempfile.TemporaryDirectory() as tmp:
            copy = os.path.join(tmp, "packet")
            shutil.copytree(PACKET_DIR, copy)
            originals = {}
            for name in ("window.objdump.txt", "plt.objdump.txt",
                         "callers.objdump.txt"):
                with open(os.path.join(copy, name), "rb") as f:
                    originals[name] = f.read()
            result = subprocess.run(
                [sys.executable,
                 os.path.join(copy, "export_excerpts.py"),
                 "--binary", BINARY],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 0,
                             result.stdout + result.stderr)
            for name, blob in originals.items():
                with open(os.path.join(copy, name), "rb") as f:
                    self.assertEqual(f.read(), blob, name)

    def test_sampled_instructions_match_fresh_objdump(self):
        # Pre-submit self-check, as a test: three instructions sampled
        # from the raw excerpt must match a fresh objdump run
        # byte-for-byte (address, encoding bytes, and target).
        result = subprocess.run(
            ["objdump", "-d", "--start-address=0x514bf60",
             "--stop-address=0x514bfe0", BINARY],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        fresh = {}
        for line in result.stdout.splitlines():
            parts = line.split(":", 1)
            if len(parts) == 2 and parts[0].strip():
                try:
                    fresh[int(parts[0].strip(), 16)] = line
                except ValueError:
                    pass
        with open(os.path.join(PACKET_DIR, "window.objdump.txt")) as f:
            excerpt = {}
            for line in f.read().splitlines():
                parts = line.split(":", 1)
                if len(parts) == 2 and parts[0].strip():
                    try:
                        excerpt[int(parts[0].strip(), 16)] = line
                    except ValueError:
                        pass
        for va in (0x514BF60, 0x514BF77, 0x514BFBC):
            self.assertIn(va, fresh)
            self.assertIn(va, excerpt)
            # Same address, same encoding bytes, same mnemonic/target.
            self.assertEqual(
                excerpt[va].split("\t")[1].strip(),
                fresh[va].split("\t")[1].strip())
            self.assertEqual(
                excerpt[va].split("\t")[2].strip(),
                fresh[va].split("\t")[2].strip())


def main(argv=None):
    global BINARY
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default=BINARY)
    args = ap.parse_args(argv)
    BINARY = args.binary
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
