#!/usr/bin/env python3
"""Unit tests for the foundation recursive-teardown checker.

Stdlib only. Run from the repository root:

    python3 -m unittest tests.test_foundation_recursive_teardown -v
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join("tools"))
import foundation_recursive_teardown as checker

PACKET_DIR = os.path.join(
    "research", "work-items", "RE-001-recursive-teardown-94")
ARTIFACTS_BINARY = os.path.join("artifacts", "node", "94", "hl-node")
WORK_BINARY = os.path.join("work", "hl-node-94.bin")
TARGET_SHA = checker.TARGET_SHA256


def load_binary():
    for path in (ARTIFACTS_BINARY, WORK_BINARY):
        if not os.path.exists(path):
            continue
        with open(path, "rb") as fh:
            binary = fh.read()
        if hashlib.sha256(binary).hexdigest() == TARGET_SHA:
            return binary, path
    return None, None


class ModelTests(unittest.TestCase):
    def test_null_input_frees_nothing(self):
        self.assertEqual(checker.teardown(None), [])

    def test_single_inline_node_frees_only_the_node(self):
        node = checker.Node("a", str_inline=True)
        self.assertEqual(checker.teardown(node),
                         [("free_node", "a", 0x48)])

    def test_single_heap_node_frees_string_then_node(self):
        node = checker.Node("a", str_inline=False, str_capacity=15)
        self.assertEqual(checker.teardown(node),
                         [("free_string", "a", 16),
                          ("free_node", "a", 0x48)])

    def test_capacity_plus_one_wraps_at_2_to_64(self):
        node = checker.Node("a", str_inline=False,
                            str_capacity=(1 << 64) - 1)
        self.assertEqual(checker.teardown(node),
                         [("free_string", "a", 0),
                          ("free_node", "a", 0x48)])

    def test_chain_frees_in_order_and_survives_each_delete(self):
        b = checker.Node("b", str_inline=False, str_capacity=7)
        a = checker.Node("a", next=b, str_inline=True)
        self.assertEqual(checker.teardown(a),
                         [("free_node", "a", 0x48),
                          ("free_string", "b", 8),
                          ("free_node", "b", 0x48)])

    def test_child_subtree_frees_before_its_parent(self):
        child = checker.Node("c", str_inline=False, str_capacity=3)
        parent = checker.Node("p", child=child, str_inline=True)
        self.assertEqual(checker.teardown(parent),
                         [("free_string", "c", 4),
                          ("free_node", "c", 0x48),
                          ("free_node", "p", 0x48)])

    def test_child_chain_and_parent_chain_interleave_correctly(self):
        d = checker.Node("d", str_inline=True)
        c = checker.Node("c", next=d, str_inline=False, str_capacity=1)
        b = checker.Node("b", str_inline=True)
        a = checker.Node("a", child=c, next=b, str_inline=False,
                         str_capacity=31)
        self.assertEqual(checker.teardown(a),
                         [("free_string", "c", 2),
                          ("free_node", "c", 0x48),
                          ("free_node", "d", 0x48),
                          ("free_string", "a", 32),
                          ("free_node", "a", 0x48),
                          ("free_node", "b", 0x48)])

    def test_node_size_is_0x48_on_every_path(self):
        for node in (checker.Node("x"),
                     checker.Node("y", str_inline=False,
                                  str_capacity=0)):
            sizes = [size for kind, _label, size
                     in checker.teardown(node) if kind == "free_node"]
            self.assertEqual(sizes, [0x48])


class PacketTests(unittest.TestCase):
    def test_packet_verifies_against_the_digest_pinned_binary(self):
        _binary, path = load_binary()
        if path is None:
            self.skipTest("digest-pinned node #94 binary not present")
        self.assertEqual(checker.check_packet(PACKET_DIR, path), [])

    def test_excerpt_regeneration_is_byte_identical(self):
        _binary, path = load_binary()
        if path is None:
            self.skipTest("digest-pinned node #94 binary not present")
        with open(os.path.join(PACKET_DIR, "window.objdump.txt"),
                  "rb") as f:
            original = f.read()
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copytree(PACKET_DIR, os.path.join(tmp, "packet"))
            copied = os.path.join(tmp, "packet")
            result = subprocess.run(
                [sys.executable, os.path.join(copied, "export_excerpts.py"),
                 "--binary", path],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            with open(os.path.join(copied, "window.objdump.txt"),
                      "rb") as f:
                regenerated = f.read()
        self.assertEqual(regenerated, original)

    def test_corrupt_records_sha_fails_verification(self):
        _binary, path = load_binary()
        if path is None:
            self.skipTest("digest-pinned node #94 binary not present")
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copytree(PACKET_DIR, os.path.join(tmp, "packet"))
            copied = os.path.join(tmp, "packet")
            records_path = os.path.join(copied, "records.json")
            with open(records_path) as f:
                rec = json.load(f)
            rec["function"]["sha256"] = "0" * 64
            with open(records_path, "w") as f:
                json.dump(rec, f)
            errors = checker.check_packet(copied, path)
            self.assertTrue(any("SHA mismatch" in e for e in errors))

    def test_corrupt_excerpt_byte_fails_verification(self):
        _binary, path = load_binary()
        if path is None:
            self.skipTest("digest-pinned node #94 binary not present")
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copytree(PACKET_DIR, os.path.join(tmp, "packet"))
            copied = os.path.join(tmp, "packet")
            excerpt_path = os.path.join(copied, "window.objdump.txt")
            with open(excerpt_path, "rb") as f:
                blob = bytearray(f.read())
            idx = blob.find(b"48 85 ff")
            self.assertNotEqual(idx, -1)
            blob[idx:idx + 2] = b"90 90"
            with open(excerpt_path, "wb") as f:
                f.write(blob)
            errors = checker.check_packet(copied, path)
            self.assertTrue(any("excerpt bytes mismatch" in e
                                for e in errors))


if __name__ == "__main__":
    unittest.main()
