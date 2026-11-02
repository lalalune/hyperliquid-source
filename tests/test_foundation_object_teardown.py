#!/usr/bin/env python3
"""Tests for RE-001 object teardown (function 0x514bfe0, node #94).

Run from the repository root:

    python3 tests/test_foundation_object_teardown.py

The binary path defaults to the canonical captured artifact; pass
``--binary`` to point at another copy of node #94. All expectations
are read from the bytes: a null input returns with no delete, each
embedded string is freed only on the heap arm with size union + 1,
the +0x1a8 string is disposed before the +0x48 string, and the
object itself is deleted with size 0x2e0 via a tail jump.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tools.foundation_object_teardown import (  # noqa: E402
    OBJECT_SIZE, STRING_OFFSETS, Str, check_packet, teardown)

PACKET_DIR = os.path.join(
    os.path.dirname(__file__), "..", "research", "work-items",
    "RE-001-object-teardown-94")
DEFAULT_BINARY = os.path.join("artifacts", "node", "94", "hl-node")
BINARY = os.environ.get("HL_NODE94_BIN", DEFAULT_BINARY)

BASE = 0x1000


def heap_str(offset, ptr, union):
    return Str(offset, ptr, union)


def sso_str(offset):
    # pointer == its own inline-buffer address: the SSO arm.
    return Str(offset, BASE + offset + 0x10, 0xDEADBEEF)


class ModelTests(unittest.TestCase):
    def test_null_returns_without_deletes(self):
        returned, deletes = teardown(None, [])
        self.assertTrue(returned)
        self.assertEqual(deletes, [])

    def test_both_sso_only_self_delete(self):
        strs = [sso_str(0x1A8), sso_str(0x48)]
        returned, deletes = teardown(BASE, strs)
        self.assertFalse(returned)
        self.assertEqual(deletes, [(BASE, OBJECT_SIZE)])

    def test_both_heap_in_code_order(self):
        strs = [heap_str(0x1A8, 0x9000, 0x3F),
                heap_str(0x48, 0x8000, 0x1F)]
        returned, deletes = teardown(BASE, strs)
        self.assertEqual(deletes, [(0x9000, 0x40), (0x8000, 0x20),
                                   (BASE, OBJECT_SIZE)])

    def test_mixed_heap_and_sso(self):
        strs = [sso_str(0x1A8), heap_str(0x48, 0x8000, 0)]
        _, deletes = teardown(BASE, strs)
        self.assertEqual(deletes, [(0x8000, 1), (BASE, OBJECT_SIZE)])

    def test_union_plus_one_wraps(self):
        strs = [heap_str(0x1A8, 0x9000, (1 << 64) - 1)]
        _, deletes = teardown(BASE, strs)
        self.assertEqual(deletes[0], (0x9000, 0))

    def test_object_size_is_0x2e0(self):
        self.assertEqual(OBJECT_SIZE, 0x2E0)
        _, deletes = teardown(BASE, [])
        self.assertEqual(deletes, [(BASE, 0x2E0)])

    def test_string_offsets_in_code_order(self):
        self.assertEqual(STRING_OFFSETS, (0x1A8, 0x48))


class PacketTests(unittest.TestCase):
    def test_packet_verifies(self):
        errors = check_packet(PACKET_DIR, BINARY)
        self.assertEqual(errors, [], "packet errors: %r" % (errors,))

    def test_packet_verify_script_passes(self):
        result = subprocess.run(
            [sys.executable,
             os.path.join(PACKET_DIR, "verify.py"), "--binary", BINARY],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ALL CHECKS PASSED", result.stdout)

    def test_excerpts_regenerate_byte_identically(self):
        names = ("window.objdump.txt", "plt.objdump.txt")
        before = {}
        for name in names:
            with open(os.path.join(PACKET_DIR, name), "rb") as f:
                before[name] = f.read()
        with tempfile.TemporaryDirectory() as tmp:
            copy_dir = os.path.join(tmp, "packet")
            shutil.copytree(PACKET_DIR, copy_dir)
            result = subprocess.run(
                [sys.executable, os.path.join(copy_dir, "export_excerpts.py"),
                 "--binary", BINARY],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            pattern = rb"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}(?:\s|$))+)"
            rows = lambda raw: [(va, b"".join(code.split())) for va, code in
                                re.findall(pattern, raw, re.M)]
            for name in names:
                with open(os.path.join(copy_dir, name), "rb") as f:
                    fresh = f.read()
                self.assertTrue(rows(fresh), name)
                self.assertEqual(rows(fresh), rows(before[name]), name)
        for name in names:
            with open(os.path.join(PACKET_DIR, name), "rb") as f:
                self.assertEqual(f.read(), before[name], name)

    def test_corrupted_manifest_is_caught(self):
        with tempfile.TemporaryDirectory() as tmp:
            copy_dir = os.path.join(tmp, "packet")
            shutil.copytree(PACKET_DIR, copy_dir)
            manifest = os.path.join(copy_dir, "MANIFEST.sha256")
            with open(manifest, "a") as f:
                f.write("0" * 64 + "  window.objdump.txt\n")
            errors = check_packet(copy_dir, BINARY)
            self.assertTrue(
                any("MANIFEST" in e for e in errors),
                "corrupted manifest was not caught: %r" % (errors,))

    def test_corrupted_excerpt_is_caught(self):
        with tempfile.TemporaryDirectory() as tmp:
            copy_dir = os.path.join(tmp, "packet")
            shutil.copytree(PACKET_DIR, copy_dir)
            path = os.path.join(copy_dir, "window.objdump.txt")
            with open(path) as f:
                text = f.read()
            # Flip one byte hex token on the entry line.
            text = text.replace("f3 0f 1e fa", "f3 0f 1e fb", 1)
            with open(path, "w") as f:
                f.write(text)
            errors = check_packet(copy_dir, BINARY)
            self.assertTrue(
                any("excerpt" in e for e in errors),
                "corrupted excerpt was not caught: %r" % (errors,))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default=BINARY)
    args, remaining = ap.parse_known_args()
    BINARY = args.binary
    unittest.main(argv=[sys.argv[0]] + remaining)
