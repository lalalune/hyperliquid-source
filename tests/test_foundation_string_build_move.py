#!/usr/bin/env python3
"""Tests for RE-001 string build-and-move (function 0x514bdf0, node #94).

Run from the repository root:

    python3 tests/test_foundation_string_build_move.py

The binary path defaults to the canonical captured artifact; pass
``--binary`` to point at another copy of node #94.  All expectations
are read from the bytes: the entry move-assigns the producer's
string into out and always returns 1, and the temporary is freed
only when its pointer differs from its own inline buffer address,
with size capacity + 1.  The producer's own contents are not
modelled: the tests take the produced string as an input, exactly
as the entry receives it from the callee.
"""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tools.foundation_string_build_move import (  # noqa: E402
    check_packet, string_build_move, temp_dispose)

PACKET_DIR = os.path.join(
    os.path.dirname(__file__), "..", "research", "work-items",
    "RE-001-string-build-move-94")
DEFAULT_BINARY = os.path.join("artifacts", "node", "94", "hl-node")
BINARY = os.environ.get("HL_NODE94_BIN", DEFAULT_BINARY)


class BuildMoveTests(unittest.TestCase):
    def test_out_equals_produced_and_returns_one(self):
        self.assertEqual(string_build_move(b"hello"), (1, b"hello"))

    def test_empty_produced_string(self):
        self.assertEqual(string_build_move(b""), (1, b""))

    def test_long_produced_string(self):
        produced = bytes(range(256)) * 4
        self.assertEqual(string_build_move(produced), (1, produced))

    def test_produced_bytes_are_not_re_encoded(self):
        # Bytes pass through unchanged: no encoding is claimed.
        produced = b"\xff\x00\xfe binary \x80"
        ret, out = string_build_move(produced)
        self.assertEqual((ret, out), (1, produced))

    def test_result_is_a_copy_not_an_alias(self):
        produced = bytearray(b"mutable")
        ret, out = string_build_move(produced)
        produced[0] = 0x58
        self.assertEqual(out, b"mutable")
        self.assertEqual(ret, 1)


class TempDisposeTests(unittest.TestCase):
    def test_inline_storage_is_not_freed(self):
        base = 0x7FFD1000
        self.assertIsNone(temp_dispose(base + 0x10, base, 15))

    def test_heap_storage_frees_capacity_plus_one(self):
        base = 0x7FFD1000
        self.assertEqual(temp_dispose(0x600000, base, 15), 16)
        self.assertEqual(temp_dispose(0x600000, base, 0), 1)

    def test_capacity_plus_one_wraps_at_64_bits(self):
        base = 0x7FFD1000
        self.assertEqual(temp_dispose(0x600000, base, (1 << 64) - 1), 0)

    def test_pointer_one_past_inline_is_heap(self):
        base = 0x7FFD1000
        self.assertEqual(temp_dispose(base + 0x11, base, 31), 32)


class PacketTests(unittest.TestCase):
    def test_packet_verifies_against_binary(self):
        errors = check_packet(PACKET_DIR, BINARY)
        self.assertEqual(errors, [])

    def test_packet_verify_script_passes(self):
        import subprocess
        packet_verify = os.path.join(PACKET_DIR, "verify.py")
        result = subprocess.run(
            [sys.executable, packet_verify, "--binary", BINARY],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ALL CHECKS PASSED", result.stdout)

    def test_excerpts_regenerate_byte_identically(self):
        import shutil
        import subprocess
        import tempfile
        packet_dir = os.path.abspath(PACKET_DIR)
        names = ("window.objdump.txt", "callee.objdump.txt")
        before = {}
        for name in names:
            with open(os.path.join(packet_dir, name), "rb") as f:
                before[name] = f.read()
        with tempfile.TemporaryDirectory() as temporary:
            copied = os.path.join(temporary, "packet")
            shutil.copytree(packet_dir, copied)
            result = subprocess.run(
                [sys.executable, os.path.join(copied, "export_excerpts.py"),
                 "--binary", BINARY],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            pattern = rb"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}(?:\s|$))+)"
            rows = lambda raw: [(va, b"".join(code.split())) for va, code in
                                re.findall(pattern, raw, re.M)]
            for name in names:
                with open(os.path.join(copied, name), "rb") as f:
                    fresh = f.read()
                self.assertTrue(rows(fresh), name)
                self.assertEqual(rows(fresh), rows(before[name]), name)
        for name in names:
            with open(os.path.join(packet_dir, name), "rb") as f:
                self.assertEqual(f.read(), before[name], name)


class CorruptionTests(unittest.TestCase):
    def test_corrupted_manifest_is_caught(self):
        import shutil
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            copy_dir = os.path.join(tmp, "packet")
            shutil.copytree(os.path.abspath(PACKET_DIR), copy_dir)
            manifest = os.path.join(copy_dir, "MANIFEST.sha256")
            with open(manifest, "a") as f:
                f.write("0" * 64 + "  window.objdump.txt\n")
            errors = check_packet(copy_dir, BINARY)
            self.assertTrue(
                any("MANIFEST" in e for e in errors),
                "corrupted manifest was not caught: %r" % (errors,))

    def test_corrupted_excerpt_is_caught(self):
        import shutil
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            copy_dir = os.path.join(tmp, "packet")
            shutil.copytree(os.path.abspath(PACKET_DIR), copy_dir)
            excerpt = os.path.join(copy_dir, "window.objdump.txt")
            with open(excerpt) as f:
                text = f.read()
            # Flip one byte hex token on the entry line.
            text = text.replace("f3 0f 1e fa", "f3 0f 1e fb", 1)
            with open(excerpt, "w") as f:
                f.write(text)
            errors = check_packet(copy_dir, BINARY)
            self.assertTrue(
                any("excerpt" in e for e in errors),
                "corrupted excerpt was not caught: %r" % (errors,))

    def test_corrupted_record_is_caught(self):
        import json
        import shutil
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            copy_dir = os.path.join(tmp, "packet")
            shutil.copytree(os.path.abspath(PACKET_DIR), copy_dir)
            records = os.path.join(copy_dir, "records.json")
            with open(records) as f:
                rec = json.load(f)
            rec["function"]["sha256"] = "0" * 64
            with open(records, "w") as f:
                json.dump(rec, f)
            errors = check_packet(copy_dir, BINARY)
            self.assertTrue(errors, "corrupted record was not caught")


if __name__ == "__main__":
    unittest.main(verbosity=2)
