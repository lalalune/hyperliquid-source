#!/usr/bin/env python3
"""Tests for node #94's string-plus-block copy 0x514de00 (RE-001)."""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools"))
from foundation_string_block_copy import (  # noqa: E402
    BLOCK_SIZE, copy_string_block, dest_string_bytes)

PACKET = REPO / "research" / "work-items" / "RE-001-string-block-copy-94"
BINARY = REPO / "work" / "hl-node-94.bin"


def sample_block():
    block = bytearray(72)
    block[8:16] = (0x514b390).to_bytes(8, "little")
    block[40:48] = b"ABCDEFGH"
    return bytes(block)


class ArmTests(unittest.TestCase):
    def test_empty_string_is_sso_with_nul(self):
        dest = copy_string_block(b"", sample_block())
        self.assertEqual(dest["arm"], "sso")
        self.assertEqual(dest["length"], 0)
        self.assertEqual(dest["buffer"], b"\x00")
        self.assertIsNone(dest["capacity_slot"])

    def test_single_byte_is_sso(self):
        dest = copy_string_block(b"Z", sample_block())
        self.assertEqual(dest["arm"], "sso")
        self.assertEqual(dest["buffer"], b"Z\x00")

    def test_fifteen_bytes_is_sso_boundary(self):
        source = b"0123456789abcde"
        dest = copy_string_block(source, sample_block())
        self.assertEqual(dest["arm"], "sso")
        self.assertEqual(dest["buffer"], source + b"\x00")

    def test_sixteen_bytes_is_heap_boundary(self):
        source = b"0123456789abcdef"
        dest = copy_string_block(source, sample_block())
        self.assertEqual(dest["arm"], "heap")
        self.assertIsNone(dest["buffer"])
        self.assertEqual(dest["capacity_slot"], 16)
        self.assertEqual(dest_string_bytes(dest), source)

    def test_long_string_is_heap(self):
        source = b"x" * 100
        dest = copy_string_block(source, sample_block())
        self.assertEqual(dest["arm"], "heap")
        self.assertEqual(dest["capacity_slot"], 100)
        self.assertEqual(dest_string_bytes(dest), source)


class BlockTests(unittest.TestCase):
    def test_block_copied_verbatim(self):
        block = sample_block()
        dest = copy_string_block(b"hi", block)
        self.assertEqual(dest["block"], block)
        self.assertEqual(int.from_bytes(dest["block"][8:16], "little"),
                         0x514b390)

    def test_block_independent_of_source(self):
        block = sample_block()
        dest = copy_string_block(b"", block)
        self.assertEqual(dest["block"], block)

    def test_copy_is_deep(self):
        source = bytearray(b"hello")
        block = bytearray(sample_block())
        dest = copy_string_block(bytes(source), bytes(block))
        source[0] = ord("j")
        block[0] = 0xFF
        self.assertEqual(dest["content"], b"hello")
        self.assertEqual(dest["block"][0], 0)

    def test_wrong_block_size_rejected(self):
        with self.assertRaises(ValueError):
            copy_string_block(b"hi", b"\x00" * 71)
        with self.assertRaises(ValueError):
            copy_string_block(b"hi", b"\x00" * 73)


class EndToEndTests(unittest.TestCase):
    def test_sampled_caller_shape(self):
        # A sampled caller site: short string plus a block whose
        # +0x8 slot holds a code pointer, rest zero.
        block = bytes(72)
        block = block[:8] + (0x514cc10).to_bytes(8, "little") + block[16:]
        dest = copy_string_block(b"name", block)
        self.assertEqual(dest["arm"], "sso")
        self.assertEqual(dest_string_bytes(dest), b"name")
        self.assertEqual(int.from_bytes(dest["block"][8:16], "little"),
                         0x514cc10)

    def test_census_records_match_packet(self):
        records = json.loads((PACKET / "records.json").read_text())
        sites = records["caller_census"]["sites"]
        self.assertEqual(len(sites), 61)
        self.assertEqual(len(set(sites)), 61)
        self.assertEqual(sites[0], "0x515dc16")
        self.assertEqual(sites[-1], "0x515f15c")


class PacketTests(unittest.TestCase):
    def test_verify_passes(self):
        result = subprocess.run(
            [sys.executable, str(PACKET / "verify.py")],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ALL CHECKS PASSED", result.stdout)

    def test_excerpt_regeneration(self):
        sys.path.insert(0, str(PACKET))
        import export_excerpts
        for name, ranges in export_excerpts.RANGES.items():
            regen = "".join(export_excerpts.excerpt(s, e)
                            for s, e in ranges)
            self.assertEqual(regen, (PACKET / name).read_text(),
                             name)

    def test_corruption_controls(self):
        # Tampering with the records or an excerpt must fail verify
        # even when the real binary is supplied explicitly, so the
        # failure comes from the tamper itself, not a missing file.
        for rel, patch in [
                ("records.json", lambda p: p.write_text(
                    p.read_text().replace("514de00", "514de01"))),
                ("window.objdump.txt", lambda p: p.write_text(
                    p.read_text().replace("514deb8", "514deb9")))]:
            with tempfile.TemporaryDirectory() as tmp:
                copy = Path(tmp) / "packet"
                shutil.copytree(PACKET, copy)
                patch(copy / rel)
                result = subprocess.run(
                    [sys.executable, str(copy / "verify.py"),
                     "--binary", str(BINARY)],
                    capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0, rel)


if __name__ == "__main__":
    unittest.main()
