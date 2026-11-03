#!/usr/bin/env python3
"""Unit tests for RE-001-node115-lu-free-dealloc.

Byte-level checks only; the node binary is never executed. The full
whole-binary census lives in tools/node115_lu_free_dealloc.py
and is exercised separately (verifier exit 0).
"""
import hashlib
import re
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-001-node115-lu-free-dealloc"
BIN = ROOT / "artifacts" / "node" / "115" / "hl-node"

STRICT_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t\S")

EXCERPTS = [
    ("free.hex", 0x5A8E3C0, 0x5A8E493),
    ("drop9f0.hex", 0x5A8C9F0, 0x5A8CA2C),
    ("drop110.hex", 0x5A8C110, 0x5A8C14C),
    ("dealloc.hex", 0x635DE30, 0x635DEC6),
]

COUNTS = [
    ("free.objdump.txt", 59),
    ("drop9f0.objdump.txt", 21),
    ("drop110.objdump.txt", 21),
    ("dealloc.objdump.txt", 29),
]


def text_bytes(data, va, n):
    return data[va - 0x1000:va - 0x1000 + n]


class TestFreeDealloc(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = BIN.read_bytes()

    def test_excerpts_regenerate(self):
        for name, start, end in EXCERPTS:
            raw = bytes.fromhex((PACKET / name).read_text().strip())
            self.assertEqual(raw, text_bytes(self.data, start, end - start),
                             name)

    def test_tamper_control(self):
        raw = bytes.fromhex((PACKET / "free.hex").read_text().strip())
        bad = bytearray(raw)
        bad[0] ^= 0xFF
        self.assertNotEqual(bytes(bad),
                            text_bytes(self.data, 0x5A8E3C0, 0x5A8E493 - 0x5A8E3C0))

    def test_strict_counts(self):
        for name, want in COUNTS:
            lines = (PACKET / name).read_text().splitlines()
            count = sum(1 for ln in lines if STRICT_RE.match(ln))
            self.assertEqual(count, want, name)

    def test_body_rets(self):
        for va in (0x5A8E492, 0x5A8CA2B, 0x5A8C14B, 0x635DEC5):
            self.assertEqual(text_bytes(self.data, va, 1), b"\xc3", hex(va))

    def test_tail_jumps_resolve_to_dealloc_slot(self):
        for va in (0x5A8E483, 0x5A8CA1E, 0x5A8C13E):
            raw = text_bytes(self.data, va, 6)
            self.assertEqual(raw[0:2], bytes.fromhex("ff25"), hex(va))
            disp = struct.unpack_from("<i", raw, 2)[0]
            self.assertEqual(va + 6 + disp, 0x64DF4A0, hex(va))
        raw = text_bytes(self.data, 0x5A8E426, 6)
        self.assertEqual(raw[0:2], bytes.fromhex("ff15"), "buffer-free call")
        disp = struct.unpack_from("<i", raw, 2)[0]
        self.assertEqual(0x5A8E426 + 6 + disp, 0x64DF4A0)

    def test_dealloc_sizes(self):
        cases = [(0x5A8E470, 0x38), (0x5A8CA0D, 0xB80), (0x5A8C12D, 0xC8)]
        for va, want in cases:
            raw = text_bytes(self.data, va, 5)
            self.assertEqual(raw[0], 0xBE, hex(va))
            self.assertEqual(struct.unpack_from("<I", raw, 1)[0], want, hex(va))

    def test_dealloc_guards_and_slow_jump(self):
        self.assertEqual(text_bytes(self.data, 0x635DE34, 7),
                         bytes.fromhex("4881fe00100000"))
        self.assertEqual(text_bytes(self.data, 0x635DE41, 2),
                         bytes.fromhex("85d2"))
        self.assertEqual(text_bytes(self.data, 0x635DE49, 6),
                         bytes.fromhex("f7c7ff0f0000"))
        raw = text_bytes(self.data, 0x635DED0, 5)
        self.assertEqual(raw[0], 0xE9)
        disp = struct.unpack_from("<i", raw, 1)[0]
        self.assertEqual(0x635DED0 + 5 + disp, 0x635C6D0)

    def test_manifest_matches(self):
        manifest = (PACKET / "MANIFEST.sha256").read_text().splitlines()
        self.assertEqual(len(manifest), 13)
        for line in manifest:
            digest, path = line.split("  ")
            target = (PACKET / path).resolve()
            self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(),
                             digest, path)


if __name__ == "__main__":
    unittest.main()
