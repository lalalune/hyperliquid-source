#!/usr/bin/env python3
"""Unit tests for the RE-001-node115-lu-fallback-inner packet.

Regeneration, tamper control, strict counts, key bytes, FDE boundaries,
.rela.dyn GOT absence, census spot checks, and MANIFEST coverage.
Run: python3 tests/test_node115_lu_fallback_inner.py
"""

import hashlib
import os
import re
import struct
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PACKET = os.path.join(ROOT, "research", "work-items",
                      "RE-001-node115-lu-fallback-inner")
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")

EXCERPTS = [
    ("inner_head", 0x635FB50, 0x635FB90, 20),
    ("inner_branch", 0x635FC30, 0x635FC76, 17),
    ("inner_call", 0x635FBAD, 0x635FBE5, 13),
    ("gate_cont", 0x636063A, 0x636066F, 12),
    ("gate_tail", 0x6360680, 0x636069A, 8),
]

TEXT_ADDR, TEXT_OFF = 0x1419300, 0x1418300


def read_binary():
    with open(BIN, "rb") as f:
        return f.read()


def strict_count(path):
    n = 0
    with open(path, encoding="utf-8") as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) >= 3 and re.match(r"[a-z]", parts[2].strip()[:1]):
                n += 1
    return n


class TestFallbackInner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = read_binary()

    def test_regenerate(self):
        for name, start, end, _strict in EXCERPTS:
            raw = self.data[TEXT_OFF + (start - TEXT_ADDR):
                            TEXT_OFF + (end - TEXT_ADDR)]
            with open(os.path.join(PACKET, name + ".hex"),
                      encoding="utf-8") as f:
                self.assertEqual(bytes.fromhex("".join(f.read().split())), raw)

    def test_tamper_control(self):
        raw = self.data[TEXT_OFF + (0x635FB50 - TEXT_ADDR):
                        TEXT_OFF + (0x635FB90 - TEXT_ADDR)]
        bad = bytearray(raw)
        bad[0] ^= 0xFF
        with open(os.path.join(PACKET, "inner_head.hex"),
                  encoding="utf-8") as f:
            claimed = bytes.fromhex("".join(f.read().split()))
        self.assertNotEqual(bytes(bad), claimed)

    def test_strict_counts(self):
        for name, _s, _e, want in EXCERPTS:
            self.assertEqual(
                strict_count(os.path.join(PACKET, name + ".objdump.txt")),
                want, name)

    def test_key_bytes(self):
        checks = [
            (0x635FB6D, "807c245000"),
            (0x635FBD8, "e8c31d0600"),
            (0x635FC71, "e8ba1c0600"),
            (0x6360650, "48f736"),
            (0x6360695, "e916eeffff"),
            (0x63606BE, "e88df4ffff"),
        ]
        for va, want in checks:
            off = TEXT_OFF + (va - TEXT_ADDR)
            self.assertEqual(self.data[off:off + len(bytes.fromhex(want))].hex(),
                             want, hex(va))

    def test_fde_boundaries(self):
        # FDE starts: inner and tail-route lack endbr64 (push prologues);
        # fallback starts with endbr64. Ends are instruction boundaries.
        self.assertEqual(
            self.data[TEXT_OFF + (0x635FB50 - TEXT_ADDR):
                      TEXT_OFF + (0x635FB50 - TEXT_ADDR) + 2].hex(), "4157")
        self.assertEqual(
            self.data[TEXT_OFF + (0x6360610 - TEXT_ADDR):
                      TEXT_OFF + (0x6360610 - TEXT_ADDR) + 4].hex(), "f30f1efa")
        self.assertEqual(
            self.data[TEXT_OFF + (0x635F4B0 - TEXT_ADDR):
                      TEXT_OFF + (0x635F4B0 - TEXT_ADDR) + 4].hex(), "41574156")

    def test_rela_dyn_got_absent(self):
        # Parse section headers; .rela.dyn RELATIVE addends must not equal
        # any of the five census targets.
        data = self.data
        e_shoff = struct.unpack("<Q", data[0x28:0x30])[0]
        e_shentsize = struct.unpack("<H", data[0x3A:0x3C])[0]
        e_shnum = struct.unpack("<H", data[0x3C:0x3E])[0]
        e_shstrndx = struct.unpack("<H", data[0x3E:0x40])[0]
        headers = []
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            name, _typ, _flags, _addr, offset, size = struct.unpack(
                "<IIQQQQ", data[off:off + 40])
            headers.append((name, offset, size))
        shstr_off = headers[e_shstrndx][1]
        rela = None
        for name_off, offset, size in headers:
            end = data.index(b"\x00", shstr_off + name_off)
            if data[shstr_off + name_off:end] == b".rela.dyn":
                rela = data[offset:offset + size]
        self.assertIsNotNone(rela)
        targets = {0x635FB50, 0x6360610, 0x635F4B0, 0x63C19A0, 0x63C1930}
        for i in range(0, len(rela) - 23, 24):
            _off, info, addend = struct.unpack("<QQq", rela[i:i + 24])
            if (info & 0xFFFFFFFF) == 8:
                self.assertNotIn(addend, targets)

    def test_census_spot(self):
        # Spot-check the census anchors: fallback cold-path call, inner
        # callers' stack-arg pushes, and the tail-route E9.
        text = self.data[TEXT_OFF:]
        for va, want in [(0x63606BE, "e88df4ffff"),
                         (0x6361244, "6a00"),
                         (0x6360FF1, "4152"),
                         (0x6360695, "e916eeffff")]:
            off = va - TEXT_ADDR
            self.assertEqual(text[off:off + len(bytes.fromhex(want))].hex(),
                             want, hex(va))

    def test_manifest_coverage(self):
        with open(os.path.join(PACKET, "MANIFEST.sha256"),
                  encoding="utf-8") as f:
            entries = [l.rstrip("\n") for l in f if l.strip()]
        self.assertEqual(len(entries), 15)
        for line in entries:
            want, path = line.split("  ", 1)
            full = os.path.normpath(os.path.join(PACKET, path))
            with open(full, "rb") as g:
                self.assertEqual(hashlib.sha256(g.read()).hexdigest(), want,
                                 path)


if __name__ == "__main__":
    unittest.main()
