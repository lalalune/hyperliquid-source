#!/usr/bin/env python3
"""Unit tests for the RE-001-node115-lu-tail-route packet.

Regeneration, tamper control, strict counts, key bytes, FDE boundaries,
.rela.dyn GOT absence, census spot checks, and MANIFEST coverage.
Run: python3 tests/test_node115_lu_tail_route.py
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
                      "RE-001-node115-lu-tail-route")
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")

EXCERPTS = [
    ("tail_lookup", 0x635F4E0, 0x635F50B, 10),
    ("tail_pred", 0x635F523, 0x635F53E, 7),
    ("tail_accum", 0x635F678, 0x635F68D, 5),
    ("tail_drain", 0x635F610, 0x635F637, 6),
    ("tail_callsite", 0x635FBE5, 0x635FC1E, 15),
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


class TestTailRoute(unittest.TestCase):
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
        raw = self.data[TEXT_OFF + (0x635F4E0 - TEXT_ADDR):
                        TEXT_OFF + (0x635F50B - TEXT_ADDR)]
        bad = bytearray(raw)
        bad[0] ^= 0xFF
        with open(os.path.join(PACKET, "tail_lookup.hex"),
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
            (0x635F4B0, "41574156"),
            (0x635F4E0, "8b8650340100"),
            (0x635F506, "e8a5220900"),
            (0x635F526, "e865a20000"),
            (0x635F570, "0fb6bbac000000"),
            (0x635F610, "4881bbb800000000040000"),
            (0x635F681, "e86aa00400"),
            (0x635FC19, "e892f8ffff"),
            (0x6361129, "e882e3ffff"),
            (0x6360695, "e916eeffff"),
        ]
        for va, want in checks:
            off = TEXT_OFF + (va - TEXT_ADDR)
            self.assertEqual(self.data[off:off + len(bytes.fromhex(want))].hex(),
                             want, hex(va))

    def test_fde_boundaries(self):
        # Tail route lacks endbr64 (push prologue); its end is an
        # instruction boundary right before the next FDE's start.
        self.assertEqual(
            self.data[TEXT_OFF + (0x635F4B0 - TEXT_ADDR):
                      TEXT_OFF + (0x635F4B0 - TEXT_ADDR) + 4].hex(), "41574156")
        # FDE end: last byte of the tail FDE is the __stack_chk_fail
        # call's last rel32 byte; the next FDE starts at 0x635f697.
        self.assertEqual(
            self.data[TEXT_OFF + (0x635F697 - TEXT_ADDR) - 1:
                      TEXT_OFF + (0x635F697 - TEXT_ADDR)].hex(), "00")

    def test_rela_dyn_got_absent(self):
        # Parse section headers; .rela.dyn RELATIVE addends must not
        # equal the tail-route target.
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
        targets = {0x635F4B0}
        for i in range(0, len(rela) - 23, 24):
            _off, info, addend = struct.unpack("<QQq", rela[i:i + 24])
            if (info & 0xFFFFFFFF) == 8:
                self.assertNotIn(addend, targets)

    def test_census_spot(self):
        # Spot-check the census anchors: inner call, third-caller
        # call, and the gate tail jump.
        text = self.data[TEXT_OFF:]
        for va, want in [(0x635FC19, "e892f8ffff"),
                         (0x6361129, "e882e3ffff"),
                         (0x6360695, "e916eeffff"),
                         (0x6360F93, "48894c2418"),
                         (0x6361050, "4c89442418")]:
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
