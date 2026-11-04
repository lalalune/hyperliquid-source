#!/usr/bin/env python3
"""Unit tests for RE-001-node115-lu-central-flush.

Byte-level checks only; the node binary is never executed. The full
whole-binary census lives in tools/node115_lu_central_flush.py
and is exercised separately (verifier exit 0).
"""
import hashlib
import re
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-001-node115-lu-central-flush"
BIN = ROOT / "artifacts" / "node" / "115" / "hl-node"

STRICT_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t\S")

EXCERPTS = [
    ("small_lock.hex", 0x63EAEF0, 0x63EAF7E),
    ("large_gate.hex", 0x63EB9D0, 0x63EBA48),
    ("push_large.hex", 0x63BD640, 0x63BD687),
    ("large_tail.hex", 0x63EC019, 0x63EC068),
]

COUNTS = [
    ("small_lock.objdump.txt", 33),
    ("large_gate.objdump.txt", 25),
    ("push_large.objdump.txt", 16),
    ("large_tail.objdump.txt", 18),
]

KEY_BYTES = [
    (0x63EAD50, bytes.fromhex("f30f1efa")),
    (0x63EB870, bytes.fromhex("f30f1efa")),
    (0x63612B0, bytes.fromhex("f30f1efa")),
    (0x63BD640, bytes.fromhex("f30f1efa")),
    (0x63EB586, b"\xc3"),
    (0x63EC0AE, b"\xc3"),
    (0x63EAF51, bytes.fromhex("e85a680000")),
    (0x63EB24F, bytes.fromhex("e81c590000")),
    (0x63EBA30, bytes.fromhex("f0480111")),
    (0x63EBA3B, bytes.fromhex("f049830101")),
    (0x63EBEBA, bytes.fromhex("e8f1580000")),
    (0x63EBC6A, bytes.fromhex("e8014f0000")),
    (0x63612E1, bytes.fromhex("e85af00500")),
    (0x63BD682, bytes.fromhex("e8b92c0000")),
    (0x636130E, bytes.fromhex("e8fdf2ffff")),
    (0x63BD6AE, bytes.fromhex("e85d2ffaff")),
]

# Census spot checks: (E8 site VA, target VA).
CENSUS_SPOT = [
    (0x635D3C0, 0x63EAD50),
    (0x635C111, 0x63EB870),
    (0x6363435, 0x63EB870),
    (0x63EBD6C, 0x63BD640),
    (0x63EB3F1, 0x63612B0),
]

PRIOR_RANGES = [
    (0x4FAC710, 0x4FAC7E0),
    (0x4FB52E0, 0x4FB5440),
    (0x4DA86A0, 0x4DA8860),
    (0x4DA6C80, 0x4DA6D70),
    (0x2AC0F60, 0x2AC0FB0),
    (0x2ACE08B, 0x2ACE0EC),
    (0x2ACEB52, 0x2ACEBA0),
    (0x5A8E3C0, 0x5A8E493),
    (0x5A8C9F0, 0x5A8CA2C),
    (0x5A8C110, 0x5A8C14C),
    (0x635DE30, 0x635DEC6),
    (0x635C6D0, 0x635DE25),
]


def text_bytes(data, va, n):
    return data[va - 0x1000:va - 0x1000 + n]


def rela_relative(data):
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name, sh_type, _f, _a, sh_off, sh_size = struct.unpack_from(
            "<IIQQQQ", data, off)
        sections.append((sh_name, sh_type, sh_off, sh_size))
    str_off = sections[e_shstrndx][2]
    out = {}
    for sh_name, sh_type, sh_off, sh_size in sections:
        name_end = data.index(b"\x00", str_off + sh_name)
        name = data[str_off + sh_name:name_end].decode()
        if name == ".rela.dyn" and sh_type == 4:
            for j in range(sh_size // 24):
                r_off, r_info, r_add = struct.unpack_from(
                    "<QQq", data, sh_off + j * 24)
                if r_info & 0xFFFFFFFF == 8:
                    out[r_off] = r_add
    return out


class TestCentralFlush(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = BIN.read_bytes()

    def test_excerpts_regenerate(self):
        for name, start, end in EXCERPTS:
            raw = bytes.fromhex((PACKET / name).read_text().strip())
            self.assertEqual(raw, text_bytes(self.data, start, end - start),
                             name)

    def test_tamper_control(self):
        raw = bytes.fromhex((PACKET / "small_lock.hex").read_text().strip())
        bad = bytearray(raw)
        bad[0] ^= 0xFF
        self.assertNotEqual(bytes(bad),
                            text_bytes(self.data, 0x63EAEF0, 0x63EAF7E - 0x63EAEF0))

    def test_strict_counts(self):
        for name, want in COUNTS:
            lines = (PACKET / name).read_text().splitlines()
            count = sum(1 for ln in lines if STRICT_RE.match(ln))
            self.assertEqual(count, want, name)

    def test_key_bytes(self):
        for va, want in KEY_BYTES:
            self.assertEqual(text_bytes(self.data, va, len(want)), want,
                             hex(va))

    def test_fde_boundaries(self):
        for va in (0x63EAD50, 0x63EB870, 0x63612B0, 0x63BD640):
            self.assertEqual(text_bytes(self.data, va, 4),
                             bytes.fromhex("f30f1efa"), hex(va))
        for va in (0x63EB586, 0x63EC0AE, 0x6361303, 0x63BD6A4):
            self.assertEqual(text_bytes(self.data, va, 1), b"\xc3", hex(va))

    def test_rela_got(self):
        got = rela_relative(self.data)
        self.assertEqual(got.get(0x64EE138), 0x6711B40)
        for target in (0x63EAD50, 0x63EB870, 0x63612B0, 0x63BD640):
            self.assertNotIn(target, got.values(), hex(target))

    def test_census_spot(self):
        for site, target in CENSUS_SPOT:
            raw = text_bytes(self.data, site, 5)
            self.assertEqual(raw[0], 0xE8, hex(site))
            rel = struct.unpack_from("<i", raw, 1)[0]
            self.assertEqual(site + 5 + rel, target, hex(site))

    def test_excerpt_disjoint(self):
        for _name, start, end in EXCERPTS:
            for s2, e2 in PRIOR_RANGES:
                self.assertFalse(start < e2 and s2 < end,
                                 (hex(start), hex(s2)))


if __name__ == "__main__":
    unittest.main()
