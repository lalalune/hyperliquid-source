#!/usr/bin/env python3
"""Unit tests for RE-001-node115-lu-release.

Static only: reads bytes from artifacts/node/115/hl-node, never executes it.
"""
import hashlib
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-001-node115-lu-release"
BIN = ROOT / "artifacts" / "node" / "115" / "hl-node"

EXHIBITS = [
    ("rel_head", 0x63B3080, 0x63B30B2, 50, 16),
    ("rel_flag", 0x63B30C7, 0x63B30E3, 28, 7),
    ("rel_vcall", 0x63B31A9, 0x63B31C8, 31, 7),
    ("rel_retry", 0x63B3250, 0x63B326A, 26, 6),
    ("rel_tail", 0x63B30F0, 0x63B3116, 38, 13),
]


def read(va, n):
    data = BIN.read_bytes()
    return data[va - 0x1000: va - 0x1000 + n]


def e8_target(site):
    b = read(site, 5)
    assert b[0] == 0xE8
    return site + 5 + struct.unpack("<i", b[1:5])[0]


class TestRelease(unittest.TestCase):
    def test_regenerate(self):
        for name, start, end, nbytes, _ in EXHIBITS:
            raw = read(start, end - start)
            self.assertEqual(len(raw), nbytes)
            claimed = (PACKET / f"{name}.hex").read_text().strip()
            self.assertEqual(claimed, raw.hex(), name)

    def test_tamper_control(self):
        raw = bytearray(read(0x63B3080, 50))
        raw[0] ^= 0xFF
        claimed = (PACKET / "rel_head.hex").read_text().strip()
        self.assertNotEqual(bytes(raw).hex(), claimed)

    def test_strict_counts(self):
        total = 0
        for name, _, _, _, nstrict in EXHIBITS:
            lines = (PACKET / f"{name}.objdump.txt").read_text().splitlines()
            strict = sum(1 for l in lines if len(l.split("\t")) >= 3
                         and l.split("\t")[2].strip())
            self.assertEqual(strict, nstrict, name)
            total += strict
        self.assertEqual(total, 49)

    def test_key_bytes(self):
        self.assertEqual(read(0x63B350A, 4), bytes.fromhex("41ff5228"))
        self.assertEqual(read(0x63B338B, 4), bytes.fromhex("41ff5230"))
        self.assertEqual(read(0x63B31C2, 4), bytes.fromhex("41ff5208"))
        b = read(0x63B32FB, 5)
        self.assertEqual(0x63B32FB + 5 + struct.unpack("<i", b[1:5])[0],
                         0x63B2E60)
        b = read(0x63B31F4, 5)
        self.assertEqual(0x63B31F4 + 5 + struct.unpack("<i", b[1:5])[0],
                         0x63B5760)

    def test_fde_boundaries(self):
        self.assertEqual(0x63B38C2 - 0x63B3080, 2114)
        for _, start, end, _, _ in EXHIBITS:
            self.assertGreaterEqual(start, 0x63B3080)
            self.assertLessEqual(end, 0x63B38C2)

    def test_rela_dyn_got_absence(self):
        data = BIN.read_bytes()
        rela = data[0x6BE8: 0x6BE8 + 0x163CC8]
        self.assertEqual(len(rela) // 24, 60723)
        hits = sum(1 for off in range(0, len(rela), 24)
                   if struct.unpack_from("<q", rela, off + 16)[0] == 0x63B3080)
        self.assertEqual(hits, 0)

    def test_census_spot(self):
        for site in (0x63B3A92, 0x63C0E84, 0x63C1194):
            self.assertEqual(e8_target(site), 0x63B3080)
        b = read(0x63B3B80, 5)
        self.assertEqual(b[0], 0xE9)
        self.assertEqual(0x63B3B80 + 5 + struct.unpack("<i", b[1:5])[0],
                         0x63B3080)

    def test_manifest_coverage(self):
        manifest = (PACKET / "MANIFEST.sha256").read_text().splitlines()
        entries = {}
        for line in manifest:
            digest, _, path = line.partition("  ")
            entries[path] = digest
        self.assertEqual(len(entries), 15)
        for path, digest in entries.items():
            target = (PACKET / path).resolve()
            self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(),
                             digest, path)


if __name__ == "__main__":
    unittest.main()
