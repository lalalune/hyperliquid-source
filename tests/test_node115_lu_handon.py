#!/usr/bin/env python3
"""Unit tests for RE-001-node115-lu-handon.

Static only: reads bytes from artifacts/node/115/hl-node, never executes it.
"""
import hashlib
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-001-node115-lu-handon"
BIN = ROOT / "artifacts" / "node" / "115" / "hl-node"

EXHIBITS = [
    ("ho_lock", 0x63B38D0, 0x63B3929, 89, 26),
    ("ho_loop", 0x63B3960, 0x63B3983, 35, 10),
    ("ho_join", 0x63B39A0, 0x63B39D7, 55, 11),
    ("ho_reenter", 0x63B3A76, 0x63B3A97, 33, 9),
    ("ho_acct", 0x63B3A97, 0x63B3ACD, 54, 9),
]


def read(va, n):
    data = BIN.read_bytes()
    return data[va - 0x1000: va - 0x1000 + n]


def e8_target(site):
    b = read(site, 5)
    assert b[0] == 0xE8
    return site + 5 + struct.unpack("<i", b[1:5])[0]


class TestHandon(unittest.TestCase):
    def test_regenerate(self):
        for name, start, end, nbytes, _ in EXHIBITS:
            raw = read(start, end - start)
            self.assertEqual(len(raw), nbytes)
            claimed = (PACKET / f"{name}.hex").read_text().strip()
            self.assertEqual(claimed, raw.hex(), name)

    def test_tamper_control(self):
        raw = bytearray(read(0x63B38D0, 89))
        raw[0] ^= 0xFF
        claimed = (PACKET / "ho_lock.hex").read_text().strip()
        self.assertNotEqual(bytes(raw).hex(), claimed)

    def test_strict_counts(self):
        total = 0
        for name, _, _, _, nstrict in EXHIBITS:
            lines = (PACKET / f"{name}.objdump.txt").read_text().splitlines()
            strict = sum(1 for l in lines if len(l.split("\t")) >= 3
                         and l.split("\t")[2].strip())
            self.assertEqual(strict, nstrict, name)
            total += strict
        self.assertEqual(total, 65)

    def test_key_bytes(self):
        self.assertEqual(read(0x63B3929, 7),
                         bytes.fromhex("49f70700000100"))
        self.assertEqual(read(0x63B3932, 7),
                         bytes.fromhex("80bbe84b000000"))
        self.assertEqual(read(0x63B3949, 6),
                         bytes.fromhex("483dff3f0000"))
        self.assertEqual(read(0x63B39D7, 4),
                         bytes.fromhex("c6436800"))
        self.assertEqual(read(0x63B3B04, 8),
                         bytes.fromhex("4981600800f0ffff"))
        self.assertEqual(read(0x63B3B0C, 7),
                         bytes.fromhex("498120ff7fffff"))
        b = read(0x63B3974, 5)
        self.assertEqual(0x63B3974 + 5 + struct.unpack("<i", b[1:5])[0],
                         0x63B1B60)
        b = read(0x63B3A92, 5)
        self.assertEqual(0x63B3A92 + 5 + struct.unpack("<i", b[1:5])[0],
                         0x63B3080)

    def test_fde_boundaries(self):
        self.assertEqual(0x63B3AF1 - 0x63B38D0, 545)
        for _, start, end, _, _ in EXHIBITS:
            self.assertGreaterEqual(start, 0x63B38D0)
            self.assertLessEqual(end, 0x63B3AF1)

    def test_rela_dyn_got_absence(self):
        data = BIN.read_bytes()
        rela = data[0x6BE8: 0x6BE8 + 0x163CC8]
        self.assertEqual(len(rela) // 24, 60723)
        hits = sum(1 for off in range(0, len(rela), 24)
                   if struct.unpack_from("<q", rela, off + 16)[0] == 0x63B38D0)
        self.assertEqual(hits, 0)

    def test_census_spot(self):
        for site in (0x63B4AA1, 0x63B5186, 0x63B51A5, 0x63B545D, 0x63B54D8,
                     0x63C1F15):
            self.assertEqual(e8_target(site), 0x63B38D0)
        for site in (0x63B3111, 0x63B3B13):
            b = read(site, 5)
            self.assertEqual(b[0], 0xE9)
            self.assertEqual(site + 5 + struct.unpack("<i", b[1:5])[0],
                             0x63B38D0)

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
