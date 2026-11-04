#!/usr/bin/env python3
"""Unit tests for RE-001-node115-lu-chain.

Static only: reads bytes from artifacts/node/115/hl-node, never executes it.
"""
import hashlib
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-001-node115-lu-chain"
BIN = ROOT / "artifacts" / "node" / "115" / "hl-node"

EXHIBITS = [
    ("ch_head", 0x63B1B60, 0x63B1B90, 48, 15),
    ("ch_next", 0x63B1B90, 0x63B1BBE, 46, 10),
    ("ch_mid", 0x63B1C8B, 0x63B1CB7, 44, 12),
    ("ch_join", 0x63B1C28, 0x63B1C5B, 51, 10),
    ("ch_exit", 0x63B1D10, 0x63B1D36, 38, 14),
]


def read(va, n):
    data = BIN.read_bytes()
    return data[va - 0x1000: va - 0x1000 + n]


def e8_target(site):
    b = read(site, 5)
    assert b[0] == 0xE8
    return site + 5 + struct.unpack("<i", b[1:5])[0]


class TestChain(unittest.TestCase):
    def test_regenerate(self):
        for name, start, end, nbytes, _ in EXHIBITS:
            raw = read(start, end - start)
            self.assertEqual(len(raw), nbytes)
            claimed = (PACKET / f"{name}.hex").read_text().strip()
            self.assertEqual(claimed, raw.hex(), name)

    def test_tamper_control(self):
        raw = bytearray(read(0x63B1B60, 48))
        raw[0] ^= 0xFF
        claimed = (PACKET / "ch_head.hex").read_text().strip()
        self.assertNotEqual(bytes(raw).hex(), claimed)

    def test_strict_counts(self):
        total = 0
        for name, _, _, _, nstrict in EXHIBITS:
            lines = (PACKET / f"{name}.objdump.txt").read_text().splitlines()
            strict = sum(1 for l in lines if len(l.split("\t")) >= 3
                         and l.split("\t")[2].strip())
            self.assertEqual(strict, nstrict, name)
            total += strict
        self.assertEqual(total, 61)

    def test_key_bytes(self):
        self.assertEqual(read(0x63B1B64, 4),
                         bytes.fromhex("4c8d7170"))
        self.assertEqual(read(0x63B1B83, 5),
                         bytes.fromhex("4c894c2418"))
        self.assertEqual(read(0x63B1BA0, 7),
                         bytes.fromhex("448b83e04b0000"))
        self.assertEqual(read(0x63B1C1B, 5),
                         bytes.fromhex("c644241701"))
        self.assertEqual(read(0x63B1C86, 5),
                         bytes.fromhex("c644241700"))
        self.assertEqual(read(0x63B1D1E, 3),
                         bytes.fromhex("c60100"))
        self.assertEqual(read(0x63B1D45, 3),
                         bytes.fromhex("c60001"))
        self.assertEqual(read(0x63B1D55, 3),
                         bytes.fromhex("c60201"))
        b = read(0x63B1BAD, 5)
        self.assertEqual(0x63B1BAD + 5 + struct.unpack("<i", b[1:5])[0],
                         0x63AE260)
        b = read(0x63B1C75, 5)
        self.assertEqual(0x63B1C75 + 5 + struct.unpack("<i", b[1:5])[0],
                         0x63AE260)

    def test_fde_boundaries(self):
        self.assertEqual(0x63B1D5A - 0x63B1B60, 506)
        for _, start, end, _, _ in EXHIBITS:
            self.assertGreaterEqual(start, 0x63B1B60)
            self.assertLessEqual(end, 0x63B1D5A)

    def test_rela_dyn_got_absence(self):
        data = BIN.read_bytes()
        rela = data[0x6BE8: 0x6BE8 + 0x163CC8]
        self.assertEqual(len(rela) // 24, 60723)
        hits = sum(1 for off in range(0, len(rela), 24)
                   if struct.unpack_from("<q", rela, off + 16)[0] == 0x63B1B60)
        self.assertEqual(hits, 0)

    def test_census_spot(self):
        for site in (0x63B2734, 0x63B3974, 0x63B3A1A):
            self.assertEqual(e8_target(site), 0x63B1B60)

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
