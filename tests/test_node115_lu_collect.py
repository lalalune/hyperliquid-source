#!/usr/bin/env python3
"""Unit tests for the node #115 lu collect packet (RE-001-node115-lu-collect)."""
import hashlib
import json
import struct
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / "artifacts" / "node" / "115" / "hl-node"
PACKET = ROOT / "research" / "work-items" / "RE-001-node115-lu-collect"
VERIFIER = ROOT / "tools" / "node115_lu_collect.py"

RECORDS = json.loads((PACKET / "records.json").read_text())
EXPECT_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def va_to_off(va):
    return va - 0x1000


class CollectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = BIN.read_bytes()

    def test_binary_sha_and_size(self):
        self.assertEqual(len(self.data), 105896032)
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), EXPECT_SHA)

    def test_exhibits_regenerate(self):
        for name, ex in RECORDS["exhibits"].items():
            start = int(ex["range"][0], 16)
            end = int(ex["range"][1], 16)
            raw = self.data[va_to_off(start):va_to_off(end)]
            self.assertEqual(bytes.fromhex((PACKET / f"{name}.hex").read_text().strip()), raw)

    def test_fde_bounds(self):
        self.assertEqual(RECORDS["collect_fde_bytes"], 250)
        self.assertEqual(RECORDS["fde"], "0x6363560..0x636365a")

    def test_census_spot(self):
        # Spot-check three incoming sites (full scan lives in the verifier).
        for site in (0x63EAB9E, 0x63EB656, 0x63EB74C):
            o = va_to_off(site)
            self.assertEqual(self.data[o], 0xE8)
            rel = struct.unpack("<i", self.data[o + 1:o + 5])[0]
            self.assertEqual(site + 5 + rel, 0x6363560)

    def test_got_absence(self):
        rela_off, rela_size = 0x6BE8, 0x163CC8
        for i in range(rela_size // 24):
            _off, _info, add = struct.unpack(
                "<QQq", self.data[rela_off + i * 24:rela_off + i * 24 + 24])
            self.assertNotEqual(add, 0x6363560)

    def test_key_bytes(self):
        self.assertEqual(self.data[va_to_off(0x6363560):va_to_off(0x6363560) + 4],
                         bytes.fromhex("f30f1efa"))
        o = va_to_off(0x636359F)
        self.assertEqual(self.data[o], 0xE8)
        rel = struct.unpack("<i", self.data[o + 1:o + 5])[0]
        self.assertEqual(0x636359F + 5 + rel, 0x63ACB40)

    def test_manifest_coverage(self):
        names = set()
        for line in (PACKET / "MANIFEST.sha256").read_text().splitlines():
            _digest, path = line.split(None, 1)
            names.add(path)
        expect = {"README.md", "EVIDENCE.md", "records.json"}
        expect |= {f"{n}.hex" for n in RECORDS["exhibits"]}
        expect |= {f"{n}.objdump.txt" for n in RECORDS["exhibits"]}
        expect |= {"../../../tools/node115_lu_collect.py",
                   "../../../tests/test_node115_lu_collect.py"}
        self.assertEqual(names, expect)

    def test_strict_counts(self):
        for name, ex in RECORDS["exhibits"].items():
            strict = 0
            for line in (PACKET / f"{name}.objdump.txt").read_text().splitlines():
                parts = line.split("\t")
                if len(parts) >= 3 and parts[2].strip():
                    strict += 1
            self.assertEqual(strict, ex["strict"])

    def test_tamper_control(self):
        raw = self.data[va_to_off(0x6363560):va_to_off(0x6363560) + 4]
        tampered = bytes([raw[0] ^ 0xFF]) + raw[1:]
        self.assertNotEqual(tampered, bytes.fromhex("f30f1efa"))

    def test_verifier_exit_zero(self):
        r = subprocess.run([sys.executable, str(VERIFIER)],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
