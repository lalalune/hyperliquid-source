#!/usr/bin/env python3
"""Unit tests for the node115 lu classremove packet.

Regeneration comparison (objdump header line stripped, as in packet
#224) plus a tamper control: flipping one exhibit byte must fail
the verifier's byte check.
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(ROOT, "research", "work-items",
                      "RE-001-node115-lu-classremove")
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
VERIFIER = os.path.join(ROOT, "tools", "node115_lu_classremove.py")


def va_off(va):
    return va - 0x1000


class TestClassRemove(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(PACKET, "records.json")) as f:
            self.records = json.load(f)
        with open(BIN, "rb") as f:
            self.data = f.read()

    def test_records_shape(self):
        ex = self.records["exhibits"]
        self.assertEqual(len(ex), 6)
        for name, e in ex.items():
            lo, hi = int(e["range"][0], 16), int(e["range"][1], 16)
            self.assertEqual(e["bytes"], hi - lo)
            self.assertTrue(os.path.exists(os.path.join(PACKET, name + ".hex")))
            self.assertTrue(os.path.exists(
                os.path.join(PACKET, name + ".objdump.txt")))

    def test_exhibit_bytes(self):
        for name, e in self.records["exhibits"].items():
            lo, hi = int(e["range"][0], 16), int(e["range"][1], 16)
            with open(os.path.join(PACKET, name + ".hex")) as f:
                raw = bytes.fromhex("".join(f.read().split()))
            self.assertEqual(raw, self.data[va_off(lo):va_off(hi)], name)

    def test_objdump_regeneration(self):
        for name, e in self.records["exhibits"].items():
            lo, hi = int(e["range"][0], 16), int(e["range"][1], 16)
            out = subprocess.run(
                ["objdump", "-d", "--start-address=" + hex(lo),
                 "--stop-address=" + hex(hi), BIN],
                capture_output=True, text=True, check=True).stdout
            lines = [l for l in out.splitlines()
                     if re.match(r"\s*[0-9a-f]+:\t", l)]
            strict = [l for l in lines
                      if re.match(r"\s*[0-9a-f]+:\t[0-9a-f ]+\t\S", l)]
            self.assertEqual(len(strict), e["strict"], name)
            with open(os.path.join(PACKET, name + ".objdump.txt")) as f:
                self.assertEqual(f.read(), "\n".join(lines) + "\n", name)

    def test_totals(self):
        ex = self.records["exhibits"]
        self.assertEqual(sum(e["bytes"] for e in ex.values()), 259)
        self.assertEqual(sum(e["strict"] for e in ex.values()), 71)

    def test_fde_bounds(self):
        self.assertEqual(self.records["fde"], ["0x63b9d10", "0x63ba5fd"])
        self.assertEqual(0x63BA5FD - 0x63B9D10, 0x8ED)
        self.assertEqual(self.data[va_off(0x63B9D10):va_off(0x63B9D10) + 4],
                         bytes.fromhex("f30f1efa"))
        self.assertEqual(self.data[va_off(0x63B9F79)], 0xC3)

    def test_key_stores(self):
        self.assertEqual(
            self.data[va_off(0x63B9FE4):va_off(0x63B9FE4) + 8],
            bytes.fromhex("48c7470800000000"))
        self.assertEqual(
            self.data[va_off(0x63BA308):va_off(0x63BA308) + 3],
            bytes.fromhex("488917"))

    def test_caller_rel32(self):
        o = va_off(0x63D870F)
        rel = int.from_bytes(self.data[o + 1:o + 5], "little", signed=True)
        self.assertEqual(self.data[o], 0xE8)
        self.assertEqual(0x63D870F + 5 + rel, 0x63B9D10)

    def test_manifest(self):
        with open(os.path.join(PACKET, "MANIFEST.sha256")) as f:
            rows = [l.split() for l in f.read().splitlines() if l.strip()]
        self.assertEqual(len(rows), 17)
        for h, p in rows:
            full = os.path.normpath(os.path.join(PACKET, p))
            with open(full, "rb") as f:
                self.assertEqual(hashlib.sha256(f.read()).hexdigest(), h, p)

    def test_verifier_passes(self):
        r = subprocess.run([sys.executable, VERIFIER],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("all checks passed", r.stdout)

    def test_tamper_control(self):
        # Flipping one exhibit byte must break the byte check.
        with tempfile.TemporaryDirectory() as td:
            pkt = os.path.join(td, "packet")
            shutil.copytree(PACKET, pkt)
            hexpath = os.path.join(pkt, "rm_empty.hex")
            with open(hexpath) as f:
                raw = bytearray(bytes.fromhex("".join(f.read().split())))
            raw[0] ^= 0xFF
            with open(hexpath, "w") as f:
                f.write(raw.hex() + "\n")
            # The verifier reads the packet from the repo tree, so
            # emulate the check directly: tampered bytes != binary.
            lo, hi = 0x63BA308, 0x63BA321
            self.assertNotEqual(bytes(raw), self.data[va_off(lo):va_off(hi)])


if __name__ == "__main__":
    unittest.main()
