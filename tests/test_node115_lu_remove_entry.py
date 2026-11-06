#!/usr/bin/env python3
"""Unit tests for the node115 lu remove-entry packet.

Regeneration comparison (objdump header line stripped, as in packet
#224) plus a tamper control: flipping one exhibit byte must fail
the verifier's byte check.
"""
import json
import os
import re
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(ROOT, "research", "work-items",
                      "RE-001-node115-lu-remove-entry")
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
VERIFIER = os.path.join(ROOT, "tools", "node115_lu_remove_entry.py")


def va_off(va):
    return va - 0x1000


class TestRemoveEntry(unittest.TestCase):
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
            with open(os.path.join(PACKET, name + ".objdump.txt")) as f:
                saved = f.read()
            self.assertEqual(saved, "\n".join(lines) + "\n", name)

    def test_strict_counts(self):
        for name, e in self.records["exhibits"].items():
            with open(os.path.join(PACKET, name + ".objdump.txt")) as f:
                lines = f.read().splitlines()
            strict = [l for l in lines
                      if re.match(r"\s*[0-9a-f]+:\t[0-9a-f ]+\t\S", l)]
            self.assertEqual(len(strict), e["strict"], name)

    def test_fde_bounds(self):
        lo, hi = (int(x, 16) for x in self.records["fde"])
        self.assertEqual((lo, hi), (0x63D8630, 0x63D8790))
        self.assertEqual(hi - lo, 352)

    def test_entry_and_rets(self):
        self.assertEqual(self.data[va_off(0x63D8630):va_off(0x63D8630) + 2],
                         bytes([0x41, 0x56]))
        for site in (0x63D8690, 0x63D8745, 0x63D876C):
            self.assertEqual(self.data[va_off(site)], 0xC3, hex(site))

    def test_call_rel32s(self):
        import struct
        for site, tgt in ((0x63D86A8, 0x63E8BF0), (0x63D870F, 0x63B9D10),
                          (0x63D8717, 0x63B9680)):
            off = va_off(site)
            rel = struct.unpack("<i", self.data[off + 1:off + 5])[0]
            self.assertEqual(self.data[off], 0xE8, hex(site))
            self.assertEqual(site + 5 + rel, tgt, hex(site))

    def test_tamper_control(self):
        # Flipping one exhibit byte must break the byte comparison.
        name = "re_entry"
        e = self.records["exhibits"][name]
        lo = int(e["range"][0], 16)
        with open(os.path.join(PACKET, name + ".hex")) as f:
            raw = bytearray(bytes.fromhex("".join(f.read().split())))
        raw[0] ^= 0xFF
        self.assertNotEqual(bytes(raw),
                            self.data[va_off(lo):va_off(lo) + len(raw)])

    def test_verifier_passes(self):
        out = subprocess.run([sys.executable, VERIFIER],
                             capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stdout[-500:])
        self.assertIn("all checks passed", out.stdout)

    def test_manifest_covers_packet(self):
        with open(os.path.join(PACKET, "MANIFEST.sha256")) as f:
            lines = [l for l in f.read().splitlines() if l.strip()]
        self.assertEqual(len(lines), 17)
        for l in lines:
            h, p = l.split(None, 1)
            full = os.path.normpath(os.path.join(PACKET, p.lstrip("*")))
            self.assertTrue(os.path.exists(full), p)


if __name__ == "__main__":
    unittest.main()
