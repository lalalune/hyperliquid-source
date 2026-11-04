#!/usr/bin/env python3
"""Unit tests for RE-001-node115-lu-wait-callers (packet #252).

Regeneration comparison strips the objdump header line (which embeds the
invoked path), as packet #224's test does. The tamper control flips a byte
of g_wait.hex, expects the verifier to fail, then restores the file.
"""
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(ROOT, "research/work-items/RE-001-node115-lu-wait-callers")
NODE = os.path.join(ROOT, "artifacts/node/115/hl-node")
VERIFIER = os.path.join(ROOT, "tools/node115_lu_wait_callers.py")
SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def off(va):
    return va - 0x1000


def objdump_lines(lo, hi):
    out = subprocess.run(
        ["objdump", "-d", "--start-address=" + hex(lo), "--stop-address=" + hex(hi), NODE],
        capture_output=True, text=True).stdout
    lines = []
    for line in out.splitlines():
        m = re.match(r"\s+([0-9a-f]+):\t([0-9a-f ]+)\t(\S.*)", line)
        if m and lo <= int(m.group(1), 16) < hi:
            lines.append(line.strip())
    return lines


class TestWaitCallers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = open(NODE, "rb").read()
        cls.records = json.load(open(os.path.join(PACKET, "records.json")))

    def test_binary_sha_and_size(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), SHA)
        self.assertEqual(len(self.data), 105896032)

    def test_cited_fde_bounds_and_entries(self):
        for lo, hi, size in [(0x63CF9D0, 0x63CFF1B, 1355), (0x6364280, 0x6364342, 194),
                             (0x63B5A40, 0x63B5B3D, 253), (0x63EC7A0, 0x63EC900, 352)]:
            self.assertEqual(hi - lo, size, hex(lo))
        self.assertEqual(self.data[off(0x63CF9D0):off(0x63CF9D0) + 4], bytes.fromhex("f30f1efa"))
        self.assertEqual(self.data[off(0x6364280):off(0x6364280) + 4], bytes.fromhex("f30f1efa"))
        self.assertEqual(self.data[off(0x63B5A40):off(0x63B5A40) + 4], bytes.fromhex("f30f1efa"))
        # The 0x63ec7a0 FDE starts with pushes, not endbr64 (packet #238 lesson).
        self.assertEqual(self.data[off(0x63EC7A0):off(0x63EC7A0) + 2], bytes.fromhex("4156"))

    def test_exhibit_bytes(self):
        for name, ex in self.records["exhibits"].items():
            lo = int(ex["range"][0], 16)
            hi = int(ex["range"][1], 16)
            raw = bytes.fromhex("".join(open(os.path.join(PACKET, name + ".hex")).read().split()))
            self.assertEqual(len(raw), ex["bytes"])
            self.assertEqual(self.data[off(lo):off(hi)], raw)

    def test_objdump_regeneration_stripped(self):
        # Header line embeds the invoked path; strip it on both sides.
        for name, ex in self.records["exhibits"].items():
            lo = int(ex["range"][0], 16)
            hi = int(ex["range"][1], 16)
            regen = objdump_lines(lo, hi)
            saved = [l for l in open(os.path.join(PACKET, name + ".objdump.txt")).read().splitlines() if l.strip()]
            self.assertEqual(regen, saved, name)
            self.assertEqual(len(regen), ex["strict"], name)

    def test_exhibit_call_rel32(self):
        for site, tgt in [(0x63CFEF2, 0x63BF680), (0x63CFF0A, 0x63BF680),
                          (0x6364334, 0x63BF680), (0x63B5B2C, 0x63BF680),
                          (0x63EC897, 0x63BF680), (0x63642CA, 0x63F17B0),
                          (0x63B5A5C, 0x63F17B0)]:
            o = off(site)
            rel = struct.unpack("<i", self.data[o + 1:o + 5])[0]
            self.assertEqual(self.data[o], 0xE8)
            self.assertEqual(site + 5 + rel, tgt, hex(site))

    def test_surveyed_crosscheck_bytes(self):
        # Non-exhibited surveyed bytes: r28 trylock setup and the global unlock path.
        self.assertEqual(self.data[off(0x63EC7B2):off(0x63EC7B2) + 7],
                         bytes.fromhex("4c8dade8280000"))
        o = off(0x63EC7BC)
        self.assertEqual(0x63EC7BC + 5 + struct.unpack("<i", self.data[o + 1:o + 5])[0], 0x63F17B0)
        self.assertEqual(self.data[off(0x63CFEB4):off(0x63CFEB4) + 5],
                         bytes.fromhex("41c6416800"))
        self.assertEqual(self.data[off(0x63CFEB9):off(0x63CFEB9) + 4],
                         bytes.fromhex("498d7940"))
        o = off(0x63CFEBD)
        self.assertEqual(0x63CFEBD + 5 + struct.unpack("<i", self.data[o + 1:o + 5])[0], 0x63F0B70)

    def test_record_offset_arithmetic(self):
        self.assertEqual(0x38 + 0x40, 0x78)
        self.assertEqual(0x38 + 0x68, 0xA0)
        self.assertEqual(0x18 + 0x40, 0x58)
        self.assertEqual(0x18 + 0x68, 0x80)
        self.assertEqual(0x28A8 + 0x40, 0x28E8)
        self.assertEqual(0x28A8 + 0x68, 0x2910)
        self.assertEqual(0x67145A0 + 0x68, 0x6714608)
        self.assertEqual(0x6714520 + 0x68, 0x6714588)

    def test_manifest_hashes(self):
        man = open(os.path.join(PACKET, "MANIFEST.sha256")).read().splitlines()
        self.assertEqual(len([l for l in man if l.strip()]), 17)
        for line in man:
            if not line.strip():
                continue
            h, p = line.split(None, 1)
            p = p.strip()
            fp = os.path.join(ROOT, p[9:]) if p.startswith("../../../") else os.path.join(PACKET, p)
            self.assertEqual(hashlib.sha256(open(fp, "rb").read()).hexdigest(), h, p)

    def test_verifier_exit_0(self):
        r = subprocess.run([sys.executable, VERIFIER], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout[-2000:] + r.stderr[-2000:])
        self.assertIn("all checks passed", r.stdout)

    def test_tamper_control(self):
        hexpath = os.path.join(PACKET, "g_wait.hex")
        orig = open(hexpath).read()
        try:
            raw = bytearray(bytes.fromhex("".join(orig.split())))
            raw[0] ^= 0xFF
            open(hexpath, "w").write(raw.hex() + "\n")
            r = subprocess.run([sys.executable, VERIFIER], capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0)
        finally:
            open(hexpath, "w").write(orig)
        self.assertEqual(open(hexpath).read(), orig)


if __name__ == "__main__":
    unittest.main()
