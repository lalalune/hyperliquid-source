#!/usr/bin/env python3
"""Unit tests for RE-001-node115-lu-wait-provenance (packet #253).

Regeneration comparison strips the objdump header line (which embeds the
invoked path), as packet #224's test does. The tamper control flips a byte
of pv_loop_calc.hex, expects the verifier to fail, then restores the file.
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
PACKET = os.path.join(ROOT, "research/work-items/RE-001-node115-lu-wait-provenance")
NODE = os.path.join(ROOT, "artifacts/node/115/hl-node")
VERIFIER = os.path.join(ROOT, "tools/node115_lu_wait_provenance.py")
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


class TestWaitProvenance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = open(NODE, "rb").read()
        cls.records = json.load(open(os.path.join(PACKET, "records.json")))

    def test_binary_sha_and_size(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), SHA)
        self.assertEqual(len(self.data), 105896032)

    def test_fde_bounds_and_entry(self):
        self.assertEqual(0x63A6470 - 0x63A5BF0, 2176)
        self.assertEqual(self.data[off(0x63A5BF0):off(0x63A5BF0) + 4], bytes.fromhex("f30f1efa"))
        self.assertEqual(self.data[off(0x63A5BEF)], 0xCC)
        self.assertEqual(self.data[off(0x63A615B)], 0xC3)

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

    def test_all_18_helper_sites_rel32(self):
        for site in self.records["census"]["sites"]:
            s = int(site, 16)
            o = off(s)
            rel = struct.unpack("<i", self.data[o + 1:o + 5])[0]
            self.assertEqual(self.data[o], 0xE8)
            self.assertEqual(s + 5 + rel, 0x63BF680, site)

    def test_exhibit_call_and_trylock_rel32(self):
        for site, tgt in [(0x63A610A, 0x63BF680), (0x63A6191, 0x63BF680),
                          (0x63A6461, 0x63BF680), (0x63A60FE, 0x63F17B0),
                          (0x63A6017, 0x63F17B0), (0x63A62A1, 0x63F17B0)]:
            o = off(site)
            rel = struct.unpack("<i", self.data[o + 1:o + 5])[0]
            self.assertEqual(self.data[o], 0xE8)
            self.assertEqual(site + 5 + rel, tgt, hex(site))

    def test_surveyed_crosscheck_bytes(self):
        self.assertEqual(self.data[off(0x63A61BD):off(0x63A61BD) + 3], bytes.fromhex("4c89ff"))
        self.assertEqual(self.data[off(0x63A61CA):off(0x63A61CA) + 8],
                         bytes.fromhex("41c6819029000001"))
        self.assertEqual(self.data[off(0x63A5CC3):off(0x63A5CC3) + 7],
                         bytes.fromhex("488d0df6391600"))

    # Record-offset arithmetic for all 18 sites is checked by the verifier
    # itself (run by test_verifier_exit_0); no separate test duplicates it.

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
        hexpath = os.path.join(PACKET, "pv_loop_calc.hex")
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
