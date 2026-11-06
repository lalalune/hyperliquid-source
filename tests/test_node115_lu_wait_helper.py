#!/usr/bin/env python3
"""Unit tests for RE-001-node115-lu-wait-helper (packet #251).

Regeneration comparison strips the objdump header line (which embeds the
invoked path), as packet #224's test does. The tamper control flips a byte
of wt_entry.hex, expects the verifier to fail, then restores the file.
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
PACKET = os.path.join(ROOT, "research/work-items/RE-001-node115-lu-wait-helper")
NODE = os.path.join(ROOT, "artifacts/node/115/hl-node")
VERIFIER = os.path.join(ROOT, "tools/node115_lu_wait_helper.py")
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


class TestWaitHelper(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = open(NODE, "rb").read()
        cls.records = json.load(open(os.path.join(PACKET, "records.json")))

    def test_binary_sha_and_size(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), SHA)
        self.assertEqual(len(self.data), 105896032)

    def test_fde_bounds_and_padding(self):
        lo, hi = 0x63bf680, 0x63bf7ee
        self.assertEqual(hi - lo, 366)
        self.assertEqual(self.data[off(lo):off(lo) + 4], bytes.fromhex("f30f1efa"))
        self.assertEqual(self.data[off(0x63bf677):off(lo)], b"\xcc" * 9)
        self.assertEqual(self.data[off(hi):off(0x63bf7f0)], b"\xcc" * 2)
        self.assertEqual(self.data[off(0x63bf71d)], 0xC3)

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

    def test_key_bytes(self):
        self.assertEqual(self.data[off(0x63bf68e):off(0x63bf68e) + 4], bytes.fromhex("488d6f40"))
        self.assertEqual(self.data[off(0x63bf745):off(0x63bf745) + 5], bytes.fromhex("f0410fc118"))
        self.assertEqual(self.data[off(0x63bf761):off(0x63bf761) + 6], bytes.fromhex("41c644246801"))
        # The GOT slot is zero-filled in the file (RELATIVE reloc applied
        # at load); check the relocation entry instead of file bytes.
        rela = subprocess.run(["readelf", "-rW", NODE], capture_output=True, text=True).stdout
        self.assertTrue(any("64df1e8" in ln and "R_X86_64_RELATIVE" in ln and "63bfa70" in ln
                            for ln in rela.splitlines()))

    def test_internal_call_rel32_spot(self):
        for site, tgt in [(0x63bf6ee, 0x63f17b0), (0x63bf750, 0x63f17b0),
                          (0x63bf75c, 0x63f0b60), (0x63bf730, 0x63bfcf0)]:
            o = off(site)
            rel = struct.unpack("<i", self.data[o + 1:o + 5])[0]
            self.assertEqual(self.data[o], 0xE8)
            self.assertEqual(site + 5 + rel, tgt)

    def test_caller_b_sites_rel32(self):
        for site in (0x63b92e3, 0x63b92fb):
            o = off(site)
            rel = struct.unpack("<i", self.data[o + 1:o + 5])[0]
            self.assertEqual(self.data[o], 0xE8)
            self.assertEqual(site + 5 + rel, 0x63bf680)

    def test_manifest_hashes(self):
        man = open(os.path.join(PACKET, "MANIFEST.sha256")).read().splitlines()
        self.assertEqual(len([l for l in man if l.strip()]), 15)
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
        hexpath = os.path.join(PACKET, "wt_entry.hex")
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
