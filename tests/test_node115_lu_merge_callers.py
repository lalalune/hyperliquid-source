#!/usr/bin/env python3
"""Unit tests for packet #250 (node #115 lu merge callers).

Regeneration comparison + tamper control. Objdump's header embeds the
invoked path, so comparisons strip the header line (address-tab lines
only), as in packet #224's test.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(ROOT, "research/work-items/RE-001-node115-lu-merge-callers")
BINARY = os.path.join(ROOT, "artifacts/node/115/hl-node")
sys.path.insert(0, os.path.join(ROOT, "tools"))
import node115_lu_merge_callers as verifier  # noqa: E402

with open(os.path.join(PACKET, "records.json")) as _f:
    REC = json.load(_f)
with open(BINARY, "rb") as _f:
    RAW = _f.read()


def off(va):
    return va - 0x1000


def objdump_lines(lo, hi):
    out = subprocess.run(
        ["objdump", "-d", "--start-address=%s" % hex(lo),
         "--stop-address=%s" % hex(hi), BINARY],
        capture_output=True, text=True, check=True).stdout
    return [l for l in out.splitlines() if re.match(r"^\s*[0-9a-f]+:\t", l)]


class TestMergeCallers(unittest.TestCase):
    def test_verifier_passes(self):
        r = subprocess.run([sys.executable,
                            os.path.join(ROOT, "tools/node115_lu_merge_callers.py")],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout[-2000:])

    def test_exhibit_bytes_match_binary(self):
        for name, e in REC["exhibits"].items():
            lo, hi = int(e["range"][0], 16), int(e["range"][1], 16)
            with open(os.path.join(PACKET, name + ".hex")) as _f:
                hexs = "".join(_f.read().split())
            self.assertEqual(RAW[off(lo):off(hi)], bytes.fromhex(hexs), name)
            self.assertEqual(len(bytes.fromhex(hexs)), e["bytes"], name)

    def test_objdump_regeneration(self):
        for name, e in REC["exhibits"].items():
            lo, hi = int(e["range"][0], 16), int(e["range"][1], 16)
            with open(os.path.join(PACKET, name + ".objdump.txt")) as _f:
                stored = _f.read()
            self.assertEqual(stored, "\n".join(objdump_lines(lo, hi)) + "\n", name)

    def test_strict_counts(self):
        for name, e in REC["exhibits"].items():
            lo, hi = int(e["range"][0], 16), int(e["range"][1], 16)
            strict = sum(1 for l in objdump_lines(lo, hi) if l.count("\t") >= 2)
            self.assertEqual(strict, e["strict"], name)
        self.assertEqual(sum(e["strict"] for e in REC["exhibits"].values()), 86)
        self.assertEqual(sum(e["bytes"] for e in REC["exhibits"].values()), 382)

    def test_fde_bounds_and_padding(self):
        a_lo, a_hi = (int(x, 16) for x in REC["callerA"]["fde"])
        b_lo, b_hi = (int(x, 16) for x in REC["callerB"]["fde"])
        self.assertEqual(a_hi - a_lo, 82)
        self.assertEqual(b_hi - b_lo, 300)
        self.assertEqual(RAW[off(a_lo):off(a_lo) + 4], bytes.fromhex("f30f1efa"))
        self.assertEqual(RAW[off(b_lo):off(b_lo) + 4], bytes.fromhex("f30f1efa"))
        self.assertEqual(RAW[off(a_hi):off(b_lo)], b"\xcc" * 14)
        self.assertEqual(RAW[off(b_hi):off(b_hi) + 4], b"\xcc" * 4)
        self.assertEqual(RAW[off(b_hi) + 4:off(b_hi) + 8],
                         bytes.fromhex("f30f1efa"))

    def test_ret_and_tail_exit(self):
        self.assertEqual(RAW[off(0x63b91d1)], 0xC3)
        lines = objdump_lines(0x63b91e0, 0x63b930c)
        mnems = [l.split("\t")[2].split()[0] for l in lines if l.count("\t") >= 2]
        self.assertNotIn("ret", mnems)
        self.assertIn("jmp", mnems)

    def test_key_bytes(self):
        self.assertEqual(RAW[off(0x63b92b0):off(0x63b92b0) + 7],
                         bytes.fromhex("c683a800000000"))
        self.assertEqual(RAW[off(0x63b92bf):off(0x63b92bf) + 7],
                         bytes.fromhex("c6831801000000"))
        self.assertEqual(RAW[off(0x63b9219):off(0x63b9219) + 8],
                         bytes.fromhex("488383e800000001"))

    def test_census_call_sites(self):
        import struct
        for site, tgt in [(0x63a734e, 0x63b9180), (0x63c0ad3, 0x63b91e0),
                          (0x63b9190, 0x63d8b20), (0x63b9272, 0x63d8b20)]:
            o = off(site)
            self.assertEqual(RAW[o], 0xE8, hex(site))
            rel = struct.unpack("<i", RAW[o + 1:o + 5])[0]
            self.assertEqual(site + 5 + rel, tgt, hex(site))

    def test_manifest_hashes(self):
        import hashlib
        with open(os.path.join(PACKET, "MANIFEST.sha256")) as _f:
            lines = [l.split() for l in _f.read().splitlines() if l.strip()]
        self.assertEqual(len(lines), 15)
        for h, rel in lines:
            p = os.path.normpath(os.path.join(PACKET, rel))
            self.assertTrue(os.path.exists(p), rel)
            self.assertEqual(hashlib.sha256(open(p, "rb").read()).hexdigest(), h, rel)

    def test_tamper_control(self):
        tmp = tempfile.mkdtemp()
        try:
            dst = os.path.join(tmp, "mc_callA.hex")
            shutil.copy(os.path.join(PACKET, "mc_callA.hex"), dst)
            with open(dst, "r+") as _f:
                s = _f.read()
                _f.seek(0)
                _f.write(("00" if s[:2] != "00" else "ff") + s[2:])
            with open(dst) as _f:
                hexs = "".join(_f.read().split())
            lo = int(REC["exhibits"]["mc_callA"]["range"][0], 16)
            hi = int(REC["exhibits"]["mc_callA"]["range"][1], 16)
            self.assertNotEqual(RAW[off(lo):off(hi)], bytes.fromhex(hexs))
        finally:
            shutil.rmtree(tmp)


if __name__ == "__main__":
    unittest.main()
