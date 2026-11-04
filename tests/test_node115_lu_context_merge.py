#!/usr/bin/env python3
"""Unit tests for packet #249 (node #115 lu context merge).

Regeneration comparison + tamper control. Objdump's header embeds the
invoked path, so comparisons strip the header line (address-tab lines
only), as in packet #224's test.
"""
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(ROOT, "research/work-items/RE-001-node115-lu-context-merge")
BINARY = os.path.join(ROOT, "artifacts/node/115/hl-node")
sys.path.insert(0, os.path.join(ROOT, "tools"))
import node115_lu_context_merge as verifier  # noqa: E402

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


class TestContextMerge(unittest.TestCase):
    def test_verifier_passes(self):
        r = subprocess.run([sys.executable,
                            os.path.join(ROOT, "tools/node115_lu_context_merge.py")],
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
        self.assertEqual(sum(e["strict"] for e in REC["exhibits"].values()), 51)
        self.assertEqual(sum(e["bytes"] for e in REC["exhibits"].values()), 333)

    def test_fde_bounds_and_padding(self):
        lo, hi = int(REC["fde"][0], 16), int(REC["fde"][1], 16)
        self.assertEqual(hi - lo, 839)
        self.assertEqual(RAW[off(lo):off(lo) + 4], bytes.fromhex("f30f1efa"))
        self.assertEqual(RAW[off(0x63d8b15):off(0x63d8b20)], b"\xcc" * 11)
        self.assertEqual(RAW[off(hi):off(hi) + 9], b"\xcc" * 9)
        self.assertEqual(RAW[off(0x63d8e70):off(0x63d8e70) + 4],
                         bytes.fromhex("f30f1efa"))

    def test_ret_site_and_jumps(self):
        full = objdump_lines(0x63d8b20, 0x63d8e67)
        rets = [int(l.split(":")[0].strip(), 16) for l in full
                if len(l.split("\t")) >= 3 and l.split("\t")[2].split()[0] == "ret"]
        self.assertEqual(rets, [0x63d8e66])
        calls = [l for l in full
                 if len(l.split("\t")) >= 3 and l.split("\t")[2].split()[0] == "call"]
        self.assertEqual(calls, [])
        jne = [l for l in full
               if len(l.split("\t")) >= 3 and l.split("\t")[2].split()[0] == "jne"]
        self.assertEqual(len(jne), 1)
        self.assertIn("63d8be0", jne[0])

    def test_key_bytes(self):
        self.assertEqual(RAW[off(0x63d8b24):off(0x63d8b2a)],
                         bytes.fromhex("4889f14889f8"))
        self.assertEqual(RAW[off(0x63d8b8c):off(0x63d8b93)],
                         bytes.fromhex("4c8d91000c0000"))
        self.assertEqual(RAW[off(0x63d8bea):off(0x63d8bf7)],
                         bytes.fromhex("4881c180010000480580010000"))

    def test_census_call_sites(self):
        for site in REC["census"]["e8_to_fde"]:
            s = int(site, 16)
            o = off(s)
            self.assertEqual(RAW[o], 0xE8, site)
            self.assertEqual(s + 5 + struct.unpack("<i", RAW[o + 1:o + 5])[0],
                             0x63d8b20, site)
        self.assertEqual(REC["census"]["rela_dyn_entries"], 60723)
        self.assertEqual(REC["census"]["rela_dyn_addend_hits"], 0)

    def test_manifest_hashes(self):
        with open(os.path.join(PACKET, "MANIFEST.sha256")) as _f:
            man = _f.read().strip().splitlines()
        self.assertEqual(len(man), 13)
        for line in man:
            h, path = line.split(None, 1)
            full = os.path.normpath(os.path.join(PACKET, path.strip().lstrip("*")))
            with open(full, "rb") as _f:
                digest = hashlib.sha256(_f.read()).hexdigest()
            self.assertEqual(digest, h, path)

    def test_tamper_control(self):
        with tempfile.TemporaryDirectory() as tmp:
            copy = os.path.join(tmp, "packet")
            shutil.copytree(PACKET, copy)
            p = os.path.join(copy, "mg_entry.hex")
            with open(p) as _f:
                data = _f.read()
            flipped = ("00" if data[:2] != "00" else "ff") + data[2:]
            with open(p, "w") as _f:
                _f.write(flipped)
            old = verifier.PACKET
            verifier.PACKET = copy
            try:
                verifier.FAILURES.clear()
                verifier.main()
            except SystemExit as e:
                self.assertNotEqual(e.code, 0)
            else:
                self.fail("tampered packet passed verification")
            finally:
                verifier.PACKET = old


if __name__ == "__main__":
    unittest.main()
