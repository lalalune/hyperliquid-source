#!/usr/bin/env python3
"""Unit tests for the packet #261 verifier (node115_value_leaves_bin).

Tamper tests run first (test_01..test_03) and must FAIL the verifier
before any green run is trusted (packet #257's lesson). Run standalone:
  python3 tests/test_node115_value_leaves_bin.py
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PKT = os.path.join(ROOT,
                   "research/work-items/RE-001-node115-lu-value-leaves-bin")
BIN = os.path.join(ROOT, "artifacts/node/115/hl-node")
VERIFIER = os.path.join(ROOT, "tools/node115_value_leaves_bin.py")
STRICT_RE = re.compile(r"^\s*[0-9a-f]+:\s+[0-9a-f ]+\s+[a-z]")


def run_verifier(root, scan_roots=None):
    env = dict(os.environ)
    if scan_roots is not None:
        env["HL261_SCAN_ROOTS"] = scan_roots
    return subprocess.run([sys.executable, VERIFIER, root],
                          capture_output=True, text=True, env=env)


def make_temp_root():
    tmp = tempfile.mkdtemp(prefix="hl261test-")
    pkt_dst = os.path.join(
        tmp, "research/work-items/RE-001-node115-lu-value-leaves-bin")
    shutil.copytree(PKT, pkt_dst)
    bin_dst = os.path.join(tmp, "artifacts/node/115")
    os.makedirs(bin_dst)
    os.symlink(BIN, os.path.join(bin_dst, "hl-node"))
    empty_scan = os.path.join(tmp, "scan")
    os.makedirs(empty_scan)
    # MANIFEST's ../../../ entries must resolve from the packet dir;
    # in temp roots they are empty placeholders, so hash checks there
    # fail by design — tamper tests only need a nonzero exit.
    for sub in ("tools", "tests"):
        os.makedirs(os.path.join(tmp, sub), exist_ok=True)
    open(os.path.join(tmp, "tools",
                      "node115_value_leaves_bin.py"), "w").close()
    open(os.path.join(tmp, "tests",
                      "test_node115_value_leaves_bin.py"), "w").close()
    return tmp, pkt_dst, empty_scan


class TestTamperFirst(unittest.TestCase):
    def test_01_tamper_hex_fails(self):
        tmp, pkt_dst, scan = make_temp_root()
        try:
            p = os.path.join(pkt_dst, "opt_prof.hex")
            b = bytearray(open(p, "rb").read())
            b[0] ^= 0xFF
            open(p, "wb").write(bytes(b))
            r = run_verifier(tmp, scan_roots=scan)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("FAIL", r.stdout)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_02_tamper_strict_fails(self):
        tmp, pkt_dst, scan = make_temp_root()
        try:
            rp = os.path.join(pkt_dst, "records.json")
            with open(rp) as fh:
                rec = json.load(fh)
            rec["exhibits"][0]["strict"] += 1
            with open(rp, "w") as fh:
                json.dump(rec, fh)
            r = run_verifier(tmp, scan_roots=scan)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("FAIL", r.stdout)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_03_tamper_overlap_fails(self):
        tmp, pkt_dst, scan = make_temp_root()
        try:
            fake_dir = os.path.join(scan, "RE-001-node115-fake")
            os.makedirs(fake_dir)
            fake = {"exhibits": [{"name": "x",
                                  "range": "0x63737c0..0x6373846"}]}
            with open(os.path.join(fake_dir, "records.json"), "w") as fh:
                json.dump(fake, fh)
            r = run_verifier(tmp, scan_roots=scan)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("overlap", r.stdout)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestGreen(unittest.TestCase):
    def test_04_verifier_exit_0(self):
        r = run_verifier(ROOT)
        self.assertEqual(r.returncode, 0, r.stdout[-3000:])
        self.assertIn("RESULT: PASS", r.stdout)

    def test_05_hex_regeneration(self):
        rec = json.load(open(os.path.join(PKT, "records.json")))
        data = open(BIN, "rb").read()
        for ex in rec["exhibits"]:
            m = re.fullmatch(r"0x([0-9a-f]+)\.\.0x([0-9a-f]+)",
                             ex["range"])
            s, e = int(m.group(1), 16), int(m.group(2), 16)
            raw = open(os.path.join(PKT, ex["name"] + ".hex"),
                       "rb").read()
            self.assertEqual(raw, data[s - 0x1000:e - 0x1000],
                             ex["name"])

    def test_06_objdump_regeneration(self):
        rec = json.load(open(os.path.join(PKT, "records.json")))
        for ex in rec["exhibits"]:
            m = re.fullmatch(r"0x([0-9a-f]+)\.\.0x([0-9a-f]+)",
                             ex["range"])
            s, e = int(m.group(1), 16), int(m.group(2), 16)
            r = subprocess.run(["objdump", "-d",
                                "--start-address=%s" % hex(s),
                                "--stop-address=%s" % hex(e), BIN],
                               capture_output=True, text=True)
            strip = lambda t: "\n".join(
                l for l in t.splitlines() if "file format" not in l)
            stored = open(os.path.join(PKT,
                                       ex["name"] + ".objdump.txt")).read()
            self.assertEqual(strip(r.stdout), strip(stored), ex["name"])

    def test_07_strict_counts(self):
        rec = json.load(open(os.path.join(PKT, "records.json")))
        for ex in rec["exhibits"]:
            txt = open(os.path.join(PKT,
                                    ex["name"] + ".objdump.txt")).read()
            strict = sum(1 for l in txt.splitlines()
                         if STRICT_RE.match(l))
            self.assertEqual(strict, ex["strict"], ex["name"])

    def test_08_named_sites(self):
        import struct
        data = open(BIN, "rb").read()
        named = [
            (0x63ed3fd, 0xE8, 0x63ec4c0), (0x63ed50c, 0xE8, 0x63ec4c0),
            (0x63ed5ad, 0xE8, 0x63ec4c0), (0x63ed63a, 0xE8, 0x63ec4c0),
            (0x63ed3e1, 0xE8, 0x634ebb0), (0x63ed5e9, 0xE8, 0x634ebb0),
            (0x63ed723, 0xE8, 0x634ebb0),
            (0x63ef834, 0xE8, 0x63c3b70), (0x63ef83c, 0xE8, 0x63539d0),
            (0x63ef844, 0xE8, 0x6353a20), (0x63ef858, 0xE8, 0x63efd20),
            (0x634f44f, 0xE8, 0x63c41c0), (0x63ee02d, 0xE9, 0x63ec4c0),
        ]
        for site, op, tgt in named:
            off = site - 0x1000
            self.assertEqual(data[off], op, hex(site))
            rel = struct.unpack_from("<i", data, off + 1)[0]
            self.assertEqual(site + 5 + rel, tgt, hex(site))

    def test_09_leaf_arithmetic(self):
        rec = json.load(open(os.path.join(PKT, "records.json")))
        self.assertEqual(rec["leaves_classified_before"]
                         + len(rec["leaves_classified_here"])
                         + rec["leaves_remaining_unclassified"], 204)

    def test_10_manifest(self):
        import hashlib
        man = {}
        for line in open(os.path.join(PKT, "MANIFEST.sha256")):
            parts = line.split()
            if len(parts) == 2:
                man[parts[1]] = parts[0]
        for rel, want in man.items():
            p = os.path.normpath(os.path.join(PKT, rel))
            got = hashlib.sha256(open(p, "rb").read()).hexdigest()
            self.assertEqual(got, want, rel)


if __name__ == "__main__":
    unittest.main(verbosity=2)
