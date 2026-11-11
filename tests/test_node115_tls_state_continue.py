#!/usr/bin/env python3
"""Unit tests for the packet #260 verifier (node115_tls_state_continue).

Tamper tests run first (test_01..test_03) and must FAIL the verifier
before any green run is trusted (packet #257's lesson). Run standalone:
  python3 tests/test_node115_tls_state_continue.py
"""
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PKT = os.path.join(ROOT,
                   "research/work-items/RE-001-node115-lu-tls-state-continue")
BIN = os.path.join(ROOT, "artifacts/node/115/hl-node")
VERIFIER = os.path.join(ROOT, "tools/node115_tls_state_continue.py")
STRICT_RE = re.compile(r"^[ \t]+[0-9a-f]+:[ \t]+[0-9a-f ]+[ \t]+[a-z]")
LABEL_RE = re.compile(r"^[0-9a-f]+ <.*>:$")


def run_verifier(root, scan_roots=None):
    env = dict(os.environ)
    if scan_roots is not None:
        env["HL260_SCAN_ROOTS"] = scan_roots
    return subprocess.run([sys.executable, VERIFIER, root],
                          capture_output=True, text=True, env=env)


def make_temp_root():
    tmp = tempfile.mkdtemp(prefix="hl260test-")
    pkt_dst = os.path.join(
        tmp, "research/work-items/RE-001-node115-lu-tls-state-continue")
    shutil.copytree(PKT, pkt_dst)
    bin_dst = os.path.join(tmp, "artifacts/node/115")
    os.makedirs(bin_dst)
    os.symlink(BIN, os.path.join(bin_dst, "hl-node"))
    empty_scan = os.path.join(tmp, "scan")
    os.makedirs(empty_scan)
    # MANIFEST's ../../../ entries must resolve from the packet dir;
    # existence (not content) is what the verifier checks there.
    for sub in ("tools", "tests"):
        os.makedirs(os.path.join(tmp, sub), exist_ok=True)
    open(os.path.join(tmp, "tools",
                      "node115_tls_state_continue.py"), "w").close()
    open(os.path.join(tmp, "tests",
                      "test_node115_tls_state_continue.py"), "w").close()
    return tmp, pkt_dst, empty_scan


class TestTamperFirst(unittest.TestCase):
    def test_01_tamper_hex_fails(self):
        tmp, pkt_dst, scan = make_temp_root()
        try:
            p = os.path.join(pkt_dst, "tls_state_refresh.hex")
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
            rec = json.load(open(rp))
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
                                  "range": "0x63ef5e0..0x63ef640"}]}
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
            out = subprocess.check_output(
                ["objdump", "-d", f"--start-address={hex(s)}",
                 f"--stop-address={hex(e)}", BIN], text=True)
            fresh = strip_header(out)
            stored = strip_header(
                open(os.path.join(PKT, ex["name"] + ".objdump.txt"),
                     errors="replace").read())
            self.assertEqual(stored, fresh, ex["name"])

    def test_07_manifest_sha256(self):
        r = subprocess.run(["sha256sum", "-c", "MANIFEST.sha256"],
                           cwd=PKT, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_08_strict_counts_recomputed(self):
        rec = json.load(open(os.path.join(PKT, "records.json")))
        for ex in rec["exhibits"]:
            txt = open(os.path.join(PKT, ex["name"] + ".objdump.txt"),
                       errors="replace").read()
            n = sum(1 for line in txt.splitlines()
                    if STRICT_RE.match(line))
            self.assertEqual(n, ex["strict"], ex["name"])

    def test_09_census_site_recomputed(self):
        data = open(BIN, "rb").read()
        # call at 0x63ef7a5 must be E8 -> 0x63ef410
        off = 0x63ef7a5 - 0x1000
        self.assertEqual(data[off], 0xE8)
        rel = struct.unpack("<i", data[off + 1:off + 5])[0]
        self.assertEqual(0x63ef7a5 + 5 + rel, 0x63ef410)
        # raw ef5e0 census over the code window
        lo, hi = 0x6300000, 0x6500000
        buf = data[lo - 0x1000:hi - 0x1000]
        e8 = e9 = 0
        for i in range(len(buf) - 5):
            op = buf[i]
            if op not in (0xE8, 0xE9):
                continue
            rel = struct.unpack("<i", buf[i + 1:i + 5])[0]
            if lo + i + 5 + rel == 0x63ef5e0:
                if op == 0xE8:
                    e8 += 1
                else:
                    e9 += 1
        self.assertEqual((e8, e9), (82, 1))

    def test_10_leaf_arithmetic_and_files(self):
        rec = json.load(open(os.path.join(PKT, "records.json")))
        self.assertEqual(rec["leaves_classified_before"] +
                         len(rec["leaves_classified_here"]) +
                         rec["leaves_remaining_unclassified"], 204)
        self.assertEqual(len(rec["exhibits"]), 14)
        listed = set()
        for line in open(os.path.join(PKT, "MANIFEST.sha256")):
            parts = line.split()
            if len(parts) == 2:
                listed.add(parts[1])
        local = {f for f in listed if not f.startswith("../")}
        actual = set(f for f in os.listdir(PKT)
                     if f != "MANIFEST.sha256")
        self.assertEqual(local, actual)
        for f in listed:
            if f.startswith("../"):
                self.assertTrue(os.path.isfile(os.path.join(PKT, f)), f)


def strip_header(text):
    """Drop objdump header lines through the FDE label line."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if LABEL_RE.match(line.strip()):
            return "\n".join(lines[i + 1:])
    return text


if __name__ == "__main__":
    unittest.main(verbosity=2)
