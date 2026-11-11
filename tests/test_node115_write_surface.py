#!/usr/bin/env python3
"""Unit tests for the RE-001-node115-lu-write-surface packet (#257).

Standalone: no repo harness needed. Run from the repo root with
`python3 -m unittest tests.test_node115_write_surface`.
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
PACKET = "RE-001-node115-lu-write-surface"
PDIR = os.path.join(ROOT, "research", "work-items", PACKET)
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
TOOL = os.path.join(ROOT, "tools", "node115_write_surface.py")
SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
INSTR_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t\S+")


def load_records():
    with open(os.path.join(PDIR, "records.json")) as f:
        return json.load(f)


class TestWriteSurface(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = open(BIN, "rb").read()
        cls.rec = load_records()

    def test_binary_identity(self):
        self.assertEqual(len(self.data), 105896032)
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), SHA)

    def test_exhibit_bytes_regeneration(self):
        for e in self.rec["exhibits"]:
            a, b = int(e["range"][0], 16), int(e["range"][1], 16)
            raw = open(os.path.join(PDIR, e["name"] + ".hex"), "rb").read()
            self.assertEqual(raw, self.data[a - 0x1000:b - 0x1000], e["name"])
            self.assertEqual(len(raw), e["bytes"], e["name"])

    def test_objdump_regeneration_header_stripped(self):
        for e in self.rec["exhibits"]:
            a, b = int(e["range"][0], 16), int(e["range"][1], 16)
            out = subprocess.run(
                ["objdump", "-d", f"--start-address={hex(a)}",
                 f"--stop-address={hex(b)}", BIN],
                capture_output=True, text=True, check=True).stdout
            fresh = [ln for ln in out.splitlines() if INSTR_RE.match(ln)]
            stored = open(os.path.join(PDIR, e["name"] + ".objdump.txt")).read()
            stored_lines = [ln for ln in stored.splitlines() if INSTR_RE.match(ln)]
            self.assertEqual(fresh, stored_lines, e["name"])
            self.assertEqual(len(fresh), e["strict"], e["name"])

    def test_strict_counts_consistent(self):
        total_b = sum(e["bytes"] for e in self.rec["exhibits"])
        total_s = sum(e["strict"] for e in self.rec["exhibits"])
        self.assertEqual(total_b, 851)
        self.assertEqual(total_s, 210)

    def test_flag_write_spots(self):
        spots = [
            (0x634EF6A, "c705400b1b0002000000"),
            (0x634F2D0, "c705da071b0001000000"),
            (0x634F680, "c7052a041b0000000000"),
        ]
        for va, hx in spots:
            want = bytes.fromhex(hx)
            self.assertEqual(self.data[va - 0x1000:va - 0x1000 + len(want)], want, hex(va))

    def test_handler_call_targets(self):
        # The five decoded leaf handlers are reached only by indirect
        # dispatch: no direct E8/E9 site may target them. Verified by the
        # verifier's census; here re-check the epoch advance call target.
        out = subprocess.run(
            ["objdump", "-d", "--start-address=0x63a802b",
             "--stop-address=0x63a8030", BIN],
            capture_output=True, text=True, check=True).stdout
        self.assertIn("call   63a77d0", out)

    def test_tree_leaf_inventory(self):
        leaves = self.rec["census"]["tree"]["leaves"]
        self.assertEqual(len(leaves), 204)
        by_path = {p: (v, d["handler"]) for p, v, d in leaves}
        self.assertEqual(by_path["/epoch"][1], 0x63A7FC0)
        self.assertEqual(by_path["/stats/mutexes/reset"][1], 0x63A5BF0)
        self.assertEqual(by_path["/thread/tcache/flush"][1], 0x636DE20)
        self.assertEqual(by_path["/thread/peak/reset"][1], 0x636E210)
        self.assertEqual(by_path["/prof/dump"][1], 0x6377850)
        self.assertEqual(len(self.rec["census"]["tree"]["dynamic"]), 7)

    def test_manifest_covers_packet(self):
        man = open(os.path.join(PDIR, "MANIFEST.sha256")).read().splitlines()
        listed = [ln.split(" *", 1)[1] if " *" in ln else ln.split("  ", 1)[1]
                  for ln in man if ln.strip()]
        # 27 packet files (excl. MANIFEST itself) + tools + tests = 29.
        self.assertEqual(len(listed), 29)
        for rel in listed:
            p = os.path.normpath(os.path.join(PDIR, rel))
            self.assertTrue(os.path.exists(p), rel)
            h = hashlib.sha256(open(p, "rb").read()).hexdigest()
            self.assertTrue(any(ln.startswith(h) and ln.endswith(rel) for ln in man), rel)

    def test_tamper_control(self):
        # Corrupting one exhibit byte must fail the verifier.
        tmp = tempfile.mkdtemp()
        try:
            fake_root = os.path.join(tmp, "root")
            fake_packet = os.path.join(fake_root, "research", "work-items", PACKET)
            os.makedirs(fake_packet)
            for fn in os.listdir(PDIR):
                shutil.copy(os.path.join(PDIR, fn), os.path.join(fake_packet, fn))
            raw = bytearray(open(os.path.join(fake_packet, "pred_thunk.hex"), "rb").read())
            raw[0] ^= 0xFF
            open(os.path.join(fake_packet, "pred_thunk.hex"), "wb").write(bytes(raw))
            # Point the verifier at the tampered tree: it resolves the
            # binary from --root, so stage a symlink tree for artifacts.
            os.makedirs(os.path.join(fake_root, "artifacts", "node", "115"))
            os.symlink(BIN, os.path.join(fake_root, "artifacts", "node", "115", "hl-node"))
            r = subprocess.run([sys.executable, TOOL, "--root", fake_root],
                               capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("pred_thunk.hex bytes", r.stdout + r.stderr)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_verifier_exit_0(self):
        r = subprocess.run([sys.executable, TOOL],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("ALL CHECKS PASSED", r.stdout)


if __name__ == "__main__":
    unittest.main()
