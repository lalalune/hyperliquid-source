#!/usr/bin/env python3
"""Unit tests for RE-001-node115-lu-leaf-write-class (packet #258)."""
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
PACKET = "RE-001-node115-lu-leaf-write-class"
PDIR = os.path.join(ROOT, "research", "work-items", PACKET)
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
TOOL = os.path.join(ROOT, "tools", "node115_leaf_write_class.py")
STRICT_PAT = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t\S")


def strip_header(text):
    out = []
    for line in text.splitlines():
        if "file format elf64-x86-64" in line:
            continue
        if line.startswith("Disassembly of section"):
            continue
        out.append(line)
    return "\n".join(out).strip()


class TestLeafWriteClass(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(PDIR, "records.json")) as f:
            self.rec = json.load(f)
        with open(BIN, "rb") as f:
            self.data = f.read()

    def test_binary_identity(self):
        self.assertEqual(len(self.data), 105896032)
        self.assertEqual(hashlib.sha256(self.data).hexdigest(),
                         "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")

    def test_exhibit_bytes(self):
        for e in self.rec["exhibits"]:
            a, b = int(e["range"][0], 16), int(e["range"][1], 16)
            with open(os.path.join(PDIR, e["name"] + ".hex"), "rb") as f:
                raw = f.read()
            self.assertEqual(raw, self.data[a - 0x1000: a - 0x1000 + (b - a)], e["name"])

    def test_objdump_regeneration(self):
        for e in self.rec["exhibits"]:
            a, b = int(e["range"][0], 16), int(e["range"][1], 16)
            out = subprocess.run(["objdump", "-d", f"--start-address={hex(a)}",
                                  f"--stop-address={hex(b)}", BIN],
                                 capture_output=True, text=True).stdout
            with open(os.path.join(PDIR, e["name"] + ".objdump.txt")) as f:
                saved = f.read()
            self.assertEqual(strip_header(out), strip_header(saved), e["name"])

    def test_strict_totals(self):
        total_b = sum(int(e["range"][1], 16) - int(e["range"][0], 16) for e in self.rec["exhibits"])
        total_s = 0
        for e in self.rec["exhibits"]:
            with open(os.path.join(PDIR, e["name"] + ".objdump.txt")) as f:
                sc = sum(1 for line in f if STRICT_PAT.match(line))
            self.assertEqual(sc, e["strict"], e["name"])
            total_s += sc
        self.assertEqual((total_b, total_s), (1361, 365))
        self.assertEqual((total_b, total_s),
                         (self.rec["exhibit_totals"]["bytes"], self.rec["exhibit_totals"]["strict"]))

    def test_call_target_spots(self):
        def rel32(call_va):
            off = call_va - 0x1000
            return call_va + 5 + int.from_bytes(self.data[off + 1: off + 5], "little", signed=True)
        spots = [(0x63a5986, 0x63f17b0), (0x63a59fc, 0x63a5550), (0x63779e1, 0x63ee0a0),
                 (0x63778d7, 0x63ee2a0), (0x636d652, 0x63b6ee0), (0x6376d77, 0x63b70b0),
                 (0x637782b, 0x63d4ad8), (0x63777d4, 0x63d4bbe), (0x636def6, 0x63c3e20),
                 (0x6368e57, 0x63f17b0), (0x63efa95, 0x63f0cf0)]
        for site, want in spots:
            self.assertEqual(rel32(site), want, hex(site))

    def test_profbyte_census_consistency(self):
        pb = self.rec["census"]["profbyte_0x6713606"]
        self.assertEqual(len(pb["sites"]), 76)
        self.assertEqual(pb["total_sites"], 76)
        writes = [s for s in pb["sites"] if s["class"].startswith("WRITE")]
        self.assertEqual(len(writes), 3)
        self.assertEqual(pb["reads"], 73)
        self.assertEqual(pb["rela_addends"], 0)
        # writer instruction bytes
        self.assertEqual(self.data[0x634c043 - 0x1000: 0x634c043 - 0x1000 + 4],
                         bytes([0x41, 0xC6, 0x00, 0x00]))
        self.assertEqual(self.data[0x634d09a - 0x1000: 0x634d09a - 0x1000 + 3],
                         bytes([0xC6, 0x03, 0x01]))
        self.assertEqual(self.data[0x63c41a0 - 0x1000: 0x63c41a0 - 0x1000 + 7],
                         bytes([0xC6, 0x05, 0x5F, 0xF4, 0x34, 0x00, 0x01]))

    def test_leaf_inventory(self):
        entries = self.rec["census"]["leaf_handler_direct_entries"]
        self.assertEqual(len(entries), 8)
        for leaf, entry in entries.items():
            self.assertEqual(entry["E8"], [], leaf)
            self.assertEqual(entry["E9"], [], leaf)
            self.assertEqual(entry["addrtaken_lea_movabs"], 0, leaf)
            self.assertEqual(int(entry["rela_slot"], 16) - int(entry["node"], 16), 0x20, leaf)
        self.assertEqual(len(self.rec["census"]["leaves_classified_here"]), 8)
        self.assertEqual(self.rec["census"]["leaves_remaining_unclassified"], 190)

    def test_exhibits_disjoint(self):
        ranges = sorted((int(e["range"][0], 16), int(e["range"][1], 16)) for e in self.rec["exhibits"])
        for (a1, b1), (a2, b2) in zip(ranges, ranges[1:]):
            self.assertLessEqual(b1, a2, (hex(a1), hex(b1), hex(a2), hex(b2)))

    def test_tamper_control(self):
        # Corrupting one exhibit byte must fail the verifier.
        tmp = tempfile.mkdtemp()
        try:
            fake_root = os.path.join(tmp, "root")
            fake_packet = os.path.join(fake_root, "research", "work-items", PACKET)
            os.makedirs(fake_packet)
            for fn in os.listdir(PDIR):
                shutil.copy(os.path.join(PDIR, fn), os.path.join(fake_packet, fn))
            with open(os.path.join(fake_packet, "log_stop.hex"), "rb") as f:
                raw = bytearray(f.read())
            raw[0] ^= 0xFF
            with open(os.path.join(fake_packet, "log_stop.hex"), "wb") as f:
                f.write(bytes(raw))
            os.makedirs(os.path.join(fake_root, "artifacts", "node", "115"))
            os.symlink(BIN, os.path.join(fake_root, "artifacts", "node", "115", "hl-node"))
            r = subprocess.run([sys.executable, TOOL, "--root", fake_root],
                               capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("log_stop bytes", r.stdout + r.stderr)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_verifier_exit_0(self):
        r = subprocess.run([sys.executable, TOOL], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("ALL CHECKS PASSED", r.stdout)


if __name__ == "__main__":
    unittest.main()
