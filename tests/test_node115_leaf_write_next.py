#!/usr/bin/env python3
"""Unit tests for RE-001-node115-lu-leaf-write-next (packet #259).

The tamper control runs first: a corrupted exhibit must fail the
verifier before any green run is trusted (packet #257 lesson).
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
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
PDIR = os.path.join(ROOT, "research", "work-items",
                    "RE-001-node115-lu-leaf-write-next")
TOOL = os.path.join(ROOT, "tools", "node115_leaf_write_next.py")
STRICT = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t\S")


def toff(va):
    return va - 0x1000


class TestLeafWriteNext(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(BIN, "rb") as f:
            cls.data = f.read()
        with open(os.path.join(PDIR, "records.json")) as f:
            cls.rec = json.load(f)

    def test_tamper_control(self):
        # Corrupting one exhibit byte must fail the verifier.
        tmp = tempfile.mkdtemp()
        try:
            fake_root = os.path.join(tmp, "root")
            fake_packet = os.path.join(fake_root, "research", "work-items",
                                       "RE-001-node115-lu-leaf-write-next")
            os.makedirs(fake_packet)
            for fn in os.listdir(PDIR):
                shutil.copy(os.path.join(PDIR, fn),
                            os.path.join(fake_packet, fn))
            with open(os.path.join(fake_packet, "prof_gdump.hex"),
                      "rb") as f:
                raw = bytearray(f.read())
            raw[0] ^= 0xFF
            with open(os.path.join(fake_packet, "prof_gdump.hex"),
                      "wb") as f:
                f.write(bytes(raw))
            os.makedirs(os.path.join(fake_root, "artifacts", "node", "115"))
            os.symlink(BIN, os.path.join(fake_root, "artifacts", "node",
                                         "115", "hl-node"))
            r = subprocess.run([sys.executable, TOOL, "--root", fake_root],
                               capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("prof_gdump bytes", r.stdout + r.stderr)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_verifier_green(self):
        r = subprocess.run([sys.executable, TOOL],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_exhibit_regeneration(self):
        for e in self.rec["exhibits"]:
            s, en = int(e["range"][0], 16), int(e["range"][1], 16)
            with open(os.path.join(PDIR, e["name"] + ".hex"), "rb") as f:
                self.assertEqual(f.read(), self.data[toff(s):toff(en)],
                                 e["name"])
            out = subprocess.run(
                ["objdump", "-d", f"--start-address={hex(s)}",
                 f"--stop-address={hex(en)}", BIN],
                capture_output=True, text=True).stdout
            with open(os.path.join(PDIR, e["name"] + ".objdump.txt")) as f:
                saved = f.read()
            self.assertEqual(out.split("\n", 1)[1],
                             saved.split("\n", 1)[1], e["name"])

    def test_strict_counts_match_records(self):
        for e in self.rec["exhibits"]:
            n = 0
            with open(os.path.join(PDIR, e["name"] + ".objdump.txt")) as f:
                for line in f:
                    if STRICT.match(line):
                        n += 1
            self.assertEqual(n, e["strict"], e["name"])
        self.assertEqual(sum(e["strict"] for e in self.rec["exhibits"]),
                         self.rec["exhibit_totals"]["strict"])

    def test_rel32_spot_checks(self):
        def tgt(site):
            off = toff(site)
            return site + 5 + struct.unpack(
                "<i", self.data[off + 1: off + 5])[0]
        self.assertEqual(tgt(0x63A5757), 0x63A5550)
        self.assertEqual(tgt(0x636E02F), 0x63C3D50)
        self.assertEqual(tgt(0x63EF7B1), 0x63EEC10)
        self.assertEqual(tgt(0x634D07F), 0x63F1500)

    def test_rodata_strings(self):
        def cstr(va):
            return self.data[va:self.data.index(b"\x00", va)].decode()
        self.assertEqual(cstr(0x4343E3), "prof")
        self.assertEqual(cstr(0x43F883), "true")
        self.assertEqual(cstr(0x430E89), "false")
        self.assertEqual(cstr(0x44C4AA), "prof_leak_error")

    def test_rela_slots(self):
        rela = subprocess.run(["readelf", "-r", BIN],
                              capture_output=True, text=True).stdout
        m = {}
        for line in rela.splitlines():
            mm = re.match(r"^\s*([0-9a-f]+)\s+[0-9a-f]+\s+R_X86_64_RELATIVE"
                          r"\s+([0-9a-f]+)", line)
            if mm:
                m[int(mm.group(1), 16)] = int(mm.group(2), 16)
        for leaf, info in self.rec["census"]["leaf_nodes"].items():
            self.assertEqual(m.get(int(info["rela_slot"], 16)),
                             int(info["handler"], 16), leaf)

    def test_exhibits_within_fdes(self):
        fdes = self.rec["census"]["leaf_fdes"]
        by_name = {e["name"]: e for e in self.rec["exhibits"]}
        checks = [("arenas_create_head", "experimental/arenas_create_ext"),
                  ("tcache_enabled", "thread/tcache/enabled"),
                  ("prof_name_core", "thread/prof/name"),
                  ("hooks_backtrace_head", "experimental/hooks/prof_backtrace"),
                  ("hooks_profdump_head", "experimental/hooks/prof_dump"),
                  ("hooks_safety", "experimental/hooks/safety_check_abort"),
                  ("prof_active", "prof/active"),
                  ("prof_gdump", "prof/gdump"),
                  ("prof_interval_head", "prof/interval")]
        for ex_name, leaf in checks:
            e = by_name[ex_name]
            fs, fe = (int(x, 16) for x in fdes[leaf])
            s, en = int(e["range"][0], 16), int(e["range"][1], 16)
            self.assertTrue(fs <= s and en <= fe, ex_name)

    def test_claimed_ranges_pairwise_disjoint(self):
        ranges = sorted((int(e["range"][0], 16), int(e["range"][1], 16))
                        for e in self.rec["exhibits"])
        for (s1, e1), (s2, e2) in zip(ranges, ranges[1:]):
            self.assertLessEqual(e1, s2)

    def test_manifest_present_and_sane(self):
        man_path = os.path.join(PDIR, "MANIFEST.sha256")
        self.assertTrue(os.path.isfile(man_path))
        with open(man_path) as f:
            for line in f:
                line = line.strip()
                if line:
                    h, p = line.split(None, 1)
                    self.assertEqual(len(h), 64)
                    self.assertNotEqual(p, "MANIFEST.sha256")


if __name__ == "__main__":
    unittest.main()
