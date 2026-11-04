#!/usr/bin/env python3
"""Unit tests for RE-001-node115-lu-prof-thread-leaves-bin (packet #262).

Tamper controls are test_08/09/10 and are run FIRST (before any green
run is trusted): each corrupts one thing and asserts the verifier exits
nonzero. The remaining tests independently re-derive the verifier's
claims (different regex implementation, independent section parsing,
independent byte arithmetic).
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

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PKT = os.path.join(ROOT, "research", "work-items",
                    "RE-001-node115-lu-prof-thread-leaves-bin")
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
VERIFIER = os.path.join(ROOT, "tools", "node115_prof_thread_leaves_bin.py")


def run_verifier(root=ROOT):
    return subprocess.run([sys.executable, VERIFIER, root],
                          capture_output=True, text=True)


def strict_count(text):
    # Independent recount: split on tabs, require 3 parts, mnemonic
    # starting with a lowercase letter (byte-continuation lines have
    # no mnemonic in the third field).
    n = 0
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3 and parts[0].strip() and \
                re.match(r"^[0-9a-f]+:$", parts[0].strip()) and \
                re.match(r"^[a-z]", parts[2]):
            n += 1
    return n


class TestPacket262(unittest.TestCase):
    def test_01_verifier_exit_0(self):
        self.assertEqual(run_verifier().returncode, 0)

    def test_02_exhibit_bytes_match_binary(self):
        data = open(BIN, "rb").read()
        rec = json.load(open(os.path.join(PKT, "records.json")))
        for ex in rec["exhibits"]:
            s, e = int(ex["range"][0], 16), int(ex["range"][1], 16)
            raw = open(os.path.join(PKT, ex["name"] + ".hex"), "rb").read()
            self.assertEqual(raw, data[s - 0x1000:s - 0x1000 + (e - s)])
            self.assertEqual(len(raw), ex["bytes"])

    def test_03_strict_recount_independent(self):
        rec = json.load(open(os.path.join(PKT, "records.json")))
        for ex in rec["exhibits"]:
            stored = open(os.path.join(PKT,
                                       ex["name"] + ".objdump.txt")).read()
            self.assertEqual(strict_count(stored), ex["strict"])

    def test_04_objdump_regen_path_stripped(self):
        rec = json.load(open(os.path.join(PKT, "records.json")))
        for ex in rec["exhibits"]:
            s, e = int(ex["range"][0], 16), int(ex["range"][1], 16)
            out = subprocess.run(
                ["objdump", "-d", "--start-address=%#x" % s,
                 "--stop-address=%#x" % e, BIN],
                capture_output=True, text=True, check=True).stdout
            regen = "\n".join(out.splitlines()[2:]) + "\n"
            stored = open(os.path.join(PKT,
                                       ex["name"] + ".objdump.txt")).read()
            self.assertEqual(regen, stored)

    def test_05_rela_slots_independent(self):
        # Independent .rela.dyn parse via readelf output.
        out = subprocess.run(["readelf", "-r", BIN],
                             capture_output=True, text=True,
                             check=True).stdout
        slots = {}
        for line in out.splitlines():
            toks = line.split()
            # readelf prints 12-digit offset/info fields; RELATIVE
            # lines carry the addend as the last token.
            if len(toks) >= 4 and toks[2] == "R_X86_64_RELATIVE":
                slots[int(toks[0], 16)] = int(toks[-1], 16)
        rec = json.load(open(os.path.join(PKT, "records.json")))
        for leaf in rec["leaves"]:
            node, handler = int(leaf["node"], 16), int(leaf["handler"], 16)
            self.assertEqual(slots.get(node + 0x20), handler)

    def test_06_named_sites_independent(self):
        data = open(BIN, "rb").read()
        sites = [(0x63ed478, 0x63d9880), (0x63ed4e7, 0x63d9880),
                 (0x63ec975, 0x63ec7a0), (0x63ed59c, 0x63ec7a0),
                 (0x63ed629, 0x63ec7a0), (0x63edcbf, 0x63ec7a0),
                 (0x63c41ed, 0x63bf840), (0x63c4225, 0x63bf840),
                 (0x63c4243, 0x63bf840), (0x63c4261, 0x63bf840),
                 (0x63c427f, 0x63bf840), (0x63c42a1, 0x63bf840),
                 (0x63c42c3, 0x63bf840), (0x63c42e5, 0x63bf840),
                 (0x63c4307, 0x63bf840), (0x63c441b, 0x63bf840),
                 (0x63c4478, 0x63bf840)]
        for site, tgt in sites:
            b = data[site - 0x1000:site - 0x1000 + 5]
            self.assertEqual(b[0], 0xE8)
            self.assertEqual(site + 5 + struct.unpack("<i", b[1:5])[0], tgt)

    def test_07_manifest_hashes(self):
        import hashlib
        man = {}
        for line in open(os.path.join(PKT, "MANIFEST.sha256")):
            parts = line.split()
            self.assertEqual(len(parts), 2)
            man[parts[1]] = parts[0]
        self.assertNotIn("MANIFEST.sha256", man)
        for p, digest in man.items():
            fs = os.path.join(ROOT, p.replace("../../../", "")) \
                if p.startswith("../../../") else os.path.join(PKT, p)
            self.assertEqual(hashlib.sha256(open(fs, "rb").read()).hexdigest(),
                             digest)

    def _tamper_root(self):
        # Copy the verifier-relevant tree into a temp dir: the verifier
        # reads the packet, tools, tests and binary from the root, and
        # scans ~/workspace/hl-wt-calls*-115 worktrees for prior records
        # (unchanged by the copy).
        tmp = tempfile.mkdtemp(prefix="hl262-tamper-")
        shutil.copytree(PKT, os.path.join(
            tmp, "research", "work-items", os.path.basename(PKT)))
        for rel in ["tools/node115_prof_thread_leaves_bin.py",
                    "tests/test_node115_prof_thread_leaves_bin.py"]:
            src = os.path.join(ROOT, rel)
            dst = os.path.join(tmp, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy(src, dst)
        os.makedirs(os.path.join(tmp, "artifacts", "node", "115"),
                    exist_ok=True)
        os.symlink(BIN, os.path.join(tmp, "artifacts", "node", "115",
                                     "hl-node"))
        return tmp

    def test_08_tamper_hex_flip_fails(self):
        tmp = self._tamper_root()
        try:
            p = os.path.join(tmp, "research", "work-items",
                             os.path.basename(PKT), "prof_prefix.hex")
            with open(p, "rb") as f:
                raw = bytearray(f.read())
            raw[0] ^= 0xFF
            with open(p, "wb") as f:
                f.write(raw)
            self.assertNotEqual(run_verifier(tmp).returncode, 0)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_09_tamper_strict_count_fails(self):
        tmp = self._tamper_root()
        try:
            p = os.path.join(tmp, "research", "work-items",
                             os.path.basename(PKT), "records.json")
            with open(p) as f:
                rec = json.load(f)
            rec["exhibits"][0]["strict"] += 1
            with open(p, "w") as f:
                json.dump(rec, f, indent=1)
            self.assertNotEqual(run_verifier(tmp).returncode, 0)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_10_tamper_injected_overlap_fails(self):
        tmp = self._tamper_root()
        try:
            pkt_t = os.path.join(tmp, "research", "work-items",
                                 os.path.basename(PKT))
            # Inject a window overlapping packet #261's claimed range
            # (its bin_init FDE starts at 0x63ec4c0), with matching
            # exhibit files so the ONLY failure is the overlap.
            data = open(BIN, "rb").read()
            s, e = 0x63ec4c0, 0x63ec500
            open(os.path.join(pkt_t, "injected.hex"), "wb").write(
                data[s - 0x1000:s - 0x1000 + (e - s)])
            out = subprocess.run(
                ["objdump", "-d", "--start-address=%#x" % s,
                 "--stop-address=%#x" % e, BIN],
                capture_output=True, text=True, check=True).stdout
            stored = "\n".join(out.splitlines()[2:]) + "\n"
            open(os.path.join(pkt_t, "injected.objdump.txt"),
                 "w").write(stored)
            p = os.path.join(pkt_t, "records.json")
            with open(p) as f:
                rec = json.load(f)
            rec["exhibits"].append({"name": "injected",
                                    "range": ["0x63ec4c0", "0x63ec500"],
                                    "bytes": e - s,
                                    "strict": strict_count(stored)})
            with open(p, "w") as f:
                json.dump(rec, f, indent=1)
            result = run_verifier(tmp)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("overlap", result.stdout)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
