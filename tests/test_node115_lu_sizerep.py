"""Unit tests for the node #115 lu size representative packet.

Regeneration comparison + tamper control + census spot checks for the
0x63e8c80 size representative helper. Static only; never executes the
node binary.
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

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(REPO, "research", "work-items", "RE-001-node115-lu-sizerep")
NODE = os.path.join(REPO, "artifacts", "node", "115", "hl-node")
VERIFIER = os.path.join(REPO, "tools", "node115_lu_sizerep.py")

FDE_START = 0x63E8C80
FDE_END = 0x63E8D87
RET_SITES = (0x63E8D4A, 0x63E8D5F)
CALLERS = (0x63B09CB, 0x63B0F62, 0x63B0FBC, 0x63D934B)
EXHIBITS = {
    "sr_entry": (0x63E8C80, 0x63E8CA5, 37, 8),
    "sr_index": (0x63E8CAB, 0x63E8CD3, 40, 10),
    "sr_small": (0x63E8D50, 0x63E8D60, 16, 6),
    "sr_table": (0x63E8CE1, 0x63E8CF5, 20, 5),
    "sr_round2": (0x63E8D08, 0x63E8D4B, 67, 18),
}

INSN_RE = re.compile(r"\s*[0-9a-f]+:\t[0-9a-f ]+\t(\S+)")


def text_off(va):
    return va - 0x1000


def objdump_lines(start, end):
    out = subprocess.run(
        ["objdump", "-d", f"--start-address={hex(start)}",
         f"--stop-address={hex(end)}", NODE],
        capture_output=True, text=True).stdout
    return [l for l in out.splitlines()
            if re.match(r"\s*[0-9a-f]+:\t", l)]


class SizeRepTests(unittest.TestCase):
    def test_binary_sha_and_size(self):
        with open(NODE, "rb") as f:
            data = f.read()
        self.assertEqual(len(data), 105896032)
        self.assertEqual(
            hashlib.sha256(data).hexdigest(),
            "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")

    def test_exhibits_regenerate(self):
        with open(NODE, "rb") as f:
            data = f.read()
        for name, (start, end, nbytes, strict) in EXHIBITS.items():
            with open(os.path.join(PACKET, name + ".hex")) as f:
                raw = bytes.fromhex("".join(f.read().split()))
            self.assertEqual(len(raw), nbytes, name)
            self.assertEqual(data[text_off(start):text_off(end)], raw, name)
            with open(os.path.join(PACKET, name + ".objdump.txt")) as f:
                saved = f.read().splitlines()
            # Saved files hold instruction lines only (no objdump
            # header, which embeds the invoked path); compare the
            # same filtered lines from a fresh objdump run.
            self.assertEqual(saved, objdump_lines(start, end), name)

    def test_fde_bounds(self):
        frames = subprocess.run(
            ["readelf", "--debug-dump=frames", NODE],
            capture_output=True, text=True).stdout
        self.assertIn("pc=00000000063e8c80..00000000063e8d87", frames)
        self.assertEqual(FDE_END - FDE_START, 263)

    def test_key_bytes(self):
        with open(NODE, "rb") as f:
            data = f.read()
        self.assertEqual(data[text_off(FDE_START):text_off(FDE_START) + 4],
                         bytes.fromhex("f30f1efa"))
        for site in RET_SITES:
            self.assertEqual(data[text_off(site)], 0xC3, hex(site))
        self.assertEqual(data[text_off(0x63E8C84):text_off(0x63E8C84) + 10],
                         bytes.fromhex("48b90000000000000070"))

    def test_manifest_coverage(self):
        with open(os.path.join(PACKET, "MANIFEST.sha256")) as f:
            lines = [l for l in f.read().splitlines() if l.strip()]
        self.assertEqual(len(lines), 15)
        names = [l.split(None, 1)[1] if len(l.split(None, 1)) > 1 else "" for l in lines]
        for name, (start, end, nbytes, strict) in EXHIBITS.items():
            self.assertIn(name + ".hex", names)
            self.assertIn(name + ".objdump.txt", names)
        for extra in ("README.md", "EVIDENCE.md", "records.json",
                      "../../../tools/node115_lu_sizerep.py",
                      "../../../tests/test_node115_lu_sizerep.py"):
            self.assertIn(extra, names)
        self.assertNotIn("MANIFEST.sha256", names)

    def test_strict_counts(self):
        for name, (start, end, nbytes, strict) in EXHIBITS.items():
            with open(os.path.join(PACKET, name + ".objdump.txt")) as f:
                dump = f.read()
            self.assertEqual(len(INSN_RE.findall(dump)), strict, name)

    def test_tamper_control(self):
        with open(NODE, "rb") as f:
            data = f.read()
        tmp = tempfile.mkdtemp()
        try:
            bad = bytearray(data)
            bad[text_off(FDE_START)] ^= 0xFF
            badpath = os.path.join(tmp, "hl-node-bad")
            with open(badpath, "wb") as f:
                f.write(bad)
            with open(os.path.join(PACKET, "sr_entry.hex")) as f:
                raw = bytes.fromhex("".join(f.read().split()))
            self.assertNotEqual(bad[text_off(FDE_START):text_off(0x63E8CA5)], raw)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_verifier_exit_zero(self):
        r = subprocess.run([sys.executable, VERIFIER],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_census_sites(self):
        with open(NODE, "rb") as f:
            data = f.read()
        for site in CALLERS:
            o = text_off(site)
            self.assertEqual(data[o], 0xE8, hex(site))
            rel = struct.unpack("<i", data[o + 1:o + 5])[0]
            self.assertEqual(site + 5 + rel, FDE_START, hex(site))
        dump = subprocess.run(
            ["objdump", "-d", f"--start-address={hex(FDE_START)}",
             f"--stop-address={hex(FDE_END)}", NODE],
            capture_output=True, text=True).stdout
        self.assertEqual(INSN_RE.findall(dump).count("call"), 0)

    def test_got_absence(self):
        with open(NODE, "rb") as f:
            data = f.read()
        e_shoff = struct.unpack("<Q", data[0x28:0x30])[0]
        e_shentsize, e_shnum, e_shstrndx = struct.unpack("<HHH", data[0x3A:0x40])
        secs = []
        for n in range(e_shnum):
            o = e_shoff + n * e_shentsize
            name, typ, flags, addr, off, size = struct.unpack("<IIQQQQ", data[o:o + 40])
            secs.append((name, typ, addr, off, size))
        shstr_off = secs[e_shstrndx][3]

        def secname(x):
            e = data.index(b"\x00", shstr_off + x)
            return data[shstr_off + x:e].decode()

        for name, typ, addr, off, size in secs:
            if secname(name) == ".rela.dyn":
                total = size // 24
                self.assertEqual(total, 60723)
                for k in range(total):
                    r_off, r_info, r_add = struct.unpack(
                        "<QQq", data[off + k * 24:off + k * 24 + 24])
                    self.assertNotEqual(r_add, FDE_START)


if __name__ == "__main__":
    unittest.main()
