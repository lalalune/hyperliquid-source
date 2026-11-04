"""Unit tests for the node #115 lu descriptor-builder packet.

Regeneration comparison + tamper control + census spot checks for
the 0x63da080 thunk and the 0x63d9ba0 body. Static only; never
executes the node binary.
"""

import hashlib
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(REPO, "research", "work-items", "RE-001-node115-lu-descbuild")
NODE = os.path.join(REPO, "artifacts", "node", "115", "hl-node")
VERIFIER = os.path.join(REPO, "tools", "node115_lu_descbuild.py")

THUNK_START = 0x63DA080
THUNK_END = 0x63DA089
BODY_START = 0x63D9BA0
BODY_END = 0x63D9ED3
RET_SITES = (0x63D9ED2,)
THUNK_CALLERS = (0x634ED44,)
BODY_CALLERS = (0x634C2A5,)
BODY_JUMPERS = (0x63DA084,)
EXHIBITS = {
    "db_thunk": (0x63DA080, 0x63DA089, 9, 2),
    "db_entry": (0x63D9BA0, 0x63D9C08, 104, 23),
    "db_first": (0x63D9C08, 0x63D9C78, 112, 28),
    "db_main": (0x63D9D10, 0x63D9D53, 67, 15),
    "db_final": (0x63D9E3F, 0x63D9EC8, 137, 30),
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


class DescbuildTests(unittest.TestCase):
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
        self.assertIn("pc=00000000063da080..00000000063da089", frames)
        self.assertIn("pc=00000000063d9ba0..00000000063d9ed3", frames)
        self.assertEqual(BODY_END - BODY_START, 819)
        self.assertEqual(THUNK_END - THUNK_START, 9)

    def test_key_bytes(self):
        with open(NODE, "rb") as f:
            data = f.read()
        self.assertEqual(data[text_off(THUNK_START):text_off(THUNK_START) + 4],
                         bytes.fromhex("f30f1efa"))
        self.assertEqual(data[text_off(BODY_START):text_off(BODY_START) + 4],
                         bytes.fromhex("f30f1efa"))
        for site in RET_SITES:
            self.assertEqual(data[text_off(site)], 0xC3, hex(site))
        o = text_off(0x63DA084)
        self.assertEqual(data[o], 0xE9)
        rel = struct.unpack("<i", data[o + 1:o + 5])[0]
        self.assertEqual(0x63DA084 + 5 + rel, BODY_START)

    def test_manifest_coverage(self):
        with open(os.path.join(PACKET, "MANIFEST.sha256")) as f:
            lines = [l for l in f.read().splitlines() if l.strip()]
        self.assertEqual(len(lines), 15)
        names = [l.split(None, 1)[1] if len(l.split(None, 1)) > 1 else "" for l in lines]
        for name, (start, end, nbytes, strict) in EXHIBITS.items():
            self.assertIn(name + ".hex", names)
            self.assertIn(name + ".objdump.txt", names)
        for extra in ("README.md", "EVIDENCE.md", "records.json",
                      "../../../tools/node115_lu_descbuild.py",
                      "../../../tests/test_node115_lu_descbuild.py"):
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
            bad[text_off(BODY_START)] ^= 0xFF
            badpath = os.path.join(tmp, "hl-node-bad")
            with open(badpath, "wb") as f:
                f.write(bad)
            with open(os.path.join(PACKET, "db_entry.hex")) as f:
                raw = bytes.fromhex("".join(f.read().split()))
            self.assertNotEqual(bad[text_off(BODY_START):text_off(0x63D9C08)], raw)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_verifier_exit_zero(self):
        r = subprocess.run([sys.executable, VERIFIER],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_census_sites(self):
        with open(NODE, "rb") as f:
            data = f.read()
        for site in THUNK_CALLERS:
            o = text_off(site)
            self.assertEqual(data[o], 0xE8, hex(site))
            rel = struct.unpack("<i", data[o + 1:o + 5])[0]
            self.assertEqual(site + 5 + rel, THUNK_START, hex(site))
        for site in BODY_CALLERS:
            o = text_off(site)
            self.assertEqual(data[o], 0xE8, hex(site))
            rel = struct.unpack("<i", data[o + 1:o + 5])[0]
            self.assertEqual(site + 5 + rel, BODY_START, hex(site))
        for site in BODY_JUMPERS:
            o = text_off(site)
            self.assertEqual(data[o], 0xE9, hex(site))
            rel = struct.unpack("<i", data[o + 1:o + 5])[0]
            self.assertEqual(site + 5 + rel, BODY_START, hex(site))
        dump = subprocess.run(
            ["objdump", "-d", f"--start-address={hex(BODY_START)}",
             f"--stop-address={hex(BODY_END)}", NODE],
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
                    self.assertNotEqual(r_add, THUNK_START)
                    self.assertNotEqual(r_add, BODY_START)


if __name__ == "__main__":
    unittest.main()
