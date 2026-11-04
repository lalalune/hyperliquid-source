"""Unit tests for the node #115 lu slot-find packet.

Regeneration comparison + tamper control + census spot checks for the
0x63b0980 slot-find helper. Static only; never executes the node binary.
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
PACKET = os.path.join(REPO, "research", "work-items", "RE-001-node115-lu-slotfind")
NODE = os.path.join(REPO, "artifacts", "node", "115", "hl-node")
VERIFIER = os.path.join(REPO, "tools", "node115_lu_slotfind.py")

FDE_START = 0x63B0980
FDE_END = 0x63B15E9
RET_SITE = 0x63B132B
CALLER = 0x63B49A3
INTERNAL_CALLS = {
    0x63B09CB: 0x63E8C80,
    0x63B0BBB: 0x63ABCF0,
    0x63B0BC7: 0x63ABD00,
    0x63B0F62: 0x63E8C80,
    0x63B0FBC: 0x63E8C80,
    0x63B1131: 0x63ABD00,
    0x63B1490: 0x63ABD00,
    0x63B14ED: 0x63ABD00,
}
EXHIBITS = {
    "fe_entry": (0x63B0980, 0x63B09D0, 80, 21),
    "fe_index": (0x63B09EA, 0x63B0A22, 56, 16),
    "fe_flag": (0x63B0BAC, 0x63B0BD6, 42, 12),
    "fe_scan": (0x63B0C15, 0x63B0C6E, 89, 26),
    "fe_range": (0x63B1136, 0x63B1172, 60, 16),
}

INSN_RE = re.compile(r"\s*[0-9a-f]+:\t[0-9a-f ]+\t(\S+)")


def text_off(va):
    return va - 0x1000


def objdump(start, end):
    out = subprocess.run(
        ["objdump", "-d", f"--start-address={hex(start)}",
         f"--stop-address={hex(end)}", NODE],
        capture_output=True, text=True).stdout
    return out


class SlotFindTests(unittest.TestCase):
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
                saved = f.read()
            # The objdump header embeds the path passed on the command
            # line, which differs between generation (relative) and this
            # test (absolute); compare from the disassembly body onward.
            def body(text):
                idx = text.find("Disassembly of section")
                return text[idx:] if idx >= 0 else text
            self.assertEqual(body(saved), body(objdump(start, end)), name)

    def test_fde_bounds(self):
        frames = subprocess.run(
            ["readelf", "--debug-dump=frames", NODE],
            capture_output=True, text=True).stdout
        self.assertIn("pc=00000000063b0980..00000000063b15e9", frames)
        self.assertEqual(FDE_END - FDE_START, 3177)

    def test_key_bytes(self):
        with open(NODE, "rb") as f:
            data = f.read()
        self.assertEqual(data[text_off(0x63B0980):text_off(0x63B0980) + 4],
                         bytes.fromhex("f30f1efa"))
        self.assertEqual(data[text_off(RET_SITE)], 0xC3)
        self.assertEqual(data[text_off(0x63B1136):text_off(0x63B1136) + 4],
                         bytes.fromhex("488b0c24"))

    def test_manifest_coverage(self):
        with open(os.path.join(PACKET, "MANIFEST.sha256")) as f:
            lines = [l for l in f.read().splitlines() if l.strip()]
        self.assertEqual(len(lines), 15)
        names = [l.split(None, 1)[1] if len(l.split(None, 1)) > 1 else "" for l in lines]
        for name, (start, end, nbytes, strict) in EXHIBITS.items():
            self.assertIn(name + ".hex", names)
            self.assertIn(name + ".objdump.txt", names)
        for extra in ("README.md", "EVIDENCE.md", "records.json",
                      "../../../tools/node115_lu_slotfind.py",
                      "../../../tests/test_node115_lu_slotfind.py"):
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
            bad[text_off(0x63B0980)] ^= 0xFF
            badpath = os.path.join(tmp, "hl-node-bad")
            with open(badpath, "wb") as f:
                f.write(bad)
            with open(os.path.join(PACKET, "fe_entry.hex")) as f:
                raw = bytes.fromhex("".join(f.read().split()))
            self.assertNotEqual(bad[text_off(0x63B0980):text_off(0x63B09D0)], raw)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_verifier_exit_zero(self):
        r = subprocess.run([sys.executable, VERIFIER],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_internal_calls_and_census(self):
        with open(NODE, "rb") as f:
            data = f.read()
        for site, tgt in INTERNAL_CALLS.items():
            o = text_off(site)
            self.assertEqual(data[o], 0xE8, hex(site))
            rel = struct.unpack("<i", data[o + 1:o + 5])[0]
            self.assertEqual(site + 5 + rel, tgt, hex(site))
        o = text_off(CALLER)
        self.assertEqual(data[o], 0xE8, hex(CALLER))
        rel = struct.unpack("<i", data[o + 1:o + 5])[0]
        self.assertEqual(CALLER + 5 + rel, FDE_START, hex(CALLER))
        dump = objdump(FDE_START, FDE_END)
        self.assertEqual(INSN_RE.findall(dump).count("call"), 8)

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
