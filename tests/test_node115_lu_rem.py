#!/usr/bin/env python3
"""Unit tests for the RE-001-node115-lu-rem verifier (stdlib only)."""
import hashlib
import os
import struct
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PACKET = os.path.join(ROOT, "research", "work-items", "RE-001-node115-lu-rem")
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
SIZE = 105896032

EXHIBITS = {
    "rm_entry": (0x6369fe0, 0x636a00a, 14),
    "rm_small": (0x636a010, 0x636a032, 7),
    "rm_call": (0x636a032, 0x636a047, 5),
    "rm_large": (0x636a0df, 0x636a12c, 18),
    "rm_acct": (0x636a095, 0x636a0bf, 7),
}
REM_E8 = [0x636a9d0, 0x636b2b3]


def read_at(data, va, n):
    return data[va - 0x1000: va - 0x1000 + n]


def strict_count(od):
    n = 0
    for l in od.splitlines():
        if l.strip() and l.strip()[0].isdigit() and ":" in l.split()[0]:
            parts = l.split("\t")
            if len(parts) >= 3 and parts[2].strip():
                n += 1
    return n


class TestRem(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(BIN, "rb") as f:
            cls.data = f.read()

    def test_binary_sha_and_size(self):
        self.assertEqual(len(self.data), SIZE)
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), SHA)

    def test_regenerate(self):
        for name, (s, e, _strict) in EXHIBITS.items():
            with open(os.path.join(PACKET, name + ".hex")) as f:
                claimed = bytes.fromhex("".join(f.read().split()))
            self.assertEqual(claimed, read_at(self.data, s, e - s))

    def test_tamper_control(self):
        for name, (s, e, _strict) in EXHIBITS.items():
            with open(os.path.join(PACKET, name + ".hex")) as f:
                claimed = bytearray(bytes.fromhex("".join(f.read().split())))
            claimed[0] ^= 0xFF
            self.assertNotEqual(bytes(claimed), read_at(self.data, s, e - s))

    def test_strict_counts(self):
        for name, (s, e, strict) in EXHIBITS.items():
            od = subprocess.run(["objdump", "-d",
                                 f"--start-address={hex(s)}",
                                 f"--stop-address={hex(e)}", BIN],
                                capture_output=True, text=True).stdout
            self.assertEqual(strict_count(od), strict, name)

    def test_key_bytes(self):
        self.assertEqual(read_at(self.data, 0x6369fe0, 5),
                         bytes.fromhex("41554989d5"))
        self.assertEqual(read_at(self.data, 0x636a035, 5),
                         bytes.fromhex("e896200400"))
        self.assertEqual(read_at(self.data, 0x636a0c9, 1),
                         bytes.fromhex("c3"))

    def test_fde_bounds(self):
        frames = subprocess.run(["objdump", "--dwarf=frames", BIN],
                                capture_output=True, text=True).stdout
        self.assertIn("pc=0000000006369fe0..000000000636a136", frames)

    def test_got_absence(self):
        e_shoff = struct.unpack("<Q", self.data[0x28:0x30])[0]
        e_shentsize, e_shnum, e_shstrndx = struct.unpack(
            "<HHH", self.data[0x3a:0x40])
        hdrs = []
        for i in range(e_shnum):
            o = e_shoff + i * e_shentsize
            name, _typ, _fl, addr, off, size = struct.unpack(
                "<IIQQQQ", self.data[o:o + 40])
            hdrs.append((name, addr, off, size))
        str_off = hdrs[e_shstrndx][2]
        strtab = self.data[str_off:]
        for (name, _addr, off, size) in hdrs:
            end = strtab.find(b"\x00", name)
            if strtab[name:end].decode() == ".rela.dyn":
                for i in range(size // 24):
                    o = off + i * 24
                    _r_off, _r_info, r_add = struct.unpack(
                        "<QQq", self.data[o:o + 24])
                    self.assertNotEqual(r_add, 0x6369fe0)

    def test_census_spot(self):
        for site in (0x636a9d0, 0x636b2b3):
            b = read_at(self.data, site, 5)
            self.assertEqual(b[0], 0xe8)
            got = site + 5 + struct.unpack("<i", b[1:5])[0]
            self.assertEqual(got, 0x6369fe0)
        self.assertEqual(len(REM_E8), 2)

    def test_manifest_coverage(self):
        man = os.path.join(PACKET, "MANIFEST.sha256")
        with open(man) as f:
            lines = [l.strip() for l in f if l.strip()]
        self.assertEqual(len(lines), 15)
        rc = subprocess.run(["sha256sum", "-c", "MANIFEST.sha256"],
                            cwd=PACKET, capture_output=True, text=True)
        self.assertEqual(rc.returncode, 0, rc.stdout + rc.stderr)


if __name__ == "__main__":
    unittest.main()
