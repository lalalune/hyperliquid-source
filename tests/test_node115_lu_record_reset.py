"""Unit tests for RE-001-node115-lu-record-reset (packet #254).

Run from the worktree root: python3 -m unittest
tests.test_node115_lu_record_reset
"""
import hashlib
import json
import os
import re
import struct
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(ROOT, "research", "work-items",
                      "RE-001-node115-lu-record-reset")
BINARY = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
FDE_START, FDE_END = 0x63bf7F0, 0x63bf83D


def off_text(va):
    return va - 0x1000


def load_records():
    with open(os.path.join(PACKET, "records.json")) as f:
        return json.load(f)


def load_binary():
    with open(BINARY, "rb") as f:
        return f.read()


class TestRecordReset(unittest.TestCase):
    def test_verifier_exit_0(self):
        r = subprocess.run(
            ["python3", os.path.join(ROOT, "tools",
                                     "node115_lu_record_reset.py")],
            capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout[-2000:])

    def test_manifest_ok(self):
        manifest = os.path.join(PACKET, "MANIFEST.sha256")
        entries = []
        with open(manifest) as f:
            for line in f:
                if line.strip():
                    digest, rel = line.split()
                    entries.append((digest, rel))
        self.assertEqual(len(entries), 13)
        for digest, rel in entries:
            p = os.path.normpath(os.path.join(PACKET, rel))
            with open(p, "rb") as f:
                self.assertEqual(hashlib.sha256(f.read()).hexdigest(), digest,
                                 rel)

    def test_exhibit_bytes_match_binary(self):
        data = load_binary()
        records = load_records()
        for name, ex in records["exhibits"].items():
            start = int(ex["range"][0], 16)
            end = int(ex["range"][1], 16)
            with open(os.path.join(PACKET, name + ".hex")) as f:
                hexs = "".join(f.read().split())
            self.assertEqual(bytes.fromhex(hexs),
                             data[off_text(start):off_text(end)], name)
            self.assertEqual(len(bytes.fromhex(hexs)), ex["bytes"], name)

    def test_objdump_regeneration(self):
        records = load_records()
        for name, ex in records["exhibits"].items():
            start = int(ex["range"][0], 16)
            end = int(ex["range"][1], 16)
            out = subprocess.run(
                ["objdump", "-d", "--start-address=" + hex(start),
                 "--stop-address=" + hex(end), BINARY],
                capture_output=True, text=True).stdout
            lines = out.splitlines()
            idx = next(i for i, l in enumerate(lines)
                       if re.match(r"^[0-9a-f]+ <.*>:$", l))
            regen = "\n".join(l.lstrip() for l in lines[idx + 1:]
                               if l.strip()) + "\n"
            with open(os.path.join(PACKET, name + ".objdump.txt")) as f:
                self.assertEqual(regen, f.read(), name)

    def test_strict_counts(self):
        records = load_records()
        total = 0
        for name, ex in records["exhibits"].items():
            with open(os.path.join(PACKET, name + ".objdump.txt")) as f:
                lines = f.read().splitlines()
            strict = sum(1 for l in lines
                         if re.match(r"^[0-9a-f]+:\t[0-9a-f ]+\t\S", l))
            self.assertEqual(strict, ex["strict"], name)
            total += strict
        self.assertEqual(total, 22)

    def test_fde_bounds_padding_ret(self):
        data = load_binary()
        self.assertEqual(FDE_END - FDE_START, 77)
        self.assertEqual(data[off_text(FDE_START):off_text(FDE_START) + 4],
                         bytes.fromhex("f30f1efa"))
        self.assertEqual(data[off_text(0x63BF7EE):off_text(FDE_START)],
                         b"\xcc\xcc")
        self.assertEqual(data[off_text(FDE_END):off_text(0x63BF840)],
                         b"\xcc\xcc\xcc")
        self.assertEqual(data[off_text(0x63BF83C)], 0xC3)

    def test_copy_call_rel32s(self):
        data = load_binary()
        for site in (0x63BF81E, 0x63BF829):
            o = off_text(site)
            rel = struct.unpack_from("<i", data, o + 1)[0]
            self.assertEqual(data[o], 0xE8)
            self.assertEqual(site + 5 + rel, 0x63BFBF0)

    def test_zero_constant_and_tag_clobber(self):
        data = load_binary()
        self.assertEqual(data[0xB9E830:0xB9E838], b"\x00" * 8)
        entry = data[off_text(FDE_START):off_text(0x63BF800)]
        self.assertEqual(entry,
                         bytes.fromhex("f30f1efa55660fefc0488d2d30f07dfa"))
        # First write to rdi is the lea at 0x63bf800; nothing before it
        # reads rdi (endbr64, push, pxor, lea rbp only).

    def test_census_sites_inside_caller_fde(self):
        data = load_binary()
        records = load_records()
        sites = records["census"]["sites"]
        self.assertEqual(len(sites), 18)
        for s in sites:
            site = int(s, 16)
            self.assertTrue(0x63A5BF0 <= site < 0x63A6470, s)
            o = off_text(site)
            rel = struct.unpack_from("<i", data, o + 1)[0]
            self.assertEqual(data[o], 0xE8, s)
            self.assertEqual(site + 5 + rel, FDE_START, s)

    def test_tamper_control(self):
        data = load_binary()
        records = load_records()
        ex = records["exhibits"]["wk_zero"]
        start = int(ex["range"][0], 16)
        end = int(ex["range"][1], 16)
        with open(os.path.join(PACKET, "wk_zero.hex")) as f:
            raw = bytes.fromhex("".join(f.read().split()))
        self.assertEqual(raw, data[off_text(start):off_text(end)])
        with tempfile.TemporaryDirectory() as tmp:
            bad = bytearray(raw)
            bad[0] ^= 0xFF
            p = os.path.join(tmp, "wk_zero.hex")
            with open(p, "wb") as f:
                f.write(bad)
            with open(p, "rb") as f:
                tampered = f.read()
            self.assertNotEqual(tampered, data[off_text(start):off_text(end)])
        # Original file untouched.
        with open(os.path.join(PACKET, "wk_zero.hex")) as f:
            self.assertEqual(bytes.fromhex("".join(f.read().split())), raw)


if __name__ == "__main__":
    unittest.main()
