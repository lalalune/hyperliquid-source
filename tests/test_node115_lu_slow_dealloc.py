#!/usr/bin/env python3
"""Unit tests for RE-001-node115-lu-slow-dealloc.

Byte-level checks only; the node binary is never executed. The full
whole-binary census lives in tools/node115_lu_slow_dealloc.py
and is exercised separately (verifier exit 0).
"""
import hashlib
import json
import re
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-001-node115-lu-slow-dealloc"
BIN = ROOT / "artifacts" / "node" / "115" / "hl-node"

STRICT_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t\S")

EXCERPTS = [
    ("dispatch.hex", 0x635C6D0, 0x635C886),
    ("full.hex", 0x635CDF8, 0x635CE47),
    ("page.hex", 0x635CCE8, 0x635CD7F),
]

COUNTS = [
    ("dispatch.objdump.txt", 95),
    ("full.objdump.txt", 19),
    ("page.objdump.txt", 32),
]

KEY_BYTES = [
    (0x635C6D0, bytes.fromhex("f30f1efa")),
    (0x635C886, b"\xc3"),
    (0x635CE27, bytes.fromhex("e824df0800")),
    (0x635CD7A, bytes.fromhex("e841090600")),
    (0x635CE82, bytes.fromhex("ff15a82c1a00")),
    (0x6349380, bytes.fromhex("f30f1efa4889f2be5a000000e9ff760a00")),
    (0x635DED0, bytes.fromhex("e9fbe7ffff")),
]


def text_bytes(data, va, n):
    return data[va - 0x1000:va - 0x1000 + n]


def rela_relative(data):
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name, sh_type, _f, _a, sh_off, sh_size = struct.unpack_from(
            "<IIQQQQ", data, off)
        sections.append((sh_name, sh_type, sh_off, sh_size))
    str_off = sections[e_shstrndx][2]
    out = {}
    for sh_name, sh_type, sh_off, sh_size in sections:
        name_end = data.index(b"\x00", str_off + sh_name)
        name = data[str_off + sh_name:name_end].decode()
        if name == ".rela.dyn" and sh_type == 4:
            for j in range(sh_size // 24):
                r_off, r_info, r_add = struct.unpack_from(
                    "<QQq", data, sh_off + j * 24)
                if r_info & 0xFFFFFFFF == 8:
                    out[r_off] = r_add
    return out


class TestSlowDealloc(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = BIN.read_bytes()

    def test_excerpts_regenerate(self):
        for name, start, end in EXCERPTS:
            raw = bytes.fromhex((PACKET / name).read_text().strip())
            self.assertEqual(raw, text_bytes(self.data, start, end - start),
                             name)

    def test_tamper_control(self):
        raw = bytes.fromhex((PACKET / "dispatch.hex").read_text().strip())
        bad = bytearray(raw)
        bad[0] ^= 0xFF
        self.assertNotEqual(bytes(bad),
                            text_bytes(self.data, 0x635C6D0, 0x635C886 - 0x635C6D0))

    def test_strict_counts(self):
        for name, want in COUNTS:
            lines = (PACKET / name).read_text().splitlines()
            count = sum(1 for ln in lines if STRICT_RE.match(ln))
            self.assertEqual(count, want, name)

    def test_key_bytes(self):
        for va, want in KEY_BYTES:
            self.assertEqual(text_bytes(self.data, va, len(want)), want,
                             hex(va))

    def test_poison_rela(self):
        rela = rela_relative(self.data)
        self.assertEqual(rela.get(0x64FFB30), 0x6349380)
        self.assertEqual(rela.get(0x64DF4A0), 0x635DE30)
        self.assertNotIn(0x635C6D0, rela.values())

    def test_fde_no_syscall(self):
        fde = text_bytes(self.data, 0x635C6D0, 0x635DE25 - 0x635C6D0)
        self.assertEqual(len(fde), 5973)
        self.assertNotIn(b"\x0f\x05", fde)

    def test_records_agreement(self):
        records = json.loads((PACKET / "records.json").read_text())
        for exc in records["excerpts"]:
            self.assertEqual(exc["bytes"],
                             int(exc["end"], 16) - int(exc["start"], 16))
            lines = (PACKET / exc["objdump"]).read_text().splitlines()
            count = sum(1 for ln in lines if STRICT_RE.match(ln))
            self.assertEqual(count, exc["strict_mnemonic_lines"],
                             exc["file"])
        self.assertEqual(records["slow_path"]["size_bytes"], 5973)
        self.assertEqual(records["slow_path"]["strict_mnemonic_lines"], 1220)

    def test_manifest_coverage(self):
        man = (PACKET / "MANIFEST.sha256").read_text().splitlines()
        listed = {}
        for line in man:
            digest, path = line.split("  ", 1)
            listed[path] = digest
        expect = {"README.md", "EVIDENCE.md", "records.json",
                  "dispatch.hex", "dispatch.objdump.txt",
                  "full.hex", "full.objdump.txt",
                  "page.hex", "page.objdump.txt",
                  "../../../tools/node115_lu_slow_dealloc.py",
                  "../../../tests/test_node115_lu_slow_dealloc.py"}
        self.assertEqual(set(listed), expect)
        for path, digest in listed.items():
            blob = (PACKET / path).read_bytes()
            self.assertEqual(hashlib.sha256(blob).hexdigest(), digest, path)


if __name__ == "__main__":
    unittest.main()
