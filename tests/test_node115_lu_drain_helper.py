#!/usr/bin/env python3
"""Unit tests for RE-001-node115-lu-drain-helper.

Regeneration, tamper control, strict counts, key bytes, FDE
boundaries, .rela.dyn GOT absence, census spot check, and MANIFEST
coverage. Static byte reads only; the node binary is never executed.
"""

import hashlib
import os
import re
import struct
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(ROOT, "research", "work-items",
                      "RE-001-node115-lu-drain-helper")
BINARY = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")

EXHIBITS = [
    ("drain", 0x63697A0, 0x63697D2, 15),
    ("accum", 0x63A9712, 0x63A9742, 12),
    ("stub", 0x63BFB90, 0x63BFB98, 3),
]

STRICT_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t\S+")


def read_bytes(va, n):
    off = va - 0x1000
    out = subprocess.run(["od", "-An", "-tx1", "-j", str(off), "-N", str(n),
                          BINARY], capture_output=True, text=True,
                         check=True).stdout
    return bytes.fromhex(out.replace(" ", "").replace("\n", ""))


def hex_of(name):
    with open(os.path.join(PACKET, f"{name}.hex"), encoding="utf-8") as f:
        return bytes.fromhex("".join(f.read().split()))


def objdump_lines(name, start, end):
    out = subprocess.run(
        ["objdump", "-d", f"--start-address={hex(start)}",
         f"--stop-address={hex(end)}", BINARY],
        capture_output=True, text=True, check=True).stdout
    return [ln for ln in out.splitlines()
            if re.match(r"^\s*[0-9a-f]+:\t", ln)
            and start <= int(ln.split(":")[0].strip(), 16) < end]


class TestDrainHelper(unittest.TestCase):
    def test_regenerate(self):
        for name, start, end, _ in EXHIBITS:
            self.assertEqual(hex_of(name), read_bytes(start, end - start),
                             f"{name}.hex regeneration failed")

    def test_tamper_control(self):
        raw = bytearray(hex_of("drain"))
        raw[10] ^= 0xFF
        self.assertNotEqual(bytes(raw),
                            read_bytes(0x63697A0, 50),
                            "tampered drain bytes must not match binary")

    def test_strict_counts(self):
        for name, start, end, want in EXHIBITS:
            lines = objdump_lines(name, start, end)
            got = sum(1 for ln in lines if STRICT_RE.match(ln))
            self.assertEqual(got, want, f"{name} strict count {got} != {want}")

    def test_key_bytes(self):
        self.assertEqual(read_bytes(0x63697AB, 2), bytes.fromhex("7410"))
        self.assertEqual(read_bytes(0x63697B0, 5),
                         bytes.fromhex("e8db630500"))
        self.assertEqual(read_bytes(0x63697B5, 6),
                         bytes.fromhex("483dffe0f505"))
        self.assertEqual(read_bytes(0x63697C2, 5),
                         bytes.fromhex("e939800800"))
        self.assertEqual(read_bytes(0x63A9714, 3),
                         bytes.fromhex("48f7f5"))
        self.assertEqual(read_bytes(0x63A9724, 7),
                         bytes.fromhex("488d0d154a7ffa"))
        self.assertEqual(read_bytes(0x63BFB94, 3),
                         bytes.fromhex("488b07"))

    def test_fde_boundaries(self):
        # Drain FDE start endbr64, silent-ret at 0x63697d1.
        self.assertEqual(read_bytes(0x63697A0, 4),
                         bytes.fromhex("f30f1efa"))
        self.assertEqual(read_bytes(0x63697D1, 1), b"\xc3")
        # Accumulator FDE start endbr64, stub start endbr64 + ret.
        self.assertEqual(read_bytes(0x63A96F0, 4),
                         bytes.fromhex("f30f1efa"))
        self.assertEqual(read_bytes(0x63BFB90, 4),
                         bytes.fromhex("f30f1efa"))
        self.assertEqual(read_bytes(0x63BFB97, 1), b"\xc3")

    def test_rela_got_absence(self):
        out = subprocess.run(["readelf", "-r", BINARY], capture_output=True,
                             text=True, check=True).stdout
        targets = {0x63697A0, 0x63A96F0, 0x6369790}
        for line in out.splitlines():
            m = re.match(r"\s*[0-9a-f]+\s+[0-9a-f]+\s+R_X86_64_RELATIVE\s+"
                         r"([0-9a-f]+)", line)
            if m:
                self.assertNotIn(int(m.group(1), 16), targets,
                                 "GOT RELATIVE addend equals a target")

    def test_census_spot(self):
        out = subprocess.run(["readelf", "-SW", BINARY], capture_output=True,
                             text=True, check=True).stdout
        va = off = size = None
        for line in out.splitlines():
            m = re.search(r"\.text\s+\w+\s+([0-9a-f]+)\s+([0-9a-f]+)\s+"
                          r"([0-9a-f]+)", line)
            if m:
                va, off, size = (int(x, 16) for x in m.groups())
                break
        with open(BINARY, "rb") as f:
            f.seek(off)
            blob = f.read(size)
        sites = []
        i = 0
        while True:
            i = blob.find(b"\xe8", i)
            if i < 0:
                break
            if i + 5 <= len(blob):
                disp = struct.unpack("<i", blob[i + 1:i + 5])[0]
                if va + i + 5 + disp == 0x63697A0:
                    sites.append(va + i)
            i += 1
        self.assertEqual(sites, [0x635F632, 0x635F645],
                         "drain census spot check failed")

    def test_manifest_coverage(self):
        with open(os.path.join(PACKET, "MANIFEST.sha256"),
                  encoding="utf-8") as f:
            entries = [ln.split() for ln in f.read().splitlines()
                       if ln.strip()]
        self.assertEqual(len(entries), 11, "MANIFEST entry count")
        covered = set()
        for digest, rel in entries:
            p = os.path.normpath(os.path.join(PACKET, rel))
            with open(p, "rb") as f:
                self.assertEqual(hashlib.sha256(f.read()).hexdigest(), digest,
                                 f"MANIFEST mismatch for {rel}")
            covered.add(rel)
        want = {"README.md", "EVIDENCE.md", "records.json",
                "drain.hex", "drain.objdump.txt",
                "accum.hex", "accum.objdump.txt",
                "stub.hex", "stub.objdump.txt",
                "../../../tools/node115_lu_drain_helper.py",
                "../../../tests/test_node115_lu_drain_helper.py"}
        self.assertEqual(covered, want, "MANIFEST coverage mismatch")


if __name__ == "__main__":
    unittest.main()
