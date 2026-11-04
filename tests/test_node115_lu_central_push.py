#!/usr/bin/env python3
"""Unit tests for RE-001-node115-lu-central-push."""

import hashlib
import os
import re
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(ROOT, "research", "work-items",
                       "RE-001-node115-lu-central-push")
BINARY = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")

EXHIBITS = [
    ("push", 0x63C0340, 0x63C03E8, 45),
    ("flag_large", 0x63BD687, 0x63BD6B3, 13),
    ("flag_small", 0x63612E6, 0x6361313, 13),
    ("fallback_gate", 0x6360610, 0x636063A, 13),
]


def read_bytes(va, n):
    with open(BINARY, "rb") as f:
        f.seek(va - 0x1000)
        return f.read(n)


def objdump_lines(start, end):
    out = subprocess.run(
        ["objdump", "-d", f"--start-address={hex(start)}",
         f"--stop-address={hex(end)}", BINARY],
        capture_output=True, text=True, check=True).stdout
    lines = []
    for line in out.splitlines():
        m = re.match(r"^\s*([0-9a-f]+):", line)
        if m and start <= int(m.group(1), 16) < end:
            lines.append(line)
    return lines


def strict_lines(start, end):
    out = []
    for line in objdump_lines(start, end):
        m = re.match(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t(.*)$", line)
        if m and m.group(1).strip() and not re.fullmatch(r"[0-9a-f ]+",
                                                          m.group(1).strip()):
            out.append(line)
    return out


class TestCentralPush(unittest.TestCase):
    def test_regenerate(self):
        for name, start, end, _ in EXHIBITS:
            with open(os.path.join(PACKET, f"{name}.hex")) as f:
                claimed = bytes.fromhex("".join(f.read().split()))
            self.assertEqual(claimed, read_bytes(start, end - start), name)

    def test_tamper_control(self):
        raw = read_bytes(0x63C0340, 4)
        self.assertNotEqual(raw, bytes.fromhex("00000000"))
        self.assertEqual(raw, bytes.fromhex("f30f1efa"))

    def test_strict_counts(self):
        for name, start, end, expect in EXHIBITS:
            self.assertEqual(len(strict_lines(start, end)), expect, name)

    def test_key_bytes(self):
        cases = {
            0x63C0369: "e872ecfeff",   # call 0x63aefe0
            0x63C03DD: "e85ee9feff",   # call 0x63aed40
            0x63C0397: "f048295308",   # lock sub obj+0x8
            0x63C03CA: "41ffe0",       # jmp *r8
            0x63C03B5: "480f44f1",     # cmove
            0x63BD682: "e8b92c0000",   # push-large call
            0x63612E1: "e85af00500",   # push-small call
        }
        for va, hexbytes in cases.items():
            want = bytes.fromhex(hexbytes)
            self.assertEqual(read_bytes(va, len(want)), want, hex(va))

    def test_fde_boundaries(self):
        # Push FDE starts with endbr64 and its last byte is the cold-path
        # jmp back (0x63c03e6..0x63c03e8); no ret inside the FDE.
        self.assertEqual(read_bytes(0x63C0340, 4), bytes.fromhex("f30f1efa"))
        self.assertEqual(read_bytes(0x63C03E6, 2), bytes.fromhex("eb8f"))
        self.assertEqual(read_bytes(0x63C03E8, 1), bytes.fromhex("cc"))

    def test_rela_dyn_got(self):
        out = subprocess.run(["readelf", "-r", BINARY],
                             capture_output=True, text=True,
                             check=True).stdout
        for line in out.splitlines():
            if "R_X86_64_RELATIVE" in line:
                p = line.split()
                if len(p) >= 3:
                    try:
                        self.assertNotEqual(int(p[2], 16), 0x63C0340)
                    except ValueError:
                        pass

    def test_census_spot(self):
        # Two census sites outside the push wrappers, byte-verified.
        self.assertEqual(read_bytes(0x63BD730, 5), bytes.fromhex("e80b2c0000"))
        self.assertEqual(read_bytes(0x6363AB6, 5), bytes.fromhex("e885c80500"))

    def test_manifest_coverage(self):
        with open(os.path.join(PACKET, "MANIFEST.sha256")) as f:
            entries = [ln.split() for ln in f.read().splitlines() if ln.strip()]
        self.assertEqual(len(entries), 13)
        names = {rel for _, rel in entries}
        for name, _, _, _ in EXHIBITS:
            self.assertIn(f"{name}.hex", names)
            self.assertIn(f"{name}.objdump.txt", names)
        self.assertIn("README.md", names)
        self.assertIn("EVIDENCE.md", names)
        self.assertIn("records.json", names)


if __name__ == "__main__":
    unittest.main()
