#!/usr/bin/env python3
"""Unit tests for RE-001-node115-lu-miss (packet #215).

Stdlib unittest only (pytest is not installed in this environment).
Regenerates excerpts from node #115, checks strict counts, key bytes,
FDE bounds, census spot sites, MANIFEST coverage, and a tamper control.
"""

import hashlib
import json
import re
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
BIN = REPO / "artifacts" / "node" / "115" / "hl-node"
PACKET = REPO / "research" / "work-items" / "RE-001-node115-lu-miss"
TOOLS = REPO / "tools"

sys.path.insert(0, str(TOOLS))
import node115_lu_miss as V  # noqa: E402

EXPECT_SHA = V.EXPECT_SHA
EXPECT_SIZE = V.EXPECT_SIZE


def read_va(va, n):
    with open(BIN, "rb") as f:
        f.seek(va - 0x1000)
        return f.read(n)


class TestRegenerate(unittest.TestCase):
    def test_binary_sha_and_size(self):
        data = open(BIN, "rb").read()
        self.assertEqual(hashlib.sha256(data).hexdigest(), EXPECT_SHA)
        self.assertEqual(len(data), EXPECT_SIZE)

    def test_excerpts_regenerate(self):
        for name, start, stop, strict in V.EXCERPTS:
            raw = read_va(start, stop - start)
            claimed = bytes.fromhex(
                (PACKET / f"{name}.hex").read_text().split()[0])
            self.assertEqual(raw, claimed, name)
            lines, got = V.objdump_lines(start, stop)
            stored = (PACKET / f"{name}.objdump.txt").read_text().splitlines()
            self.assertEqual(lines, stored, name)
            self.assertEqual(got, strict, name)

    def test_exhibit_totals(self):
        total_b = sum(stop - start for _, start, stop, _ in V.EXCERPTS)
        total_s = sum(s for *_, s in V.EXCERPTS)
        self.assertEqual(total_b, 246)
        self.assertEqual(total_s, 62)
        rec = json.loads((PACKET / "records.json").read_text())
        self.assertEqual(rec["exhibit_bytes"], 246)
        self.assertEqual(rec["exhibit_strict"], 62)


class TestTamper(unittest.TestCase):
    def test_flipped_byte_rejected(self):
        name, start, stop, _ = V.EXCERPTS[0]
        raw = bytearray(read_va(start, stop - start))
        raw[0] ^= 0xFF
        claimed = bytes.fromhex(
            (PACKET / f"{name}.hex").read_text().split()[0])
        self.assertNotEqual(bytes(raw), claimed)


class TestKeyBytesAndCalls(unittest.TestCase):
    def test_key_bytes(self):
        for va, hx in V.KEY_BYTES:
            self.assertEqual(read_va(va, len(bytes.fromhex(hx))).hex(), hx,
                             hex(va))

    def test_key_calls(self):
        for site, target in V.KEY_CALLS:
            raw = read_va(site, 5)
            self.assertEqual(raw[0], 0xE8, hex(site))
            got = site + 5 + struct.unpack("<i", raw[1:5])[0]
            self.assertEqual(got, target, hex(site))


class TestFdeAndCensus(unittest.TestCase):
    def test_fde_bounds(self):
        out = subprocess.run(["objdump", "--dwarf=frames", str(BIN)],
                             capture_output=True, text=True,
                             check=True).stdout
        self.assertIn("pc=00000000063d9700..00000000063d987b", out)

    def test_census_spot(self):
        # Worker site + one site per mode, confirmed as E8 -> handler.
        for site in (0x63AE239, 0x63ADE8D, 0x63AE627):
            raw = read_va(site, 5)
            self.assertEqual(raw[0], 0xE8, hex(site))
            got = site + 5 + struct.unpack("<i", raw[1:5])[0]
            self.assertEqual(got, 0x63D9700, hex(site))
        rec = json.loads((PACKET / "records.json").read_text())
        self.assertEqual(len(rec["census_e8_sites"]), 168)
        self.assertEqual(rec["census"]["handler_e8"], 168)
        self.assertEqual(rec["census"]["handler_e9"], 0)
        self.assertEqual(rec["census"]["handler_lea"], 0)
        self.assertEqual(rec["census"]["handler_got"], 0)


class TestManifest(unittest.TestCase):
    def test_manifest_coverage(self):
        out = subprocess.run(["sha256sum", "-c", "MANIFEST.sha256"],
                             cwd=str(PACKET), capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        entries = [l for l in out.stdout.splitlines() if l.strip()]
        self.assertEqual(len(entries), 15)
        # Every packet file except MANIFEST itself is listed.
        listed = set()
        for line in entries:
            # sha256sum -c prints "file: OK".
            listed.add(line.rsplit(": ", 1)[0].strip())
        self.assertIn("README.md", listed)
        self.assertIn("EVIDENCE.md", listed)
        self.assertIn("records.json", listed)
        self.assertIn("../../../tools/node115_lu_miss.py", listed)
        self.assertIn("../../../tests/test_node115_lu_miss.py", listed)


if __name__ == "__main__":
    unittest.main()
