#!/usr/bin/env python3
"""Unit tests for the RE-001-node115-lu-qtable-slot8 packet.

Corruption controls mutate one pinned value at a time and require the
verifier to fail; the unmutated run must pass. Tests read the node binary
and packet files only; they never execute the node.
"""
import hashlib
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-001-node115-lu-qtable-slot8"
TOOL = ROOT / "tools" / "node115_lu_qtable_slot8.py"
NODE = ROOT / "artifacts" / "node" / "115" / "hl-node"


def run_tool():
    return subprocess.run([sys.executable, str(TOOL)],
                          capture_output=True, text=True)


class TestQtableSlot8(unittest.TestCase):
    def test_verifier_passes(self):
        r = run_tool()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("lea sites: 11", r.stdout)
        self.assertIn("slot2 2, slot3 6", r.stdout)

    def test_slot8_wake_hex_matches_binary(self):
        body = NODE.read_bytes()[0x5CFD8C0 - 0x1000:0x5CFD991 - 0x1000]
        pinned = bytes.fromhex((PACKET / "slot8_wake.hex").read_text().strip())
        self.assertEqual(pinned, body)
        self.assertEqual(
            hashlib.sha256(pinned).hexdigest(),
            "23b7197ad9830ea95986fac04b952227e6cfb89e0236565482d8b79bfb8a25c5")

    def test_slot2_wake_by_ref_hex_matches_binary(self):
        body = NODE.read_bytes()[0x5CFD600 - 0x1000:0x5CFD6A0 - 0x1000]
        pinned = bytes.fromhex((PACKET / "slot2_wake_by_ref.hex").read_text().strip())
        self.assertEqual(pinned, body)
        self.assertEqual(
            hashlib.sha256(pinned).hexdigest(),
            "9e8b5b9398cb3bf3bc18b1d862a6f9b61f934d78ce359c8d75c94666aabbdf2d")

    def test_corrupt_slot8_hex_rejected(self):
        src = (PACKET / "slot8_wake.hex").read_text()
        bad = ("00" if src[:2] != "00" else "ff") + src[2:]
        (PACKET / "slot8_wake.hex").write_text(bad)
        try:
            r = run_tool()
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("slot8_wake.hex", r.stdout + r.stderr)
        finally:
            (PACKET / "slot8_wake.hex").write_text(src)

    def test_corrupt_slot8_state_byte_rejected(self):
        src = (PACKET / "slot8_wake.hex").read_text()
        # Body offset 13 is the xchg-state immediate 0x02 (mov eax,0x2 at
        # 0x5cfd8cc, body offset 12..16); flipping it must break the
        # pinned-body check.
        raw = bytearray(bytes.fromhex(src.strip()))
        self.assertEqual(raw[13], 0x02)
        raw[13] = 0x03
        (PACKET / "slot8_wake.hex").write_text(raw.hex() + "\n")
        try:
            r = run_tool()
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("slot8_wake.hex", r.stdout + r.stderr)
        finally:
            (PACKET / "slot8_wake.hex").write_text(src)


if __name__ == "__main__":
    unittest.main()
