#!/usr/bin/env python3
"""Unit tests for the RE-001-node115-lu-coop-context packet.

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
PACKET = ROOT / "research" / "work-items" / "RE-001-node115-lu-coop-context"
TOOL = ROOT / "tools" / "node115_lu_coop_context.py"
NODE = ROOT / "artifacts" / "node" / "115" / "hl-node"


def run_tool():
    return subprocess.run([sys.executable, str(TOOL)],
                          capture_output=True, text=True)


class TestCoopContext(unittest.TestCase):
    def test_verifier_passes(self):
        r = run_tool()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("162B", r.stdout)
        self.assertIn("195B", r.stdout)
        self.assertIn("52", r.stdout)

    def test_coop_hex_matches_binary(self):
        body = NODE.read_bytes()[0x5CF3B90 - 0x1000:0x5CF3C32 - 0x1000]
        pinned = bytes.fromhex((PACKET / "coop.hex").read_text().strip())
        self.assertEqual(pinned, body)
        self.assertEqual(
            hashlib.sha256(pinned).hexdigest(),
            "4e1e4bdf5cc0958d8dcda1d39d881129a4e7da55b093d24049090e460c5c20ab")

    def test_proceed_hex_matches_binary(self):
        body = NODE.read_bytes()[0x5CFC310 - 0x1000:0x5CFC3D3 - 0x1000]
        pinned = bytes.fromhex((PACKET / "proceed.hex").read_text().strip())
        self.assertEqual(pinned, body)
        self.assertEqual(
            hashlib.sha256(pinned).hexdigest(),
            "324f8fca50735d84a2e13d3c3d667b274a06ccd412587091544846b7a3122a81")

    def test_corrupt_coop_hex_rejected(self):
        src = (PACKET / "coop.hex").read_text()
        bad = ("00" if src[:2] != "00" else "ff") + src[2:]
        (PACKET / "coop.hex").write_text(bad)
        try:
            r = run_tool()
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("coop.hex", r.stdout + r.stderr)
        finally:
            (PACKET / "coop.hex").write_text(src)

    def test_corrupt_proceed_tail_jmp_rejected(self):
        src = (PACKET / "proceed.hex").read_text()
        # The dedup call [rax] lives at proceed offset 0x5cfc35a-0x5cfc310 = 0x4a.
        raw = bytearray(bytes.fromhex(src.strip()))
        raw[0x4A] = 0x11 if raw[0x4A] != 0x11 else 0x10  # ff 10 -> ff 11
        (PACKET / "proceed.hex").write_text(raw.hex() + "\n")
        try:
            r = run_tool()
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("proceed.hex", r.stdout + r.stderr)
        finally:
            (PACKET / "proceed.hex").write_text(src)


if __name__ == "__main__":
    unittest.main()
