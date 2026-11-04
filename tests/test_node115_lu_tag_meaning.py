#!/usr/bin/env python3
"""Unit tests for the RE-001-node115-lu-tag-meaning packet.

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
PACKET = ROOT / "research" / "work-items" / "RE-001-node115-lu-tag-meaning"
TOOL = ROOT / "tools" / "node115_lu_tag_meaning.py"
NODE = ROOT / "artifacts" / "node" / "115" / "hl-node"


def run_tool():
    return subprocess.run([sys.executable, str(TOOL)],
                          capture_output=True, text=True)


class TestTagMeaning(unittest.TestCase):
    def test_verifier_passes(self):
        r = run_tool()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("703B", r.stdout)

    def test_helper_hex_matches_binary(self):
        body = NODE.read_bytes()[0x5CF2D30 - 0x1000:0x5CF2FEF - 0x1000]
        pinned = bytes.fromhex((PACKET / "helper.hex").read_text().strip())
        self.assertEqual(pinned, body)
        self.assertEqual(
            hashlib.sha256(pinned).hexdigest(),
            "fb3fb193f0b14f251e01da509c670d299323482419d1edef4170d948604cbbb2")

    def test_callsite_excerpt_matches_binary(self):
        body = NODE.read_bytes()[0x15D5F37 - 0x1000:0x15D5F8E - 0x1000]
        self.assertEqual(
            hashlib.sha256(body).hexdigest(),
            "56fbd53f6667c43e9170489c9afa13064f9c88334123219dd640d03a3b6cdcbb")

    def test_corrupt_helper_hex_rejected(self):
        src = (PACKET / "helper.hex").read_text()
        bad = ("00" if src[:2] != "00" else "ff") + src[2:]
        (PACKET / "helper.hex").write_text(bad)
        try:
            r = run_tool()
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("helper.hex", r.stdout + r.stderr)
        finally:
            (PACKET / "helper.hex").write_text(src)

    def test_corrupt_callsite_direction_byte_rejected(self):
        src = (PACKET / "callsite.hex").read_text()
        # The direction bytes live at callsite offset 0x15d5f4a-0x15d5f37 = 19.
        raw = bytearray(bytes.fromhex(src.strip()))
        raw[19 + 2] = 0x74 if raw[19 + 2] != 0x74 else 0x75  # jne -> je
        (PACKET / "callsite.hex").write_text(raw.hex() + "\n")
        try:
            r = run_tool()
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("callsite.hex", r.stdout + r.stderr)
        finally:
            (PACKET / "callsite.hex").write_text(src)


if __name__ == "__main__":
    unittest.main()
