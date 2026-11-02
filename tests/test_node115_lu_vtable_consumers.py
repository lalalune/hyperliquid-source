#!/usr/bin/env python3
"""Unit tests for the RE-001-node115-lu-vtable-consumers packet.

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
PACKET = ROOT / "research" / "work-items" / "RE-001-node115-lu-vtable-consumers"
TOOL = ROOT / "tools" / "node115_lu_vtable_consumers.py"
NODE = ROOT / "artifacts" / "node" / "115" / "hl-node"


def run_tool():
    return subprocess.run([sys.executable, str(TOOL)],
                          capture_output=True, text=True)


class TestVtableConsumers(unittest.TestCase):
    def test_verifier_passes(self):
        r = run_tool()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("224B", r.stdout)
        self.assertIn("535B", r.stdout)
        self.assertIn("lea sites: 2 + 2", r.stdout)

    def test_consumer_caller2_hex_matches_binary(self):
        body = NODE.read_bytes()[0x15D6230 - 0x1000:0x15D6310 - 0x1000]
        pinned = bytes.fromhex((PACKET / "consumer_caller2.hex").read_text().strip())
        self.assertEqual(pinned, body)
        self.assertEqual(
            hashlib.sha256(pinned).hexdigest(),
            "4982a51852ff7709fdd0d104296add56d533678116639b9e048b58dd98c9958a")

    def test_drop_dispatch_hex_matches_binary(self):
        body = NODE.read_bytes()[0x15DACD0 - 0x1000:0x15DAD33 - 0x1000]
        pinned = bytes.fromhex((PACKET / "drop_dispatch.hex").read_text().strip())
        self.assertEqual(pinned, body)
        self.assertEqual(
            hashlib.sha256(pinned).hexdigest(),
            "f2bec9916cea0d6777f085c003c668dc9c6bda5537e22b77432fbd4420295aad")

    def test_corrupt_consumer_hex_rejected(self):
        src = (PACKET / "consumer_caller2.hex").read_text()
        bad = ("00" if src[:2] != "00" else "ff") + src[2:]
        (PACKET / "consumer_caller2.hex").write_text(bad)
        try:
            r = run_tool()
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("consumer_caller2.hex", r.stdout + r.stderr)
        finally:
            (PACKET / "consumer_caller2.hex").write_text(src)

    def test_corrupt_drop_twin_tag_rejected(self):
        src = (PACKET / "drop_caller2.hex").read_text()
        # First tag-check displacement byte: body offset 6 is 0x98
        # (cmp BYTE PTR [rdi+0x98],0x3); the state-machine twin has 0xa0.
        raw = bytearray(bytes.fromhex(src.strip()))
        self.assertEqual(raw[6], 0x98)
        raw[6] = 0x97
        (PACKET / "drop_caller2.hex").write_text(raw.hex() + "\n")
        try:
            r = run_tool()
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("drop_caller2.hex", r.stdout + r.stderr)
        finally:
            (PACKET / "drop_caller2.hex").write_text(src)


if __name__ == "__main__":
    unittest.main()
