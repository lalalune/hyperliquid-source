#!/usr/bin/env python3
"""Unit tests for the RE-001-node115-lu-park-queue packet.

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
PACKET = ROOT / "research" / "work-items" / "RE-001-node115-lu-park-queue"
TOOL = ROOT / "tools" / "node115_lu_park_queue.py"
NODE = ROOT / "artifacts" / "node" / "115" / "hl-node"


def run_tool():
    return subprocess.run([sys.executable, str(TOOL)],
                          capture_output=True, text=True)


class TestParkQueue(unittest.TestCase):
    def test_verifier_passes(self):
        r = run_tool()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("899B", r.stdout)
        self.assertIn("3 GOT sites", r.stdout)

    def test_park_hex_matches_binary(self):
        body = NODE.read_bytes()[0x5BB42E0 - 0x1000:0x5BB4663 - 0x1000]
        pinned = bytes.fromhex((PACKET / "park.hex").read_text().strip())
        self.assertEqual(len(body), 899)
        self.assertEqual(pinned, body)
        self.assertEqual(
            hashlib.sha256(pinned).hexdigest(),
            "15a928dcf95723b20a24cf6f2e8fed16118e2f4b0f3fbbe869dc6c6502d82c02")

    def test_single_ret_inside_fde(self):
        body = NODE.read_bytes()[0x5BB42E0 - 0x1000:0x5BB4663 - 0x1000]
        # ret at 0x5bb45d5 is body offset 0x2f5; the byte before it is pop rbp.
        self.assertEqual(body[0x2F5], 0xC3)
        self.assertEqual(body[0x2F4], 0x5D)

    def test_corrupt_park_hex_rejected(self):
        src = (PACKET / "park.hex").read_text()
        bad = ("00" if src[:2] != "00" else "ff") + src[2:]
        (PACKET / "park.hex").write_text(bad)
        try:
            r = run_tool()
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("park.hex", r.stdout + r.stderr)
        finally:
            (PACKET / "park.hex").write_text(src)

    def test_corrupt_futex_nr_rejected(self):
        # Body offset of the futex tail call's mov edi,0xca: 0x5bb45a6
        # is body offset 0x2c6; the immediate 0xca sits at offset 0x2c7.
        src = (PACKET / "park.hex").read_text()
        raw = bytearray(bytes.fromhex(src.strip()))
        self.assertEqual(raw[0x2C7], 0xCA)
        raw[0x2C7] = 0xCB
        (PACKET / "park.hex").write_text(raw.hex() + "\n")
        try:
            r = run_tool()
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("futex nr 202", r.stdout + r.stderr)
        finally:
            (PACKET / "park.hex").write_text(src)

    def test_corrupt_xorshift_shift_rejected(self):
        # shl esi,0xd at 0x5bb44ef: body offset 0x20f; shift byte at 0x211.
        src = (PACKET / "park.hex").read_text()
        raw = bytearray(bytes.fromhex(src.strip()))
        self.assertEqual(raw[0x211], 0x0D)
        raw[0x211] = 0x0E
        (PACKET / "park.hex").write_text(raw.hex() + "\n")
        try:
            r = run_tool()
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("shl 13", r.stdout + r.stderr)
        finally:
            (PACKET / "park.hex").write_text(src)

    def test_corrupt_records_byte_count_rejected(self):
        import json
        src = (PACKET / "records.json").read_text()
        rec = json.loads(src)
        rec["bodies"]["park"]["bytes"] = 643
        (PACKET / "records.json").write_text(json.dumps(rec))
        try:
            r = run_tool()
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("899", r.stdout + r.stderr)
        finally:
            (PACKET / "records.json").write_text(src)


if __name__ == "__main__":
    unittest.main()
