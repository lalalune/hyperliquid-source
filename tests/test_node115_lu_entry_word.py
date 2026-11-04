#!/usr/bin/env python3
"""Unit tests for the RE-001-node115-lu-entry-word packet.

Corruption controls mutate one pinned value at a time and require the
verifier to fail; the unmutated run must pass. Tests read the node binary
and packet files only; they never execute the node.
"""
import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-001-node115-lu-entry-word"
TOOL = ROOT / "tools" / "node115_lu_entry_word.py"
NODE = ROOT / "artifacts" / "node" / "115" / "hl-node"

HELPER_SHA = "a94378e14e8639339101729a199bd051e7795fc54c0ca9f2ff528bffcf902be8"


def run_tool():
    return subprocess.run([sys.executable, str(TOOL)],
                          capture_output=True, text=True)


class TestEntryWord(unittest.TestCase):
    def test_verifier_passes(self):
        r = run_tool()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("329B", r.stdout)
        self.assertIn("13 GOT helper", r.stdout)

    def test_helper_hex_matches_binary(self):
        body = NODE.read_bytes()[0x5BB6790 - 0x1000:0x5BB68D9 - 0x1000]
        pinned = bytes.fromhex((PACKET / "helper.hex").read_text().strip())
        self.assertEqual(len(body), 329)
        self.assertEqual(pinned, body)
        self.assertEqual(hashlib.sha256(pinned).hexdigest(), HELPER_SHA)

    def test_single_ret_inside_fde(self):
        body = NODE.read_bytes()[0x5BB6790 - 0x1000:0x5BB68D9 - 0x1000]
        # ret at 0x5bb68d8 is body offset 0x148; the byte before it is pop rbp.
        self.assertEqual(body[0x148], 0xC3)
        self.assertEqual(body[0x147], 0x5D)

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

    def test_corrupt_push_site_rejected(self):
        # Push cmpxchg at 0x5bb687a is body offset 0xea; its opcode byte
        # 0xf0 sits at offset 0xea.
        src = (PACKET / "helper.hex").read_text()
        raw = bytearray(bytes.fromhex(src.strip()))
        self.assertEqual(raw[0xEA], 0xF0)
        raw[0xEA] = 0xF1
        (PACKET / "helper.hex").write_text(raw.hex() + "\n")
        try:
            r = run_tool()
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("push cmpxchg", r.stdout + r.stderr)
        finally:
            (PACKET / "helper.hex").write_text(src)

    def test_corrupt_futex_nr_rejected(self):
        # Futex tail call's mov edi,0xca at 0x5bb68a0 is body offset 0x110;
        # the immediate 0xca sits at offset 0x111.
        src = (PACKET / "helper.hex").read_text()
        raw = bytearray(bytes.fromhex(src.strip()))
        self.assertEqual(raw[0x111], 0xCA)
        raw[0x111] = 0xCB
        (PACKET / "helper.hex").write_text(raw.hex() + "\n")
        try:
            r = run_tool()
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("futex nr 202", r.stdout + r.stderr)
        finally:
            (PACKET / "helper.hex").write_text(src)

    def test_corrupt_records_byte_count_rejected(self):
        src = (PACKET / "records.json").read_text()
        rec = json.loads(src)
        rec["bodies"]["helper"]["bytes"] = 643
        (PACKET / "records.json").write_text(json.dumps(rec))
        try:
            r = run_tool()
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("329", r.stdout + r.stderr)
        finally:
            (PACKET / "records.json").write_text(src)


if __name__ == "__main__":
    unittest.main()
