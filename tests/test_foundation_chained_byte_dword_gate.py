#!/usr/bin/env python3
"""Unit tests for the node #94 chained byte/dword gate checker.

These test the checker logic against the retained evidence, never execute
target code, and never claim anything about the fields' meanings or about
the nearby cluster windows.
"""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_chained_byte_dword_gate as checker

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = (ROOT / 'research/work-items/foundation-chained-byte-dword-gate-94'
            / 'evidence.json')
TARGET = ROOT / 'artifacts/node/94/hl-node'


class TestChainedByteDwordGate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = TARGET.read_bytes()
        cls.want = json.loads(EVIDENCE.read_text())

    def test_check_reproduces(self):
        self.assertEqual(checker.analyze(self.data), self.want)

    def test_rule_edges(self):
        # (first byte, second byte, third byte, dword+0x9c, dword+0x98)
        self.assertEqual(checker.gate(1, 0, 1, 0, 1), 0)
        self.assertEqual(checker.gate(0xff, 0x41, 0, 0, 0), 0)
        self.assertEqual(checker.gate(0, 0x41, 1, 0, 1), 0x41)
        self.assertEqual(checker.gate(0, 0xff, 1, 0, 0), 0xff)
        self.assertEqual(checker.gate(0, 0, 0, 0, 1), 0)
        self.assertEqual(checker.gate(0, 0, 1, 3, 4), 1)
        self.assertEqual(checker.gate(0, 0, 1, 4, 4), 0)
        self.assertEqual(checker.gate(0, 0, 1, 5, 4), 0)
        self.assertEqual(checker.gate(0, 0, 1, 0, 0xffffffff), 1)
        self.assertEqual(checker.gate(0, 0, 1, 0xffffffff, 0), 0)

    def test_body_byte_corruption_fails(self):
        from elf_index import sections
        secs = sections(self.data)
        text = [s for s in secs if s['name'] == '.text'][0]
        off = text['offset'] + 0x5382d50 - text['address']
        bad = bytearray(self.data)
        bad[off] ^= 0x01
        with self.assertRaises(ValueError):
            checker.analyze(bytes(bad))

    def test_padding_byte_corruption_fails(self):
        from elf_index import sections
        secs = sections(self.data)
        text = [s for s in secs if s['name'] == '.text'][0]
        off = text['offset'] + 0x5382d8b - text['address']
        bad = bytearray(self.data)
        bad[off] = 0x90
        with self.assertRaises(ValueError):
            checker.analyze(bytes(bad))

    def test_naming_slot_corruption_fails(self):
        from elf_index import sections
        secs = sections(self.data)
        rela = [s for s in secs if s['name'] == '.rela.dyn'][0]
        bad = bytearray(self.data)
        # First naming slot's addend field (offset + 16 within the 24-byte entry).
        import struct
        for i in range(rela['size'] // 24):
            off_, _info, add = struct.unpack_from(
                '<QQq', bad, rela['offset'] + i * 24)
            if add == 0x5382d50:
                struct.pack_into('<q', bad, rela['offset'] + i * 24 + 16, 0x0)
                break
        with self.assertRaises(ValueError):
            checker.analyze(bytes(bad))

    def test_target_digest_corruption_fails(self):
        bad = bytearray(self.data)
        bad[0] ^= 0x01
        with self.assertRaises(ValueError):
            checker.analyze(bytes(bad))

    def test_evidence_mismatch_fails(self):
        got = checker.analyze(self.data)
        tampered = dict(got)
        tampered['window_size'] = got['window_size'] + 1
        self.assertNotEqual(got, tampered)


if __name__ == '__main__':
    unittest.main()
