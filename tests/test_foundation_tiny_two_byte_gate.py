#!/usr/bin/env python3
"""Unit tests for the node #94 tiny two-byte gate checker.

These test the checker logic against the retained evidence, never execute
target code, and never claim anything about the fields' meanings, the two
naming slots, or any other use of the window.
"""
import json
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_tiny_two_byte_gate as checker

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = (ROOT / 'research/work-items/foundation-tiny-two-byte-gate-94'
            / 'evidence.json')
TARGET = ROOT / 'artifacts/node/94/hl-node'


class TestTinyTwoByteGate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = TARGET.read_bytes()
        cls.want = json.loads(EVIDENCE.read_text())

    def test_check_reproduces(self):
        self.assertEqual(checker.analyze(self.data), self.want)

    def test_rule_edges(self):
        # (first byte, second byte) -> return value
        self.assertEqual(checker.gate(0, 0), 0)
        self.assertEqual(checker.gate(0, 0xff), 0)
        self.assertEqual(checker.gate(1, 0), 1)
        self.assertEqual(checker.gate(0xff, 0), 1)
        self.assertEqual(checker.gate(1, 1), 0)
        self.assertEqual(checker.gate(0xff, 0xff), 0)
        self.assertEqual(checker.gate(0x80, 0x00), 1)

    def test_body_byte_corruption_fails(self):
        from elf_index import sections
        secs = sections(self.data)
        text = [s for s in secs if s['name'] == '.text'][0]
        off = text['offset'] + 0x51647b0 - text['address']
        bad = bytearray(self.data)
        bad[off] ^= 0x01
        with self.assertRaises(ValueError):
            checker.analyze(bytes(bad))

    def test_padding_byte_corruption_fails(self):
        from elf_index import sections
        secs = sections(self.data)
        text = [s for s in secs if s['name'] == '.text'][0]
        off = text['offset'] + 0x51647c4 - text['address']
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
        # Mutate in place without copying the 91MB buffer per entry.
        for i in range(rela['size'] // 24):
            off_, _info, add = struct.unpack_from(
                '<QQq', bad, rela['offset'] + i * 24)
            if add == 0x51647b0:
                struct.pack_into('<q', bad, rela['offset'] + i * 24 + 16,
                                 add + 1)
                break
        with self.assertRaises(ValueError):
            checker.analyze(bytes(bad))

    def test_fde_corruption_fails(self):
        from elf_index import sections
        secs = sections(self.data)
        eh = [s for s in secs if s['name'] == '.eh_frame'][0]
        bad = bytearray(self.data)
        bad[eh['offset'] + 0x29b594 + 8] ^= 0x01
        with self.assertRaises(ValueError):
            checker.analyze(bytes(bad))

    def test_next_fde_corruption_fails(self):
        from elf_index import sections
        secs = sections(self.data)
        eh = [s for s in secs if s['name'] == '.eh_frame'][0]
        bad = bytearray(self.data)
        bad[eh['offset'] + 0x29b5a8 + 8] ^= 0x01
        with self.assertRaises(ValueError):
            checker.analyze(bytes(bad))


if __name__ == '__main__':
    unittest.main()
