#!/usr/bin/env python3
"""Unit tests for the node #94 cursor/state machine checker.

These test the checker logic against the retained evidence, never execute
target code, and never claim anything about the fields' meanings, the marker
bytes, the pointer table, or any return value.
"""
import json
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_cursor_state_machine as checker

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = (ROOT / 'research/work-items/foundation-cursor-state-machine-94'
            / 'evidence.json')
TARGET = ROOT / 'artifacts/node/94/hl-node'


class TestCursorStateMachine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = TARGET.read_bytes()
        cls.want = json.loads(EVIDENCE.read_text())

    def test_check_reproduces(self):
        self.assertEqual(checker.analyze(self.data), self.want)

    def test_rule_edges(self):
        # (flag byte, counter, length word) -> (marker, new counter, delta)
        self.assertEqual(checker.step(0, 7, 0x1234), (0x67, 7, None))
        self.assertEqual(checker.step(0, 0, 0x0000), (0x67, 0, None))
        self.assertEqual(checker.step(1, 0, 0x1234), (0x50, 0, None))
        self.assertEqual(checker.step(1, 1, 0x1234), (0x50, 1, None))
        self.assertEqual(checker.step(1, 2, 0x0001), (None, 0, 258))
        self.assertEqual(checker.step(1, 2, 0x0100), (None, 0, 3))
        self.assertEqual(checker.step(1, 3, 0xffff), (None, 1, 1))
        self.assertEqual(checker.step(1, 3, 0x0080), (None, 1, -32766))
        self.assertEqual(checker.step(1, 3, 0x7fff), (None, 1, -127))
        self.assertEqual(checker.step(0xff, 0xffffffffffffffff, 0x0000),
                         (None, 0xfffffffffffffffd, 2))

    def test_bswap16(self):
        self.assertEqual(checker.bswap16(0x0001), 0x0100)
        self.assertEqual(checker.bswap16(0x0100), 0x0001)
        self.assertEqual(checker.bswap16(0x0080), 0x8000)
        self.assertEqual(checker.bswap16(0xffff), 0xffff)

    def test_body_byte_corruption_fails(self):
        from elf_index import sections
        secs = sections(self.data)
        text = [s for s in secs if s['name'] == '.text'][0]
        off = text['offset'] + 0x47d6b90 - text['address']
        bad = bytearray(self.data)
        bad[off] ^= 0x01
        with self.assertRaises(ValueError):
            checker.analyze(bytes(bad))

    def test_padding_byte_corruption_fails(self):
        from elf_index import sections
        secs = sections(self.data)
        text = [s for s in secs if s['name'] == '.text'][0]
        off = text['offset'] + 0x47d6be2 - text['address']
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
            if add == 0x47d6b90:
                struct.pack_into('<q', bad, rela['offset'] + i * 24 + 16, 0x0)
                break
        with self.assertRaises(ValueError):
            checker.analyze(bytes(bad))

    def test_target_digest_corruption_fails(self):
        bad = bytearray(self.data)
        bad[0] ^= 0x01
        with self.assertRaises(ValueError):
            checker.analyze(bytes(bad))


if __name__ == '__main__':
    unittest.main()
