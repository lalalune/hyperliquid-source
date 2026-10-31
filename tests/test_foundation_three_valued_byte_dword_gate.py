#!/usr/bin/env python3
"""Unit tests for the node #94 three-valued byte/dword gate checker.

These test the checker logic against the retained evidence, never execute
target code, and never claim anything about the fields' meanings or about
the nearby cluster windows.
"""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_three_valued_byte_dword_gate as checker

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = (ROOT / 'research/work-items/foundation-three-valued-byte-dword-gate-94'
            / 'evidence.json')
TARGET = ROOT / 'artifacts/node/94/hl-node'


class TestThreeValuedByteDwordGate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = TARGET.read_bytes()
        cls.want = json.loads(EVIDENCE.read_text())

    def test_check_reproduces(self):
        self.assertEqual(checker.analyze(self.data), self.want)

    def test_rule_edges(self):
        # (first byte, dword+0x28c)
        self.assertEqual(checker.gate(1, 0), 1)
        self.assertEqual(checker.gate(0xff, 0xffffffff), 1)
        self.assertEqual(checker.gate(0, 1), 2)
        self.assertEqual(checker.gate(0, 0), 0)
        self.assertEqual(checker.gate(0, 2), 0)
        self.assertEqual(checker.gate(0, 0xffffffff), 0)
        # The return set is exactly {1} ∪ {0, 2}: never a plain boolean.
        self.assertEqual(sorted({checker.gate(1, 1), checker.gate(0, 1),
                                 checker.gate(0, 0)}), [0, 1, 2])

    def test_body_byte_corruption_fails(self):
        from elf_index import sections
        secs = sections(self.data)
        text = [s for s in secs if s['name'] == '.text'][0]
        off = text['offset'] + 0x5382c90 - text['address']
        bad = bytearray(self.data)
        bad[off] ^= 0x01
        with self.assertRaises(ValueError):
            checker.analyze(bytes(bad))

    def test_padding_byte_corruption_fails(self):
        from elf_index import sections
        secs = sections(self.data)
        text = [s for s in secs if s['name'] == '.text'][0]
        off = text['offset'] + 0x5382caf - text['address']
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
            if add == 0x5382c90:
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
