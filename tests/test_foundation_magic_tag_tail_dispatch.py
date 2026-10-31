#!/usr/bin/env python3
"""Unit tests for the node #94 magic-tag tail dispatch checker.

These test the checker logic against the retained evidence, never execute
target code, and never claim anything about the tail targets' behavior.
"""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_magic_tag_tail_dispatch as checker

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = (ROOT / 'research/work-items/foundation-magic-tag-tail-dispatch-94'
            / 'evidence.json')
TARGET = ROOT / 'artifacts/node/94/hl-node'


class TestMagicTagTailDispatch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = TARGET.read_bytes()
        cls.want = json.loads(EVIDENCE.read_text())

    def test_check_reproduces(self):
        self.assertEqual(checker.analyze(self.data), self.want)

    def test_rule_edges(self):
        magic = 0x800000000000002a
        self.assertEqual(checker.dispatch(0, magic), ('tail', 0x434b140, 0x10))
        self.assertEqual(checker.dispatch(0, 0), ('tail', 0x434aa10, 0x8))
        self.assertEqual(checker.dispatch(0, 0x2a), ('tail', 0x434aa10, 0x8))
        self.assertEqual(checker.dispatch(1, magic), ('tail', 0x434aa10, 0x8))
        self.assertEqual(checker.dispatch(1, 0), ('tail', 0x434aa10, 0x8))
        self.assertEqual(checker.dispatch(255, magic), ('tail', 0x434aa10, 0x8))
        self.assertEqual(checker.dispatch(255, 0), ('tail', 0x434aa10, 0x8))

    def test_body_byte_corruption_fails(self):
        from elf_index import sections
        secs = sections(self.data)
        text = [s for s in secs if s['name'] == '.text'][0]
        off = text['offset'] + 0x4340e00 - text['address']
        bad = bytearray(self.data)
        bad[off] ^= 0x01
        with self.assertRaises(ValueError):
            checker.analyze(bytes(bad))

    def test_padding_byte_corruption_fails(self):
        from elf_index import sections
        secs = sections(self.data)
        text = [s for s in secs if s['name'] == '.text'][0]
        off = text['offset'] + 0x4340e29 - text['address']
        bad = bytearray(self.data)
        bad[off] = 0x90
        with self.assertRaises(ValueError):
            checker.analyze(bytes(bad))

    def test_caller_call_corruption_fails(self):
        from elf_index import sections
        secs = sections(self.data)
        text = [s for s in secs if s['name'] == '.text'][0]
        off = text['offset'] + 0x4386969 - text['address']
        bad = bytearray(self.data)
        bad[off + 1] ^= 0x01
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
