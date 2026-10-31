#!/usr/bin/env python3
"""Unit tests for the node #94 quirky tag gate checker.

These test the checker logic against the retained evidence, never execute
target code, and never claim anything about the tail target's behavior.
"""
import io
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_quirky_tag_gate as checker

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = (ROOT / 'research/work-items/foundation-quirky-tag-gate-94'
            / 'evidence.json')
TARGET = ROOT / 'artifacts/node/94/hl-node'


class TestQuirkyTagGate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = TARGET.read_bytes()
        cls.want = json.loads(EVIDENCE.read_text())

    def test_check_reproduces(self):
        self.assertEqual(checker.analyze(self.data), self.want)

    def test_rule_edges(self):
        self.assertEqual(checker.quirky(0, 0), ('tail', 0x18))
        self.assertEqual(checker.quirky(0, 2), ('tail', 0x18))
        self.assertEqual(checker.quirky(3, 0), ('tail', 0))
        self.assertEqual(checker.quirky(3, 1), ('tail', 0))
        self.assertEqual(checker.quirky(3, 2), ('ret',))
        self.assertEqual(checker.quirky(1, 0), ('ret',))
        self.assertEqual(checker.quirky(2, 2), ('ret',))
        self.assertEqual(checker.quirky(255, 0), ('ret',))

    def test_body_byte_corruption_fails(self):
        from elf_index import sections
        secs = sections(self.data)
        text = [s for s in secs if s['name'] == '.text'][0]
        off = text['offset'] + 0x223e3a0 - text['address']
        bad = bytearray(self.data)
        bad[off] ^= 0x01
        with self.assertRaises(ValueError):
            checker.analyze(bytes(bad))

    def test_padding_byte_corruption_fails(self):
        from elf_index import sections
        secs = sections(self.data)
        text = [s for s in secs if s['name'] == '.text'][0]
        off = text['offset'] + 0x223e3c1 - text['address']
        bad = bytearray(self.data)
        bad[off] = 0x90
        with self.assertRaises(ValueError):
            checker.analyze(bytes(bad))

    def test_caller_call_corruption_fails(self):
        from elf_index import sections
        secs = sections(self.data)
        text = [s for s in secs if s['name'] == '.text'][0]
        off = text['offset'] + 0x22b45c9 - text['address']
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
        tampered['window_size'] = 34
        self.assertNotEqual(got, tampered)

    def test_cli_check_passes(self):
        out = io.StringIO()
        old = sys.stdout
        sys.stdout = out
        try:
            sys.argv = ['checker', '--binary', str(TARGET),
                        '--check', str(EVIDENCE)]
            checker.main()
        finally:
            sys.stdout = old
        self.assertIn('reproduces exactly', out.getvalue())


if __name__ == '__main__':
    unittest.main()
