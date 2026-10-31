#!/usr/bin/env python3
"""Unit tests for the node #94 pointer-select evidence checker.

All tests are static: they read the pinned binary, mutate in-memory copies,
and assert the checker accepts the retained evidence and rejects corruptions.
Nothing here executes target code.
"""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))

import foundation_pointer_select as fps

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
EVIDENCE = (ROOT / 'research/work-items/foundation-pointer-select-94'
            / 'evidence.json')

START = fps.START
TEXT_OFF = 0x1342c80
TEXT_VA = 0x1343c80
EH_OFF = 0xce1518


def load():
    return bytearray(TARGET.read_bytes())


def va_to_off(va):
    return TEXT_OFF + (va - TEXT_VA)


class PointerSelectTests(unittest.TestCase):
    def test_check_passes(self):
        self.assertEqual(fps.analyze(TARGET.read_bytes()),
                         json.loads(EVIDENCE.read_text()))

    def test_body_byte_corruption_rejected(self):
        data = load()
        data[va_to_off(START) + 10] ^= 0xff
        with self.assertRaises(ValueError):
            fps.analyze(bytes(data))

    def test_padding_corruption_rejected(self):
        data = load()
        data[va_to_off(fps.END)] ^= 0xff
        with self.assertRaises(ValueError):
            fps.analyze(bytes(data))

    def test_fde_record_corruption_rejected(self):
        data = load()
        data[EH_OFF + 0x2caeb0 + 12] ^= 0xff
        with self.assertRaises(ValueError):
            fps.analyze(bytes(data))

    def test_select_displacement_corruption_rejected(self):
        data = load()
        data[va_to_off(START) + 7] ^= 0xff
        with self.assertRaises(ValueError):
            fps.analyze(bytes(data))

    def test_default_displacement_corruption_rejected(self):
        data = load()
        data[va_to_off(START) + 14] ^= 0xff
        with self.assertRaises(ValueError):
            fps.analyze(bytes(data))

    def test_field_offset_corruption_rejected(self):
        data = load()
        data[va_to_off(START) + 28] ^= 0xff
        with self.assertRaises(ValueError):
            fps.analyze(bytes(data))

    def test_caller_call_corruption_rejected(self):
        data = load()
        data[va_to_off(0x551e8d0) + 1] ^= 0xff
        with self.assertRaises(ValueError):
            fps.analyze(bytes(data))

    def test_select_rule_edges(self):
        self.assertEqual(fps.select_offset(1), 0xe518)
        self.assertEqual(fps.select_offset(0), 0xec10)
        self.assertEqual(fps.select_offset(2), 0xec10)
        # The compare is 32-bit: upper bits of rsi are ignored.
        self.assertEqual(fps.select_offset(0x100000001 & 0xffffffff), 0xe518)
        self.assertEqual(0xe518 + 0x78, 0xe590)
        self.assertEqual(0xec10 + 0x78, 0xec88)

    def test_evidence_edges_match_rule(self):
        evidence = json.loads(EVIDENCE.read_text())
        edges = evidence['behavior']['edges']
        self.assertEqual(edges['selector_1'], '0xe590')
        self.assertEqual(edges['selector_0'], '0xec88')
        self.assertEqual(edges['selector_2'], '0xec88')
        self.assertEqual(evidence['incoming_pattern_scan']['e8_candidates'],
                         ['0x54cbfc2', '0x54cc11a', '0x551e8d0', '0x551e8e7'])


if __name__ == '__main__':
    unittest.main()
