#!/usr/bin/env python3
"""Unit tests for the foundation multi-field-store evidence checker (stdlib only)."""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_multi_field_store as tool

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'research/work-items/foundation-multi-field-store-94/evidence.json'
BINARY = ROOT / 'artifacts/node/94/hl-node'


def mutated(replace):
    data = bytearray(BINARY.read_bytes())
    for offset, old, new in replace:
        assert data[offset:offset + len(old)] == old, (hex(offset), old.hex())
        data[offset:offset + len(old)] = new
    return bytes(data)


class MultiFieldStoreTests(unittest.TestCase):
    def test_check_reproduces(self):
        result = tool.inspect(BINARY)
        self.assertEqual(result, json.loads(EVIDENCE.read_text()))

    def test_rule_edges(self):
        self.assertEqual(tool.apply_model(0, 0, 0, 0, 0),
                         dict(store_14=0, field_08=3, field_0c=0x40,
                              field_04=6, field_10=0, return_eax=3))
        self.assertEqual(tool.apply_model(10, 5, 1, 0, 0),
                         dict(store_14=10, field_08=3, field_0c=1,
                              field_04=3, field_10=7, return_eax=3))
        self.assertEqual(tool.apply_model(20, 0, 0, 4, 9),
                         dict(store_14=20, field_08=3, field_0c=0x40,
                              field_04=4, field_10=9, return_eax=3))
        self.assertEqual(tool.apply_model(5, 7, 2, 0, 0),
                         dict(store_14=5, field_08=6, field_0c=2,
                              field_04=6, field_10=0, return_eax=6))
        self.assertEqual(tool.apply_model(14, 9, 3, 0, 0),
                         dict(store_14=14, field_08=6, field_0c=3,
                              field_04=6, field_10=8, return_eax=6))
        self.assertEqual(tool.apply_model(13, 2, 0, 0, 0),
                         dict(store_14=13, field_08=2, field_0c=0x40,
                              field_04=6, field_10=7, return_eax=2))
        self.assertEqual(tool.apply_model(7, 0, 0, 0, 0),
                         dict(store_14=7, field_08=0, field_0c=0x40,
                              field_04=0, field_10=7, return_eax=0))
        self.assertEqual(tool.apply_model(0xffffffff, 1, 1, 0, 0),
                         dict(store_14=0xffffffff, field_08=1, field_0c=1,
                              field_04=6, field_10=0xfffffff9, return_eax=1))
        self.assertEqual(tool.apply_model(100, 10, 5, 4, 3),
                         dict(store_14=100, field_08=4, field_0c=5,
                              field_04=4, field_10=3, return_eax=4))

    def test_rule_uses_defaulted_d_for_later_steps(self):
        # Field +0x10 and +0x8 both use the possibly-defaulted D, not the
        # entry D: with entry D = 0 and source 10, D_final is 3, so the
        # difference is 7 and the final min is min(5, 3) = 3.
        state = tool.apply_model(10, 5, 1, 0, 0)
        self.assertEqual((state['field_04'], state['field_10'], state['field_08']),
                         (3, 7, 3))

    def test_rule_wraparound_default(self):
        # Source below 7 wraps (source - 7) mod 2^32, so the unsigned min
        # picks 6; source 7 gives exactly 0; source 12 gives 5.
        self.assertEqual(tool.apply_model(0, 9, 0, 0, 0)['field_04'], 6)
        self.assertEqual(tool.apply_model(7, 9, 0, 0, 0)['field_04'], 0)
        self.assertEqual(tool.apply_model(12, 9, 0, 0, 0)['field_04'], 5)

    def test_body_corruption_fails(self):
        with self.assertRaises(ValueError):
            tool.analyze(mutated([(0x55c6be0 - 0x1000 + 8, b'\x03', b'\x04')]))

    def test_padding_corruption_fails(self):
        with self.assertRaises(ValueError):
            tool.analyze(mutated([(0x55c6c3a - 0x1000, b'\xcc', b'\x90')]))

    def test_default_select_corruption_fails(self):
        with self.assertRaises(ValueError):
            tool.analyze(mutated([(0x55c6be0 - 0x1000 + 20, b'\x44', b'\x45')]))

    def test_cap_select_corruption_fails(self):
        with self.assertRaises(ValueError):
            tool.analyze(mutated([(0x55c6be0 - 0x1000 + 54, b'\x42', b'\x43')]))

    def test_final_min_corruption_fails(self):
        with self.assertRaises(ValueError):
            tool.analyze(mutated([(0x55c6be0 - 0x1000 + 84, b'\x47', b'\x46')]))

    def test_caller_corruption_fails(self):
        with self.assertRaises(ValueError):
            tool.analyze(mutated([(0x555deab - 0x1000, b'\xe8', b'\xe9')]))


if __name__ == '__main__':
    unittest.main()
