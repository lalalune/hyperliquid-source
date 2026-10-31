#!/usr/bin/env python3
"""Unit tests for the foundation negate-or-zero evidence checker (stdlib only)."""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_negate_or_zero as tool

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'research/work-items/foundation-negate-or-zero-94/evidence.json'
BINARY = ROOT / 'artifacts/node/94/hl-node'


def mutated(replace):
    data = bytearray(BINARY.read_bytes())
    for offset, old, new in replace:
        assert data[offset:offset + len(old)] == old, (hex(offset), old.hex())
        data[offset:offset + len(old)] = new
    return bytes(data)


class NegateOrZeroTests(unittest.TestCase):
    def test_check_reproduces(self):
        result = tool.inspect(BINARY)
        self.assertEqual(result, json.loads(EVIDENCE.read_text()))

    def test_rule_edges(self):
        self.assertEqual(tool.rule(0xffffffffffffffff), 1)
        self.assertEqual(tool.rule(0xffffffffffffff89), 119)
        self.assertEqual(tool.rule(0xffffffffffffff88), 0)
        self.assertEqual(tool.rule(0), 0)
        self.assertEqual(tool.rule(1), 0)
        self.assertEqual(tool.rule(119), 0)
        self.assertEqual(tool.rule(0x1ffffff89), 0)

    def test_signed_range_exhaustive(self):
        # Every sign-extended value in [-119, -1] negates; neighbors return 0.
        for v in range(-119, 0):
            self.assertEqual(tool.rule(v & 0xffffffffffffffff), -v)
        self.assertEqual(tool.rule((-120) & 0xffffffffffffffff), 0)
        self.assertEqual(tool.rule(0), 0)

    def test_body_corruption_fails(self):
        with self.assertRaises(ValueError):
            tool.analyze(mutated([(0x555ac00 - 0x1000 + 4, b'\x89', b'\x90')]))

    def test_padding_corruption_fails(self):
        with self.assertRaises(ValueError):
            tool.analyze(mutated([(0x555ac12 - 0x1000, b'\xcc', b'\x90')]))

    def test_compare_constant_corruption_fails(self):
        with self.assertRaises(ValueError):
            tool.analyze(mutated([(0x555ac00 - 0x1000 + 13, b'\x88', b'\x87')]))

    def test_cmov_corruption_fails(self):
        with self.assertRaises(ValueError):
            tool.analyze(mutated([(0x555ac00 - 0x1000 + 15, b'\x46', b'\x45')]))

    def test_fde_corruption_fails(self):
        eh_off = 0xce1518 + 0x2cfa04
        with self.assertRaises(ValueError):
            tool.analyze(mutated([(eh_off + 12, b'\x12\x00\x00\x00', b'\x13\x00\x00\x00')]))

    def test_caller_call_corruption_fails(self):
        with self.assertRaises(ValueError):
            tool.analyze(mutated([(0x55da082 - 0x1000, b'\xe8', b'\x90')]))

    def test_caller_fde_corruption_fails(self):
        eh_off = 0xce1518 + 0x2d4754
        with self.assertRaises(ValueError):
            tool.analyze(mutated([(eh_off + 12, b'\x1c\x10\x00\x00', b'\x1d\x10\x00\x00')]))

    def test_extra_caller_fails(self):
        # Moving one caller's target away from the window must break the
        # locked scan count (6), not silently pass.
        with self.assertRaises(ValueError):
            tool.analyze(mutated([(0x55da082 - 0x1000 + 1,
                                   bytes.fromhex('790bf8ff'), bytes.fromhex('790bf8fe'))]))


if __name__ == '__main__':
    unittest.main()
