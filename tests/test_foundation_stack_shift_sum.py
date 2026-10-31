#!/usr/bin/env python3
"""Unit tests for the foundation stack-shift-sum evidence checker (stdlib only)."""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_stack_shift_sum as tool

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'research/work-items/foundation-stack-shift-sum-94/evidence.json'
BINARY = ROOT / 'artifacts/node/94/hl-node'


def mutated(replace):
    data = bytearray(BINARY.read_bytes())
    for offset, old, new in replace:
        assert data[offset:offset + len(old)] == old, (hex(offset), old.hex())
        data[offset:offset + len(old)] = new
    return bytes(data)


class StackShiftSumTests(unittest.TestCase):
    def test_check_reproduces(self):
        result = tool.inspect(BINARY)
        self.assertEqual(result, json.loads(EVIDENCE.read_text()))

    def test_rule_edges(self):
        self.assertEqual(tool.rule(0, 5, 3), 0)
        self.assertEqual(tool.rule(2, 5, 3), 0)
        self.assertEqual(tool.rule(1, 0, 0), 9)
        self.assertEqual(tool.rule(1, 5, 3), 260)
        self.assertEqual(tool.rule(1, 3, 5), 65)
        self.assertEqual(tool.rule(1, 64, 0), 9)
        self.assertEqual(tool.rule(1, 65, 65), 17)
        self.assertEqual(tool.rule(1, 70, 0), 576)
        self.assertEqual(tool.rule(1, 0xffffffff, 0), 1 << 63)

    def test_rule_gate_polarity(self):
        # The gate is flag == 1 computes, flag != 1 returns 0 — the scout
        # note had this backwards; the bytes (je to the compute path,
        # fall-through ret with eax zeroed) settle it.
        for flag in (0, 2, 3, 0xffffffff):
            self.assertEqual(tool.rule(flag, 5, 3), 0)
        self.assertEqual(tool.rule(1, 5, 3), 260)

    def test_rule_unsigned_min_and_mod64(self):
        # Unsigned min: arg1 = 0xffffffff, arg2 = 1 -> min 1, diff mod 64 = 62.
        self.assertEqual(tool.rule(1, 0xffffffff, 1), (1 << 62) + 0)
        # Shift counts wrap mod 64, they do not saturate.
        self.assertEqual(tool.rule(1, 128, 128), 9)
        self.assertEqual(tool.rule(1, 129, 0), (1 << 1) + (8 << 1))

    def test_body_corruption_fails(self):
        with self.assertRaises(ValueError):
            tool.analyze(mutated([(0x55c6c40 - 0x1000 + 4, b'\x31', b'\x30')]))

    def test_padding_corruption_fails(self):
        with self.assertRaises(ValueError):
            tool.analyze(mutated([(0x55c6c77 - 0x1000, b'\xcc', b'\x90')]))

    def test_flag_compare_corruption_fails(self):
        with self.assertRaises(ValueError):
            tool.analyze(mutated([(0x55c6c40 - 0x1000 + 10, b'\x01', b'\x02')]))

    def test_flag_branch_corruption_fails(self):
        with self.assertRaises(ValueError):
            tool.analyze(mutated([(0x55c6c40 - 0x1000 + 11, b'\x74', b'\x75')]))

    def test_min_select_corruption_fails(self):
        with self.assertRaises(ValueError):
            tool.analyze(mutated([(0x55c6c40 - 0x1000 + 34, b'\x46', b'\x42')]))

    def test_caller_corruption_fails(self):
        with self.assertRaises(ValueError):
            tool.analyze(mutated([(0x555ba70 - 0x1000, b'\xe8', b'\xe9')]))


if __name__ == '__main__':
    unittest.main()
