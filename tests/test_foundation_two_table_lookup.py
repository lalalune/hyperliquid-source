#!/usr/bin/env python3
"""Unit tests for the foundation two-table lookup checker.

Every expectation is grounded in the retained window bytes; table contents
are never asserted, only the gate choice and the index arithmetic.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from foundation_two_table_lookup import analyze, lookup


class LookupRuleTests(unittest.TestCase):
    def test_table2_gate_rows(self):
        self.assertEqual(lookup(3, 1, 0), ('table2', 0))
        self.assertEqual(lookup(4, 1, 0), ('table2', 1))
        self.assertEqual(lookup(5, 1, 0), ('table2', 2))

    def test_table2_index_scales_by_three(self):
        self.assertEqual(lookup(3, 1, 2), ('table2', 6))
        self.assertEqual(lookup(5, 1, 4), ('table2', 14))

    def test_gate_above_two_falls_to_table1(self):
        self.assertEqual(lookup(6, 1, 0), ('table1', 6))
        self.assertEqual(lookup(2, 1, 0), ('table1', 2))

    def test_tag_not_one_falls_to_table1(self):
        self.assertEqual(lookup(3, 0, 0), ('table1', 3))
        self.assertEqual(lookup(4, 2, 1), ('table1', 14))

    def test_table1_index_scales_by_ten(self):
        self.assertEqual(lookup(7, 0, 3), ('table1', 37))
        self.assertEqual(lookup(0, 0, 5), ('table1', 50))

    def test_sign_extension(self):
        # low32 edi = 0xFFFFFFFE is -2 signed; gate is unsigned, so table1.
        self.assertEqual(lookup(0xFFFFFFFE, 1, 0), ('table1', -2))
        self.assertEqual(lookup(3, 1, 0xFFFFFFFF), ('table2', -3))

    def test_unsigned_gate_wraps(self):
        # edi = 2 gives gate 0xFFFFFFFF, unsigned > 2, so table1.
        self.assertEqual(lookup(2, 1, 0), ('table1', 2))


class CheckerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        cls.data = (root / 'artifacts/node/94/hl-node').read_bytes()

    def test_check_passes(self):
        found = analyze(self.data)
        self.assertEqual(found['window'], '0x5560660')
        self.assertEqual(found['table1'], '0x576d9e0')
        self.assertEqual(found['table2'], '0x576db20')
        self.assertEqual(found['caller'], '0x55c8554')

    def test_body_corruption_fails(self):
        mutated = bytearray(self.data)
        # .text VA 0x1343c80 maps to file offset VA - 0x1000.
        mutated[0x5560660 - 0x1000 + 7] ^= 0x01
        with self.assertRaises(ValueError):
            analyze(bytes(mutated))

    def test_padding_corruption_fails(self):
        mutated = bytearray(self.data)
        mutated[0x55606a8 - 0x1000] ^= 0x01
        with self.assertRaises(ValueError):
            analyze(bytes(mutated))

    def test_call_bytes_corruption_fails(self):
        mutated = bytearray(self.data)
        mutated[0x55c8554 - 0x1000 + 1] ^= 0x01
        with self.assertRaises(ValueError):
            analyze(bytes(mutated))

    def test_fde_record_corruption_fails(self):
        mutated = bytearray(self.data)
        # .eh_frame address == file offset; window FDE range byte at +12.
        mutated[13505816 + 0x2d0108 + 12] ^= 0x01
        with self.assertRaises(ValueError):
            analyze(bytes(mutated))


if __name__ == '__main__':
    unittest.main()
