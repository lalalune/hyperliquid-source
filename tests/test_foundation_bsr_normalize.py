#!/usr/bin/env python3
"""Unit tests for the foundation bsr/normalize checker.

Every expectation is grounded in the retained window bytes; the
bsr-undefined input is tested only as an exclusion (model returns None),
never as a claimed behavior.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from foundation_bsr_normalize import analyze, normalize


class NormalizeRuleTests(unittest.TestCase):
    def test_flag_path(self):
        self.assertEqual(normalize(0, 0, 1, 0), 0)
        self.assertEqual(normalize(0, 0, 1, 7), 0x100)
        # ecx is tested as low32: high bits alone do not set the flag.
        self.assertEqual(normalize(0, 0, 1, 0x100000000), 0)
        # edx is compared as low32 as well.
        self.assertEqual(normalize(0, 0, 0x100000001, 5), 0x100)

    def test_main_path_zero_word(self):
        # w = 1, t = 0, base = 0; ecx == 0 skips the add.
        self.assertEqual(normalize(0, 0x1234, 0, 0), 0x1234)
        # ecx != 0 adds (1 << 8) >> 0 = 256.
        self.assertEqual(normalize(0, 0x1234, 0, 1), 0x1134)

    def test_main_path_ff_word(self):
        # w = 0x100, t = 8, base = 0x800.
        self.assertEqual(normalize(0xFF, 0x2000, 0, 0), 0x1800)
        # ecx != 0 adds (0x10000 >> 8) = 0x100, base = 0x900.
        self.assertEqual(normalize(0xFF, 0x2000, 0, 3), 0x1700)

    def test_main_path_top_word(self):
        # w = 0xffffffff, t = 31, base = 0x1f00; ecx != 0 adds
        # (0xffffff00 >> 31) = 1, base = 0x1f01.
        self.assertEqual(normalize(0xFFFFFFFE, 0x3000, 0, 1), 0x10FF)
        self.assertEqual(normalize(0xFFFFFFFE, 0x3000, 0, 0), 0x1100)

    def test_main_path_wraps_mod_2_32(self):
        # base 0x900 exceeds esi 0x100; the 32-bit sub wraps.
        self.assertEqual(normalize(0xFF, 0x100, 0, 3), 0xFFFFF800)

    def test_bsr_undefined_input_excluded(self):
        # w = 0 exactly when mem_word == 0xffffffff; bsr(0) is undefined.
        self.assertIsNone(normalize(0xFFFFFFFF, 0x1000, 0, 0))
        self.assertIsNone(normalize(0xFFFFFFFF, 0x1000, 0, 1))


class CheckerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        cls.data = (root / 'artifacts/node/94/hl-node').read_bytes()

    def test_check_passes(self):
        found = analyze(self.data)
        self.assertEqual(found['window'], '0x55c9800')
        self.assertEqual(found['fde_end'], '0x55c9830')
        self.assertEqual(found['next_fde'], '0x55c9830')
        self.assertEqual(found['caller_fde_end'], '0x55cc408')
        self.assertEqual(found['padding'], 'none')
        self.assertEqual(found['direct_callers'],
                         ['0x55cb6fb', '0x55cb7f0', '0x55cbde5', '0x55cc00a'])

    def test_body_corruption_fails(self):
        mutated = bytearray(self.data)
        # .text VA 0x1343c80 maps to file offset VA - 0x1000.
        mutated[0x55c9800 - 0x1000 + 12] ^= 0x01
        with self.assertRaises(ValueError):
            analyze(bytes(mutated))

    def test_call_bytes_corruption_fails(self):
        mutated = bytearray(self.data)
        mutated[0x55cb6fb - 0x1000 + 1] ^= 0x01
        with self.assertRaises(ValueError):
            analyze(bytes(mutated))

    def test_fde_record_corruption_fails(self):
        mutated = bytearray(self.data)
        # .eh_frame address == file offset; window FDE range byte at +12.
        mutated[13505816 + 0x2d3cec + 12] ^= 0x01
        with self.assertRaises(ValueError):
            analyze(bytes(mutated))


if __name__ == '__main__':
    unittest.main()
