"""Corruption controls against the actual node #94 traffic-recorder observation."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check
from traffic_recorder_static import CONTROLS, RANGES, STRINGS, division_identity, fde_ranges, mapped, static_controls


class TrafficRecorderStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        binary = ROOT / 'artifacts/node/94/hl-node'
        item = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                    if i['path'] == 'artifacts/node/94/hl-node')
        check(binary, item)
        cls.data = binary.read_bytes()

    def test_real_target_controls(self):
        self.assertEqual(len(static_controls(self.data)), 32)
        self.assertEqual(len(STRINGS), 6)

    def test_real_instruction_corruptions(self):
        # Invoke controls below the whole-artifact hash gate, so each rejection
        # demonstrates the relevant evidence check rather than only SHA mismatch.
        for va in [0x3D13D0A, 0x3D13D16, 0x3D13D7E, 0x3D13D92, 0x3D13D98,
                   0x3D13DC8, 0x3D13DD2, 0x3D13DDE, 0x3D13EBE, 0x3D13EDB,
                   0x3D1412B, 0x3D14076, 0x3D14463, 0x3D21763, 0x3D217C2]:
            with self.subTest(va=hex(va)):
                changed = bytearray(self.data)
                offset, _ = mapped(changed, va, 1)
                changed[offset] ^= 1
                with self.assertRaisesRegex(ValueError, 'control changed'):
                    static_controls(changed)

    def test_real_string_anchor_corruptions(self):
        for va in STRINGS:
            with self.subTest(va=hex(va)):
                changed = bytearray(self.data)
                offset, _ = mapped(changed, va, 1)
                changed[offset] ^= 1
                with self.assertRaisesRegex(ValueError, 'control changed'):
                    static_controls(changed)

    def test_real_fde_ranges(self):
        self.assertEqual(fde_ranges(self.data), RANGES)

    def test_magic_division_identity(self):
        result = division_identity(exhaustive_bits=16, samples=101)
        self.assertTrue(result['is_ceil_2_75_over_5_9'])
        for x in (0, 1, 1953124, 1953125, 1953126, (1 << 24) - 1):
            self.assertEqual(((x * 0x44B82FA09B5A53) >> 75), x // 5 ** 9, hex(x))
        for b in (0, 10 ** 9 - 1, 10 ** 9, 10 ** 9 + 1):
            self.assertEqual((((b >> 9) * 0x44B82FA09B5A53 >> 64) >> 11), b // 10 ** 9, hex(b))


if __name__ == '__main__':
    unittest.main()
