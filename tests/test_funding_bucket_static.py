"""Digest-specific instruction controls and explicitly bounded arithmetic model."""
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import funding_bucket_static as funding


@unittest.skipUnless(funding.TARGET.stat().st_size == 91774280, 'materialize node94')
class FundingBucketTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = funding.TARGET.read_bytes()
        cls.report = funding.analyze(cls.data)

    def test_all_three_actual_ranges_and_field_profiles(self):
        rows = self.report['ranges']
        self.assertEqual(len(rows), 3)
        self.assertEqual([r['bytes'] for r in rows], [387] * 3)
        self.assertEqual([r['interval_field_offset'] for r in rows], ['0x37d0', '0x37d0', '0x4250'])
        self.assertEqual([r['previous_bucket_field_offset'] for r in rows], ['0x37d8', '0x37d8', '0x4258'])
        self.assertEqual(len({r['calendar_prefix_sha256'] for r in rows}), 1)
        self.assertEqual(self.report['stack_constant']['f64_interpretation'], [0.01, 0.05])
        self.assertFalse(self.report['captured_binary_executed'])

    def test_each_copy_rejects_division_comparison_store_and_call_corruption(self):
        for start, *_ in funding.PROFILES:
            for at in [0xd4, 0xdf, 0xeb, 0xef, 0x118, 0x17a, 0x161]:
                with self.subTest(start=hex(start), offset=hex(at)):
                    changed = bytearray(self.data)
                    off, _ = funding.mapping(changed, start + at, 1)
                    changed[off] ^= 1
                    with self.assertRaises(ValueError):
                        funding.analyze(changed)

    def test_label_and_constant_corruption_are_rejected_below_digest_gate(self):
        for va in [0x3efa58, 0x714e59, 0x205e70]:
            changed = bytearray(self.data)
            off, _ = funding.mapping(changed, va, 1)
            changed[off] ^= 1
            with self.subTest(va=hex(va)), self.assertRaises(ValueError):
                funding.analyze(changed)

    def test_post_clamp_model_boundaries(self):
        # 192 mathematical fragment cases; no calendar model or target execution.
        for dividend in [0, 1, 999, 1000, 2**32-1, 2**32, 2**32+1, 2**63-1]:
            for divisor in [1, 999, 1000, 2**32-1, 2**32, 2**32+1, 2**63, 2**64-1]:
                q, r = divmod(dividend, divisor)
                for old in [0, q, 2**64-1]:
                    result = funding.fragment(dividend, divisor, old)
                    self.assertEqual(result['bucket'], q)
                    self.assertEqual(result['stored_bucket'], max(old, q))
                    self.assertEqual(result['acquired'], q > old)
                    self.assertEqual(result['division_width'], 32 if dividend <= 2**32-1 and divisor <= 2**32-1 else 64)
                    self.assertEqual(q * divisor + r, dividend)
        for args in [(0, 0, 0), (-1, 1, 0), (2**63, 1, 0), (0, 1, 2**64)]:
            with self.assertRaises(ValueError):
                funding.fragment(*args)

    @unittest.skipUnless(shutil.which('objdump') and shutil.which('readelf'), 'GNU binutils required')
    def test_retained_native_exports_reproduce(self):
        packet = ROOT / 'research/work-items/RE-001-funding-bucket-advance-94'
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            self.assertEqual(funding.generate(funding.TARGET, out), self.report)
            for name in ['records.json', 'frames.txt', *(f'{start:x}.objdump.txt' for start, *_ in funding.PROFILES)]:
                self.assertEqual((out / name).read_bytes(), (packet / name).read_bytes(), name)


if __name__ == '__main__':
    unittest.main()
