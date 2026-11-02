"""Digest-bound static evidence and corruption controls for largest-record summary and worker lifecycle."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-001-capacity-summary-94'


def load(name):
    spec = importlib.util.spec_from_file_location('capacity_summary_' + name, PACKET / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CapacitySummaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = load('verify')
        cls.data = cls.v.TARGET.read_bytes()
        if cls.data.startswith(b'version https://git-lfs'):
            raise unittest.SkipTest('pinned node94 LFS input not materialized')

    def test_complete_native_exports_and_records(self):
        result = self.v.build(self.data)
        self.assertEqual(result, json.loads((PACKET / 'records.json').read_text()))
        self.assertEqual(result['primary_bytes'], 926)
        self.assertEqual(len(result['bodies']), 2)

    def test_semantic_corruptions_below_digest_guards(self):
        result = self.v.controls(self.data)
        self.assertEqual(result, json.loads((PACKET / 'controls.json').read_text()))
        self.assertEqual(len(result['rejected']), 50)
        self.assertFalse(result['survived'])

    def test_independent_integrity_guards(self):
        v = self.v
        changed = bytearray(self.data)
        changed[v.Image(changed).off(0x13cc100)] ^= 1  # Prologue outside semantic spans.
        with self.assertRaisesRegex(ValueError, 'wrong node94'):
            v.build(changed)
        with self.assertRaisesRegex(ValueError, 'body digest'):
            v.observe(changed)
        with self.assertRaisesRegex(ValueError, 'export bytes'):
            v.observe(changed, body_hashes=False)

    def test_clamp_scale_release_and_option_arithmetic(self):
        result = load('arithmetic').verify_arithmetic()
        self.assertEqual(result, json.loads((PACKET / 'arithmetic.json').read_text()))
        self.assertEqual(result['pair_count'], 45)
        self.assertEqual(result['signed_division_values'], 11)
        self.assertEqual(result['release_capacity_values'], 4100)
        self.assertEqual(result['worker_option_bytes'], 13)


if __name__ == '__main__':
    unittest.main()
