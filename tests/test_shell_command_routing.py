"""Digest-bound static evidence and controls for the shell command router."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-001-shell-command-routing-94'


def load(name):
    spec = importlib.util.spec_from_file_location('shell_routing_' + name, PACKET / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ShellCommandRoutingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = load('verify')
        cls.data = cls.v.TARGET.read_bytes()
        if cls.data.startswith(b'version https://git-lfs'):
            raise unittest.SkipTest('pinned node94 LFS input not materialized')

    def test_complete_native_exports_and_records(self):
        result = self.v.build(self.data)
        self.assertEqual(result, json.loads((PACKET / 'records.json').read_text()))
        self.assertEqual(result['primary_bytes'], 2947)
        self.assertEqual(len(result['bodies']), 4)

    def test_semantic_corruptions_below_digest_guards(self):
        result = self.v.controls(self.data)
        self.assertEqual(result, json.loads((PACKET / 'controls.json').read_text()))
        self.assertEqual(len(result['rejected']), 67)
        self.assertFalse(result['survived'])

    def test_body_guard_and_independent_export_guard(self):
        v = self.v
        data = bytearray(self.data)
        data[v.Image(data).off(0x13e4e40)] ^= 1  # Outside the selected semantic spans.
        with self.assertRaisesRegex(ValueError, 'wrong node94'):
            v.build(data)
        with self.assertRaisesRegex(ValueError, 'body digest'):
            v.observe(data)
        with self.assertRaisesRegex(ValueError, 'export bytes'):
            v.observe(data, body_hashes=False)

    def test_search_coverage_and_mask_identity(self):
        result = load('coverage').verify_coverage()
        self.assertEqual(result, json.loads((PACKET / 'coverage.json').read_text()))
        self.assertEqual(result['lengths_checked'], 4097)
        self.assertEqual(result['nonzero_16_bit_masks_checked'], 65535)


if __name__ == '__main__':
    unittest.main()
