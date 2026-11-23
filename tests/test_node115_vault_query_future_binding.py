#!/usr/bin/env python3
"""Target-bound controls for the vault query future binding packet."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-001-node115-vault-query-future-binding'
SPEC = importlib.util.spec_from_file_location('vault_query_future_binding_verify', PACKET / 'verify.py')
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class VaultQueryFutureBinding(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = VERIFY.TARGET.read_bytes()

    def test_native_fdes_vtable_bindings_and_pending_ready_envelope(self):
        actual = VERIFY.observe(self.data)
        expected = json.loads((PACKET / 'verification.json').read_text())
        actual.pop('controls', None)
        expected.pop('controls', None)
        self.assertEqual(actual, expected)
        self.assertEqual(actual['result_bytes'], 24)
        self.assertEqual([row['target'] for row in actual['relative_bindings']],
                         ['0x297f560', '0x2979c10'])

    def test_real_byte_corruption_controls(self):
        actual = VERIFY.controls(self.data)
        self.assertEqual(actual, json.loads((PACKET / 'controls.json').read_text()))
        self.assertEqual(len(actual), 6)
        self.assertTrue(all(row['rejected'] for row in actual))


if __name__ == '__main__':
    unittest.main()
