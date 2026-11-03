#!/usr/bin/env python3
"""Target-bound controls for the rpc-store-update-dispatch static research packet."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-001-node115-rpc-store-update-dispatch'


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, PACKET / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class NativeEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.verify = load('rpc_store_update_dispatch_verify', 'verify.py')
        previous = sys.modules.get('verify')
        sys.modules['verify'] = cls.verify
        try:
            cls.relations = load('rpc_store_update_dispatch_relations', 'relations.py')
        finally:
            if previous is None:
                sys.modules.pop('verify', None)
            else:
                sys.modules['verify'] = previous
        cls.data = cls.verify.TARGET.read_bytes()

    def test_native_body_source_locations_call_bindings_and_incoming_sites(self):
        actual = self.verify.build(self.data)
        self.assertEqual(actual, json.loads((PACKET / 'records.json').read_text()))
        self.assertEqual(actual['measured_bytes'], 2657)
        self.assertEqual(len(actual['bodies']), 2)

    def test_instruction_source_relocation_and_unwind_corruption_guards(self):
        actual = self.verify.controls(self.data)
        self.assertEqual(actual, json.loads((PACKET / 'controls.json').read_text()))
        self.assertEqual(len(actual['rejected']), 70)
        self.assertFalse(actual['survived'])

    def test_whole_image_body_and_native_export_guards_are_independent(self):
        with self.assertRaisesRegex(ValueError, 'wrong node115'):
            self.verify.build(self.data[:-1])
        changed = bytearray(self.data)
        changed[self.verify.Image(changed).off(0x4faf560)] ^= 1
        with self.assertRaisesRegex(ValueError, 'wrong node115'):
            self.verify.build(changed)
        with self.assertRaisesRegex(ValueError, 'body digest'):
            self.verify.observe(changed, exports=False)
        with self.assertRaisesRegex(ValueError, 'export bytes'):
            self.verify.observe(changed, body_hashes=False)

    def test_operand_derived_relations_and_counterfactuals(self):
        actual = self.relations.evaluate(self.data)
        self.assertEqual(actual, json.loads((PACKET / 'relations.json').read_text()))
        self.assertGreaterEqual(len(actual['counterfactuals']), 3)


if __name__ == '__main__':
    unittest.main()
