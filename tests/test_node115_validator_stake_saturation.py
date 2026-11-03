#!/usr/bin/env python3
"""Target-bound controls for the validator-stake saturation static research packet."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-001-node115-validator-stake-saturation'


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, PACKET / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ValidatorStakeSaturation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.verify = load('validator_stake_verify', 'verify.py')
        previous = sys.modules.get('verify')
        sys.modules['verify'] = cls.verify
        try:
            cls.relations = load('validator_stake_relations', 'relations.py')
        finally:
            if previous is None:
                sys.modules.pop('verify', None)
            else:
                sys.modules['verify'] = previous
        cls.data = cls.verify.TARGET.read_bytes()

    def test_native_body_source_locations_call_bindings_and_incoming_sites(self):
        actual = self.verify.build(self.data)
        self.assertEqual(actual, json.loads((PACKET / 'records.json').read_text()))
        self.assertEqual(actual['measured_bytes'], 1549)
        self.assertEqual(len(actual['bodies']), 3)
        self.assertEqual([x['role'] for x in actual['bodies']], ['predicate', 'keyed_fold', 'all_fold'])
        self.assertEqual(actual['dynamic_imports'][0]['symbol']['name'], 'memcmp')

    def test_instruction_source_relocation_and_unwind_corruption_guards(self):
        actual = self.verify.controls(self.data)
        self.assertEqual(actual, json.loads((PACKET / 'controls.json').read_text()))
        self.assertEqual(len(actual['rejected']), 42)
        self.assertFalse(actual['survived'])

    def test_whole_image_body_and_native_export_guards_are_independent(self):
        with self.assertRaisesRegex(ValueError, 'wrong node115'):
            self.verify.build(self.data[:-1])
        changed = bytearray(self.data)
        changed[self.verify.Image(changed).off(0x4d3e1a0)] ^= 1
        with self.assertRaisesRegex(ValueError, 'wrong node115'):
            self.verify.build(changed)
        with self.assertRaisesRegex(ValueError, 'body digest'):
            self.verify.observe(changed, exports=False)
        with self.assertRaisesRegex(ValueError, 'export bytes'):
            self.verify.observe(changed, body_hashes=False)

    def test_saturating_folds_wide_predicate_and_flat_lookup_boundaries(self):
        actual = self.relations.evaluate(self.data)
        self.assertEqual(actual, json.loads((PACKET / 'relations.json').read_text()))
        maximum = (1 << 64) - 1
        self.assertEqual(self.relations.fold([maximum, 1]), maximum)
        self.assertFalse(self.relations.wide_predicate(2, 3))
        self.assertTrue(self.relations.wide_predicate(maximum, maximum))
        self.assertIsNone(self.relations.flat_lookup_weight(4, 4096, 3, 2, 1, 0))
        self.assertIsNone(self.relations.flat_lookup_weight(4, 4096, 3, 2, 0, 2))
        self.assertEqual(self.relations.flat_lookup_weight(4, 4096, 3, 2, 2, 1), 4120)
        self.assertEqual(len(actual['actual_carry_counterfactuals']), 3)


if __name__ == '__main__':
    unittest.main()
