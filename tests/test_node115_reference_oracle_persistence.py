"""Artifact-backed checks for the bounded node115 reference-oracle packet."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-001-node115-reference-oracle-persistence'


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, PACKET / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReferenceOraclePersistenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.verify = load('oracle_persistence_verify', 'verify.py')
        previous = sys.modules.get('verify')
        sys.modules['verify'] = cls.verify
        try:
            cls.relations = load('oracle_persistence_relations', 'relations.py')
        finally:
            if previous is None:
                sys.modules.pop('verify', None)
            else:
                sys.modules['verify'] = previous
        cls.data = cls.verify.TARGET.read_bytes()

    def test_native_exports_fdes_relocations_calls_and_manifested_records(self):
        actual = self.verify.build(self.data)
        self.assertEqual(actual, json.loads((PACKET / 'records.json').read_text()))
        self.assertEqual([(r['bytes'], r['instructions']) for r in actual['bodies']],
                         [(740, 183), (416, 107), (934, 190)])
        decision = actual['bodies'][0]
        self.assertEqual(decision['returns'], ['0x366fbe3'])
        self.assertEqual(len(decision['calls_and_tail_jumps']), 10)

    def test_deep_instruction_data_relocation_and_fde_corruptions(self):
        actual = self.verify.controls(self.data)
        self.assertEqual(actual, json.loads((PACKET / 'controls.json').read_text()))
        self.assertEqual(len(actual['rejected']), 47)
        self.assertFalse(actual['survived'])

    def test_identity_and_native_export_guards_independently_reject_changes(self):
        with self.assertRaisesRegex(ValueError, 'wrong node115'):
            self.verify.build(self.data[:-1])
        image = self.verify.Image(self.data)
        changed = bytearray(self.data)
        changed[image.off(0x366f900)] ^= 1
        with self.assertRaisesRegex(ValueError, 'wrong node115'):
            self.verify.build(changed)
        with self.assertRaisesRegex(ValueError, 'body digest'):
            self.verify.observe(changed, exports=False)
        with self.assertRaisesRegex(ValueError, 'export bytes'):
            self.verify.observe(changed, body_hashes=False)

    def test_independent_arithmetic_boundaries_and_real_operand_counterfacts(self):
        actual = self.relations.deductions(self.data)
        actual['actual_byte_counterfacts'] = self.relations.counterfacts(self.data)
        self.assertEqual(actual, json.loads((PACKET / 'relations.json').read_text()))
        self.assertEqual(len(actual['actual_byte_counterfacts']), 8)
        p = self.relations.parameters(self.data)
        # A tie defers the request but does not clear an odd return flag.
        self.assertEqual(self.relations.flag_tail(1, 10.0, 10.0, p), (1, False))
        self.assertEqual(self.relations.flag_tail(1, 11.0, 10.0, p), (1, True))
        self.assertEqual(self.relations.flag_tail(0, 11.0, 10.0, p), (0, False))


if __name__ == '__main__':
    unittest.main()
