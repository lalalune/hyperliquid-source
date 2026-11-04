#!/usr/bin/env python3
"""Target-bound controls for the portfolio-simulation static research packet."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-001-node115-portfolio-simulation-balances'


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, PACKET / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PortfolioSimulationBalances(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.verify = load('portfolio_simulation_verify', 'verify.py')
        previous = sys.modules.get('verify')
        sys.modules['verify'] = cls.verify
        try:
            cls.relations = load('portfolio_simulation_relations', 'relations.py')
        finally:
            if previous is None:
                sys.modules.pop('verify', None)
            else:
                sys.modules['verify'] = previous
        cls.data = cls.verify.TARGET.read_bytes()

    def test_native_body_source_locations_call_bindings_and_incoming_sites(self):
        actual = self.verify.build(self.data)
        self.assertEqual(actual, json.loads((PACKET / 'records.json').read_text()))
        body, = actual['bodies']
        self.assertEqual((body['bytes'], body['instructions']), (4362, 841))
        self.assertEqual(len(body['calls_and_tail_jumps']), 51)
        self.assertEqual(body['returns'], ['0x2c6585e'])
        self.assertEqual(len(actual['incoming']['qualified_candidates']), 4)

    def test_instruction_source_relocation_and_unwind_corruption_guards(self):
        actual = self.verify.controls(self.data)
        self.assertEqual(actual, json.loads((PACKET / 'controls.json').read_text()))
        self.assertEqual(len(actual['rejected']), 48)
        self.assertFalse(actual['survived'])

    def test_whole_image_body_and_native_export_guards_are_independent(self):
        with self.assertRaisesRegex(ValueError, 'wrong node115'):
            self.verify.build(self.data[:-1])
        changed = bytearray(self.data)
        changed[self.verify.Image(changed).off(0x2c64870)] ^= 1
        with self.assertRaisesRegex(ValueError, 'wrong node115'):
            self.verify.build(changed)
        with self.assertRaisesRegex(ValueError, 'body digest'):
            self.verify.observe(changed, exports=False)
        with self.assertRaisesRegex(ValueError, 'export bytes'):
            self.verify.observe(changed, body_hashes=False)

    def test_arithmetic_boundaries_and_actual_byte_counterfacts(self):
        actual = self.relations.deductions(self.data)
        actual['actual_byte_counterfacts'] = self.relations.counterfacts(self.data)
        self.assertEqual(actual, json.loads((PACKET / 'relations.json').read_text()))
        p = self.relations.parameters(self.data)
        self.assertEqual(self.relations.residual(1, 1, 100, p),
                         {'request': True, 'destination': 'surplus', 'location_line': 110, 'value': 0})
        self.assertFalse(self.relations.residual(184467440737095517, 1, 0, p)['request'])
        self.assertEqual(len(actual['actual_byte_counterfacts']), 7)


if __name__ == '__main__':
    unittest.main()
