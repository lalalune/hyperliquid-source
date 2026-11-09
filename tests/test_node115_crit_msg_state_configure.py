#!/usr/bin/env python3
"""Target-bound controls for the crit_msg_state configuration static research packet."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-001-node115-crit-msg-state-configure'


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, PACKET / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class NativeEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.verify = load('crit_msg_state_configure_verify', 'verify.py')
        cls.data = cls.verify.TARGET.read_bytes()

    def test_bodies_layout_bindings_and_incoming_census(self):
        actual = self.verify.build(self.data)
        self.assertEqual(actual, json.loads((PACKET / 'records.json').read_text()))
        self.assertEqual(actual['measured_bytes'], 3144)
        self.assertEqual(actual['measured_instructions'], 718)
        self.assertEqual(actual['obligations'], 230)
        calls = actual['incoming']['calls']
        self.assertEqual([r['site'] for r in calls['0x15444d0']], ['0x154c66e', '0x154c682'])
        self.assertEqual(actual['incoming']['rip_relative_users']['0x64efeb8'], ['0x150ad00', '0x150b310'])

    def test_operand_derived_projection(self):
        rel = self.verify.relations(self.verify.layout())
        self.assertEqual(rel['selection'], {'Sandbox': ['0xd0', 'copy of first'], 'Testnet': ['0xb8', '0xa0'],
                                            'Mainnet': ['0xa0', '0xa0']})
        self.assertIsNone(rel['cases'][0]['result'])
        self.assertEqual(rel['cases'][2]['result']['label'], 'hl node chain=Testnet ips=[203.0.113.7 10.0.0.2]')
        self.assertTrue(rel['crash_on_crit_production'].startswith('assertion failed'))
        self.assertEqual(rel['role_tags']['a\tb'], 'a\tb')

    def test_corruption_controls(self):
        actual = self.verify.controls(self.data)
        self.assertEqual(actual, json.loads((PACKET / 'controls.json').read_text()))
        self.assertEqual(len(actual['rejected']), 291)
        self.assertFalse(actual['survived'])

    def test_same_size_unwind_mutation_invalidates_cached_fdes(self):
        self.verify.frame_records(self.verify.Image(self.data))
        frame = next(section for section in self.verify.Image(self.data).sections
                     if section['name'] == '.eh_frame')
        changed = bytearray(self.data)
        changed[frame['offset']:frame['offset'] + 4] = bytes(4)
        self.assertEqual(len(changed), len(self.data))
        # Below the outer digest guard: path and size are unchanged. A stale
        # FDE cache would miss the new terminator followed by nonzero records.
        with self.assertRaisesRegex(ValueError, 'Non-zero bytes after .eh_frame terminator'):
            self.verify.observe(bytes(changed), body_hashes=False, exports=False)

    def test_whole_image_body_and_export_guards_are_independent(self):
        with self.assertRaisesRegex(ValueError, 'wrong node115'):
            self.verify.build(self.data[:-1])
        changed = bytearray(self.data)
        changed[self.verify.Image(changed).off(0x1544600)] ^= 1
        with self.assertRaisesRegex(ValueError, 'wrong node115'):
            self.verify.build(bytes(changed))
        with self.assertRaisesRegex(ValueError, 'body digest'):
            self.verify.observe(bytes(changed), exports=False)
        with self.assertRaisesRegex(ValueError, 'export bytes'):
            self.verify.observe(bytes(changed), body_hashes=False)


if __name__ == '__main__':
    unittest.main()
