import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'tools')]

import input_writers_static as packet

PACKET_DIR = ROOT / 'research/work-items' / packet.WORK_ITEM
DATA = packet.TARGET.read_bytes() if packet.TARGET.exists() else b''
MATERIALISED = (
    len(DATA) == packet.TARGET_SIZE
    and hashlib.sha256(DATA).hexdigest() == packet.TARGET_SHA256)


@unittest.skipUnless(MATERIALISED, 'node 115 artifact is not materialised')
class InputWritersPacketTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records = packet.analyze(DATA)

    def test_regeneration_matches_retained_records(self):
        retained = json.loads((PACKET_DIR / 'records.json').read_text())
        self.assertEqual(self.records, retained)

    def test_nine_owners_pinned(self):
        owners = self.records['owners']
        self.assertEqual(len(owners), 9)
        self.assertEqual(owners['stage_twin_a']['start'], '0x2e466b0')
        self.assertEqual(owners['stage_twin_a']['end'], '0x2e469a9')
        self.assertEqual(owners['stage_twin_a']['bytes'], 761)
        self.assertEqual(owners['caller_b_side']['bytes'], 28357)
        self.assertEqual(owners['caller_twin_a_1']['bytes'], 2071)

    def test_dispatcher_input_records(self):
        dispatchers = self.records['dispatchers']
        bulk_a = dispatchers['bulk_a']
        self.assertEqual(len(bulk_a['call_sites']), 2)
        self.assertEqual(
            bulk_a['call_sites'][0]['selector_struct_offset'], '+0x210')
        self.assertEqual(
            bulk_a['call_sites'][1]['incoming_limit_struct_offset'],
            '+0x300')
        twin_a = dispatchers['twin_a']
        self.assertEqual(
            twin_a['call_sites'][0]['source_pointer_struct_offset'],
            '+0x50')
        self.assertIn('struct +0x20', twin_a['source_object'])
        self.assertIn('never stored', twin_a['first_writer'])
        twin_b = dispatchers['twin_b']
        self.assertEqual(len(twin_b['call_sites']), 2)
        self.assertEqual(
            twin_b['call_sites'][1]['sibling_arena_offset'], '+0xd18')
        self.assertEqual(
            dispatchers['bulk_b']['call_sites'][0]
            ['selector_arena_offset'], '+0xeb8')

    def test_access_census(self):
        census = self.records['access_census']
        self.assertEqual(
            census['stage_twin_a']['exact_counts']['[rbx+0x28]'], 1)
        self.assertEqual(
            census['ctor_twin_a']['exact_counts']['[rsp+0x38]'], 5)
        self.assertEqual(
            len(census['caller_b_side']['zero_patterns']), 13)
        self.assertTrue(all(
            count == 0
            for count in census['caller_b_side']['zero_patterns']
            .values()))
        for role in ('caller_twin_a_1', 'caller_twin_a_2'):
            self.assertEqual(
                census[role]['zero_patterns']['[rbx+0x150]'], 0)
            self.assertEqual(
                census[role]['zero_patterns']['[rbx+0x158]'], 0)

    def test_call_census(self):
        census = self.records['call_census']
        sites = census['direct_call_sites']
        self.assertEqual(len(sites['builder_twin_a']), 1)
        self.assertEqual(sites['builder_twin_a'][0]['site'], '0x2cb20b3')
        self.assertEqual(len(sites['builder_bulk_a']), 1)
        self.assertEqual(len(sites['stage_twin_a']), 3)
        self.assertEqual(len(sites['ctor_twin_a']), 1)
        self.assertEqual(sites['ctor_twin_a'][0]['site'], '0x2b6aa53')
        self.assertTrue(all(
            refs == [] for refs in census['lea_references'].values()))

    def test_twin_a_result_0x28_record(self):
        record = self.records['twin_a_result_0x28']
        self.assertIn('0x2e46968', record['writer'])
        self.assertIn('0x2e467a8', record['defined_value_arm'])
        self.assertIn('0x26ff66c', record['consumers'])
        self.assertIn('0x2ce1730', record['next_level'])

    def test_counterfactual_mutations_raise(self):
        cases = [
            ('stage sole +0x28 store', 0x2E46968, 3),
            ('constructor +0x28 reload', 0x26FF330, 2),
            ('bulk a dispatcher call', 0x2AD7FF7, 1),
            ('twin builder block length', 0x2B14767, 0),
            ('b-side twin head store', 0x5A83658, 3),
        ]
        for name, va, delta in cases:
            with self.subTest(name=name):
                raw = bytearray(DATA)
                offset, _ = packet.read(va + delta, bytes(raw), 1)
                raw[offset] ^= 0xFF
                with self.assertRaises(ValueError):
                    packet.analyze(bytes(raw))


if __name__ == '__main__':
    unittest.main()
