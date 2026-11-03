import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'tools')]

import block_fill_writers_static as packet

PACKET_DIR = ROOT / 'research/work-items' / packet.WORK_ITEM
DATA = packet.TARGET.read_bytes() if packet.TARGET.exists() else b''
MATERIALISED = (
    len(DATA) == packet.TARGET_SIZE
    and hashlib.sha256(DATA).hexdigest() == packet.TARGET_SHA256)


@unittest.skipUnless(MATERIALISED, 'node 115 artifact is not materialised')
class BlockFillWritersPacketTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records = packet.analyze(DATA)

    def test_regeneration_matches_retained_records(self):
        retained = json.loads((PACKET_DIR / 'records.json').read_text())
        self.assertEqual(self.records, retained)

    def test_twelve_owners_pinned(self):
        owners = self.records['owners']
        self.assertEqual(len(owners), 12)
        self.assertEqual(owners['decoder_nested']['start'], '0x2ce1730')
        self.assertEqual(owners['decoder_nested']['end'], '0x2ce198a')
        self.assertEqual(owners['decoder_nested']['bytes'], 602)
        self.assertEqual(owners['phase_after_twin_a_1']['bytes'], 2619)
        # The two re-pinned callers are byte-identical to the bodies
        # pinned by the input-writers packet.
        self.assertEqual(
            owners['caller_bulk_a_1']['sha256'],
            'eab07e49a79bfe3de2f5e51d312ef9163f4a5f78f04240982b6a3e5b9c922e7e')
        self.assertEqual(
            owners['caller_bulk_a_2']['sha256'],
            '3efcb009eaf0ab2e2a477d73edbf7834894109e9fdcd943460d2bce59b9a0c57')
        self.assertEqual(
            owners['phase_after_twin_a_1']['sha256'],
            'c842a6d6b0c05a9b3978bcf786d556c62d71c4b055da335bf4b5617bbeb859be')

    def test_call_census(self):
        census = self.records['call_census']
        sites = census['direct_call_sites']
        self.assertEqual(sites['caller_b_side'], [])
        self.assertEqual(len(sites['decoder_nested']), 1)
        self.assertEqual(sites['decoder_nested'][0]['site'], '0x2e46771')
        self.assertEqual(len(sites['caller_twin_a_1']), 3)
        self.assertEqual(len(sites['phase_after_twin_a_1']), 4)
        self.assertEqual(len(sites['lvl2_c']), 2)
        self.assertTrue(all(
            refs == [] for refs in census['lea_references'].values()))
        self.assertTrue(all(
            found == [] for found in census['tail_call_sites'].values()))

    def test_access_census(self):
        census = self.records['access_census']
        self.assertEqual(
            census['decoder_nested']['exact_counts']['[rbx+0x28]'], 1)
        self.assertEqual(
            census['caller_bulk_a_1']['exact_counts']['[rbx+0x1c0]'], 2)
        self.assertEqual(
            census['caller_bulk_a_1']['exact_counts']['[rbx+0x1c8]'], 2)
        self.assertEqual(
            census['caller_bulk_a_1']['zero_patterns']['[rbx+0xc0]'], 0)
        self.assertEqual(
            census['caller_bulk_a_2']['exact_counts']['[r15+0x280]'], 2)
        self.assertEqual(
            census['caller_bulk_a_2']['exact_counts']['[r15+0x1d8]'], 3)
        for role in ('outer_bulk_a_1', 'outer_bulk_a_2',
                     'phase_after_bulk_a_1', 'phase_after_twin_a_1',
                     'lvl2_a', 'lvl2_b', 'lvl2_c', 'lvl2_d', 'lvl2_e'):
            self.assertTrue(all(
                count == 0
                for count in census[role]['zero_patterns'].values()),
                role)

    def test_slot_census(self):
        slot = self.records['slot_census']
        self.assertEqual(slot['file_wide_qword_occurrences'], 1)
        self.assertEqual(slot['relocation']['slot'], '0x64b91c0')
        self.assertEqual(slot['relocation']['type'], 8)
        self.assertEqual(slot['neighbour_addends']['0x64b91a0'],
                         '0x5a820d0')
        self.assertEqual(slot['rip_relative_references_to_slot'], [])

    def test_block_fill_records(self):
        fill = self.records['block_fill']
        self.assertIn('twelve', fill['bulk_selector_and_incoming_limit']
                      ['verdict'])
        self.assertIn('0x2ad8459',
                      fill['shaping_arm_exception']['sibling_store'])
        self.assertIn('0x2ad84cb',
                      fill['shaping_arm_exception']['limit_copy'])
        self.assertIn('0x64b91c0',
                      self.records['b_side_boundary']['data_occurrence'])
        record = self.records['decoder_result_0x28']
        self.assertIn('0x2ce191e', record['writer'])
        self.assertIn('fourth', record['value'])
        self.assertIn('0x2ce1971', record['failure_arms'])

    def test_counterfactual_mutations_raise(self):
        cases = [
            ('decoder sole +0x28 store', 0x2CE191E, 3),
            ('decoder fourth-read capture', 0x2CE17BB, 2),
            ('outer bulk a 1 caller call', 0x2AF4D07, 1),
            ('bulk a 1 shaping sibling store', 0x2AD8459, 3),
            ('phase after twin twin call', 0x2AE097F, 1),
            ('lvl2 b record load', 0x2B41B93, 0),
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
