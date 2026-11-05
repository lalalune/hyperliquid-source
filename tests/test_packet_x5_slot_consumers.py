import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'tools')]

import packet_x5_slot_consumers as packet

PACKET_DIR = ROOT / 'research/work-items' / packet.WORK_ITEM
DATA = packet.TARGET.read_bytes() if packet.TARGET.exists() else b''
MATERIALISED = (
    len(DATA) == packet.TARGET_SIZE
    and hashlib.sha256(DATA).hexdigest() == packet.TARGET_SHA256)


@unittest.skipUnless(MATERIALISED, 'node 115 artifact is not materialised')
class X5SlotConsumersPacketTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records = packet.analyze(DATA)

    def test_regeneration_matches_retained_records(self):
        retained = json.loads((PACKET_DIR / 'records.json').read_text())
        self.assertEqual(self.records, retained)

    def test_slot_and_target_pin(self):
        slot = self.records['slot']
        self.assertEqual(slot['va'], '0x64e7718')
        self.assertEqual(slot['relocation'],
                         {'r_offset': '0x64e7718', 'type': 8,
                          'addend': '0x5cf5100'})
        body = slot['target_body']
        self.assertEqual(body['start'], '0x5cf5100')
        self.assertEqual(body['end'], '0x5cf55d7')
        self.assertEqual(body['bytes'], 1239)
        # Byte-identical to the caller body pinned by the X5 env-pair
        # packet (RE-005-node115-x5-env-pair-source).
        self.assertEqual(
            body['sha256'],
            '3ede3e0de6239df2546301485ff8664996a025ed907a977b2d99c6cdc054fcd8')
        self.assertEqual(slot['target_direct_callers'], 0)

    def test_sixty_three_consumers_all_indirect_calls(self):
        consumers = self.records['consumers']
        self.assertEqual(self.records['consumer_count'], 63)
        self.assertEqual(len(consumers), 63)
        sites = [c['site'] for c in consumers]
        self.assertEqual(len(set(sites)), 63)
        bodies = [c['body']['start'] for c in consumers]
        self.assertEqual(len(set(bodies)), 63)
        for c in consumers:
            self.assertTrue(c['site_bytes'].startswith('ff15'),
                            c['site'])
            self.assertEqual(
                c['body']['bytes'],
                int(c['body']['end'], 16) - int(c['body']['start'], 16))

    def test_no_other_reference_form(self):
        census = self.records['census']
        self.assertEqual(census['verified_rip_relative_refs']['slot'], 63)
        self.assertEqual(census['verified_rip_relative_refs']['caller'], 0)
        self.assertEqual(census['absolute_disp32_refs'], 0)
        self.assertEqual(
            census['stored_qword_copies_outside_rela_dyn'], 0)
        self.assertEqual(census['relocations_with_addend_eq_slot'], 0)
        self.assertEqual(census['relocations_with_addend_eq_caller'], 1)

    def test_call_template_complete_for_every_consumer(self):
        for c in self.records['consumers']:
            t = c['template']
            self.assertIsNotNone(t['alloc_call'], c['site'])
            self.assertIsNotNone(t['copy_call'], c['site'])
            self.assertIsNotNone(t['pair_add_1f8'], c['site'])
            self.assertTrue(t['mov_edx_1_at_site_minus_5'], c['site'])
            self.assertTrue(t['return_pair_test'], c['site'])
            self.assertIn(c['alloc_size'], (0x100, 0x300, 0x400, 0x480))
            self.assertGreaterEqual(c['direct_callers'], 1)

    def test_clusters(self):
        clusters = self.records['clusters']
        self.assertEqual([c['bodies'] for c in clusters],
                         [23, 1, 1, 1, 36, 1])
        self.assertEqual(clusters[0]['first_body'], '0x2b3a8c0')
        self.assertEqual(clusters[4]['body_sizes'], [1169])
        self.assertEqual(clusters[4]['first_body'], '0x5a9c620')
        self.assertEqual(clusters[5]['first_body'], '0x5cf4540')

    def test_neighbour_controls(self):
        n = self.records['neighbours']
        self.assertEqual(n['0x64e7710']['target'], '0x5ceb1b0')
        self.assertEqual(len(n['0x64e7710']['verified_ref_sites']), 4)
        self.assertEqual(n['0x64e7720']['target'], '0x595b1a0')
        self.assertEqual(len(n['0x64e7720']['verified_ref_sites']), 1)

    def test_frames_match_regeneration(self):
        retained = (PACKET_DIR / 'frames.txt').read_text()
        regenerated = '\n'.join(
            packet.frames_lines(DATA, self.records)) + '\n'
        self.assertEqual(regenerated, retained)
        self.assertEqual(len(retained.strip().split('\n')), 64)

    def test_manifest_hashes(self):
        manifest = (PACKET_DIR / 'MANIFEST.sha256').read_text()
        for line in manifest.strip().split('\n'):
            digest, name = line.split('  ')
            raw = (PACKET_DIR / name).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), digest,
                             name)


if __name__ == '__main__':
    unittest.main()
