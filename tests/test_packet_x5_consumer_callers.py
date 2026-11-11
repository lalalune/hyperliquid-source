import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'tools')]

import packet_x5_consumer_callers as packet

PACKET_DIR = ROOT / 'research/work-items' / packet.WORK_ITEM
DATA = packet.TARGET.read_bytes() if packet.TARGET.exists() else b''
MATERIALISED = (
    len(DATA) == packet.TARGET_SIZE
    and hashlib.sha256(DATA).hexdigest() == packet.TARGET_SHA256)

# Sites that appear incidentally in earlier packets: 11 RE-017
# transfer/call rows, 1 RE-011 call row, and the 3 sites inside
# RE-012's instruction window over caller body 0x2b41b70 (one of
# which, 0x2b4261c, is also an RE-017 row).
PRIOR_RECORDED_SITES = {
    '0x2b420da', '0x2b4261c', '0x2b428ab', '0x2a0afd5',
    '0x4e359fc', '0x4e35c7c', '0x4e36191', '0x4e3642f', '0x4e45a61',
    '0x4e460c1', '0x4e46e71', '0x4e47938', '0x4e47cdf', '0x4e4a771',
}

ZERO_DIRECT_CALLER_BODIES = {
    '0x159d600', '0x17457f0', '0x2a225c0', '0x2a2a0e0', '0x2a64e20',
    '0x5a93b50', '0x5a940c0',
}


@unittest.skipUnless(MATERIALISED, 'node 115 artifact is not materialised')
class X5ConsumerCallersPacketTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records = packet.analyze(DATA)

    def test_regeneration_matches_retained_records(self):
        retained = json.loads((PACKET_DIR / 'records.json').read_text())
        self.assertEqual(self.records, retained)

    def test_source_pin(self):
        source = self.records['source']
        self.assertEqual(source['slot'], '0x64e7718')
        self.assertEqual(source['consumer_count'], 63)
        self.assertEqual(source['work_item'],
                         'RE-005-node115-x5-caller-slot-consumers')
        consumers = {c['body']['start']: c
                     for c in self.records['consumers']}
        self.assertEqual(len(consumers), 63)
        # Byte-identical to the consumer body pinned by PR #3235.
        self.assertEqual(
            consumers['0x2b3aba0']['body']['sha256'],
            'b33592b3e2458d7cc2201a464dbb439e5665a536dfedb6fed2a208c3dfa85245')
        self.assertEqual(consumers['0x2b3aba0']['body']['bytes'], 732)

    def test_all_sites_are_direct_calls_in_fde_bodies(self):
        census = self.records['census']
        self.assertEqual(census['verified_direct_call_sites'], 67)
        self.assertEqual(census['verified_direct_jump_sites'], 0)
        self.assertEqual(census['caller_bodies'], 65)
        self.assertTrue(census['candidate_scan_matches_linear_sweep'])
        self.assertEqual(census['sites_outside_fde_bodies'], 0)
        sites = []
        for caller in self.records['callers']:
            body = caller['body']
            self.assertEqual(
                body['bytes'],
                int(body['end'], 16) - int(body['start'], 16))
            for s in caller['sites']:
                sites.append(s['site'])
                self.assertTrue(s['site_bytes'].startswith('e8'),
                                s['site'])
                self.assertTrue(
                    int(body['start'], 16) <= int(s['site'], 16)
                    < int(body['end'], 16), s['site'])
        self.assertEqual(len(sites), 67)
        self.assertEqual(len(set(sites)), 67)
        for consumer in self.records['consumers']:
            self.assertGreaterEqual(len(consumer['call_sites']), 1,
                                    consumer['body']['start'])

    def test_no_indirect_path(self):
        census = self.records['census']
        self.assertEqual(
            census['relocations_with_addend_eq_any_consumer'], 0)
        self.assertEqual(
            census['stored_qword_copies_of_consumer_starts_outside_rela'],
            0)
        self.assertEqual(
            census['imm_materialisations_of_consumer_starts'], 0)
        self.assertEqual(
            census['rip_relative_refs_to_consumer_starts'], 0)
        self.assertEqual(
            census['dynsym_entries_with_consumer_st_value'], 0)

    def test_families(self):
        fams = self.records['families']
        self.assertEqual(fams['flag_pair']['call_sites'], 36)
        self.assertEqual(
            fams['static_second_argument']['call_sites'], 28)
        self.assertEqual(fams['residual']['call_sites'], 3)
        uniform = {c['body']['start'] for c in self.records['consumers']
                   if 0x5a9c620 <= int(c['body']['start'], 16)
                   <= 0x5aa6c91}
        self.assertEqual(len(uniform), 36)
        residual_sites = set()
        for caller in self.records['callers']:
            for s in caller['sites']:
                if s['family'] == 'flag_pair':
                    self.assertIn(s['consumer'], uniform)
                    t = s['template']
                    self.assertTrue(t['zeroed_stack_byte_pair_before'])
                    self.assertTrue(t['lea_rdx_rip_before'])
                    self.assertTrue(t['test_rax_rax_after'])
                    self.assertIsNotNone(s['rdx_static'])
                elif s['family'] == 'static_second_argument':
                    self.assertTrue(
                        s['template']['lea_rsi_rip_before'])
                    self.assertIsNotNone(s['rsi_static'])
                else:
                    residual_sites.add(s['site'])
        self.assertEqual(residual_sites,
                         {'0x5a93ce9', '0x5a94259', '0x5ceb5ab'})

    def test_pairing(self):
        by_start = {c['body']['start']: c
                    for c in self.records['callers']}
        self.assertEqual(len(by_start['0x2b41b70']['sites']), 3)
        self.assertEqual(
            {s['consumer'] for s in by_start['0x2b41b70']['sites']},
            {'0x2b3aba0', '0x2b3b3e0', '0x2b3d250'})
        for start, caller in by_start.items():
            if start != '0x2b41b70':
                self.assertEqual(len(caller['sites']), 1, start)
        consumers = {c['body']['start']: c
                     for c in self.records['consumers']}
        self.assertEqual(len(consumers['0x2e8e7b0']['call_sites']), 3)
        self.assertEqual(len(consumers['0x2b3c9d0']['call_sites']), 2)
        self.assertEqual(len(consumers['0x5a79730']['call_sites']), 2)

    def test_prior_recorded_sites_are_included(self):
        sites = {s['site'] for c in self.records['callers']
                 for s in c['sites']}
        self.assertTrue(PRIOR_RECORDED_SITES <= sites)

    def test_one_level_up_counts(self):
        self.assertEqual(
            set(self.records['one_level_up']
                ['zero_direct_caller_bodies']),
            ZERO_DIRECT_CALLER_BODIES)
        for caller in self.records['callers']:
            if caller['body']['start'] in ZERO_DIRECT_CALLER_BODIES:
                self.assertEqual(caller['direct_callers'], 0)
                self.assertEqual(caller['relocation_addends'], 1)
            else:
                self.assertGreaterEqual(caller['direct_callers'], 1)

    def test_frames_match_regeneration(self):
        retained = (PACKET_DIR / 'frames.txt').read_text()
        regenerated = '\n'.join(
            packet.frames_lines(DATA, self.records)) + '\n'
        self.assertEqual(regenerated, retained)
        self.assertEqual(len(retained.strip().split('\n')), 128)

    def test_manifest_hashes(self):
        manifest = (PACKET_DIR / 'MANIFEST.sha256').read_text()
        for line in manifest.strip().split('\n'):
            digest, name = line.split('  ')
            raw = (PACKET_DIR / name).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), digest,
                             name)


if __name__ == '__main__':
    unittest.main()
