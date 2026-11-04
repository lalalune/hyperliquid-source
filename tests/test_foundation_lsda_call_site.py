'''RE-001 node #115: committed controls for the LSDA call-site checker.

The checker authenticates artifacts/node/115/hl-node in place, parses
.eh_frame and .gcc_except_table, and re-derives one FDE-bound LSDA header
with its complete call-site table. The target is never executed or copied.
'''

import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from tools import foundation_lsda_call_site as lsda  # noqa: E402

TARGET = os.path.join(ROOT, 'artifacts', 'node', '115', 'hl-node')
PACKET = os.path.join(ROOT, 'research', 'work-items', 'RE-001-node115-lsda-call-site')


def derive_in_root():
    previous = os.getcwd()
    os.chdir(ROOT)
    try:
        return lsda.analyse()
    finally:
        os.chdir(previous)


def load_packet_evidence():
    with open(os.path.join(PACKET, 'evidence.json'), 'r', encoding='utf-8') as handle:
        return json.load(handle)


class LsdaCallSiteTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not os.path.isfile(TARGET):
            raise unittest.SkipTest('pinned node #115 target is absent')
        cls.derived = derive_in_root()

    def test_target_identity(self):
        target = self.derived['target']
        self.assertEqual(target['sha256'], lsda.TARGET_SHA256)
        self.assertEqual(target['size'], lsda.TARGET_SIZE)
        self.assertEqual(target['release'], 115)

    def test_recorded_target_matches_binary(self):
        evidence = load_packet_evidence()
        self.assertEqual(evidence['target']['sha256'], self.derived['target']['sha256'])
        self.assertEqual(evidence['target']['size'], self.derived['target']['size'])

    def test_selected_fde_extent_and_range(self):
        fde = self.derived['fde']
        self.assertEqual(fde['entry'], '0x14193f0')
        self.assertEqual(fde['end'], '0x1419618')
        self.assertEqual(fde['range'], 552)
        self.assertEqual(fde['initial_location_encoding'], '0x1b')

    def test_call_site_table_covers_declared_length(self):
        record = self.derived['lsda']
        sites = record['call_sites']
        header = record['header']
        self.assertEqual(len(sites), 4)
        self.assertEqual(header['call_site_encoding'], 1)
        self.assertEqual(header['call_site_table_length'], 21)
        self.assertEqual(sum(site['byte_length'] for site in sites), 518)
        self.assertEqual(len(bytes.fromhex(record['call_site_table_bytes_hex'])), 21)

    def test_negative_controls_discriminate(self):
        controls = self.derived['negative_controls']
        self.assertEqual([entry['control'] for entry in controls],
                         ['eh-frame-record-length-overflow',
                          'lsda-pointer-outside-section',
                          'call-site-table-truncated',
                          'declared-table-length-shortened'])
        self.assertEqual([entry['outcome'] for entry in controls], ['rejected'] * 4)

    def test_packet_evidence_matches_derivation(self):
        path = os.path.join(PACKET, 'evidence.json')
        self.assertTrue(os.path.isfile(path), 'packet evidence.json is missing')
        problems = lsda.compare_recorded(load_packet_evidence()['derived'], self.derived)
        self.assertEqual(problems, [])

    def test_committed_checker_accepts_packet(self):
        self.assertEqual(lsda.main(['--target', TARGET, '--packet', PACKET]), 0)

    def test_committed_checker_rejects_corrupted_record(self):
        evidence = load_packet_evidence()
        evidence['derived']['fde']['range'] = 553
        with tempfile.TemporaryDirectory() as work:
            with open(os.path.join(work, 'evidence.json'), 'w', encoding='utf-8') as handle:
                json.dump(evidence, handle)
            self.assertEqual(lsda.main(['--target', TARGET, '--packet', work]), 1)


if __name__ == '__main__':
    unittest.main()
