"""Tests for the RE-005 remaining-edges evidence."""

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import remaining_edges_static as packet  # noqa: E402


def materialised():
    target = packet.TARGET
    return target.is_file() and not target.is_symlink() \
        and target.stat().st_size == packet.TARGET_SIZE


@unittest.skipUnless(materialised(), 'node 115 not materialised')
class RemainingEdgesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = packet.TARGET.read_bytes()
        cls.records = packet.analyze(cls.data)

    def test_artifact_identity(self):
        self.assertEqual(self.records['artifact']['size'],
                         packet.TARGET_SIZE)
        self.assertEqual(self.records['artifact']['sha256'],
                         packet.TARGET_SHA256)

    def test_four_exported_bodies(self):
        self.assertEqual(sorted(packet.EXPORTED),
                         ['accessor', 'advance', 'flag_writer',
                          'tls_dtor'])
        for role in packet.EXPORTED:
            rec = self.records['owners'][role]
            self.assertEqual(rec['bytes'],
                             int(rec['end'], 16)
                             - int(rec['start'], 16))

    def test_flag_write_is_single_xchg(self):
        sc = self.records['store_censuses']
        self.assertEqual(
            sc['flag_writer_flag_writes'],
            [{'site': '0x5ce093d', 'base': 'rsi', 'disp': 0x80}])

    def test_horizon_single_store_and_no_flag_access(self):
        sc = self.records['store_censuses']
        self.assertEqual(
            sc['advance_horizon_stores'],
            [{'site': '0x5ceabc4', 'base': 'rbx', 'disp': 0x28}])
        self.assertEqual(sc['advance_flag_accesses'], [])

    def test_cluster_byte_stores_are_lock_body_only(self):
        sc = self.records['store_censuses']
        sites = [e['site'] for e in
                 sc['cluster_disp30_nonstack_byte_stores']]
        self.assertEqual(sites, ['0x5cf4842', '0x5cf48d7',
                                 '0x5cf4a52'])

    def test_flag_writer_callers_exactly_two(self):
        cc = self.records['call_censuses']
        self.assertEqual(
            [(e['site'], e['kind']) for e in cc['flag_writer']],
            [('0x5ceb47e', 'call'), ('0x5cfc20d', 'call')])
        self.assertEqual(self.records['relative_refs']
                         ['flag_writer'], [])

    def test_gate_and_driver_call_graph(self):
        cc = self.records['call_censuses']
        self.assertEqual([e['site'] for e in cc['gate_c']],
                         ['0x2cde6f4', '0x2cdf58b'])
        self.assertEqual([e['site'] for e in cc['gate_a']],
                         ['0x2ae4627', '0x2ae548c'])
        self.assertEqual([e['site'] for e in cc['driver_c']],
                         ['0x2ae1eeb'])
        self.assertEqual([e['site'] for e in cc['dispatcher']],
                         ['0x2cd83a2'])
        self.assertEqual(cc['thunk'], [])
        for role in ('gate_c', 'gate_a', 'driver_c',
                     'dispatcher', 'thunk'):
            self.assertEqual(self.records['relative_refs'][role],
                             [])

    def test_poll_is_data_held_only(self):
        self.assertEqual(self.records['call_censuses']['poll'],
                         [])
        self.assertEqual(self.records['relative_refs']['poll'],
                         ['0x64dfe40'])
        self.assertEqual(self.records['slots']['0x64dfe40'],
                         '0x5ceafd0')

    def test_gate_c_has_no_record_1d8_store(self):
        sc = self.records['store_censuses']
        self.assertEqual(sc['gate_c_record_1d8_stores'], [])
        self.assertEqual(
            sc['driver_c_record_1d8_stores'],
            [{'site': '0x2cdf724', 'base': 'r13', 'disp': 0x3F8,
              'mnem': 'mov', 'store': True}])

    def test_tls_template_is_no_context(self):
        tls = self.records['tls']
        self.assertEqual(tls['template_tag'], '0x2')
        self.assertEqual(tls['template_handle'], '0x0')
        self.assertEqual(tls['template_counter'], '0x0')
        self.assertEqual(tls['template_state_byte'], 0)
        self.assertEqual(self.records['slots']['0x64e0510'],
                         '0x5ca0d20')

    def test_timers_location(self):
        loc = self.records['locations']['0x64c6fa8']
        self.assertEqual((loc['line'], loc['col']), (190, 32))
        self.assertEqual(loc['file_ptr'], '0x43e4fe')
        self.assertEqual(
            self.records['strings']['time_mod_path']['text'],
            '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/'
            'runtime/time/mod.rs')

    def test_records_file_matches_rederive(self):
        expected = json.loads((packet.OUT / 'records.json')
                              .read_text())
        self.assertEqual(self.records, expected)

    def test_mutated_artifact_rejected(self):
        bad = bytearray(self.data)
        bad[0x5CE093D] ^= 0xFF
        with self.assertRaises(ValueError):
            packet.analyze(bytes(bad))

    def test_mutated_records_rejected(self):
        bad = copy.deepcopy(self.records)
        bad['owners']['flag_writer']['bytes'] = 1
        self.assertNotEqual(bad, self.records)


if __name__ == '__main__':
    unittest.main()
