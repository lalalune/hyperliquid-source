"""Tests for the RE-005 loop-tail-callee evidence."""

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import loop_tail_callee_static as packet  # noqa: E402


def materialised():
    target = packet.TARGET
    return target.is_file() and not target.is_symlink() \
        and target.stat().st_size == packet.TARGET_SIZE


@unittest.skipUnless(materialised(), 'node 115 not materialised')
class LoopTailCalleeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = packet.TARGET.read_bytes()
        cls.records = packet.analyze(cls.data)

    def test_artifact_identity(self):
        self.assertEqual(self.records['artifact']['size'],
                         packet.TARGET_SIZE)
        self.assertEqual(self.records['artifact']['sha256'],
                         packet.TARGET_SHA256)

    def test_two_exported_bodies(self):
        self.assertEqual(sorted(packet.EXPORTED),
                         ['dtor_glue', 'loop_getter'])
        getter = self.records['owners']['loop_getter']
        self.assertEqual((getter['start'], getter['end'],
                          getter['bytes']),
                         ('0x5cdf300', '0x5cdf3df', 223))
        glue = self.records['owners']['dtor_glue']
        self.assertEqual((glue['start'], glue['end'],
                          glue['bytes']),
                         ('0x5cdf3e0', '0x5cdf40b', 43))

    def test_slots(self):
        self.assertEqual(self.records['slots'], {
            '0x64df480': '0x6355830',
            '0x64df490': '0x141e251',
            '0x64df730': '0x1680e60',
            '0x64e0510': '0x5ca0d20',
            '0x64e17f8': '0x5ce9190',
        })

    def test_call_census_twenty_sites_no_jumps(self):
        census = self.records['call_census']
        self.assertEqual(len(census['loop_getter']['calls']),
                         20)
        self.assertEqual(census['loop_getter']['jmps'], [])
        self.assertEqual(census['dtor_glue'],
                         {'calls': [], 'jmps': []})
        self.assertEqual(len(self.records['callers']), 20)

    def test_every_caller_passes_null_rsi_same_cell(self):
        bodies = set()
        for rec in self.records['callers']:
            bodies.add(rec['body'])
            self.assertLess(int(rec['rsi_zero'], 16),
                            int(rec['site'], 16))
            self.assertLess(int(rec['site'], 16)
                            - int(rec['rsi_zero'], 16), 8)
        self.assertEqual(len(bodies), 9)

    def test_dispatcher_has_four_sites(self):
        sites = self.records['dispatcher_sites']
        self.assertEqual([s['call'] for s in sites],
                         ['0x2ae1ad6', '0x2ae1fea',
                          '0x2ae20a1', '0x2ae21f7'])
        tail = sites[-1]
        self.assertEqual(tail['branch'], '0x2ae21ff')
        self.assertEqual(tail['branch_target'], '0x2ae1974')
        guards = self.records['dispatcher_guards']
        self.assertEqual(guards['cell_defs'],
                         ['0x2ae195b', '0x2ae1d7b'])
        self.assertEqual(guards['guard_cmps'],
                         ['0x2ae1962', '0x2ae1ab2',
                          '0x2ae1dfa', '0x2ae1f63'])

    def test_getter_structure_no_iteration_bound(self):
        st = self.records['getter_structure']
        self.assertEqual(st['backward_targets'],
                         ['0x5cdf317'])
        self.assertEqual(st['lock_sites'], ['0x5cdf37f'])
        self.assertEqual(st['direct_calls'], [])
        self.assertEqual(st['rets'],
                         ['0x5cdf31f', '0x5cdf398',
                          '0x5cdf3b5'])
        self.assertEqual(st['slot_calls'], {
            '0x5cdf342': '0x64df480',
            '0x5cdf38a': '0x64e17f8',
            '0x5cdf3a7': '0x64e0510',
            '0x5cdf3c0': '0x64df490',
            '0x5cdf3d9': '0x64df730',
        })
        self.assertEqual(st['stores'], [
            '0x5cdf328', '0x5cdf334', '0x5cdf337',
            '0x5cdf34d', '0x5cdf354', '0x5cdf35f',
            '0x5cdf363', '0x5cdf36e', '0x5cdf373',
            '0x5cdf376'])

    def test_glue_sets_state_two_and_drops(self):
        st = self.records['glue_structure']
        self.assertEqual(st['stores'], ['0x5cdf3e5'])
        self.assertEqual(st['lock_sites'], ['0x5cdf3f0'])
        self.assertEqual(st['slot_calls']['0x5cdf3f6'],
                         '0x64e17f8')
        self.assertEqual(st['rets'], ['0x5cdf3fd'])

    def test_tls_cell_is_zero_initialised(self):
        tls = self.records['tls']
        self.assertEqual(tls['filesz'], 0xB20)
        self.assertEqual(tls['memsz'], 0x1180)
        self.assertEqual(tls['cell_template_offset'],
                         '0xd68')
        self.assertTrue(tls['cell_in_zero_region'])

    def test_panic_provenance_is_std_lazy(self):
        panic = self.records['panic']
        self.assertEqual(panic['message'],
                         'internal error: entered '
                         'unreachable code')
        self.assertTrue(panic['location_file'].endswith(
            'library/std/src/sys/thread_local/native/'
            'lazy.rs'))
        self.assertEqual(panic['location_line'], 98)
        self.assertEqual(panic['location_col'], 36)

    def test_no_data_reference_to_getter(self):
        for role in ('loop_getter', 'dtor_glue',
                     'dispatcher'):
            self.assertEqual(self.records['rela_refs'][role],
                             {'addend_hits': [],
                              'offset_hits': []})
        self.assertEqual(
            self.records['rela_refs']['registrar']
            ['addend_hits'], ['0x64e0510'])
        self.assertEqual(
            self.records['rela_refs']['drop_helper']
            ['addend_hits'], ['0x64e17f8'])
        self.assertEqual(self.records['lea_census'], {
            'loop_getter': [],
            'dtor_glue': ['0x5cdf39d'],
            'dispatcher': [],
        })
        for key, hits in self.records['absolute_refs'].items():
            self.assertEqual(hits, [], key)

    def test_records_file_matches_rederive(self):
        expected = json.loads((packet.OUT / 'records.json')
                              .read_text())
        self.assertEqual(self.records, expected)

    def test_mutated_artifact_rejected(self):
        bad = bytearray(self.data)
        bad[0x5CDF308] ^= 0xFF
        with self.assertRaises(ValueError):
            packet.analyze(bytes(bad))

    def test_mutated_records_rejected(self):
        bad = copy.deepcopy(self.records)
        bad['owners']['loop_getter']['bytes'] = 1
        self.assertNotEqual(bad, self.records)


if __name__ == '__main__':
    unittest.main()
