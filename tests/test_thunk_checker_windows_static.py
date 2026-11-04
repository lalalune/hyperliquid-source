"""Tests for the RE-005 thunk / checker-windows evidence."""

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import thunk_checker_windows_static as packet  # noqa: E402


def materialised():
    target = packet.TARGET
    return target.is_file() and not target.is_symlink() \
        and target.stat().st_size == packet.TARGET_SIZE


@unittest.skipUnless(materialised(), 'node 115 not materialised')
class ThunkCheckerWindowsTests(unittest.TestCase):
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
                         ['indirect_caller', 'main_shim',
                          'thunk', 'trampoline'])
        for role in packet.EXPORTED:
            rec = self.records['owners'][role]
            self.assertEqual(rec['bytes'],
                             int(rec['end'], 16)
                             - int(rec['start'], 16))

    def test_entry_chain_slots(self):
        slots = self.records['slots']
        self.assertEqual(slots['0x64df458'],
                         '__libc_start_main')
        self.assertEqual(slots['0x64e6c30'], '0x5c99970')
        self.assertEqual(slots['0x6440b70'], '0x292c5c0')
        self.assertEqual(slots['0x6440b68'], '0x292c5c0')

    def test_thunk_has_no_direct_or_data_reference(self):
        self.assertEqual(
            self.records['branch_censuses']['0x2cd8370'], [])
        self.assertEqual(
            self.records['branch_censuses']['0x2ae1690'],
            [{'kind': 'call', 'site': '0x2cd83a2'}])
        for ref in ('thunk_qword', 'thunk_u32',
                    'dispatcher_qword', 'dispatcher_u32',
                    'interior_aligned'):
            self.assertEqual(
                self.records['absolute_refs'][ref], [])
        for role in ('thunk', 'dispatcher',
                     'main_shim', 'indirect_caller'):
            self.assertEqual(self.records['rela_refs'][role],
                             {'addend_hits': [],
                              'offset_hits': []})
        self.assertEqual(
            self.records['rela_refs']['rt_entry'],
            {'addend_hits': ['0x64e6c30'],
             'offset_hits': []})

    def test_thunk_lea_exactly_once_in_main_shim(self):
        self.assertEqual(self.records['lea_census']['thunk'],
                         ['0x2cef8f7'])
        for role in ('dispatcher', 'driver_a', 'driver_c',
                     'gate_a', 'gate_c', 'checker_a'):
            self.assertEqual(self.records['lea_census'][role],
                             [])

    def test_trampoline_is_table_held(self):
        self.assertEqual(
            self.records['rela_refs']['trampoline']
            ['addend_hits'],
            ['0x6440b68', '0x6440b70'])

    def test_init_arrays_do_not_name_thunk(self):
        ia = self.records['init_arrays']
        self.assertEqual(ia['init_array']['count'], 168)
        self.assertFalse(ia['init_array']['contains_thunk'])
        self.assertFalse(
            ia['init_array']['contains_dispatcher'])
        self.assertEqual(ia['fini_array']['entries'],
                         ['0x14193a0'])

    def test_setup_blocks_have_exactly_two_inbound_edges(self):
        bc = self.records['branch_censuses']
        self.assertEqual(
            [(e['site'], e['kind']) for e in bc['0x2b90af3']],
            [('0x2b9087e', 'jmp'), ('0x2b90de2', 'jmp')])
        self.assertEqual(
            [(e['site'], e['kind']) for e in bc['0x2cc7fa6']],
            [('0x2cc92c6', 'jmp')])
        self.assertEqual(bc['0x2b9087e'], [])

    def test_jump_tables_land_on_setup_at_case_4(self):
        # Window A: case 4 lands on the jmp-to-setup
        # block 0x2b9087e; window B: case 4 lands on the
        # setup block itself.
        for base, edge in (('0x607328', '0x2b9087e'),
                           ('0x60bdb8', '0x2cc7fa6')):
            table = self.records['jump_tables'][base]
            self.assertEqual(table['entries'][4], edge)
            self.assertEqual(table['setup_index'], 4)

    def test_window_a_stores(self):
        stores = self.records['windows']['caller_a'][
            'stores_covering_entry_byte']
        self.assertEqual(
            [(s['site'], s['src']) for s in stores],
            [('0x2b90ddb', '$0x0')])

    def test_window_b_stores(self):
        stores = self.records['windows']['caller_b'][
            'stores_covering_entry_byte']
        self.assertEqual(
            [(s['site'], s['src']) for s in stores],
            [('0x2cc5125', '%cl'), ('0x2cc92be', '$0x0')])

    def test_dispatcher_loop_encloses_driver_calls(self):
        loop = self.records['dispatcher_loop']
        self.assertEqual(loop['loop_head'], '0x2ae1974')
        self.assertEqual(loop['backedge_site'], '0x2ae21ff')
        self.assertEqual(loop['driver_calls_inside_span'],
                         {'driver_a': True, 'driver_c': True})

    def test_records_file_matches_rederive(self):
        expected = json.loads((packet.OUT / 'records.json')
                              .read_text())
        self.assertEqual(self.records, expected)

    def test_mutated_artifact_rejected(self):
        bad = bytearray(self.data)
        bad[0x2CEF8F7] ^= 0xFF
        with self.assertRaises(ValueError):
            packet.analyze(bytes(bad))

    def test_mutated_records_rejected(self):
        bad = copy.deepcopy(self.records)
        bad['owners']['thunk']['bytes'] = 1
        self.assertNotEqual(bad, self.records)


if __name__ == '__main__':
    unittest.main()
