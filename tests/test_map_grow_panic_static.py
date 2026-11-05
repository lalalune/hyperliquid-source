#!/usr/bin/env python3
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from map_grow_panic_static import (  # noqa: E402
    GUARD_STRING_VA, PERSONALITY_SLOT, SIBLING_LSDA_VA, TARGET,
    analyze, generate)


def data_or_skip(test):
    if not TARGET.exists() or TARGET.stat().st_size != 105896032:
        test.skipTest('node115 artifact is an LFS pointer in this checkout')
    return TARGET.read_bytes()


def file_offset(data, va):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
    from map_grow_panic_static import _reader, _sections
    offset, _raw = _reader(_sections(data), data)(va, 1)
    return offset


class MapGrowPanicStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not TARGET.exists() or TARGET.stat().st_size != 105896032:
            raise unittest.SkipTest(
                'node115 artifact is an LFS pointer in this checkout')
        cls.data = TARGET.read_bytes()
        cls.report = analyze(cls.data)

    def test_shape(self):
        self.assertEqual(
            [row['role'] for row in self.report['owners']],
            ['map_grow', 'sibling_grow', 'marked_cleanup', 'pad_helper'])
        self.assertEqual(
            [row['role'] for row in self.report['boundaries']],
            ['prev_body', 'whole_map_drop', 'next_body', 'map_insert',
             'sibling_hasher', 'insert_value_drop'])
        self.assertEqual(
            [row['role'] for row in self.report['shims']],
            ['rust_personality', 'panic_formatter', 'panic_impl_shim',
             'alloc_error_adapter', 'alloc_handler_shim',
             'cleanup_guard', 'guard_panic_entry'])

    def test_grow_frame_has_no_lsda(self):
        unwind = self.report['unwind']
        self.assertEqual(unwind['map_grow'], {
            'cie': '0xca6ed8', 'augmentation': 'zR', 'lsda': None,
            'personality_slot': None, 'lsda_encoding': None})
        for role in ('marked_cleanup', 'pad_helper', 'whole_map_drop',
                     'prev_body', 'next_body'):
            self.assertEqual(unwind[role]['cie'], '0xca6ed8', role)
            self.assertIsNone(unwind[role]['lsda'], role)
        for role, lsda in (('sibling_grow', '0x34c4f8'),
                           ('map_insert', '0x34caf4')):
            self.assertEqual(unwind[role]['cie'], '0x103d604', role)
            self.assertEqual(unwind[role]['augmentation'], 'zPLR', role)
            self.assertEqual(unwind[role]['personality_slot'],
                             '0x64efa28', role)
            self.assertEqual(unwind[role]['lsda_encoding'], 0x1b, role)
            self.assertEqual(unwind[role]['lsda'], lsda, role)

    def test_personality_binding(self):
        self.assertEqual(self.report['personality'], {
            'slot': '0x64efa28', 'type': 8, 'addend': '0x5cad7b0',
            'accessor_slots': {
                '0x64eca58': '_Unwind_GetLanguageSpecificData',
                '0x64eca60': '_Unwind_GetIPInfo',
                '0x64eca68': '_Unwind_GetRegionStart'},
            'unwind_resume': '0x63f0a50'})
        bindings = self.report['slot_bindings']
        self.assertEqual(bindings['0x64df4c0']['addend'], '0x1680cab')
        self.assertEqual(bindings['0x64e1f30']['addend'], '0x5c826c0')
        self.assertEqual(bindings['0x64df6b8']['addend'], '0x1680e80')
        self.assertEqual(bindings['0x64df490']['addend'], '0x141e251')

    def test_lsda_tables(self):
        sibling = self.report['sibling_lsda']
        self.assertEqual(
            [(e['start'], e['length'], e['landing_pad'], e['action'])
             for e in sibling['entries']],
            [('0x4743990', 0x24f, None, 0),
             ('0x4743bdf', 0xa, '0x4743fc0', 0),
             ('0x4743be9', 0x16f, None, 0),
             ('0x4743d58', 0xa, '0x4743fd5', 0),
             ('0x4743d62', 0x276, None, 0),
             ('0x4743fd8', 0xa, '0x4743fea', 1),
             ('0x4743fe2', 0xe, None, 0)])
        self.assertEqual(sibling['ttype_base'], '0x34c528')
        self.assertEqual(sibling['action_table'], '0x34c525')
        self.assertEqual(sibling['action_table_head_hex'], '7f00')
        insert = self.report['insert_lsda']
        self.assertEqual(
            [(e['start'], e['length'], e['landing_pad'], e['action'])
             for e in insert['entries']],
            [('0x474b620', 0x3ce, None, 0),
             ('0x474b9ee', 0x23, '0x474ba2e', 0),
             ('0x474ba31', 0xa, '0x474ba57', 1),
             ('0x474ba3b', 0x22, None, 0)])
        self.assertEqual(insert['ttype_base'], '0x34cb14')
        self.assertEqual(self.report['grow_call_site_range'], {
            'call': '0x474ba06',
            'range': ['0x474b9ee', '0x474ba11'],
            'landing_pad': '0x474ba2e'})

    def test_failure_branches(self):
        self.assertEqual(self.report['failure_branches'], {
            '0x4742ab7': '0x4742bd1', '0x4742b5b': '0x4742bd1',
            '0x4742b9f': '0x4742bd1', '0x4742bd3': '0x4743316'})
        self.assertEqual(self.report['null_branch'], '0x4742bfb')
        self.assertEqual(self.report['path_split'], '0x4742c24')
        self.assertEqual(
            {site: call['slot'] for site, call in
             self.report['grow_slot_calls'].items()},
            {'0x4742bf2': '0x64df480', '0x4742c34': '0x64df750',
             '0x4742f33': '0x64df568', '0x4743301': '0x64df4a0',
             '0x4743329': '0x64df6b8', '0x4743337': '0x64df490'})

    def test_direct_call_census(self):
        self.assertEqual(self.report['direct_call_census'], {
            '0x47425c0': ['0x4743fdd'],
            '0x4742680': ['0x4743fc8'],
            '0x4744490': ['0x4743be4', '0x4743d5d', '0x4748984',
                          '0x47491b3', '0x474a1c3', '0x474ba7e']})
        self.assertEqual(self.report['guard_string'], {
            'address': '0x46e9bd',
            'text': 'panic in a destructor during cleanup'})
        self.assertEqual(self.report['panic_message'], {
            'address': '0x49bd80',
            'text': 'Hash table capacity overflow'})

    def _mutated(self, offset):
        data = bytearray(self.data)
        data[offset] ^= 0x01
        return bytes(data)

    def test_counterfactual_lsda_pad_byte(self):
        # The pad-offset uleb of the sibling's second call-site entry.
        offset = file_offset(self.data, SIBLING_LSDA_VA + 12)
        with self.assertRaises(ValueError):
            analyze(self._mutated(offset))

    def test_counterfactual_pad_call_displacement(self):
        offset = file_offset(self.data, 0x4743fdd + 1)
        with self.assertRaises(ValueError):
            analyze(self._mutated(offset))

    def test_counterfactual_stub_branch_displacement(self):
        offset = file_offset(self.data, 0x4742ab7 + 2)
        with self.assertRaises(ValueError):
            analyze(self._mutated(offset))

    def test_counterfactual_personality_addend(self):
        from map_grow_panic_static import _sections
        secs = _sections(self.data)
        rela = secs['.rela.dyn']
        target = None
        for offset in range(rela['offset'],
                            rela['offset'] + rela['size'], 24):
            r_offset, _info, _addend = struct.unpack_from(
                '<QQq', self.data, offset)
            if r_offset == PERSONALITY_SLOT:
                target = offset + 16
                break
        self.assertIsNotNone(target)
        with self.assertRaises(ValueError):
            analyze(self._mutated(target))

    def test_counterfactual_guard_string(self):
        offset = file_offset(self.data, GUARD_STRING_VA)
        with self.assertRaises(ValueError):
            analyze(self._mutated(offset))

    def test_generate_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            generate(TARGET, Path(tmp))
            recorded = json.loads((Path(tmp) / 'records.json')
                                  .read_text())
            self.assertEqual(recorded, self.report)
            for name in ('frames.txt',
                         'grow_failure_entry_objdump.txt',
                         'grow_install_tail_objdump.txt',
                         'sibling_hash_call_fresh_objdump.txt',
                         'sibling_hash_call_inplace_objdump.txt',
                         'sibling_pads_objdump.txt',
                         'insert_pads_objdump.txt',
                         'pad_helper_objdump.txt',
                         'panic_guard_objdump.txt',
                         'panic_fmt_objdump.txt'):
                self.assertTrue((Path(tmp) / name).exists(), name)

    def test_committed_records_match(self):
        packet = (Path(__file__).resolve().parents[1] / 'research' /
                  'work-items' / 'RE-015-node115-map-grow-panic' /
                  'records.json')
        recorded = json.loads(packet.read_text())
        self.assertEqual(recorded, self.report)


if __name__ == '__main__':
    unittest.main()
