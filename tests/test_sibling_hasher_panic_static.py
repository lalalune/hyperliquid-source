#!/usr/bin/env python3
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from sibling_hasher_panic_static import (  # noqa: E402
    ABSORB, CALLER_B_LSDA_VA, HASHER, PERSONALITY_SLOT, TARGET,
    analyze, generate)


def data_or_skip(test):
    if not TARGET.exists() or TARGET.stat().st_size != 105896032:
        test.skipTest('node115 artifact is an LFS pointer in this checkout')
    return TARGET.read_bytes()


def file_offset(data, va):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
    from sibling_hasher_panic_static import _reader, _sections
    offset, _raw = _reader(_sections(data), data)(va, 1)
    return offset


class SiblingHasherPanicStaticTests(unittest.TestCase):
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
            ['seeded_hasher', 'absorb'])
        self.assertEqual(
            [row['role'] for row in self.report['boundaries']],
            ['sibling_grow', 'caller_a', 'caller_b', 'caller_c',
             'prev_variant', 'next_variant'])
        self.assertEqual(
            [row['role'] for row in self.report['shims']],
            ['rust_personality'])

    def test_owner_frames_have_no_lsda(self):
        unwind = self.report['unwind']
        for role in ('seeded_hasher', 'absorb', 'prev_variant',
                     'next_variant'):
            self.assertEqual(unwind[role], {
                'cie': '0xca6ed8', 'augmentation': 'zR', 'lsda': None,
                'personality_slot': None, 'lsda_encoding': None}, role)
        for role, lsda in (('sibling_grow', '0x34c4f8'),
                           ('caller_a', '0x34c818'),
                           ('caller_b', '0x34c9a0'),
                           ('caller_c', '0x34cb18')):
            self.assertEqual(unwind[role]['cie'], '0x103d604', role)
            self.assertEqual(unwind[role]['augmentation'], 'zPLR', role)
            self.assertEqual(unwind[role]['lsda'], lsda, role)
            self.assertEqual(unwind[role]['personality_slot'],
                             '0x64efa28', role)

    def test_instruction_census(self):
        census = self.report['instruction_census']
        hasher = census['seeded_hasher']
        self.assertEqual(hasher['instructions'], 93)
        self.assertEqual(hasher['calls'], [
            {'site': '0x47444eb', 'target': '0x4744980'},
            {'site': '0x4744502', 'target': '0x4744980'}])
        self.assertEqual(hasher['branches'], {})
        self.assertEqual(hasher['divisions'], [])
        self.assertEqual(hasher['traps'], [])
        absorb = census['absorb']
        self.assertEqual(absorb['instructions'], 141)
        self.assertEqual(absorb['calls'], [])
        self.assertEqual(len(absorb['branches']), 15)
        for target in absorb['branches'].values():
            self.assertTrue('0x4744980' <= target < '0x4744b57', target)
        self.assertEqual(absorb['divisions'], [])
        self.assertEqual(absorb['traps'], [])

    def test_direct_call_census(self):
        census = self.report['direct_call_census']
        self.assertEqual(census['0x4744490'], [
            '0x4743be4', '0x4743d5d', '0x4748984', '0x47491b3',
            '0x474a1c3', '0x474ba7e'])
        self.assertEqual(census['0x4744980'], [
            '0x4744380', '0x4744397', '0x47444eb', '0x4744502',
            '0x474465a', '0x4744671'])

    def test_call_site_coverage(self):
        coverage = self.report['call_site_coverage']
        self.assertEqual(coverage, {
            '0x4743be4': {'caller': 'sibling_grow',
                          'range': ['0x4743bdf', '0x4743be9'],
                          'landing_pad': '0x4743fc0'},
            '0x4743d5d': {'caller': 'sibling_grow',
                          'range': ['0x4743d58', '0x4743d62'],
                          'landing_pad': '0x4743fd5'},
            '0x4748984': {'caller': 'caller_a',
                          'range': ['0x4748977', '0x4748989'],
                          'landing_pad': '0x4749948'},
            '0x47491b3': {'caller': 'caller_a',
                          'range': ['0x47491a3', '0x47491b8'],
                          'landing_pad': '0x4749814'},
            '0x474a1c3': {'caller': 'caller_b',
                          'range': ['0x474a1c0', '0x474a1c8'],
                          'landing_pad': '0x474a361'},
            '0x474ba7e': {'caller': 'caller_c',
                          'range': ['0x474ba7b', '0x474ba83'],
                          'landing_pad': '0x474bcb4'}})

    def test_lsda_tables(self):
        tables = self.report['lsda_tables']
        self.assertEqual(len(tables['sibling_grow']['entries']), 7)
        self.assertEqual(len(tables['caller_a']['entries']), 30)
        self.assertEqual(len(tables['caller_b']['entries']), 5)
        self.assertEqual(len(tables['caller_c']['entries']), 4)
        self.assertEqual(
            tables['sibling_grow']['action_table_head_hex'], '7f00')
        self.assertEqual(
            tables['caller_a']['action_table_head_hex'], '7f00')
        self.assertEqual(
            tables['caller_b']['action_table_head_hex'], '0000')
        self.assertEqual(
            tables['caller_c']['action_table_head_hex'], '0000')
        self.assertIsNone(tables['caller_b']['ttype_base'])
        self.assertIsNone(tables['caller_c']['ttype_base'])

    def _mutated(self, offset):
        data = bytearray(self.data)
        data[offset] ^= 0x01
        return bytes(data)

    def test_counterfactual_hasher_call_displacement(self):
        offset = file_offset(self.data, 0x47444eb + 1)
        with self.assertRaises(ValueError):
            analyze(self._mutated(offset))

    def test_counterfactual_caller_b_lsda_pad_offset(self):
        # The covering entry's pad offset is the two-byte uleb128
        # 0x81 0x04 starting ten bytes into caller B's LSDA blob.
        offset = file_offset(self.data, CALLER_B_LSDA_VA + 10)
        with self.assertRaises(ValueError):
            analyze(self._mutated(offset))

    def test_counterfactual_personality_addend(self):
        from sibling_hasher_panic_static import _sections
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

    def test_counterfactual_absorb_body_byte(self):
        offset = file_offset(self.data, ABSORB)
        with self.assertRaises(ValueError):
            analyze(self._mutated(offset))

    def test_counterfactual_hasher_body_byte(self):
        offset = file_offset(self.data, HASHER)
        with self.assertRaises(ValueError):
            analyze(self._mutated(offset))

    def test_generate_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            generate(TARGET, Path(tmp))
            recorded = json.loads((Path(tmp) / 'records.json')
                                  .read_text())
            self.assertEqual(recorded, self.report)
            for name in ('frames.txt',
                         'hasher_objdump.txt',
                         'absorb_objdump.txt',
                         'sibling_hasher_call_fresh_objdump.txt',
                         'sibling_hasher_call_inplace_objdump.txt',
                         'caller_a_call_first_objdump.txt',
                         'caller_a_call_second_objdump.txt',
                         'caller_a_pad_first_objdump.txt',
                         'caller_a_pad_second_objdump.txt',
                         'caller_b_call_objdump.txt',
                         'caller_b_pad_objdump.txt',
                         'caller_c_call_objdump.txt',
                         'caller_c_pad_objdump.txt'):
                self.assertTrue((Path(tmp) / name).exists(), name)

    def test_committed_records_match(self):
        packet = (Path(__file__).resolve().parents[1] / 'research' /
                  'work-items' / 'RE-015-node115-sibling-hasher-panic' /
                  'records.json')
        recorded = json.loads(packet.read_text())
        self.assertEqual(recorded, self.report)


if __name__ == '__main__':
    unittest.main()
