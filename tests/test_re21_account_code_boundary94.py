"""Offline controls for the node 94 account/code preparation evidence."""
import json
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import elf_index
import re21_account_code_boundary94 as target


class AccountCodeBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = target.TARGET.read_bytes()
        cls.secs = elf_index.sections(cls.data)
        cls.files = target.collect(cls.data)
        cls.summary = json.loads(cls.files['summary.json'])
        cls.expected_hash = bytes.fromhex(cls.summary['empty_code_hash'])

    def test_artifact_digest_and_corruption(self):
        target.verify_digest(self.data)
        damaged = bytearray(self.data)
        damaged[0] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            target.verify_digest(damaged)

    def test_retained_outputs_match_generation(self):
        directory = ROOT / 'research/work-items/RE-021-account-code-boundary-94'
        self.assertEqual(len(self.files), 18)
        for name, expected in self.files.items():
            with self.subTest(name=name):
                self.assertEqual((directory / name).read_bytes(), expected)

    def test_unique_file_mappings_reject_nobits_and_bad_ranges(self):
        with self.assertRaises(ValueError):
            target.offset_for(self.secs, 0x5788348, 1)
        with self.assertRaises(ValueError):
            target.offset_for(self.secs, 0xffffffffffffffff, 8)
        with self.assertRaises(ValueError):
            target.offset_for(self.secs, 0x4e6f360, 0)
        text = next(s for s in self.secs if s['name'] == '.text')
        with self.assertRaises(ValueError):
            target.offset_for(self.secs, text['address'] + text['size'] - 1, 2, True)
        with self.assertRaises(ValueError):
            target.offset_for(self.secs + [dict(text)], 0x4e6f360, 1, True)
        with self.assertRaises(ValueError):
            target.offset_for(self.secs, 0x206160, 1, True)

    def test_nobits_does_not_shadow_file_backed_section(self):
        good = {'type': 1, 'flags': 2, 'address': 10, 'size': 8, 'offset': 30}
        nobits = {'type': 8, 'flags': 2, 'address': 10, 'size': 8, 'offset': 80}
        self.assertEqual(target.offset_for([good, nobits], 12, 1), 32)

    def test_byte_predicate_corruption_is_rejected(self):
        site, raw = 0x4e6fd79, bytes.fromhex('41833e04')
        self.assertEqual(target.checked_pin(self.data, self.secs, site, raw), raw)
        altered = bytearray(self.data)
        altered[target.offset_for(self.secs, site + 3, 1, True)] ^= 1
        with self.assertRaisesRegex(ValueError, 'predicate'):
            target.checked_pin(altered, self.secs, site, raw)

    def test_fde_selection_requires_unique_index_and_extent(self):
        fde = {'start': 16, 'end': 32, 'fde': 48}
        index = [{'start': 16, 'fde': 48}]
        self.assertEqual(target.selected_fdes([fde], index, {16: 32})[16], fde)
        for fdes, entries, bounds in [([], index, {16: 32}),
                                     ([fde, fde], index, {16: 32}),
                                     ([fde], index, {16: 33}),
                                     ([fde], [], {16: 32}),
                                     ([fde], [{'start': 16, 'fde': 49}], {16: 32}),
                                     ([fde], index + index, {16: 32})]:
            with self.subTest(fdes=fdes, entries=entries, bounds=bounds):
                with self.assertRaises(ValueError):
                    target.selected_fdes(fdes, entries, bounds)

    def test_decoder_direct_branch_and_rip_slot(self):
        near = target.decode_one(bytes.fromhex('e8c8fdffff'), 0)
        self.assertEqual(0x4e6ff83 + near['relative'], 0x4e6fd50)
        indirect = target.decode_one(bytes.fromhex('ff15084e9000'), 0)
        self.assertEqual(indirect['kind'], 'indirect-call')
        self.assertEqual(0x4e7001a + indirect['rip'], 0x5774e28)
        self.assertEqual(target.walk(bytes.fromhex('7501c3c3'))[0][1]['relative'], 3)

    def test_decoder_rejects_truncation_unknown_and_interior_target(self):
        for raw in (b'\xe8\x00', b'\x0f\x0f', bytes.fromhex('ebffc3'), b'\x66' * 16):
            with self.subTest(raw=raw.hex()):
                with self.assertRaises(ValueError):
                    target.walk(raw)

    def test_normal_return_requires_tag_store(self):
        proof = json.loads(self.files['normal-return-proof.json'])
        self.assertEqual(proof['return_vas'], ['0x4e6f5e7'])
        self.assertEqual(proof['store_va'], '0x4e6f5d3')
        tail = bytes.fromhex('c60305c3')
        target.prove_tagged_returns(tail, 0x1000, 0, tail)
        with self.assertRaisesRegex(ValueError, 'bypasses'):
            target.prove_tagged_returns(bytes.fromhex('7403c60305c3'), 0x1000, 2, tail)
        with self.assertRaisesRegex(ValueError, 'epilogue'):
            target.prove_tagged_returns(bytes.fromhex('c60304c3'), 0x1000, 0, tail)

    def test_target_branch_redirected_past_tag_store_is_rejected(self):
        base, end = 0x4e6f360, 0x4e6f68c
        raw = bytearray(target.read_va(self.data, self.secs, base, end - base, True))
        branch, ret = 0x4e6f3b2, 0x4e6f5e7
        self.assertEqual(raw[branch - base:branch - base + 2], bytes.fromhex('0f84'))
        struct.pack_into('<i', raw, branch - base + 2, ret - (branch + 6))
        tail = bytes.fromhex('c603054881c4980100005b415c415d415e415f5dc3')
        with self.assertRaisesRegex(ValueError, 'bypasses'):
            target.prove_tagged_returns(raw, base, 0x273, tail)

    def test_relative_relocation_type_and_addend_controls(self):
        relocs = {100: {'info': 8, 'addend': 200}}
        self.assertEqual(target.relative_relocation(relocs, 100, 200)['addend'], 200)
        for rows, slot, add in (({}, 100, 200), ({100: {'info': 6, 'addend': 200}}, 100, 200),
                                (relocs, 100, 201), (relocs, 101, 200)):
            with self.subTest(rows=rows, slot=slot, add=add):
                with self.assertRaises(ValueError):
                    target.relative_relocation(rows, slot, add)

    def test_cleanup_jump_table_and_corrupt_valid_target(self):
        bounds = {0x4e6ed17, 0x4e6ed34, 0x4e6ed6b, 0x4e6ed85}
        rows = target.cleanup_table(self.data, self.secs, bounds)
        self.assertEqual([row[-1] for row in rows], ['0x4e6ed17', '0x4e6ed34', '0x4e6ed6b', '0x4e6ed17'])
        changed = bytearray(self.data)
        off = target.offset_for(self.secs, 0x7c353c, 4)
        struct.pack_into('<i', changed, off, 0x4e6ed85 - 0x7c353c)
        with self.assertRaisesRegex(ValueError, 'destination'):
            target.cleanup_table(changed, self.secs, bounds)

    def test_lsda_header_and_landing_corruption(self):
        fde = {'start': 0x4e6fd50, 'end': 0x4e6fee2, 'lsda': 0xbbff40}
        decoded = target.parse_lsda(self.data, self.secs, fde)
        self.assertEqual(len(decoded['entries']), 5)
        self.assertEqual(decoded['entries'][1]['landing'], 0x4e6feb3)
        changed = bytearray(self.data)
        changed[target.offset_for(self.secs, fde['lsda'], 1)] = 0
        with self.assertRaisesRegex(ValueError, 'LPStart'):
            target.parse_lsda(changed, self.secs, fde)
        changed = bytearray(self.data)
        call_table = target.offset_for(self.secs, fde['lsda'], 1) + len(bytes.fromhex(decoded['header']))
        second = call_table + len(bytes.fromhex(decoded['entries'][0]['raw']))
        changed[second + 2:second + 4] = bytes.fromhex('ff7f')
        with self.assertRaisesRegex(ValueError, 'landing'):
            target.parse_lsda(changed, self.secs, fde)
        truncated_fde = dict(fde, end=0x4e6fd60)
        with self.assertRaises(ValueError):
            target.parse_lsda(self.data, self.secs, truncated_fde)

    def test_code_decision_equal_and_all_single_bit_hash_changes(self):
        expected = self.expected_hash
        self.assertEqual(target.code_decision(5, 4, expected, expected), 'default-equal-hash')
        for bit in range(256):
            changed = bytearray(expected)
            changed[bit // 8] ^= 1 << (bit % 8)
            self.assertEqual(target.code_decision(5, 4, changed, expected), 'default-other-hash', bit)

    def test_both_hash_branches_call_the_same_constructor(self):
        branch = target.read_va(self.data, self.secs, 0x4e6fdac, 6, True)
        jump = target.decode_one(branch, 0)
        self.assertEqual(jump['kind'], 'jcc')
        self.assertEqual(0x4e6fdac + jump['relative'], 0x4e6fe39)
        for site in (0x4e6fdb7, 0x4e6fe3c):
            raw = target.read_va(self.data, self.secs, site, 5, True)
            ins = target.decode_one(raw, 0)
            self.assertEqual(ins['kind'], 'call')
            self.assertEqual(site + ins['relative'], 0x4e6c8b0)

    def test_code_padding_instructions_cover_thirty_three_zero_bytes(self):
        expected = bytes.fromhex('0f57c0430f11043c430f11443c1043c6443c2000')
        actual = target.read_va(self.data, self.secs, 0x4e6cb58, len(expected), True)
        self.assertEqual(actual, expected)
        self.assertEqual([r[1]['size'] for r in target.walk(actual)], [3, 5, 6, 6])

    def test_prior_object_and_same_key_boundary(self):
        anchor = json.loads(self.files['prior-object.json'])
        self.assertEqual(bytes.fromhex(anchor['key_bytes']), bytes(19) + b'\x09')
        self.assertEqual(anchor['relocation_addend'], '0x4e9d2a0')
        rows = self.files['prior-boundaries.tsv'].decode('ascii').splitlines()
        self.assertTrue(any(line.startswith('0x4e6ff7e\t488d542420\t') for line in rows))
        self.assertTrue(any(line.startswith('0x4e7005b\t498d7660\t') for line in rows))
        self.assertTrue(any(line.startswith('0x4e70927\tff1503459000\t') for line in rows))

    def test_default_code_byte_and_empty_control_template(self):
        self.assertEqual(self.summary['default_code_byte_va'], '0x1e629b')
        self.assertEqual(self.summary['default_code_byte'], '00')
        self.assertEqual(self.summary['empty_controls_bytes'], 'ff' * 16)
        relocs = target.get_relocations(self.data, self.secs)
        target.relative_relocation(relocs, 0x574fbc0, 0x202e90)
        changed = dict(relocs)
        changed[0x574fbc0] = dict(changed[0x574fbc0], addend=0x202e91)
        with self.assertRaises(ValueError):
            target.relative_relocation(changed, 0x574fbc0, 0x202e90)

    def test_code_decision_tag_precedence_and_widths(self):
        expected = self.expected_hash
        self.assertEqual(target.code_decision(0, 4, expected, expected), 'forward-result')
        self.assertEqual(target.code_decision(5, 3, expected, expected), 'retain-code')
        self.assertEqual(target.code_decision(5, 0x104, expected, expected), 'retain-code')
        for args in ((256, 4, expected, expected), (5, -1, expected, expected), (5, 4, b'', expected)):
            with self.subTest(args=args[:2]):
                with self.assertRaises(ValueError):
                    target.code_decision(*args)

    def test_account_hit_miss_and_journal_failure_order(self):
        self.assertEqual(target.account_decision(True, 0, False, 0, 0, 0),
                         ['return-tag5-byte0'])
        self.assertEqual(target.account_decision(True, 0x10, False, 0, 0, 0),
                         ['clear-flag-0x10', 'missing-frame-boundary'])
        self.assertEqual(target.account_decision(False, 0, True, 0, 0, 0),
                         ['insert-account', 'return-tag5-byte0'])
        self.assertEqual(target.account_decision(False, 0, False, 0, 0, 0),
                         ['insert-account', 'missing-frame-boundary'])
        self.assertEqual(target.account_decision(True, 0x10, True, 1, 2, 2),
                         ['clear-flag-0x10', 'reserve-journal', 'append-tag0-and-key',
                          'increment-journal-length', 'return-tag5-byte1'])
        self.assertEqual(target.account_decision(False, 0, False, 1, 3, 2),
                         ['insert-account', 'append-tag0-and-key',
                          'increment-journal-length', 'return-tag5-byte1'])
        with self.assertRaises(ValueError):
            target.account_decision(True, 256, False, 0, 0, 0)

    def test_vector_growth_boundaries_and_wrapping(self):
        for old, expected in ((0, 4), (1, 4), (2, 4), (3, 6), (4, 8), (11, 22),
                              (1 << 63, 4), ((1 << 63) + 3, 6)):
            self.assertEqual(target.vector_growth(old), expected)
        for bad in (-1, 1 << 64):
            with self.assertRaises(ValueError):
                target.vector_growth(bad)

    def test_allocation_limits_for_journal_entry_and_frame(self):
        for stride in (24, 88):
            with self.subTest(stride=stride):
                maximum = ((1 << 63) - 8) // stride
                self.assertEqual(target.checked_allocation(maximum, stride, 8), maximum * stride)
                self.assertIsNone(target.checked_allocation(maximum + 1, stride, 8))
                self.assertIsNone(target.checked_allocation((1 << 64) - 1, stride, 8))
        self.assertEqual(target.checked_allocation(4, 88, 8), 352)
        self.assertEqual(target.checked_allocation(4, 24, 8), 96)
        with self.assertRaises(ValueError):
            target.checked_allocation(1, 8, 3)
        with self.assertRaises(ValueError):
            target.checked_allocation(1, (1 << 64) - 1, 8)

    def test_fallback_padding_size_boundaries(self):
        for length, expected in ((0, 33), (1, 34), ((1 << 63) - 34, (1 << 63) - 1),
                                 ((1 << 63) - 33, 'signed-size-failure'),
                                 ((1 << 64) - 34, 'signed-size-failure'),
                                 ((1 << 64) - 33, 'unsigned-overflow')):
            with self.subTest(length=length):
                self.assertEqual(target.fallback_padding(length), expected)
        for length in (-1, 1 << 64):
            with self.assertRaises(ValueError):
                target.fallback_padding(length)

    def test_clone_counter_inc_jle_overflow_and_wrap(self):
        cases = ((0, 1, False), ((1 << 63) - 2, (1 << 63) - 1, False),
                 ((1 << 63) - 1, 1 << 63, False),
                 (1 << 63, (1 << 63) + 1, True),
                 ((1 << 64) - 1, 0, True))
        for before, after, taken in cases:
            with self.subTest(before=before):
                self.assertEqual(target.increment_jle(before), (after, taken))
        with self.assertRaises(ValueError):
            target.increment_jle(1 << 64)

    def test_other_two_jump_tables_are_tag_bounded(self):
        clone = target.relative_table(self.data, self.secs,
                                      {0x4e7369e, 0x4e73744, 0x4e736c4, 0x4e736e6},
                                      0x7c358c,
                                      (0x4e7369e, 0x4e73744, 0x4e736c4, 0x4e736e6))
        self.assertEqual(len(clone), 4)
        fallback = target.relative_table(self.data, self.secs,
                                         {0x4e8fbfe, 0x4e8fa61, 0x4e8fa67},
                                         0x7c47c8,
                                         (0x4e8fbfe, 0x4e8fa61, 0x4e8fa67, 0x4e8fa61))
        self.assertEqual([r[-1] for r in fallback], ['0x4e8fbfe', '0x4e8fa61', '0x4e8fa67', '0x4e8fa61'])

    def test_summary_has_bounded_denominators(self):
        self.assertEqual(self.summary['selected_fde_count'], 16)
        self.assertEqual(self.summary['selected_body_bytes'], 4787)
        self.assertEqual(self.summary['cleanup_table_count'], 4)
        self.assertFalse(self.summary['captured_execution'])
        self.assertFalse(self.summary['component_gate_requested'])
        self.assertEqual(self.summary['prior_boundary_count'], 28)


if __name__ == '__main__':
    unittest.main()
