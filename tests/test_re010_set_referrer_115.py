"""Offline, target-grounded positive and corruption controls for RE-010."""

from contextlib import contextmanager
import csv
import datetime
import hashlib
import io
import json
import struct
import unittest

from tools import re010_set_referrer_115 as evidence


def rows(payload):
    return list(csv.DictReader(io.StringIO(payload.decode('utf-8')), delimiter='\t'))


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # The input is mandatory; an unavailable target fails the suite.
        cls.data = bytearray(evidence.BINARY.read_bytes())
        cls.image = evidence.Image(cls.data)
        cls.values, _ = evidence.read_constants(cls.image)
        cls.output = evidence.collect(cls.data)
        cls.relocations, _ = evidence.checked_relocations(cls.image)

    @classmethod
    @contextmanager
    def patch_offset(cls, offset, new):
        old = bytes(cls.data[offset:offset + len(new)])
        cls.data[offset:offset + len(new)] = new
        try:
            yield
        finally:
            cls.data[offset:offset + len(new)] = old

    @classmethod
    @contextmanager
    def patch_va(cls, va, new, executable=False):
        with cls.patch_offset(cls.image.offset(va, len(new), executable), new):
            yield

    def test_input_digest_is_exact(self):
        evidence.authenticate(self.data)
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), evidence.TARGET_SHA256)

    def test_wrong_expected_hash_fails(self):
        with self.assertRaises(ValueError):
            evidence.authenticate(self.data, '0' * 64)

    def test_corrupt_input_hash_fails(self):
        with self.patch_offset(0, b'\x00'):
            with self.assertRaises(ValueError):
                evidence.authenticate(self.data)

    def test_all_selected_fde_bodies_are_recorded(self):
        fdes = rows(self.output['functions.tsv'])
        self.assertEqual(len(fdes), 15)
        self.assertEqual(len({row['start_va'] for row in fdes}), len(fdes))
        for row in fdes:
            raw = bytes.fromhex(row['body_hex'])
            self.assertEqual(len(raw), int(row['size']))
            self.assertEqual(hashlib.sha256(raw).hexdigest(), row['sha256'])
            self.assertEqual(int(row['end_va_exclusive'], 16) - int(row['start_va'], 16), len(raw))

    def test_selected_core_corruption_is_rejected_even_without_digest_check(self):
        va = 0x3c17eec
        original = self.image.read(va, 1, True)[0]
        with self.patch_va(va, bytes([original ^ 1]), True):
            with self.assertRaisesRegex(ValueError, 'changed selected FDE bytes'):
                evidence.selected_frames(self.image)

    def test_context_pattern_corruption_rejected(self):
        va, encoded = evidence.CONTEXT_PATTERNS[0]
        pattern = bytes.fromhex(encoded)
        with self.patch_va(va, bytes([pattern[0] ^ 1]), True):
            with self.assertRaises(ValueError):
                self.image.expect(va, pattern)

    def test_nobits_cannot_resolve_to_file_offset(self):
        sections = [{'type': 8, 'size': 16, 'address': 0x1000, 'offset': 0,
                     'flags': 3, 'name': '.bss'}]
        with self.assertRaises(ValueError):
            evidence.offset_for(sections, 64, 0x1000, 1)

    def test_ambiguous_file_backed_address_fails(self):
        sec = {'type': 1, 'size': 16, 'address': 0x1000, 'offset': 0,
               'flags': 6, 'name': '.text'}
        with self.assertRaises(ValueError):
            evidence.offset_for([sec, dict(sec)], 64, 0x1000, 1, True)

    def test_unmapped_and_negative_addresses_fail(self):
        for va, size in ((-1, 1), (0, 0), (1 << 64, 1), (0x3c17590, -1)):
            with self.subTest(va=va, size=size), self.assertRaises(ValueError):
                self.image.offset(va, size, True)

    def test_mapping_cannot_cross_file_section_end(self):
        sec = next(x for x in self.image.secs if x['name'] == '.text')
        end = sec['address'] + sec['size']
        with self.assertRaises(ValueError):
            self.image.offset(end - 1, 2, True)

    def test_code_region_has_distinct_file_offset(self):
        self.assertEqual(self.image.offset(0x3c17590, 1, True), 0x3c16590)

    def test_success_tag_and_switch_bias(self):
        self.assertEqual(self.values['decoder_success_tag'], 0xa0)
        self.assertEqual(self.values['switch_bias'], 0x86)
        self.assertEqual(self.values['decoder_success_tag'] - self.values['switch_bias'], 26)
        self.assertEqual(self.values['decoder_error_tag'], 0xe2)

    def test_decoder_switch_reads_selected_signed_entry(self):
        base = self.image.rip(0x36b8d23, '488d0d')
        slot, raw, target = self.image.table_entry(base, 26, 0x36b8c90, 0x36baeec)
        self.assertEqual((slot, raw.hex(), target), (0x79a414, '6f05f202', 0x36ba91b))

    def test_negative_table_index_fails(self):
        with self.assertRaises(ValueError):
            self.image.table_entry(0x79a3ac, -1, 0x36b8c90, 0x36baeec)

    def test_out_of_range_table_index_fails(self):
        with self.assertRaises(ValueError):
            self.image.table_entry(0x79a3ac, 1 << 62, 0x36b8c90, 0x36baeec)

    def test_corrupted_table_displacement_outside_fde_fails(self):
        with self.patch_va(0x79a414, b'\x00\x00\x00\x00'):
            with self.assertRaises(ValueError):
                self.image.table_entry(0x79a3ac, 26, 0x36b8c90, 0x36baeec)

    def test_literal_and_field_descriptor(self):
        literal = self.image.rip(0x36ba91b, '488d15')
        self.assertEqual(self.image.read(literal, self.values['decoder_type_name_length']), b'SetReferrerAction')
        self.assertEqual(self.relocations[0x648ae98]['addend'], 0x459e80)
        self.assertEqual(self.image.read(0x459e80, 4), b'code')
        self.assertEqual(self.image.rip(0x39ef816, '3b05'), 0x459e80)

    def test_outer_action_field_reaches_both_decoder_paths(self):
        literals = {row['role']: row['ascii'] for row in rows(self.output['literals.tsv'])}
        self.assertEqual([literals[x] for x in ('outer_multi_user', 'outer_signer', 'outer_action')],
                         ['multiSigUser', 'outerSigner', 'action'])
        self.assertEqual((self.values['outer_sequence_kind'], self.values['outer_map_kind']),
                         (0x14, 0x15))
        self.assertEqual(self.image.branch(0x3a1f45e)[2], 0x3a1f3b7)
        self.assertEqual(self.image.branch(0x3a1f4fe)[2], 0x3a1f630)
        self.assertEqual(self.image.direct_call(0x3a1f680), 0x36b8c90)
        self.assertEqual(self.image.direct_call(0x3a1fa9b), 0x3b92540)
        self.assertEqual(self.image.direct_call(0x3a1fd12), self.image.direct_call(0x3a1fdae))

    def test_outer_variant_layout_feeds_nested_action_pointer(self):
        switch = {row['role']: row for row in rows(self.output['switches.tsv'])}
        literals = {row['role']: row['ascii'] for row in rows(self.output['literals.tsv'])}
        self.assertEqual(self.values['outer_variant_success_tag'], 0xba)
        self.assertEqual((literals['outer_variant_type'], literals['outer_variant_payload']),
                         ('MultiSigAction', 'payload'))
        self.assertEqual(self.values['outer_variant_payload_field_index'], 2)
        self.assertEqual(self.image.branch(0x3a0212c)[2], 0x3a02280)
        self.assertEqual(self.image.direct_call(0x3a022d1), 0x3a1f060)
        self.assertEqual(int(switch['outer_variant_decoder']['index_decimal']), 52)
        self.assertEqual(switch['outer_variant_decoder']['arm_va'], '0x36baa77')
        self.assertEqual(switch['context_outer_direct_router']['arm_va'], '0x2bdb07a')
        self.assertEqual(self.image.direct_call(0x36baa98), 0x3a01c70)
        self.assertEqual(self.image.direct_call(0x3a029c7), 0x3a1f060)
        self.assertEqual(self.image.read(0x3a1fafd, 4, True), bytes.fromhex('49894500'))
        self.assertEqual(self.values['outer_variant_action_pointer_offset'], 0x18)
        self.assertEqual(self.values['nested_action_pointer_offset'], 0x18)
        self.assertEqual(self.image.direct_call(0x2bdb08a), 0x2c12690)
        self.assertEqual(self.image.direct_call(0x2c129f7), 0x2bdbaa0)

    def test_name_matcher_returns_ordinal_used_by_action_decoder(self):
        name = self.image.read(0x3661f4d, 8, True) + self.image.read(0x3661f5f, 3, True)
        self.assertEqual(name, b'setReferrer')
        self.assertEqual(self.values['matcher_name_ordinal'], 26)
        self.assertEqual(self.image.branch(0x3661f69)[2], 0x36626a9)
        self.assertEqual(self.image.read(0x36626a9, 4, True), bytes.fromhex('c640011a'))
        self.assertEqual(self.image.direct_call(0x3960c46), 0x3b68540)
        self.assertEqual(self.image.direct_call(0x3b68577), 0x36616b0)

    def test_earlier_same_length_names_do_not_shadow_selected_name(self):
        comparisons = rows(self.output['name-precedence.tsv'])
        self.assertEqual([row['derived_name'] for row in comparisons],
                         ['batchModify', 'createVault', 'setReferrer'])
        for row in comparisons:
            name = row['derived_name'].encode('ascii')
            head = bytes.fromhex(row['head_hex'])
            tail = bytes.fromhex(row['tail_hex'])
            self.assertEqual((head, tail), (name[:8], name[3:11]))
            condition, _, target = self.image.branch(int(row['branch_va'], 16))
            self.assertEqual(condition, 'je')
            self.assertEqual(target, int(row['branch_target'], 16))
        self.assertNotIn(comparisons[-1]['derived_name'],
                         [row['derived_name'] for row in comparisons[:-1]])
        self.assertEqual(int(comparisons[0]['tail_adjustment']), -2562)

    def test_name_matcher_rejects_each_single_byte_change_and_length_change(self):
        head = self.image.read(0x3661f4d, 8, True)
        tail = self.image.read(0x3661f5a, 8, True)
        name = b'setReferrer'
        self.assertTrue(evidence.selected_name_matches(name, head, tail))
        for i in range(len(name)):
            changed = name[:i] + bytes([name[i] ^ 1]) + name[i + 1:]
            self.assertFalse(evidence.selected_name_matches(changed, head, tail))
        for changed in (b'', name[:-1], name + b'X'):
            self.assertFalse(evidence.selected_name_matches(changed, head, tail))
        with self.assertRaises(ValueError):
            evidence.selected_name_matches(name, head, b'X' + tail[1:])

    def test_borrowed_and_owned_name_inputs_reach_matcher(self):
        base = self.image.rip(0x3b68559, '488d0d')
        self.assertEqual(self.image.table_entry(base, 11, 0x3b68540, 0x3b68655)[2], 0x3b685bf)
        self.assertEqual(self.image.table_entry(base, 12, 0x3b68540, 0x3b68655)[2], 0x3b6856f)
        self.assertEqual(self.image.direct_call(0x3b68577), 0x36616b0)
        self.assertEqual(self.image.direct_call(0x3b685ce), 0x36616b0)

    def test_name_matcher_literal_corruption_is_detected(self):
        va, encoded = next(x for x in evidence.CONTEXT_PATTERNS if x[0] == 0x3661f4b)
        expected = bytes.fromhex(encoded)
        with self.patch_va(0x3661f4d, b'X', True):
            with self.assertRaises(ValueError):
                self.image.expect(va, expected)

    def test_field_name_negative_controls(self):
        field = self.image.read(self.relocations[0x648ae98]['addend'], self.values['payload_code_length'])
        self.assertTrue(evidence.selected_field_matches(b'code', field))
        for value in (b'', b'cod', b'codE', b'Code', b'code\x00', b'codee'):
            self.assertFalse(evidence.selected_field_matches(value, field))

    def test_payload_kind_and_field_switch_are_bounded(self):
        self.assertEqual((self.values['payload_sequence_kind'], self.values['payload_map_kind']),
                         (0x14, 0x15))
        self.assertEqual(self.image.branch(0x39ef53d)[2], 0x39ef644)
        self.assertEqual(self.image.branch(0x39ef546)[2], 0x39efb3e)
        key_rows = rows(self.output['payload-key-kinds.tsv'])
        self.assertEqual([int(row['kind']) for row in key_rows], list(range(1, 16)))
        self.assertEqual(key_rows[11]['arm_va'], '0x39ef88c')
        self.assertEqual(key_rows[12]['arm_va'], '0x39ef80e')
        self.assertEqual(key_rows[0]['arm_va'], '0x39ef7db')
        self.assertEqual(key_rows[3]['arm_va'], '0x39ef86d')

    def test_corrupted_payload_key_switch_is_rejected(self):
        table = self.image.rip(0x39ef7cb, '488d0d')
        with self.patch_va(table + 12 * 4, b'\x00\x00\x00\x00'):
            with self.assertRaises(ValueError):
                self.image.table_entry(table, 12, 0x39ef520, 0x39efd0d)

    def test_payload_missing_and_duplicate_have_distinct_descriptors(self):
        literals = {row['role']: row['ascii'] for row in rows(self.output['literals.tsv'])}
        self.assertEqual(literals['payload_missing_prefix'], 'missing field `')
        self.assertEqual(literals['payload_duplicate_prefix'], 'duplicate field `')
        self.assertEqual(literals['payload_map_order_panic'],
                         'MapAccess::next_value called before next_key')
        self.assertEqual(self.image.branch(0x39ef5a0)[2], 0x39ef5b9)
        self.assertEqual(self.image.branch(0x39ef8f6)[2], 0x39efab4)
        self.assertEqual(self.image.branch(0x39ef90e)[2], 0x39efb14)
        self.assertEqual(self.image.direct_call(0x39ef5fa), self.image.direct_call(0x39efaf5))

    def test_payload_sequence_and_map_share_value_decoder(self):
        self.assertEqual(self.image.direct_call(0x39ef709), 0x3a9f2e0)
        self.assertEqual(self.image.direct_call(0x39ef93d), 0x3a9f2e0)
        self.assertEqual(self.image.branch(0x39ef68b)[2], 0x39ef69e)
        self.assertEqual(self.image.branch(0x39efa0b)[2], 0x39ef6c8)
        self.assertEqual(self.image.direct_call(0x39ef6ae), self.image.direct_call(0x39efa34))

    def test_direct_calls_have_expected_targets(self):
        for _, site, target in evidence.DIRECT_CALLS:
            with self.subTest(site=hex(site)):
                self.assertEqual(self.image.direct_call(site), target)

    def test_invalid_call_opcode_fails(self):
        site = 0x3c176c9
        with self.patch_va(site, b'\x90', True):
            with self.assertRaises(ValueError):
                self.image.direct_call(site)

    def test_two_context_wrappers_use_same_relative_slot(self):
        self.assertEqual(self.image.rip(0x23853f9, 'ff15'), 0x64e50b0)
        self.assertEqual(self.image.rip(0x2c1b715, 'ff15'), 0x64e50b0)
        self.assertEqual(self.relocations[0x64e50b0]['addend'], 0x3c17590)

    def test_wrong_rip_opcode_rejected(self):
        with self.assertRaises(ValueError):
            self.image.rip(0x23853f9, 'e800')

    def test_rela_addend_corruption_is_rejected(self):
        pos = self.relocations[0x64e50b0]['entry_offset'] + 16
        with self.patch_offset(pos, struct.pack('<q', 0x3c17591)):
            with self.assertRaisesRegex(ValueError, 'unexpected RELATIVE'):
                evidence.checked_relocations(self.image)

    def test_rela_type_corruption_is_rejected(self):
        pos = self.relocations[0x64e50b0]['entry_offset'] + 8
        with self.patch_offset(pos, struct.pack('<Q', 6)):
            with self.assertRaisesRegex(ValueError, 'unexpected RELATIVE'):
                evidence.checked_relocations(self.image)

    def test_dynamic_symbol_index_corruption_is_rejected(self):
        pos = self.relocations[0x64df508]['entry_offset'] + 8
        with self.patch_offset(pos, struct.pack('<Q', (0xffffffff << 32) | 6)):
            with self.assertRaises(ValueError):
                evidence.checked_relocations(self.image)

    def test_missing_relocation_is_rejected(self):
        with self.assertRaises(ValueError):
            evidence.collect_relocations(self.image, [0x64e50b1])

    def test_duplicate_requested_relocation_is_rejected(self):
        with self.assertRaises(ValueError):
            evidence.collect_relocations(self.image, [0x64e50b0, 0x64e50b0])

    def test_duplicate_stored_relocation_is_rejected(self):
        class FakeImage:
            secs = [{'name': '.rela.dyn', 'type': 4, 'offset': 0, 'size': 48}]
            data = struct.pack('<QQq', 0x1000, 8, 3) * 2
            def offset(self, va, size):
                return 0
        with self.assertRaisesRegex(ValueError, 'duplicate relocation slot'):
            evidence.collect_relocations(FakeImage(), [0x1000])

    def test_truncated_relocation_section_is_rejected(self):
        class FakeImage:
            secs = [{'name': '.rela.dyn', 'type': 4, 'offset': 0, 'size': 25}]
            data = bytes(25)
        with self.assertRaises(ValueError):
            evidence.collect_relocations(FakeImage(), [0x1000])

    def test_recorded_import_names(self):
        for slot, name in ((0x64df508, 'memcpy'), (0x64df568, 'memmove'), (0x64dfb50, 'memcmp')):
            self.assertEqual(evidence.dyn_name(self.image, self.relocations[slot]['symbol']), name)

    def test_short_and_near_branches_decode_signed_displacements(self):
        self.assertEqual(self.image.branch(0x3c17aad)[::2], ('je', 0x3c17a95))
        self.assertEqual(self.image.branch(0x3c17a06)[::2], ('je', 0x3c17f14))
        self.assertEqual(self.image.branch(0x36ba965)[::2], ('jmp', 0x36badae))

    def test_invalid_branch_opcode_is_rejected(self):
        site = 0x3c17a9d
        with self.patch_va(site, b'\x90', True):
            with self.assertRaises(ValueError):
                self.image.branch(site)

    def test_wrapper_length_boundary(self):
        cutoff = self.values['wrapper_reject_length_at_least']
        self.assertEqual(cutoff, 101)
        self.assertEqual(cutoff, self.values['direct_wrapper_reject_length_at_least'])
        self.assertFalse(100 >= cutoff)
        self.assertTrue(101 >= cutoff)
        self.assertEqual(self.values['wrapper_length_error'], 0x158)
        self.assertEqual((self.values['wrapper_success_tag'], self.values['wrapper_error_tag']), (0x0e, 0x0f))
        self.assertEqual(self.values['direct_identity_error'], 0x120)

    def test_code_miss_precedes_all_later_conditions(self):
        result = evidence.normal_transition(self.values, code_found=False, same_key=True,
                                            already=True, profile_found=False, width=0)
        self.assertEqual(result[:3], (0xa6, False, False))

    def test_equal_key_precedes_binding_entry(self):
        result = evidence.normal_transition(self.values, same_key=True, already=True)
        self.assertEqual(result[:3], (0xa2, False, False))

    def test_existing_binding_precedes_missing_profile(self):
        result = evidence.normal_transition(self.values, already=True, profile_found=False)
        self.assertEqual(result[:3], (0xa3, True, False))

    def test_missing_profile_returns_success_without_final_binding_write(self):
        result = evidence.normal_transition(self.values, profile_found=False)
        self.assertEqual(result[:3], (0x1a2, True, False))

    def test_zero_width_and_exhausted_existing_bucket_fail(self):
        for case in ({'width': 0}, {'remaining': 0}):
            with self.subTest(case=case):
                self.assertEqual(evidence.normal_transition(self.values, **case)[:3], (0xa5, True, False))

    def test_current_bucket_count_one_decrements_to_zero(self):
        self.assertEqual(evidence.normal_transition(self.values, remaining=1), (0x1a2, True, True, 0, 0))

    def test_new_bucket_resets_to_floor_before_decrement(self):
        for configured in (0, 999, 1000):
            with self.subTest(configured=configured):
                self.assertEqual(evidence.normal_transition(self.values, bucket=1, remaining=0, configured=configured),
                                 (0x1a2, True, True, 1, 999))

    def test_new_bucket_uses_config_above_floor(self):
        self.assertEqual(evidence.normal_transition(self.values, bucket=1, configured=1001)[-1], 1000)
        self.assertEqual(evidence.normal_transition(self.values, bucket=1, configured=(1 << 64) - 1)[-1], (1 << 64) - 2)

    def test_model_rejects_non_u64_and_non_boolean_inputs(self):
        for kwargs in ({'remaining': -1}, {'bucket': 1 << 64}, {'width': True}, {'same_key': 1}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                evidence.normal_transition(self.values, **kwargs)

    def test_packed_day_formula_against_proleptic_gregorian(self):
        # This uses an independent integer formula, including negative years.
        years = (-262144, -10000, -801, -800, -401, -400, -399, -398,
                 -2, -1, 0, 1, 4, 100, 400, 1900, 1969, 1970, 2000,
                 2100, 9999, 262143)
        for year in years:
            for ordinal in (0, 1, 60, 365, 366, 511):
                with self.subTest(year=year, ordinal=ordinal):
                    encoded = ((year << 13) | (ordinal << 4) | 15) & 0xffffffff
                    y = year - 1
                    expected = 365 * y + y // 4 - y // 100 + y // 400 + ordinal - 719163
                    self.assertEqual(evidence.packed_day_number(self.values, encoded), expected)

    def test_packed_millis_against_calendar_at_leap_and_epoch_boundaries(self):
        epoch = datetime.date(1970, 1, 1)
        dates = (datetime.date(1, 1, 1), datetime.date(1900, 3, 1),
                 datetime.date(1969, 12, 31), epoch, datetime.date(1972, 2, 29),
                 datetime.date(2000, 2, 29), datetime.date(2024, 3, 1),
                 datetime.date(2100, 3, 1), datetime.date(9999, 12, 31))
        for date in dates:
            ordinal = date.timetuple().tm_yday
            for seconds, nanos in ((0, 0), (1, 999999), (86399, 999999999)):
                encoded = (date.year << 13) | (ordinal << 4)
                expected = max(0, ((date - epoch).days * 86400 + seconds) * 1000 + nanos // 1000000)
                with self.subTest(date=date, seconds=seconds, nanos=nanos):
                    self.assertEqual(evidence.packed_millis(self.values, encoded, seconds, nanos), expected)

    def test_nanos_magic_at_every_u32_quotient_boundary(self):
        # Both ends of each interval have the same quotient. The multiply and
        # shift are monotone, so these endpoints cover the intervening inputs.
        magic = self.values['nanos_to_millis_magic']
        shift = self.values['nanos_to_millis_shift']
        limit = (1 << 32) - 1
        for quotient in range(limit // 1000000 + 1):
            for nanos in (quotient * 1000000, min(limit, (quotient + 1) * 1000000 - 1)):
                self.assertEqual((nanos * magic) >> shift, nanos // 1000000)

    def test_packed_date_low_flags_do_not_change_selected_calculation(self):
        encoded = (2000 << 13) | (60 << 4)
        expected = evidence.packed_millis(self.values, encoded, 0, 0)
        for flags in range(16):
            self.assertEqual(evidence.packed_millis(self.values, encoded | flags, 0, 0), expected)

    def test_bucket_division_width_and_u32_boundary(self):
        encoded = (1970 << 13) | (1 << 4)
        # The second field is intentionally an arbitrary u32; this checks the
        # arithmetic boundary and does not claim a valid civil time.
        self.assertEqual(evidence.bucket_from_time(self.values, encoded, 4294967, 0, 1000),
                         (4294967, 'u32'))
        self.assertEqual(evidence.bucket_from_time(self.values, encoded, 4294968, 0, 1000),
                         (4294968, 'u64'))
        self.assertEqual(evidence.bucket_from_time(self.values, encoded, 1, 0, 1 << 32),
                         (0, 'u64'))

    def test_time_model_rejects_invalid_ranges(self):
        for args in ((-1, 0, 0), (1 << 32, 0, 0), (0, -1, 0), (0, 0, 1 << 32)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                evidence.packed_millis(self.values, *args)
        for width in (0, -1, 1 << 64, True):
            with self.subTest(width=width), self.assertRaises(ValueError):
                evidence.bucket_from_time(self.values, 0, 0, 0, width)

    def test_state_representation_thresholds(self):
        self.assertEqual(self.values['tree_to_compact_below'], 32)
        self.assertEqual(self.values['compact_to_tree_at_least'], 64)
        self.assertEqual(1 << self.values['history_record_shift'], 32)
        self.assertEqual(self.values['history_tree_alloc_bytes'], 0x170)
        self.assertEqual(self.values['history_tree_node_limit'], 11)
        self.assertEqual(self.values['compared_key_bytes'], 20)
        self.assertEqual(self.values['binding_flag_offset'], 0xc4)
        self.assertEqual(self.values['binding_owner_offset'], 0xc5)

    def test_status_cleanup_table_a5_is_direct_return(self):
        switch = next(row for row in rows(self.output['switches.tsv'])
                      if row['role'] == 'temporary_status_cleanup')
        self.assertEqual((switch['index_decimal'], switch['arm_va']), ('104', '0x3d08faa'))
        self.assertEqual(self.image.read(int(switch['arm_va'], 16), 6, True), bytes.fromhex('5b415e415fc3'))

    def test_summary_counts_match_outputs(self):
        summary = json.loads(self.output['summary.json'])
        for field, filename in (('selected_windows', 'windows.tsv'),
                                ('selected_branches', 'branches.tsv'),
                                ('selected_relocations', 'relocations.tsv'),
                                ('selected_switch_entries', 'switches.tsv'),
                                ('selected_literals', 'literals.tsv'),
                                ('selected_name_comparisons', 'name-precedence.tsv'),
                                ('payload_key_switch_entries', 'payload-key-kinds.tsv')):
            with self.subTest(field=field):
                self.assertEqual(summary[field], len(rows(self.output[filename])))

    def test_no_selected_new_fde_is_a_context_router_or_gate(self):
        selected = {int(row['start_va'], 16) for row in rows(self.output['functions.tsv'])}
        self.assertFalse(selected.intersection({0x2bda7c0, 0x2bdbaa0, 0x55f99b0,
                                                0x55faa80, 0x54a2f90, 0x54a3a00,
                                                0x2c202b0, 0x2c206b0, 0x3ee6280,
                                                0x4717c50}))


if __name__ == '__main__':
    unittest.main()
