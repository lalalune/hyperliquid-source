# SPDX-License-Identifier: MIT
"""Target-grounded and corruption controls for the builder approval packet."""
import csv
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import node115_builder_approval as research


class PatchedImage:
    def __init__(self, underlying, patches):
        self.underlying = underlying
        self.patches = patches

    def read(self, va, size, executable=False):
        if (va, size) in self.patches:
            return self.patches[(va, size)]
        return self.underlying.read(va, size, executable)


class BuilderApprovalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = research.TARGET.read_bytes()
        cls.secs = research.sections(cls.data)
        cls.image = research.Image(cls.data, cls.secs)
        cls.temp = tempfile.TemporaryDirectory()
        cls.temp_path = Path(cls.temp.name)
        cls.summary = research.generate(cls.data, cls.temp_path)
        cls.c = cls.summary['constants']

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def rows(self, name):
        with (self.temp_path / name).open(newline='', encoding='utf-8') as f:
            return list(csv.DictReader(f, delimiter='\t'))

    def test_target_digest(self):
        self.assertEqual(research.digest(self.data),
                         'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301')
        research.verify_target(self.data)

    def test_one_changed_target_byte_fails_digest(self):
        changed = bytearray(self.data)
        changed[0x1000] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            research.verify_target(changed)

    def test_reproducible_packet_matches_committed_files(self):
        saved = ROOT / 'research/work-items/RE-010-builder-approval-115'
        for generated in sorted(self.temp_path.iterdir()):
            with self.subTest(file=generated.name):
                self.assertEqual(generated.read_bytes(), (saved / generated.name).read_bytes())

    def test_summary_selected_counts_and_no_execution(self):
        self.assertEqual(self.summary['selected_fdes'], 18)
        self.assertEqual(self.summary['selected_windows'], 70)
        self.assertEqual(self.summary['selected_direct_calls'], 32)
        self.assertEqual(self.summary['selected_direct_jumps'], 8)
        self.assertEqual(self.summary['selected_indirect_calls'], 10)
        self.assertEqual(self.summary['selected_branches'], 67)
        self.assertEqual(self.summary['status_mappings'], 7)
        self.assertEqual(self.summary['selected_imports'], 5)
        self.assertTrue(self.summary['action_names_are_formatter_associations'])

    def test_reviewed_window_rejects_changed_byte(self):
        name, start, end, expected = next(w for w in research.WINDOWS if w[0] == 'dispatch_selector')
        raw = self.image.read(start, end - start, True)
        research.assert_window(raw, expected)
        self.assertEqual(name, 'dispatch_selector')
        for offset in (0, len(raw) // 2, len(raw) - 1):
            changed = bytearray(raw)
            changed[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                research.assert_window(changed, expected)

    def test_non_file_backed_mapping_is_excluded(self):
        secs = [dict(type=8, flags=4, size=16, address=100, offset=0),
                dict(type=1, flags=4, size=16, address=100, offset=50)]
        self.assertEqual(research.file_offset(secs, 104, 4, True), 54)
        with self.assertRaises(ValueError):
            research.file_offset(secs[:1], 104, 4)

    def test_out_of_range_and_crossing_section_rejected(self):
        secs = [dict(type=1, flags=4, size=16, address=100, offset=50)]
        for va, size in ((99, 1), (116, 1), (115, 2), (-1, 1), (1 << 64, 1)):
            with self.subTest(va=va, size=size), self.assertRaises(ValueError):
                research.file_offset(secs, va, size)

    def test_ambiguous_mapping_rejected(self):
        one = dict(type=1, flags=4, size=16, address=100, offset=50)
        two = dict(type=1, flags=4, size=8, address=104, offset=80)
        with self.assertRaises(ValueError):
            research.file_offset([one, two], 105, 1)

    def test_non_executable_mapping_rejected_for_code(self):
        sec = dict(type=1, flags=2, size=16, address=100, offset=50)
        with self.assertRaises(ValueError):
            research.file_offset([sec], 101, 1, True)

    def test_switch_headers_match_target(self):
        for va, table in ((0x54a3a6d, 0x92688c), (0x2bd0ef7, 0x6098bc)):
            raw = self.image.read(va, 31, True)
            with self.subTest(site=va):
                self.assertEqual(research.decode_switch_header(raw, va), (0x86, 20, table))

    def test_switch_header_corruption_rejected(self):
        raw = self.image.read(0x54a3a6d, 31, True)
        for index in (0, 6, 11, 15, 22, 30):
            changed = bytearray(raw)
            changed[index] ^= 1
            with self.subTest(index=index), self.assertRaises(ValueError):
                research.decode_switch_header(changed, 0x54a3a6d)
        with self.assertRaises(ValueError):
            research.decode_switch_header(raw[:-1], 0x54a3a6d)

    def test_action_dispatch_targets_and_names(self):
        rows = {r['role']: r for r in self.rows('dispatch.tsv')}
        self.assertEqual((rows['user']['derived_tag'], rows['user']['dispatcher_arm_va'],
                          rows['user']['call_target_va'], rows['user']['wire_name']),
                         ('0xbc', '0x54a4276', '0x5533140', 'approveBuilderFee'))
        self.assertEqual((rows['system']['derived_tag'], rows['system']['dispatcher_arm_va'],
                          rows['system']['call_target_va'], rows['system']['type_name']),
                         ('0xcc', '0x54a3b07', '0x5520ca0', 'SystemApproveBuilderFee'))

    def test_decoder_stages_both_dispatch_tags_in_box(self):
        decode = {r['role']: r for r in self.rows('decoder.tsv')}
        dispatch = {r['role']: r for r in self.rows('dispatch.tsv')}
        for role, name in (('user', 'ApproveBuilderFeeAction'),
                           ('system', 'SystemApproveBuilderFeeAction')):
            with self.subTest(role=role):
                self.assertEqual(decode[role]['type_name'], name)
                self.assertEqual(decode[role]['decoded_tag'], dispatch[role]['derived_tag'])
                self.assertEqual(decode[role]['staging_offset'], '0x1d8')
                self.assertEqual(decode[role]['box_allocation_size'], '240')
                self.assertEqual(decode[role]['box_copy_size'], '240')
                self.assertEqual(decode[role]['result_marker'], '9')

    def test_corrupted_decoder_table_entry_is_rejected(self):
        original = research.Image.read
        def altered(image, va, size, executable=False):
            if va == 0x607270 and size == 4:
                return b'\x00' * 4
            return original(image, va, size, executable)
        with tempfile.TemporaryDirectory() as temp, patch.object(research.Image, 'read', altered):
            with self.assertRaisesRegex(ValueError, 'decoder arm'):
                research.generate(self.data, Path(temp))

    def test_corrupted_decoded_tag_is_rejected(self):
        original = research.Image.read
        def altered(image, va, size, executable=False):
            result = original(image, va, size, executable)
            if va == 0x2b86556 and size == 6:
                return result[:2] + struct.pack('<I', 0xbd)
            return result
        with tempfile.TemporaryDirectory() as temp, patch.object(research.Image, 'read', altered):
            with self.assertRaisesRegex(ValueError, 'decoded tag'):
                research.generate(self.data, Path(temp))

    def test_decoder_success_and_failure_jumps_are_distinct(self):
        rows = {r['role']: r for r in self.rows('calls.tsv')}
        self.assertEqual(rows['decoder_user_to_common']['target_va'], '0x2b86d0c')
        self.assertEqual(rows['decoder_system_to_box']['target_va'], '0x2b86d6b')
        self.assertEqual(rows['decoder_system_error']['target_va'], '0x2b86d3b')
        self.assertEqual(rows['decoder_user_error']['target_va'], '0x2b86d0f')
        self.assertEqual(rows['dispatch_user_join']['target_va'], '0x54a43aa')
        self.assertEqual(rows['dispatch_system_join']['target_va'], '0x54a43aa')

    def test_decoder_failure_branches_are_separate_from_box_return(self):
        rows = {r['role']: r for r in self.rows('branches.tsv')}
        self.assertEqual((rows['decoder_user_payload_failure']['condition'],
                          rows['decoder_user_payload_failure']['taken_va']), ('jo', '0x2b86979'))
        self.assertEqual((rows['decoder_system_payload_success']['condition'],
                          rows['decoder_system_payload_success']['taken_va']), ('je', '0x2b86701'))
        self.assertEqual(rows['decoder_box_allocation_failure']['taken_va'], '0x2b86e8b')

    def test_selected_container_preserves_box_and_two_keys(self):
        rows = {r['component']: r['observed_value'] for r in self.rows('container.tsv')}
        self.assertEqual(rows['sequence_kind'], '0x14')
        self.assertEqual(rows['field_count'], '0x3')
        self.assertEqual(rows['decoder_result_marker'], '0x9')
        self.assertEqual(rows['decoder_pointer_source'], '0x8')
        self.assertEqual(rows['output_pointer_store'], '0x0')
        self.assertEqual((rows['first_key_start'], rows['first_key_tail']), ('0x8', '0x18'))
        self.assertEqual((rows['second_key_start'], rows['second_key_tail']), ('0x1c', '0x2c'))

    def test_container_decoder_failure_bypasses_pointer_store(self):
        rows = {r['role']: r for r in self.rows('branches.tsv')}
        self.assertEqual(rows['container_action_decode_error']['condition'], 'jne')
        self.assertEqual(rows['container_action_decode_error']['taken_va'], '0x20bd879')
        self.assertEqual(rows['container_three_field_success']['taken_va'], '0x20bd7bc')

    def test_caller_direct_and_flagged_paths(self):
        self.assertEqual(research.caller_model(self.c, 0xf, 1, 10),
                         ('direct', 10, None, None))
        self.assertEqual(research.caller_model(self.c, 0xf, 0, 10),
                         ('flagged', 11, 1, 0))
        self.assertEqual(research.caller_model(self.c, 0xf, 0, (1 << 64) - 1),
                         ('flagged', (1 << 64) - 1, 1, 0))
        self.assertEqual(research.caller_model(self.c, 0xe, 0, 10),
                         ('propagate', 10, None, None))
        self.assertEqual(research.caller_model(self.c, 0x10, 0, 10),
                         ('special_or_error_unresolved', 10, None, None))

    def test_caller_model_rejects_out_of_width_inputs(self):
        for args in ((-1, 0, 0), (256, 0, 0), (15, 256, 0), (15, 0, -1),
                     (15, 0, 1 << 64)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                research.caller_model(self.c, *args)

    def test_switch_index_boundaries(self):
        for index in (-1, 53, 71, 92, 1000):
            with self.subTest(index=index), self.assertRaises(ValueError):
                research.switch_entry(self.image, 0x92688c, index)
        self.assertEqual(research.switch_entry(self.image, 0x92688c, 54)[2], 0x54a4276)
        self.assertEqual(research.switch_entry(self.image, 0x92688c, 70)[2], 0x54a3b07)

    def test_status_codes_are_connected_to_node_text(self):
        rows = {r['role']: (r['status_word'], r['text']) for r in self.rows('statuses.tsv')}
        self.assertEqual(rows['balance_error'], ('0x138', 'Builder has insufficient balance to be approved.'))
        self.assertEqual(rows['percentage_error'], ('0x13b', 'Percentage is invalid.'))
        self.assertEqual(rows['number_error'], ('0x154', 'Invalid input number'))
        self.assertEqual(rows['length_error'], ('0x158', 'Invalid input length'))
        self.assertEqual(rows['missing_root_error'], ('0x156', 'Invalid perp DEX'))
        self.assertEqual(rows['count_error'][0], '0x13c')
        self.assertTrue(rows['count_error'][1].startswith('Too many builders approved.'))
        self.assertEqual(rows['identity_error'], ('0x120', 'Can only send reduce-only orders.'))

    def test_corrupted_status_switch_target_fails(self):
        table, code = 0x7d8c1c, 0x138
        slot = table + 4 * code
        image = PatchedImage(self.image, {(slot, 4): struct.pack('<i', 0)})
        with self.assertRaisesRegex(ValueError, 'outside formatter'):
            research.status_info(image, table, code, 0x46ef710, 0x46f312f)

    def test_corrupted_status_arm_opcode_fails(self):
        image = PatchedImage(self.image, {(0x46f0815, 11): b'\x90' * 11})
        with self.assertRaisesRegex(ValueError, 'formatter arm'):
            research.status_info(image, 0x7d8c1c, 0x138, 0x46ef710, 0x46f312f)

    def test_direct_call_offsets_both_directions(self):
        self.assertEqual(research.rel32_target(bytes.fromhex('e8b5ee0800'), 0x54a4286), 0x5533140)
        self.assertEqual(research.rel32_target(bytes.fromhex('e8dd969300'), 0x3c1a8ee), 0x4553fd0)
        self.assertEqual(research.rel32_target(b'\xe9\xfb\xff\xff\xff', 100), 100)

    def test_invalid_relative_instruction_fails(self):
        for raw in (b'', b'\xe8\x00', b'\x90\x00\x00\x00\x00'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                research.rel32_target(raw, 100)

    def test_indirect_call_and_wrong_opcode(self):
        raw = bytes.fromhex('ff150a3aef00')
        self.assertEqual(research.indirect_slot(raw, 0x55f4480), 0x64e7e90)
        with self.assertRaises(ValueError):
            research.indirect_slot(b'\x90' + raw[1:], 0x55f4480)
        with self.assertRaises(ValueError):
            research.indirect_slot(raw[:-1], 0x55f4480)

    def test_relative_relocation_is_type_symbol_and_target_checked(self):
        row = dict(type=8, symbol=0, addend=0x3c1a510)
        research.relative_relocation(row, 0x3c1a510)
        for changed in (dict(row, type=6), dict(row, symbol=1), dict(row, addend=1)):
            with self.subTest(row=changed), self.assertRaises(ValueError):
                research.relative_relocation(changed, 0x3c1a510)

    def test_missing_and_duplicate_relocations_fail(self):
        raw = struct.pack('<QQq', 0x1000, 8, 0x2000)
        section = dict(type=4, offset=0, size=24)
        self.assertEqual(research.read_relocations(raw, [section], {0x1000})[0x1000]['addend'], 0x2000)
        with self.assertRaises(ValueError):
            research.read_relocations(raw, [section], {0x1001})
        with self.assertRaises(ValueError):
            research.read_relocations(raw * 2, [dict(section, size=48)], {0x1000})
        with self.assertRaises(ValueError):
            research.read_relocations(raw, [dict(section, size=23)], {0x1000})

    def test_import_symbols_are_resolved(self):
        rows = {r['role']: r['symbol_name'] for r in self.rows('imports.tsv')}
        self.assertEqual(rows, {'tree_key_comparison': 'memcmp', 'ring_move': 'memmove',
                                'decoder_box_copy': 'memcpy', 'outer_default_copy': 'memcpy',
                                'outer_record_copy': 'memcpy'})
        self.assertEqual(research.dynamic_symbol_name(self.data, self.secs, 12), 'memcmp')

    def test_dynamic_symbol_rejects_bad_tables_and_index(self):
        with self.assertRaises(ValueError):
            research.dynamic_symbol_name(self.data, [], 0)
        for i in (-1, 1000000):
            with self.subTest(index=i), self.assertRaises(ValueError):
                research.dynamic_symbol_name(self.data, self.secs, i)

    def test_branch_decoding_and_negative_displacement(self):
        self.assertEqual(research.decode_branch(bytes.fromhex('7f07'), 0x55f4468),
                         ('jg', 0x55f4471, 2))
        self.assertEqual(research.decode_branch(bytes.fromhex('0f83fefdffff'), 0x421e4c7),
                         ('jae', 0x421e2cb, 6))
        for raw in (b'', b'\x0f\x84', b'\x90\x00'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                research.decode_branch(raw, 0)

    def test_index_fde_selection_and_disagreement(self):
        idx = [{'start': 100, 'fde': 500, 'index': 0}]
        fdes = [{'start': 100, 'end': 110, 'fde': 500}]
        self.assertEqual(research.select_fdes(idx, fdes, [('a', 100)])[0][2]['end'], 110)
        for table, frames in (([], fdes), (idx, []), (idx, fdes * 2),
                              (idx * 2, fdes), (idx, [dict(fdes[0], fde=501)]),
                              (idx, [dict(fdes[0], end=100)])):
            with self.subTest(table=table, frames=frames), self.assertRaises(ValueError):
                research.select_fdes(table, frames, [('a', 100)])

    def test_length_before_suffix(self):
        self.assertEqual(research.text_route(self.c, b''), (0x13b, 'suffix_error'))
        self.assertEqual(research.text_route(self.c, b'1'), (0x13b, 'suffix_error'))
        self.assertEqual(research.text_route(self.c, b'%'), (None, 'delegate_decimal'))
        self.assertEqual(research.text_route(self.c, b'x' * 99 + b'%'), (None, 'delegate_decimal'))
        self.assertEqual(research.text_route(self.c, b'x' * 100 + b'%'), (0x158, 'length_error'))

    def test_system_limit_is_exclusive(self):
        q = 0x0ccccccccccccccc
        a = (True, 100000000, 0, False)
        self.assertEqual(research.system_model(self.c, q - 1, *a)[:2], (0x1a2, 'insert'))
        self.assertEqual(research.system_model(self.c, q, *a)[:2], (0x154, 'number_error'))
        self.assertEqual(research.system_model(self.c, q + 1, *a)[:2], (0x154, 'number_error'))

    def test_zero_bypasses_root_balance_and_count(self):
        self.assertEqual(research.system_model(self.c, 0, False, -1, 11, True),
                         (0x1a2, 'remove', False))
        self.assertEqual(research.system_model(self.c, 0, False, -1, 0, False, False),
                         (0x1a2, 'remove_absent', True))

    def test_outer_row_insertion_on_selected_spare_capacity_path(self):
        rows = {r['case']: r for r in self.rows('system-vectors.tsv')}
        for case in ('zero_missing_row', 'new_row'):
            with self.subTest(case=case):
                self.assertEqual(rows[case]['outer_row_inserted_before_value_check'], '1')
        self.assertEqual(rows['zero_absent']['outer_row_inserted_before_value_check'], '0')
        self.assertEqual(self.c['outer_default_copy_bytes'], 0xe0)
        self.assertEqual(self.c['outer_record_copy_bytes'], 0x100)
        self.assertEqual(self.c['outer_record_stride'], 0x100)
        self.assertEqual(self.c['outer_vector_length_offset'], 0x10)

    def test_outer_row_growth_and_allocation_failure_branch(self):
        rows = {r['role']: r for r in self.rows('branches.tsv')}
        self.assertEqual(rows['row_entry_existing']['taken_va'], '0x4717d07')
        self.assertEqual(rows['outer_vector_growth']['taken_va'], '0x3ec8dfe')
        self.assertEqual(rows['outer_growth_retry']['taken_va'], '0x3ec8ec7')
        self.assertEqual(rows['outer_growth_failure']['taken_va'], '0x3ec8f46')
        self.assertEqual(self.image.read(0x3ec8f56, 2, True), b'\x0f\x0b')

    def test_outer_row_append_window_rejects_corrupted_increment(self):
        _, start, end, expected = next(w for w in research.WINDOWS if w[0] == 'outer_insert_append')
        raw = bytearray(self.image.read(start, end - start, True))
        raw[0x3ec8d51 - start] ^= 1
        with self.assertRaises(ValueError):
            research.assert_window(raw, expected)

    def test_missing_root_is_not_a_normal_error_return(self):
        self.assertEqual(research.system_model(self.c, 1, False, 100000000, 0, False),
                         (None, 'panic_missing_root', False))

    def test_signed_balance_threshold(self):
        for value in (-(1 << 63), -1, 0, 99999999):
            with self.subTest(value=value):
                self.assertEqual(research.system_model(self.c, 1, True, value, 0, False)[:2],
                                 (0x138, 'balance_error'))
        self.assertEqual(research.system_model(self.c, 1, True, 100000000, 0, False)[:2],
                         (0x1a2, 'insert'))

    def test_count_guard_precedes_existing_update(self):
        for present in (False, True):
            with self.subTest(present=present):
                self.assertEqual(research.system_model(self.c, 1, True, 100000000, 11, present)[:2],
                                 (0x13c, 'count_error'))
        self.assertEqual(research.system_model(self.c, 1, True, 100000000, 10, True)[:2],
                         (0x1a2, 'replace'))
        self.assertEqual(research.system_model(self.c, 1, True, 100000000, 10, False)[:2],
                         (0x1a2, 'insert'))

    def test_balance_failure_precedes_count_guard(self):
        self.assertEqual(research.system_model(self.c, 1, True, 99999999, 11, True)[:2],
                         (0x138, 'balance_error'))

    def test_early_preflight_precedes_numeric_check(self):
        args = (0x0ccccccccccccccc, False, 0, 0, False)
        self.assertEqual(research.system_model(self.c, *args, preflight='identity_equal')[:2],
                         (0x120, 'identity_error'))
        self.assertEqual(research.system_model(self.c, *args, preflight='gate_failure')[:2],
                         (None, 'preflight_error'))

    def test_user_and_system_numeric_thresholds_differ(self):
        q = 0x0ccccccccccccccc
        self.assertEqual(research.system_model(self.c, q, True, 100000000, 0, False)[0], 0x154)
        self.assertEqual(research.user_word_model(self.c, q, True, 100000000, 0, False)[0], 0x1a2)
        upper = 0x7fffffffffffffff
        self.assertEqual(research.user_word_model(self.c, upper - 1, True, 100000000, 0, False)[0], 0x1a2)
        self.assertEqual(research.user_word_model(self.c, upper, True, 100000000, 0, False)[0], 0x13b)

    def test_binary_container_thresholds_and_layout(self):
        self.assertEqual(self.c['tree_to_compact_below'], 32)
        self.assertEqual(self.c['compact_to_tree_at_least'], 64)
        self.assertEqual(self.c['row_map_offset'], 0x80)
        self.assertEqual(self.c['row_count_offset'], 0x98)
        self.assertEqual(self.c['compact_entry_stride'], 32)
        self.assertEqual(self.c['tree_key_bytes'], 20)
        self.assertEqual(self.c['node_size'], 0x140)
        self.assertEqual(self.c['node_entry_bound'], 11)
        self.assertGreater(self.c['compact_to_tree_at_least'], self.c['count_limit'])

    def test_model_rejects_invalid_width_and_inconsistent_row(self):
        for quantity in (-1, 1 << 64):
            with self.subTest(quantity=quantity), self.assertRaises(ValueError):
                research.system_model(self.c, quantity, True, 0, 0, False)
        with self.assertRaises(ValueError):
            research.system_model(self.c, 1, True, 0, 2, True, False)
        with self.assertRaises(ValueError):
            research.user_word_model(self.c, 1, True, 1 << 63, 0, False)
        with self.assertRaises(ValueError):
            research.system_model(self.c, 1, True, 100000000, 0, True)
        with self.assertRaises(ValueError):
            research.system_model(self.c, 1, True, 100000000, 1 << 64, False)

    def test_generated_json_contains_no_source_path(self):
        raw = (self.temp_path / 'summary.json').read_text(encoding='utf-8')
        self.assertNotIn(str(ROOT), raw)
        self.assertEqual(json.loads(raw)['selected_fdes'], len(research.FUNCTIONS))


if __name__ == '__main__':
    unittest.main()
