# SPDX-License-Identifier: MIT
"""Target-backed extraction controls and bounded synthetic branch tests."""
import csv
import io
import itertools
import json
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import re010_fee_trial_115 as subject


def rows(blob):
    return list(csv.DictReader(io.StringIO(blob.decode('utf-8')), delimiter='\t'))


class ArtifactEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # A missing artifact is a failure: the target is required for this suite.
        cls.image = subject.Image(subject.BINARY.read_bytes())
        cls.output = subject.build(cls.image)
        cls.summary = json.loads(cls.output['summary.json'])

    def test_target_identity_and_input(self):
        self.assertEqual(self.summary['binary_sha256'], subject.DIGEST)
        self.assertTrue(subject.BINARY.is_file())
        self.assertEqual(self.image.read(0x2bd8013, 5, True).hex(), 'b8bd000000')

    def test_wrong_expected_digest_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            subject.verify_digest(self.image.data, '0' * 64)

    def test_mutated_target_digest_is_rejected(self):
        changed = bytearray(self.image.data)
        changed[subject.file_offset(self.image.secs, 0x3c18556, 1, True)] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            subject.verify_digest(changed)

    def test_selected_fde_identity_and_size(self):
        fdes = {r['role']: r for r in rows(self.output['functions.tsv'])}
        self.assertEqual(len(fdes), 17)
        self.assertEqual((fdes['action_decoder']['start_va'], fdes['action_decoder']['end_va_exclusive']),
                         ('0x2bd6140', '0x2bd8476'))
        self.assertEqual((fdes['payload_decoder']['start_va'], fdes['payload_decoder']['end_va_exclusive']),
                         ('0x2117d20', '0x21198c2'))
        self.assertEqual((fdes['state_core']['start_va'], fdes['state_core']['end_va_exclusive']),
                         ('0x3c18390', '0x3c18a7e'))
        self.assertTrue(all(len(f['body_sha256']) == 64 for f in fdes.values()))

    def test_existing_context_is_not_selected_as_a_function(self):
        selected = {r['start_va'] for r in rows(self.output['functions.tsv'])}
        self.assertFalse({'0x18edd30', '0x2bda7c0', '0x2bdbaa0', '0x2385530', '0x27048a0'} & selected)
        self.assertEqual(self.summary['contextual_functions_enrolled_as_selected'], 0)

    def test_embedded_action_and_record_sizes(self):
        imm = {r['name']: int(r['value']) for r in rows(self.output['immediates.tsv'])}
        self.assertEqual(imm['context_delayed_record_copy_size'], 0x148)
        self.assertEqual(imm['delayed_vector_record_stride'], 0x148)
        self.assertEqual(imm['queue_record_stride'], 0x148)
        self.assertEqual(imm['context_engine_record_stride'], 0x148)
        self.assertEqual(imm['context_consumer_record_stride'], 0x148)
        self.assertEqual(imm['context_consumer_action_offset'], 0x10)
        self.assertEqual(imm['context_consumer_action_size'], 0xf0)

    def test_delayed_descriptor_is_a_relocation(self):
        desc = {r['name']: r for r in rows(self.output['descriptors.tsv'])}['context_delayed_type']
        self.assertEqual(desc['literal_ascii'], 'struct DelayedAction with 6 elements')
        self.assertEqual(int(desc['length']), 36)
        self.assertEqual(int(desc['literal_va'], 16), 0x5c9a83)
        self.assertEqual(self.image.relative_relocation(int(desc['descriptor_va'], 16))[0], 0x5c9a83)

    def test_action_switch_and_context_switch_bind_one_tag(self):
        self.assertEqual((self.summary['ordinal'], self.summary['internal_tag'], self.summary['execute_bias']),
                         (55, '0xbd', '0x86'))
        table = {r['name']: r for r in rows(self.output['tables.tsv']) if r['name'].startswith(('action_', 'context_'))}
        self.assertEqual(table['action_selected']['target_va'], '0x2bd7fa7')
        self.assertEqual(table['context_outer_selected']['target_va'], '0x2bdb060')
        self.assertEqual(table['context_execute_selected']['target_va'], '0x2bdc804')
        self.assertEqual(table['context_format_selected']['target_va'], '0x2bcb75e')

    def test_action_decoder_calls_separate_payload_fde(self):
        calls = {r['name']: r for r in rows(self.output['calls.tsv'])}
        self.assertEqual(calls['action_to_payload']['target_va'], '0x2117d20')
        self.assertEqual(calls['context_delayed_map_action_decoder']['target_va'], '0x2bd6140')
        self.assertEqual(calls['context_delayed_sequence_action_decoder']['target_va'], '0x2bd6140')
        self.assertEqual(calls['delayed_vector_item']['target_va'], '0x18edd30')

    def test_action_delayer_field_to_nested_vector_decoder(self):
        desc = {r['name']: r for r in rows(self.output['descriptors.tsv'])}
        self.assertEqual(desc['action_delayer_type']['literal_ascii'], 'struct ActionDelayer with 6 elements')
        calls = {r['name']: r for r in rows(self.output['calls.tsv'])}
        self.assertEqual(calls['delayer_field_to_map']['target_va'], '0x18f38a0')
        self.assertEqual(calls['map_value_to_buckets']['target_va'], '0x27ba880')
        self.assertEqual(calls['bucket_vector_to_bucket']['target_va'], '0x1b447c0')
        self.assertEqual(calls['bucket_to_delayed_vector']['target_va'], '0x2684690')
        tables = {r['name']: r for r in rows(self.output['tables.tsv'])}
        self.assertEqual((tables['delayer_delayed_actions_field']['index'],
                          tables['delayer_delayed_actions_field']['target_va']), ('0', '0x1bdd460'))
        branch = {r['name']: r for r in rows(self.output['branches.tsv'])}['delayer_field_duplicate']
        self.assertEqual(branch['target_va'], '0x1bdf195')

    def test_queue_extractor_reaches_prior_consumer_through_adapter(self):
        calls = {r['name']: r for r in rows(self.output['calls.tsv'])}
        self.assertEqual((calls['context_engine_to_queue']['slot_va'],
                          calls['context_engine_to_queue']['target_va']), ('0x64e4f00', '0x3bed8a0'))
        self.assertEqual(calls['context_engine_to_adapter']['target_va'], '0x231bf90')
        self.assertEqual(calls['adapter_to_prior_consumer']['target_va'], '0x27048a0')
        self.assertEqual(calls['queue_collect_vector']['target_va'], '0x3d6c090')

    def test_queue_empty_and_allocation_branches_are_distinct(self):
        branches = {r['name']: r for r in rows(self.output['branches.tsv'])}
        self.assertEqual(branches['queue_output_empty']['target_va'], '0x3bee2ca')
        self.assertEqual(branches['queue_allocation_failure']['target_va'], '0x3bee308')
        self.assertEqual(branches['adapter_allocation_failure']['target_va'], '0x231c07e')
        self.assertNotEqual(branches['queue_output_empty']['target_va'],
                            branches['queue_allocation_failure']['target_va'])

    def test_context_slot_points_to_state_core(self):
        calls = {r['name']: r for r in rows(self.output['calls.tsv'])}
        edge = calls['context_wrapper_to_core']
        self.assertEqual((edge['scope'], edge['slot_va'], edge['target_va']),
                         ('context', '0x64e50b8', '0x3c18390'))
        self.assertEqual(calls['core_to_converter']['target_va'], '0x36a5540')
        imm = {r['name']: int(r['value']) for r in rows(self.output['immediates.tsv'])}
        self.assertEqual(imm['context_wrapper_failure_word'], 0x91)
        self.assertEqual(imm['context_wrapper_identity_failure_word'], 0xea)

    def test_imports_bind_comparator_and_record_copy(self):
        entries = {r['name']: r for r in rows(self.output['imports.tsv'])}
        self.assertEqual(entries['field_key_comparator']['symbol_name'], 'bcmp')
        self.assertEqual(entries['context_consumer_copy_first']['symbol_name'], 'memcpy')
        self.assertEqual(entries['context_consumer_copy_first']['slot_va'],
                         entries['context_consumer_copy_loop']['slot_va'])

    def test_wrong_dynamic_import_type_is_rejected(self):
        slot = 0x64df9f8
        info, addend, off = self.image.relocations[slot]
        with patch.dict(self.image.relocations, {slot: (info + 1, addend, off)}):
            with self.assertRaisesRegex(ValueError, 'GLOB_DAT'):
                self.image.dynamic_import(slot)

    def test_context_state_copy_is_contiguous(self):
        copies = rows(self.output['state-copy.tsv'])
        self.assertEqual(len(copies), 8)
        self.assertEqual([int(r['stack_offset'], 16) for r in copies], [0x848 + i * 16 for i in range(8)])
        self.assertEqual([int(r['output_offset'], 16) for r in copies], [0x25a0 + i * 16 for i in range(8)])
        self.assertEqual([int(r['width']) for r in copies], [16] * 7 + [8])

    def test_field_names_and_input_offsets(self):
        fields = rows(self.output['fields.tsv'])
        self.assertEqual([r['literal_ascii'] for r in fields],
                         ['perpAddBaseRate', 'perpCrossBaseRate', 'spotAddBaseRate', 'spotCrossBaseRate'])
        routes = rows(self.output['field-routes.tsv'])
        self.assertEqual([int(r['output_offset'], 16) for r in routes], [0, 24, 48, 72])
        self.assertEqual([r['value_callee_va'] for r in routes], ['0x2121af0'] * 4)

    def test_per_field_duplicate_and_missing_names_match(self):
        routes = rows(self.output['field-routes.tsv'])
        self.assertEqual([r['duplicate_target_va'] for r in routes],
                         ['0x21191f4', '0x211930a', '0x2119378', '0x2119260'])
        for r in routes:
            name = r['field_name'].encode('ascii')
            self.assertEqual(self.image.read(int(r['duplicate_name_va'], 16), len(name)), name)
            self.assertEqual(self.image.read(int(r['missing_name_va'], 16), len(name)), name)

    def test_converter_reorders_fields(self):
        lanes = rows(self.output['lane-map.tsv'])
        self.assertEqual([int(r['field_index']) for r in lanes], [1, 0, 3, 2])
        self.assertEqual([int(r['length_disp'], 16) for r in lanes], [0x28, 0x10, 0x58, 0x40])
        self.assertEqual([int(r['output_disp'], 16) for r in lanes], [8, 16, 24, 32])

    def test_state_record_stores_have_matching_layouts(self):
        stores = rows(self.output['stores.tsv'])
        linked = [(r['record_offset'], r['width'], r['immediate']) for r in stores if r['path'] == 'linked']
        primary = [(r['record_offset'], r['width'], r['immediate']) for r in stores if r['path'] == 'primary']
        self.assertEqual(linked, primary)
        self.assertEqual(len(linked), 11)
        self.assertEqual(linked[0], ('0x0', '8', '1'))
        self.assertIn(('0x70', '4', ''), linked)
        self.assertIn(('0x78', '8', ''), linked)

    def test_linked_and_primary_store_sources_match(self):
        flow = rows(self.output['write-dataflow.tsv'])
        linked = [(r['stack_offset'], r['record_offset'], r['store_width']) for r in flow if r['path'] == 'linked']
        primary = [(r['stack_offset'], r['record_offset'], r['store_width']) for r in flow if r['path'] == 'primary']
        self.assertEqual(linked, primary)
        self.assertEqual(linked, [('0x120', '0x8', '16'), ('0x110', '0x18', '16'),
                                  ('0x8', '0x28', '8'), ('0x40', '0x30', '8'),
                                  ('0x30', '0x38', '16'), ('0x20', '0x48', '8'),
                                  ('0x60', '0x50', '16'), ('0x50', '0x60', '16'),
                                  ('0x14', '0x70', '4'), ('0x18', '0x78', '8')])

    def test_ordered_float_comparisons_have_unordered_controls(self):
        branches = {r['name']: r for r in rows(self.output['branches.tsv'])}
        for lane in (0, 1, 2, 3):
            b = branches['core_template_lane%d_unordered' % lane]
            self.assertEqual(b['kind'], 'jcc_a')
            self.assertEqual(b['target_va'], '0x3c18540')
        for lane in (1, 3):
            self.assertEqual(branches['core_override_lane%d_unordered' % lane]['kind'], 'jcc_a')

    def test_packed_date_helper_is_the_shared_relocated_callee(self):
        calls = {r['name']: r for r in rows(self.output['calls.tsv'])}
        self.assertEqual(calls['core_date_14']['target_va'], '0x16290d0')
        self.assertEqual(calls['date_adapter_checked_add']['target_va'], '0x16290d0')
        functions = {r['role']: r for r in rows(self.output['functions.tsv'])}
        self.assertEqual(functions['packed_date_add_helper']['end_va_exclusive'], '0x16292fc')
        imm = {r['name']: int(r['value']) for r in rows(self.output['immediates.tsv'])}
        self.assertEqual((imm['date_fast_ordinal_mask'], imm['date_fast_base_year_limit'],
                          imm['date_fast_preserved_bits']), (0x1ff, 366, 0xffffe00f))

    def test_cooldown_branch_is_strict_signed_greater(self):
        b = {r['name']: r for r in rows(self.output['branches.tsv'])}['core_cooldown_strict']
        self.assertEqual((b['raw_hex'][:4], b['kind'], b['target_va']), ('0f8f', 'jcc_f', '0x3c18623'))

    def test_panic_literal_is_exact(self):
        values = {r['name']: r for r in rows(self.output['literals.tsv'])}
        self.assertEqual(values['date_overflow_message']['ascii_or_float'], '`NaiveDate + TimeDelta` overflowed')
        self.assertEqual(values['floating_one']['ascii_or_float'], '1.0')
        self.assertEqual(values['context_wire_name']['ascii_or_float'], 'startFeeTrial')
        self.assertEqual(values['context_state_delayer_field']['ascii_or_float'], 'action_delayer')

    def test_selected_tables_have_only_observed_entry_counts(self):
        table = rows(self.output['tables.tsv'])
        self.assertEqual(sum(r['name'] == 'payload_key_kind' for r in table), 15)
        self.assertEqual(sum(r['name'] == 'payload_field' for r in table), 4)
        self.assertEqual(sum(r['name'] == 'string_input_kind' for r in table), 4)
        self.assertEqual(len(table), self.summary['table_entries'])

    def test_wrong_relocation_type_is_rejected(self):
        slot = 0x64e50b8
        info, addend, off = self.image.relocations[slot]
        with patch.dict(self.image.relocations, {slot: (info + 1, addend, off)}):
            with self.assertRaisesRegex(ValueError, 'RELATIVE'):
                self.image.relative_relocation(slot)

    def test_symbol_bearing_relocation_is_rejected(self):
        slot = 0x64e50b8
        _, addend, off = self.image.relocations[slot]
        with patch.dict(self.image.relocations, {slot: ((1 << 32) | 8, addend, off)}):
            with self.assertRaisesRegex(ValueError, 'RELATIVE'):
                self.image.relative_relocation(slot)

    def test_missing_relocation_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'missing'):
            self.image.relative_relocation(0)

    def test_changed_instruction_pattern_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'unexpected'):
            self.image.expect(0x2bd8013, bytes.fromhex('b9bd000000'))

    def test_changed_relative_call_does_not_resolve_to_expected_fde(self):
        va = 0x2bd7fc8
        raw = bytearray(self.image.read(va, 5, True))
        self.assertEqual(subject.rel_call(raw, va), 0x2117d20)
        raw[1] ^= 1
        self.assertNotEqual(subject.rel_call(raw, va), 0x2117d20)
        raw[0] = 0x90
        with self.assertRaises(ValueError):
            subject.rel_call(raw, va)

    def test_rip_opcode_and_displacement_controls(self):
        va = 0x2385647
        raw = bytearray(self.image.read(va, 6, True))
        self.assertEqual(subject.rip_target(raw, va, b'\xff\x15'), 0x64e50b8)
        raw[2] ^= 1
        self.assertNotEqual(subject.rip_target(raw, va, b'\xff\x15'), 0x64e50b8)
        raw[1] = 0x25
        with self.assertRaises(ValueError):
            subject.rip_target(raw, va, b'\xff\x15')

    def test_invalid_or_unmapped_target_range_is_rejected(self):
        for va, size in ((0, 1), (-1, 1), (1 << 64, 1), (0x3c18390, 0), (0x3c18390, -1)):
            with self.subTest(va=va, size=size):
                with self.assertRaises(ValueError):
                    self.image.read(va, size, True)

    def test_data_section_cannot_satisfy_executable_range(self):
        with self.assertRaises(ValueError):
            self.image.read(0x5edf98, 1, True)

    def test_output_has_only_declared_evidence_files(self):
        self.assertEqual(set(self.output), {'functions.tsv', 'bodies.tsv', 'windows.tsv', 'branches.tsv',
                         'calls.tsv', 'tables.tsv', 'fields.tsv', 'field-routes.tsv', 'descriptors.tsv',
                         'lane-map.tsv', 'stores.tsv', 'write-dataflow.tsv', 'state-copy.tsv', 'imports.tsv', 'immediates.tsv', 'literals.tsv', 'summary.json'})


class ByteDecoderControls(unittest.TestCase):
    def test_nobits_is_never_a_file_mapping(self):
        sec = {'type': 8, 'address': 0x1000, 'size': 0x100, 'offset': 0, 'flags': 4}
        with self.assertRaises(ValueError):
            subject.file_offset([sec], 0x1010, 1, True)

    def test_ambiguous_sections_are_rejected(self):
        sec = {'type': 1, 'address': 0x1000, 'size': 0x100, 'offset': 0, 'flags': 4}
        with self.assertRaises(ValueError):
            subject.file_offset([sec, dict(sec)], 0x1010, 1, True)

    def test_section_boundaries(self):
        sec = {'type': 1, 'address': 0x1000, 'size': 0x100, 'offset': 0x200, 'flags': 4}
        self.assertEqual(subject.file_offset([sec], 0x10ff, 1, True), 0x2ff)
        with self.assertRaises(ValueError):
            subject.file_offset([sec], 0x10ff, 2, True)
        with self.assertRaises(ValueError):
            subject.file_offset([sec], 0x1100, 1, True)

    def test_near_and_short_branches_use_signed_displacement(self):
        self.assertEqual(subject.branch(bytes.fromhex('75e8'), 0x100), ('jcc_5', 2, 0xea))
        self.assertEqual(subject.branch(bytes.fromhex('0f8f51ffffff'), 0x200), ('jcc_f', 6, 0x157))
        self.assertEqual(subject.branch(bytes.fromhex('ebfe'), 0x1234), ('jmp', 2, 0x1234))

    def test_invalid_branch_opcodes_and_truncation(self):
        for raw in (b'', b'\x75', b'\x0f\x84\x00', b'\x90\x00', b'\xe9\x00'):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    subject.branch(raw, 0x100)

    def test_tampered_conditional_branch_changes_condition_or_target(self):
        raw = bytes.fromhex('0f8f51ffffff')
        original = subject.branch(raw, 0x3c186cc)
        self.assertNotEqual(subject.branch(bytes.fromhex('0f8e51ffffff'), 0x3c186cc), original)
        self.assertNotEqual(subject.branch(bytes.fromhex('0f8f50ffffff'), 0x3c186cc), original)

    def test_record_store_patterns_are_fail_closed(self):
        self.assertEqual(subject.decoded_store(bytes.fromhex('48c70001000000')), (0, 8, 7, 1))
        self.assertEqual(subject.decoded_store(bytes.fromhex('0f114018000000')), (0x18, 16, 4, None))
        self.assertEqual(subject.decoded_store(bytes.fromhex('f20f1140780000')), (0x78, 8, 5, None))
        self.assertEqual(subject.decoded_store(bytes.fromhex('89487000000000')), (0x70, 4, 3, None))
        for raw in (bytes.fromhex('90909090909090'), bytes.fromhex('0f1140ff000000')):
            with self.assertRaises(ValueError):
                subject.decoded_store(raw)

    def test_state_copy_rejects_wrong_register_and_opcode(self):
        load = bytes.fromhex('0f10842448080000')
        store = bytes.fromhex('0f1183a0250000')
        self.assertEqual(subject.state_copy(load, store), (0x848, 0x25a0, 16))
        with self.assertRaises(ValueError):
            subject.state_copy(load, bytes.fromhex('0f118ba0250000'))
        with self.assertRaises(ValueError):
            subject.state_copy(bytes.fromhex('0f11842448080000'), store)

    def test_stack_source_decoder_rejects_mutations(self):
        self.assertEqual(subject.decoded_stack_load(bytes.fromhex('0f28842420010000')), (0x120, 16, 8))
        self.assertEqual(subject.decoded_stack_load(bytes.fromhex('8b4c241400000000')), (0x14, 4, 4))
        with self.assertRaises(ValueError):
            subject.decoded_stack_load(bytes.fromhex('0f29842420010000'))
        with self.assertRaises(ValueError):
            subject.decoded_stack_load(bytes.fromhex('0f28842420'))

    def test_table_read_rejects_out_of_range_and_uses_signed_entries(self):
        class Table:
            def read(self, va, size):
                if (va, size) != (0x1004, 4):
                    raise ValueError('bad read')
                return struct.pack('<i', -16)
        self.assertEqual(subject.table_entry(Table(), 0x1000, 1, 2)[:2], (0x1004, 0xff0))
        for index in (-1, 2, 100):
            with self.assertRaises(ValueError):
                subject.table_entry(Table(), 0x1000, index, 2)

    def test_i32_comparison_conversion_bounds(self):
        self.assertEqual(subject.signed32(0x7fffffff), 2147483647)
        self.assertEqual(subject.signed32(0x80000000), -2147483648)
        self.assertEqual(subject.signed32(0xffffffff), -1)
        for v in (-1, 1 << 32):
            with self.assertRaises(ValueError):
                subject.signed32(v)


class SyntheticTemplateControls(unittest.TestCase):
    def test_exact_template_uses_physical_lane_order(self):
        self.assertEqual(subject.supports_template((1.0, 2.0, 3.0, 4.0), [(2.0, 1.0, 4.0, 3.0)], []), 'exact')
        self.assertEqual(subject.supports_template((1.0, 2.0, 3.0, 4.0), [(1.0, 2.0, 3.0, 4.0)], []), 'reject')

    def test_override_needs_matching_cross_pair_and_equal_add_values(self):
        fields = (1.0, 2.0, 1.0, 4.0)
        self.assertEqual(subject.supports_template(fields, [(2.0, 9.0, 4.0, 9.0)], [1.0]), 'override')
        self.assertEqual(subject.supports_template(fields, [(2.0, 9.0, 5.0, 9.0)], [1.0]), 'reject')
        self.assertEqual(subject.supports_template((1.0, 2.0, 3.0, 4.0), [(2.0, 9.0, 4.0, 9.0)], [1.0]), 'reject')
        self.assertEqual(subject.supports_template(fields, [(2.0, 9.0, 4.0, 9.0)], []), 'reject')

    def test_reversed_interpretation_is_a_negative_control(self):
        fields = (1.0, 2.0, 3.0, 2.0)
        row = (9.0, 1.0, 9.0, 3.0)
        self.assertEqual(subject.supports_template(fields, [row], [2.0]), 'reject')

    def test_template_pairs_must_belong_to_one_row(self):
        fields = (1.0, 2.0, 3.0, 4.0)
        self.assertEqual(subject.supports_template(fields, [(2.0, 1.0, 9.0, 3.0), (9.0, 1.0, 4.0, 3.0)], []), 'reject')

    def test_earlier_pair_can_enable_later_override(self):
        fields = (1.0, 2.0, 1.0, 4.0)
        rows_ = [(2.0, 8.0, 4.0, 9.0), (7.0, 8.0, 9.0, 9.0)]
        self.assertEqual(subject.supports_template(fields, rows_, [1.0]), 'override')

    def test_nan_is_unordered_in_each_required_lane(self):
        for i in range(4):
            fields = [1.0, 2.0, 3.0, 4.0]
            fields[i] = float('nan')
            template = [fields[1], fields[0], fields[3], fields[2]]
            with self.subTest(i=i):
                self.assertEqual(subject.supports_template(fields, [template], [fields[0]]), 'reject')

    def test_signed_zero_compares_equal(self):
        self.assertEqual(subject.supports_template((0.0, -0.0, -0.0, 0.0), [(0.0, -0.0, -0.0, 0.0)], []), 'exact')

    def test_invalid_field_and_template_lengths_rejected(self):
        with self.assertRaises(ValueError):
            subject.supports_template([1], [], [])
        with self.assertRaises(ValueError):
            subject.supports_template([1, 2, 3, 4], [[1, 2]], [])

    def test_small_finite_domain_against_independent_boolean_predicate(self):
        values = (-1.0, 0.0, 1.0)
        for fields in itertools.product(values, repeat=4):
            for row in itertools.product(values, repeat=4):
                exact = row == (fields[1], fields[0], fields[3], fields[2])
                fallback = (row[0] == fields[1] and row[2] == fields[3]
                            and fields[0] == fields[2] and fields[0] == 0.0)
                expected = 'exact' if exact else ('override' if fallback else 'reject')
                self.assertEqual(subject.supports_template(fields, [row], [0.0]), expected)


class SyntheticDateFastPathControls(unittest.TestCase):
    @staticmethod
    def packed(year, ordinal, flag):
        return (year << 13) | (ordinal << 4) | flag

    def test_positive_same_year_offsets_and_preserved_bits(self):
        start = self.packed(2024, 1, 0)
        self.assertEqual(subject.date_fast_path(start, 14), self.packed(2024, 15, 0))
        self.assertEqual(subject.date_fast_path(start, 90), self.packed(2024, 91, 0))
        common = self.packed(2023, 275, 8)
        self.assertEqual(subject.date_fast_path(common, 90), self.packed(2023, 365, 8))
        self.assertIsNone(subject.date_fast_path(common, 91))

    def test_bit_three_changes_last_fast_ordinal(self):
        self.assertIsNotNone(subject.date_fast_path(self.packed(2024, 365, 0), 1))
        self.assertIsNone(subject.date_fast_path(self.packed(2023, 365, 8), 1))
        self.assertIsNone(subject.date_fast_path(self.packed(2024, 366, 0), 1))

    def test_negative_and_overflow_leave_fast_path(self):
        first = self.packed(2024, 1, 0)
        self.assertIsNone(subject.date_fast_path(first, -1))
        self.assertIsNone(subject.date_fast_path(first, 0x7fffffff))
        self.assertIsNone(subject.date_fast_path(first, -(1 << 31)))
        self.assertEqual(subject.date_fast_path(self.packed(2024, 2, 0), -1), first)

    def test_invalid_input_range_is_rejected(self):
        for packed, delta in ((-1, 0), (1 << 32, 0), (0, 1 << 31), (0, -(1 << 31) - 1)):
            with self.subTest(packed=packed, delta=delta), self.assertRaises(ValueError):
                subject.date_fast_path(packed, delta)


class SyntheticPrecedenceControls(unittest.TestCase):
    def gate(self, **kw):
        data = dict(flag=0, active=False, conversion_word=0x1a2, accepted=True,
                    prior_date=0, adjusted_90=0, now_date=10, adjusted_14=20, improves=True)
        data.update(kw)
        return subject.selected_precedence(**data)

    def test_active_and_flag_precede_conversion(self):
        self.assertEqual(self.gate(active=True, conversion_word=0x158), ('word', 0x149))
        self.assertEqual(self.gate(flag=1, active=True, conversion_word=0x158), ('word', 0x14d))
        self.assertEqual(self.gate(flag=3), ('word', 0x155))

    def test_conversion_precedes_template_and_dates(self):
        self.assertEqual(self.gate(conversion_word=0xaf, accepted=False, prior_date=1), ('word', 0xaf))
        self.assertEqual(self.gate(accepted=False, prior_date=1, adjusted_90=0), ('word', 0x14a))

    def test_cooldown_equality_and_strict_greater(self):
        self.assertEqual(self.gate(prior_date=1, adjusted_90=10, now_date=10), ('word', 0x1a2))
        self.assertEqual(self.gate(prior_date=1, adjusted_90=11, now_date=10), ('word', 0x14c))
        self.assertEqual(self.gate(prior_date=1, adjusted_90=9, now_date=10), ('word', 0x1a2))

    def test_cooldown_uses_signed_i32(self):
        self.assertEqual(self.gate(prior_date=1, adjusted_90=0x80000000, now_date=0x7fffffff), ('word', 0x1a2))
        self.assertEqual(self.gate(prior_date=1, adjusted_90=0x7fffffff, now_date=0x80000000), ('word', 0x14c))

    def test_calendar_zero_results_are_distinct_panics(self):
        self.assertEqual(self.gate(prior_date=1, adjusted_90=0), ('panic90', None))
        self.assertEqual(self.gate(prior_date=0, adjusted_14=0), ('panic14', None))
        self.assertEqual(self.gate(prior_date=1, adjusted_90=11, now_date=10, adjusted_14=0), ('word', 0x14c))

    def test_no_improvement_and_success(self):
        self.assertEqual(self.gate(improves=False), ('word', 0x14b))
        self.assertEqual(self.gate(improves=True), ('word', 0x1a2))

    def test_invalid_flag_is_rejected(self):
        for flag in (-1, 256):
            with self.assertRaises(ValueError):
                self.gate(flag=flag)

    def test_converter_length_boundary_for_each_field(self):
        ok = [0x1a2] * 4
        flags = [True] * 4
        self.assertEqual(subject.selected_conversion_path([100] * 4, ok, flags), ('success', None, 0x1a2))
        for field in range(4):
            lengths = [100] * 4
            lengths[field] = 101
            self.assertEqual(subject.selected_conversion_path(lengths, ok, flags), ('length', field, 0x158))

    def test_converter_failure_order_and_parser_propagation(self):
        ok = [0x1a2] * 4
        flags = [True] * 4
        self.assertEqual(subject.selected_conversion_path([101, 101, 101, 101], ok, flags), ('length', 1, 0x158))
        self.assertEqual(subject.selected_conversion_path([101, 0, 0, 0], [0x1a2, 7, 0x1a2, 0x1a2], flags), ('parser', 1, 7))
        self.assertEqual(subject.selected_conversion_path([0, 0, 0, 0], ok, [True, False, True, True]), ('float', 1, 0xaf))
        self.assertEqual(subject.selected_conversion_path([0, 0, 0, 0], ok, [True, True, False, True]), ('success', None, 0x1a2))

    def test_invalid_converter_lengths_rejected(self):
        for n in (-1, 1 << 64):
            with self.assertRaises(ValueError):
                subject.selected_conversion_path([0, n, 0, 0], [0x1a2] * 4, [True] * 4)


if __name__ == '__main__':
    unittest.main()
