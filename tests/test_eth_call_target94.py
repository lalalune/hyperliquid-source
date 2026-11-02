"""Static controls for the node #94 call-target evidence exporter."""
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'tools'))
import eth_call_target94 as subject


class Overlay:
    def __init__(self, image, changes):
        self.image, self.changes = image, changes

    def read(self, va, size):
        result = bytearray(self.image.read(va, size))
        for address, value in self.changes.items():
            if va <= address < va + size:
                result[address - va] = value
        return bytes(result)


class EvidenceControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.TARGET.read_bytes()
        subject.check_digest(cls.data)
        cls.secs = subject.sections(cls.data)
        cls.image = subject.Image(cls.data, cls.secs)
        cls.output = subject.collect(cls.data)
        cls.flow = json.loads(cls.output['flow.json'])
        cls.table = (subject.table_rows(cls.image, 'borrowed-lengths',
                                       subject.rip_target(cls.image, 0x21a0f41, '488d3d'), 19,
                                       (0x21a0f30, 0x21a10fe))
                     + subject.table_rows(cls.image, 'owned-lengths',
                                          subject.rip_target(cls.image, 0x21a111c, '488d0d'), 19,
                                          (0x21a1100, 0x21a135a))
                     + subject.table_rows(cls.image, 'object-fields',
                                          subject.rip_target(cls.image, 0x1bda5bb, '488d35'), 15,
                                          (0x1bda270, 0x1bdce65))
                     + subject.table_rows(cls.image, 'error-dispatch-prefix',
                                          subject.rip_target(cls.image, 0x4e5c72a, '488d0d'), 14,
                                          (0x4e5c710, 0x4e5d582))
                     + subject.table_rows(cls.image, 'rpc-error-prefix',
                                          subject.rip_target(cls.image, 0x24cc1b7, '488d15'), 8,
                                          (0x24cc0c0, 0x24cca98)))
        cls.relas = subject.relocations(cls.data, cls.secs)

    def test_authenticated_capture(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), subject.TARGET_SHA256)

    def test_wrong_length_rejected(self):
        with self.assertRaises(ValueError):
            subject.check_digest(self.data[:-1])

    def test_wrong_digest_rejected(self):
        corrupted = bytearray(self.data)
        corrupted[-1] ^= 1
        with self.assertRaises(ValueError):
            subject.check_digest(corrupted)

    def test_full_selected_body_hash_rejects_altered_byte(self):
        corrupted = bytearray(self.data)
        start, end, _ = subject.FUNCTIONS[0]
        corrupted[self.image.offset(end - 1, 1)] ^= 1
        with self.assertRaises(ValueError):
            subject.collect(corrupted, authenticate=False)

    def test_altered_selected_fde_extent_is_rejected(self):
        rows = list(csv.DictReader(io.StringIO(self.output['functions.tsv'].decode()), delimiter='\t'))
        fde = int(rows[0]['fde_va'], 16)
        corrupted = bytearray(self.data)
        corrupted[self.image.offset(fde + 12, 1)] ^= 1
        with self.assertRaises(ValueError):
            subject.collect(corrupted, authenticate=False)

    def test_each_semantic_window_rejects_boundary_and_middle_changes(self):
        for name, start, end, digest in subject.WINDOWS:
            raw = self.image.read(start, end - start)
            subject.window_ok(raw, digest)
            for pos in {0, len(raw) // 2, len(raw) - 1}:
                changed = bytearray(raw)
                changed[pos] ^= 1
                with self.subTest(window=name, position=pos), self.assertRaises(ValueError):
                    subject.window_ok(changed, digest)

    def test_target_range_has_unique_file_mapping(self):
        for start, end, _ in subject.FUNCTIONS:
            self.assertEqual(len(self.image.read(start, end - start)), end - start)

    def test_out_of_range_mapping_rejected(self):
        with self.assertRaises(ValueError):
            self.image.read((1 << 64) - 1, 2)

    def test_zero_length_mapping_rejected(self):
        with self.assertRaises(ValueError):
            self.image.read(subject.FUNCTIONS[0][0], 0)

    def test_nobits_section_is_not_file_backed(self):
        bss = next(s for s in self.secs if s['name'] == '.bss')
        self.assertEqual(bss['type'], 8)
        with self.assertRaises(ValueError):
            subject.va_offset([bss], bss['address'], 1)

    def test_ambiguous_mapping_rejected(self):
        row = {'name': 'a', 'type': 1, 'flags': 2, 'address': 0x1000, 'size': 4, 'offset': 0}
        with self.assertRaises(ValueError):
            subject.va_offset([row, dict(row)], 0x1000, 1)

    def test_cross_section_mapping_rejected(self):
        row = {'name': 'a', 'type': 1, 'flags': 2, 'address': 0x1000, 'size': 4, 'offset': 0}
        with self.assertRaises(ValueError):
            subject.va_offset([row], 0x1003, 2)

    def test_relative_edges_match_target(self):
        for va, kind, destination in subject.EDGES:
            row = subject.checked_edge(self.image.read(va, 6), va, kind, destination)
            self.assertEqual(row['target'], destination)

    def test_changed_relative_branch_destination_rejected(self):
        va, kind, destination = subject.EDGES[0]
        raw = bytearray(self.image.read(va, 6))
        raw[-1] ^= 1
        with self.assertRaises(ValueError):
            subject.checked_edge(raw, va, kind, destination)

    def test_unsupported_edge_rejected(self):
        with self.assertRaises(ValueError):
            subject.relative_edge(b'\x90\x90', 0x1000)

    def test_truncated_edge_rejected(self):
        with self.assertRaises(ValueError):
            subject.relative_edge(b'\xe8\x00', 0x1000)

    def test_wrong_edge_kind_rejected(self):
        va, _, destination = subject.EDGES[0]
        with self.assertRaises(ValueError):
            subject.checked_edge(self.image.read(va, 6), va, 'call', destination)

    def test_relative_table_contains_both_name_routes(self):
        self.assertEqual(self.table[0]['target'], 0x21a0f51)
        self.assertEqual(self.table[19]['target'], 0x21a112c)
        self.assertEqual(self.table[39]['target'], 0x1bda952)

    def test_out_of_bounds_relative_table_entry_rejected(self):
        changed = Overlay(self.image, {0x3b5d00: 0xff, 0x3b5d01: 0xff,
                                      0x3b5d02: 0xff, 0x3b5d03: 0x7f})
        with self.assertRaises(ValueError):
            subject.table_rows(changed, 'test', 0x3b5cfc, 15, (0x1bda270, 0x1bdce65))

    def test_selected_relative_relocations(self):
        for slot, (typ, addend) in subject.RELA_EXPECTED.items():
            row = next(r for r in self.relas if r['slot'] == slot)
            self.assertEqual(row['type'], typ)
            self.assertEqual(row['addend'], addend)
            subject.check_relative_rela(bytes.fromhex(row['raw']), slot, addend)

    def test_changed_relocation_type_rejected(self):
        row = next(r for r in self.relas if r['slot'] == 0x5691890)
        raw = bytearray.fromhex(row['raw'])
        raw[8] ^= 1
        with self.assertRaises(ValueError):
            subject.check_relative_rela(raw, row['slot'], row['addend'])

    def test_changed_relocation_addend_rejected(self):
        row = next(r for r in self.relas if r['slot'] == 0x5691890)
        raw = bytearray.fromhex(row['raw'])
        raw[16] ^= 1
        with self.assertRaises(ValueError):
            subject.check_relative_rela(raw, row['slot'], row['addend'])

    def test_changed_relocation_slot_rejected(self):
        row = next(r for r in self.relas if r['slot'] == 0x5691890)
        raw = bytearray.fromhex(row['raw'])
        raw[0] ^= 1
        with self.assertRaises(ValueError):
            subject.check_relative_rela(raw, row['slot'], row['addend'])

    def test_truncated_relocation_rejected(self):
        with self.assertRaises(ValueError):
            subject.check_relative_rela(bytes(23), 0x10, 0x20)

    def test_memcpy_dynamic_symbol_is_bound(self):
        record = next(r for r in self.relas if r['slot'] == 0x576dfe0)
        self.assertEqual(record['type'], 6)
        self.assertEqual(record['symbol'], 'memcpy')
        self.assertEqual(bytes.fromhex(record['name_bytes']), b'memcpy')
        self.assertEqual(len(bytes.fromhex(record['symbol_raw'])), 24)

    def test_field_discriminant_and_duplicate_label(self):
        field = self.flow['field']
        self.assertEqual(field['key_ascii'], 'to')
        self.assertEqual(field['field_discriminant'] - field['switch_bias'], field['switch_index'])
        self.assertEqual(self.image.read(int(field['duplicate_key_literal_va'], 16), 2), b'to')
        self.assertNotEqual(b'To', b'to')

    def test_altered_name_discriminant_rejected(self):
        value = self.image.read(0x21a0f5e, 1)[0]
        altered = Overlay(self.image, {0x21a0f5e: value ^ 1})
        with self.assertRaises(ValueError):
            subject.derive_flow(altered, self.table, self.relas)

    def test_altered_object_tail_copy_length_rejected(self):
        value = self.image.read(0x1b2b069, 1)[0]
        altered = Overlay(self.image, {0x1b2b069: value ^ 1})
        with self.assertRaises(ValueError):
            subject.derive_flow(altered, self.table, self.relas)

    def test_altered_input_payload_offset_rejected(self):
        value = self.image.read(0x247e7c7, 1)[0]
        altered = Overlay(self.image, {0x247e7c7: value ^ 1})
        with self.assertRaises(ValueError):
            subject.derive_flow(altered, self.table, self.relas)

    def test_altered_staging_payload_offset_rejected(self):
        value = self.image.read(0x247f603, 1)[0]
        altered = Overlay(self.image, {0x247f603: value ^ 1})
        with self.assertRaises(ValueError):
            subject.derive_flow(altered, self.table, self.relas)

    def test_altered_final_copy_range_rejected(self):
        altered = Overlay(self.image, {0x247f927: 1, 0x247f928: 0,
                                       0x247f929: 0, 0x247f92a: 0})
        with self.assertRaises(ValueError):
            subject.derive_flow(altered, self.table, self.relas)

    def test_invalid_operand_shape_rejected(self):
        with self.assertRaises(ValueError):
            subject.get_operand(self.image, 0x247f825, '90')

    def test_auxiliary_argument_branches_have_expected_tags(self):
        rows = self.flow['auxiliary_arguments']
        self.assertEqual([r['parser_va'] for r in rows], ['0x1e67fb0', '0x1e67a80', '0x1e67d60'])
        self.assertTrue(all(r['default_tag'] == 4 and r['accepted_low32'] == 3 for r in rows))
        self.assertEqual([r['other_branch_va'] for r in rows], ['0x1f6f05a', '0x1f6f0cf', '0x1f6f163'])

    def test_changed_auxiliary_result_tag_rejected(self):
        changed = Overlay(self.image, {0x1f6ecb5: 2})
        with self.assertRaises(ValueError):
            subject.derive_flow(changed, self.table, self.relas)

    def test_result_variants_select_two_adjacent_payload_words(self):
        record = bytearray(range(128))
        record[:8] = bytes(8)
        for selector in (0, 1, 2):
            record[self.flow['result_variants']['selector_offset']] = selector
            got = subject.result_variant_case(self.flow, bytes(record))
            start = 0x20 + selector * 0x10
            self.assertEqual((got['kind'], got['tag'], got['payload_start']), ('payload', 0x21, start))
            self.assertEqual(bytes.fromhex(got['payload_hex']), bytes(record[start:start + 32]))

    def test_result_payload_outside_record_rejected(self):
        record = bytearray(32)
        record[self.flow['result_variants']['selector_offset']] = 255
        with self.assertRaises(ValueError):
            subject.result_variant_case(self.flow, bytes(record))

    def test_special_and_all_generic_result_subtypes(self):
        record = bytearray(64)
        record[:8] = (1 << 63).to_bytes(8, 'little')
        special = subject.result_variant_case(self.flow, bytes(record))
        self.assertEqual((special['kind'], special['tag'], special['subtype']), ('special-error', 13, 19))
        record[:8] = ((1 << 63) + 1).to_bytes(8, 'little')
        for auxiliary in range(256):
            record[self.flow['result_variants']['auxiliary_offset']] = auxiliary
            got = subject.result_variant_case(self.flow, bytes(record))
            expected = {0: 15, 1: 16, 2: 16, 3: 17, 4: 18, 14: 2}.get(auxiliary, 20)
            with self.subTest(auxiliary=auxiliary):
                self.assertEqual((got['kind'], got['tag'], got['subtype']), ('generic-error', 13, expected))

    def test_result_record_missing_auxiliary_byte_rejected(self):
        record = ((1 << 63) + 1).to_bytes(8, 'little')
        with self.assertRaises(ValueError):
            subject.result_variant_case(self.flow, record)

    def test_changed_result_variant_bias_rejected(self):
        value = self.image.read(0x4e59156, 1)[0]
        altered = Overlay(self.image, {0x4e59156: value ^ 1})
        with self.assertRaises(ValueError):
            subject.derive_flow(altered, self.table, self.relas)

    def test_preparation_error_packs_negative_32000_conditionally(self):
        response = self.flow['response']
        self.assertEqual(response['prepare_error_dispatch_va'], '0x4e5cc7b')
        self.assertEqual(response['prepare_limit_error_code'], -32000)
        self.assertEqual((response['subtype_range_start'], response['subtype_range_count']), (7, 2))
        self.assertEqual((response['packed_error_tag'], response['packed_error_kind']), (2, 7))
        self.assertEqual((response['result_success_tag'], response['returned_success_tag']), (0x21, 3))
        self.assertEqual(subject.synthetic_case(self.flow, 'some', bytes(20), 1, 30000001)
                         ['conditional_error_code'], -32000)

    def test_response_wrapper_preserves_packed_error_code_offset(self):
        response = self.flow['response']
        self.assertEqual((response['packed_error_kind_offset'], response['packed_error_code_offset']), (0x30, 0x34))
        self.assertEqual((response['wrapper_input_tag_offset'], response['wrapper_input_kind_offset'],
                          response['wrapper_input_code_offset']), (0x10, 0x40, 0x44))
        self.assertEqual((response['wrapper_output_error_flag'], response['wrapper_output_flag_offset'],
                          response['wrapper_output_code_offset']), (1, 0x28, 0x2c))
        self.assertEqual(response['wrapper_kind_arm_va'], '0x24cc7a8')

    def test_changed_response_wrapper_code_input_rejected(self):
        value = self.image.read(0x24cc7ab, 1)[0]
        altered = Overlay(self.image, {0x24cc7ab: value ^ 1})
        with self.assertRaises(ValueError):
            subject.derive_flow(altered, self.table, self.relas)

    def test_changed_preparation_error_code_rejected(self):
        value = self.image.read(0x4e5d9b7, 1)[0]
        altered = Overlay(self.image, {0x4e5d9b7: value ^ 1})
        with self.assertRaises(ValueError):
            subject.derive_flow(altered, self.table, self.relas)

    def test_changed_error_dispatch_slot_rejected(self):
        value = self.image.read(0x4e5ccc4, 1)[0]
        altered = Overlay(self.image, {0x4e5ccc4: value ^ 1})
        with self.assertRaises(ValueError):
            subject.derive_flow(altered, self.table, self.relas)

    def test_preparation_gate_and_state_store_operands(self):
        prep = self.flow['preparation']
        self.assertEqual((prep['mode_field_offset'], prep['check_mode']), (0x80, 1))
        self.assertEqual((prep['word_field_offset'], prep['word_limit']), (0x88, 30000000))
        self.assertEqual((prep['early_error_tag'], prep['early_error_subtype']), (0x0d, 0x08))
        self.assertEqual((prep['limit_store_offset'], prep['limit_store_value']), (0x70, 30000000))
        self.assertEqual((prep['zero_block_offset'], prep['zero_block_size']), (0x78, 16))
        self.assertEqual((prep['zero_qword_offset'], prep['zero_qword_value']), (0x88, 0))
        self.assertEqual((prep['state_byte_offsets'], prep['state_byte_values']), ([0x43, 0x45], [1, 1]))
        self.assertEqual((prep['input_zero_offset'], prep['input_zero_value']), (0x90, 0))

    def test_inconsistent_preparation_limit_store_rejected(self):
        value = self.image.read(0x247dbe1, 1)[0]
        altered = Overlay(self.image, {0x247dbe1: value ^ 1})
        with self.assertRaises(ValueError):
            subject.derive_flow(altered, self.table, self.relas)

    def test_request_to_environment_offsets(self):
        self.assertEqual(self.flow['object']['tag_offset'], 0x1bf)
        self.assertEqual(self.flow['object']['payload_offset'], 0x1c0)
        self.assertEqual((self.flow['object']['tail_copy_start'], self.flow['object']['tail_copy_size']), (0x18, 0x1c8))
        self.assertEqual(self.flow['environment']['tag_offset'], 0x294)
        self.assertEqual(self.flow['environment']['payload_offset'], 0x295)

    def test_every_address_byte_survives_synthetic_copy(self):
        payload = bytes(range(self.flow['object']['payload_size']))
        got = subject.synthetic_case(self.flow, 'some', payload)
        self.assertEqual(bytes.fromhex(got['key_hex']), payload)
        self.assertEqual(got['env_tag'], 1)

    def test_all_160_single_bit_key_changes_fail_equality(self):
        expected = bytes.fromhex(self.flow['target_key_hex'])
        self.assertTrue(subject.synthetic_case(self.flow, 'some', expected)['matches_nine'])
        for bit in range(len(expected) * 8):
            changed = bytearray(expected)
            changed[bit // 8] ^= 1 << (bit % 8)
            got = subject.synthetic_case(self.flow, 'some', bytes(changed))
            with self.subTest(bit=bit):
                self.assertFalse(got['matches_nine'])
                self.assertEqual(bytes.fromhex(got['key_hex']), bytes(changed))

    def test_null_and_absent_clear_environment_address_tag(self):
        for kind in ('null', 'absent'):
            got = subject.synthetic_case(self.flow, kind)
            self.assertEqual((got['outcome'], got['env_tag']), ('address-absent', 0))

    def test_duplicate_and_decoder_error_stop_before_environment(self):
        for kind in ('duplicate', 'decode-error'):
            got = subject.synthetic_case(self.flow, kind)
            self.assertEqual(got['outcome'], 'field-error')
            self.assertIsNone(got['env_tag'])

    def test_limit_before_equal_after(self):
        cap = self.flow['preparation']['word_limit']
        key = bytes.fromhex(self.flow['target_key_hex'])
        for value, outcome in [(cap - 1, 'address-preserved'), (cap, 'address-preserved'),
                               (cap + 1, 'early-limit-error')]:
            with self.subTest(value=value):
                self.assertEqual(subject.synthetic_case(self.flow, 'some', key, 1, value)['outcome'], outcome)
        self.assertEqual(subject.synthetic_case(self.flow, 'some', key, 0, cap + 1)['outcome'],
                         'address-preserved')

    def test_out_of_range_gate_operands_rejected_by_model(self):
        key = bytes.fromhex(self.flow['target_key_hex'])
        for mode, word in ((-1, 0), (1 << 32, 0), (0, -1), (0, 1 << 64)):
            with self.subTest(mode=mode, word=word), self.assertRaises(ValueError):
                subject.synthetic_case(self.flow, 'some', key, mode, word)

    def test_short_payload_rejected_by_model(self):
        with self.assertRaises(ValueError):
            subject.synthetic_case(self.flow, 'some', bytes(19))

    def test_unknown_model_case_rejected(self):
        with self.assertRaises(ValueError):
            subject.synthetic_case(self.flow, 'unexpected', bytes(20))

    def test_reproduced_files_equal_retained_files(self):
        path = ROOT / 'research/work-items/RE-021-eth-call-target-94'
        for name, content in self.output.items():
            with self.subTest(file=name):
                self.assertEqual((path / name).read_bytes(), content)

    def test_selected_evidence_counts(self):
        summary = json.loads(self.output['summary.json'])
        rows = list(csv.DictReader(io.StringIO(self.output['functions.tsv'].decode()), delimiter='\t'))
        self.assertEqual(summary['selected_fde_count'], len(rows))
        self.assertEqual(summary['selected_fde_bytes'], sum(int(r['size']) for r in rows))
        self.assertEqual(summary['relative_table_entries'], len(self.table))


if __name__ == '__main__':
    unittest.main()
