"""Static corruption controls for selected node-115 ABCI evidence."""
import copy
import hashlib
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import abci_expanded_result115 as evidence


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = evidence.TARGET.read_bytes()
        evidence.authenticate(cls.data)
        cls.sections = evidence.sections(cls.data)
        cls.fdes = evidence.select_fdes(cls.data, cls.sections)
        cls.windows = evidence.check_windows(cls.data, cls.sections)
        cls.transfers = evidence.transfer_rows(cls.data, cls.sections, cls.fdes)
        cls.operands, cls.values = evidence.operand_rows(cls.data, cls.sections)
        cls.unwind = [r for f in cls.fdes for r in evidence.lsda_rows(cls.data, cls.sections, f)]

    def test_target_digest(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), evidence.SHA115)
        with self.assertRaises(ValueError):
            evidence.authenticate(self.data, '0' * 64)

    def test_bad_target_fails_before_output_creation(self):
        with tempfile.TemporaryDirectory() as parent:
            base = Path(parent)
            source = base / 'wrong-input'
            target = base / 'output'
            source.write_bytes(b'not the authenticated target')
            with mock.patch.object(evidence, 'TARGET', source), mock.patch.object(
                    sys, 'argv', ['extractor', '--out', str(target)]):
                with self.assertRaises(ValueError):
                    evidence.main()
            self.assertFalse(target.exists())

    def test_every_window_detects_changed_byte(self):
        changed = bytearray(self.data)
        for label, va, expected in evidence.WINDOWS:
            off = evidence.file_offset(changed, self.sections, va, len(bytes.fromhex(expected)), executable=True)
            changed[off] ^= 1
            try:
                with self.subTest(window=label), self.assertRaises(ValueError):
                    evidence.check_windows(changed, self.sections, ((label, va, expected),))
            finally:
                changed[off] ^= 1
        self.assertEqual(evidence.check_windows(changed, self.sections), self.windows)

    def test_corrupted_fde_range_is_rejected(self):
        changed = bytearray(self.data)
        frame = self.fdes[0]
        off = evidence.file_offset(changed, self.sections, frame['fde'], 16)
        changed[off + 12] ^= 1
        with self.assertRaises(ValueError):
            evidence.select_fdes(changed, self.sections)

    def test_corrupted_fde_body_is_rejected(self):
        changed = bytearray(self.data)
        off = evidence.file_offset(changed, self.sections, self.fdes[0]['start'], 1, executable=True)
        changed[off] ^= 1
        with self.assertRaises(ValueError):
            evidence.select_fdes(changed, self.sections)

    def test_selected_fdes_are_distinct_and_nonoverlapping(self):
        spans = sorted((f['start'], f['end']) for f in self.fdes)
        self.assertEqual(len(spans), 6)
        self.assertTrue(all(a[1] <= b[0] for a, b in zip(spans, spans[1:])))
        self.assertEqual(sum(f['lsda'] is None for f in self.fdes), 1)

    def test_valid_and_invalid_file_mappings(self):
        data = bytes(range(16))
        sec = {'name': 'x', 'type': 1, 'flags': 6, 'address': 0x100, 'offset': 0, 'size': 16}
        self.assertEqual(evidence.file_offset(data, [sec], 0x10f, 1, executable=True), 15)
        for va, length in ((0xff, 1), (0x110, 1), (0x10f, 2), (0x100, 0), (-1, 1)):
            with self.subTest(va=va, length=length), self.assertRaises(ValueError):
                evidence.file_offset(data, [sec], va, length)
        with self.assertRaises(ValueError):
            evidence.file_offset(data, [sec, dict(sec)], 0x100, 1)
        with self.assertRaises(ValueError):
            evidence.file_offset(data, [dict(sec, type=8)], 0x100, 1)
        with self.assertRaises(ValueError):
            evidence.file_offset(data, [dict(sec, flags=2)], 0x100, 1, executable=True)
        with self.assertRaises(ValueError):
            evidence.file_offset(data, [dict(sec, offset=15)], 0x102, 1)

    def test_section_duplicates_and_nobits(self):
        item = {'name': '.rela.dyn', 'type': 4}
        self.assertEqual(evidence.named_section([item], '.rela.dyn'), item)
        for arr in ([], [dict(item, type=8)], [item, dict(item)], [item, dict(item, type=8)]):
            with self.subTest(sections=arr), self.assertRaises(ValueError):
                evidence.named_section(arr, '.rela.dyn')

    def test_selected_relative_relocation_validation(self):
        one = struct.pack('<QQq', 0x10, 8, 0x123)
        sec = {'name': '.rela.dyn', 'type': 4, 'offset': 0, 'size': len(one)}
        self.assertEqual(evidence.selected_relocations(one, [sec], [0x10]), {0x10: (0x123, 0)})
        with self.assertRaises(ValueError):
            evidence.selected_relocations(one, [sec], [0x18])
        bad_type = struct.pack('<QQq', 0x10, 7, 0x123)
        with self.assertRaises(ValueError):
            evidence.selected_relocations(bad_type, [sec], [0x10])
        with self.assertRaises(ValueError):
            evidence.selected_relocations(one + one, [dict(sec, size=48)], [0x10])
        with self.assertRaises(ValueError):
            evidence.selected_relocations(one, [dict(sec, size=23)], [0x10])

    def test_real_locations_and_reference(self):
        rows = evidence.location_rows(self.data, self.sections)
        self.assertEqual([(r[5], r[6]) for r in rows], [(123, 37), (460, 78)])
        refs = evidence.reference_rows(self.data, self.sections)
        self.assertEqual(refs[0][-1], '0x64aa208')

    def test_contextual_worker_relocation_and_corruption(self):
        row = evidence.contextual_worker_slot(self.data, self.sections)[0]
        self.assertEqual(row[0], 'context')
        self.assertEqual(row[6], '0x5a6e1e0')
        relocs = evidence.selected_relocations(self.data, self.sections, [0x64e71d0])
        changed = bytearray(self.data)
        relocation_offset = relocs[0x64e71d0][1]
        changed[relocation_offset + 16] ^= 1
        with self.assertRaises(ValueError):
            evidence.contextual_worker_slot(changed, self.sections)

    def test_corrupted_location_is_rejected(self):
        changed = bytearray(self.data)
        off = evidence.file_offset(changed, self.sections, 0x64aa208, 24)
        changed[off + 16] ^= 1
        with self.assertRaises(ValueError):
            evidence.location_rows(changed, self.sections)

    def test_corrupted_location_reference_is_rejected(self):
        changed = bytearray(self.data)
        off = evidence.file_offset(changed, self.sections, 0x54859e9, 7, executable=True)
        changed[off + 3] ^= 1
        with self.assertRaises(ValueError):
            evidence.reference_rows(changed, self.sections)

    def test_transfer_encodings_and_corruption(self):
        for site, expected_hex, kind, target in evidence.TRANSFERS:
            with self.subTest(site=hex(site)):
                self.assertEqual(evidence.decode_transfer(site, bytes.fromhex(expected_hex)), (kind, target))
        with self.assertRaises(ValueError):
            evidence.decode_transfer(0, b'\x90')
        changed = bytearray(self.data)
        off = evidence.file_offset(changed, self.sections, 0x5866042, 5, executable=True)
        changed[off + 1] ^= 1
        with self.assertRaises(ValueError):
            evidence.transfer_rows(changed, self.sections, self.fdes)

    def test_direct_calls_and_layout_joins(self):
        joins = evidence.verify_joins(self.values, self.transfers)
        self.assertEqual(joins['worker_callback_owner_offset'], '0x6a0')
        self.assertEqual(joins['worker_allocation_to_body_offset'], '0x10')
        self.assertEqual(joins['worker_owner_argument_offset'], '0x20')
        self.assertEqual(joins['worker_result_base'], '0x60')
        self.assertEqual(joins['worker_result_head_destination'], '0x180')
        self.assertEqual(joins['worker_result_extra_destination'], '0x120')
        self.assertEqual(joins['worker_result_flag_destination'], '0x5c')
        self.assertEqual(joins['worker_result_tail_destination'], '0x550')
        self.assertEqual(joins['worker_pending_offset'], '0x5f8')
        self.assertEqual(joins['worker_pending_sentinel'], '0x8000000000000000')
        self.assertEqual(joins['guard_state_argument_offset'], '0x28')
        self.assertEqual(joins['item_state_argument_offset'], '0x20')
        self.assertEqual(joins['handler_map_state_offset'], '0x14d8')
        self.assertEqual(joins['insert_row_stride'], '0x60')
        self.assertEqual(joins['combined_row_word_offset'], '0x10')
        self.assertEqual(joins['wrapper_count_output_offset'], '0x10')
        self.assertEqual(joins['parent_output_pointer_offset'], '0x8')
        self.assertEqual(joins['projection_cursor_offset'], '0x8')
        self.assertEqual(joins['projection_end_offset'], '0x18')
        self.assertEqual(joins['projected_stride'], '0x40')
        self.assertEqual(joins['projection_capacity_factor'], '0x48')
        self.assertEqual(joins['omitted_row_tail_bytes'], '0x8')
        self.assertEqual(joins['alias_row_stride'], '0x30')
        self.assertEqual(joins['handler_inline_key_offset'], '0x3')
        self.assertEqual(joins['state_clock_offset'], '0x60')
        self.assertEqual(joins['value_clock_offset'], '0x30')
        self.assertEqual(joins['gate_zero_code'], '0xc6')
        self.assertEqual(joins['membership_miss_code'], '0x36')
        self.assertEqual(joins['handler_nested_flag'], '0x1')
        self.assertEqual(joins['nested_stack_argument_offset'], '0x10')

    def test_context_slot_copy_preserves_the_selected_pointer(self):
        v = self.values
        original = 0x123456789abcdef0
        incoming = bytearray(0x50)
        argument_offset = v['guard_slot_argument_store'] - v['guard_argument_base']
        struct.pack_into('<Q', incoming, argument_offset, original)
        frame = bytearray(0x80)
        source = v['wrapper_input_chunk']
        destination = v['wrapper_output_chunk']
        frame[destination:destination + 16] = incoming[source:source + 16]
        read_at = v['wrapper_argument_base'] + v['item_slot_input']
        self.assertEqual(struct.unpack_from('<Q', frame, read_at)[0], original)
        self.assertNotEqual(struct.unpack_from('<Q', frame, read_at - 8)[0], original)

    def test_worker_owner_handoff_preserves_selected_body_pointer(self):
        v = self.values
        callback = bytearray(v['worker_captured_owner'] + 8)
        owner_allocation = 0x1020304050607000
        struct.pack_into('<Q', callback, v['worker_captured_owner'], owner_allocation)
        body = struct.unpack_from('<Q', callback, v['worker_captured_owner'])[0] + v['worker_owner_body']
        frame = bytearray(v['worker_owner_argument_store'] + 8)
        struct.pack_into('<Q', frame, v['worker_owner_argument_store'], body)
        argument = v['worker_argument_base']
        self.assertEqual(struct.unpack_from('<Q', frame, argument + 0x20)[0], body)
        self.assertEqual(body, owner_allocation + 0x10)
        self.assertNotEqual(struct.unpack_from('<Q', frame, argument + 0x18)[0], body)

    def test_worker_result_copy_and_sentinel_model(self):
        v = self.values
        output = bytes(range(80))
        frame = bytearray(0x600)
        base = v['worker_result_base']
        frame[base:base + len(output)] = output
        frame[v['worker_result_head_destination']:v['worker_result_head_destination'] + 16] = frame[base:base + 16]
        frame[v['worker_result_word_destination']:v['worker_result_word_destination'] + 8] = frame[base + 16:base + 24]
        frame[v['worker_result_extra_destination']:v['worker_result_extra_destination'] + 8] = frame[base + 24:base + 32]
        flag = frame[base + 32]
        struct.pack_into('<I', frame, v['worker_result_flag_destination'], flag)
        frame[v['worker_result_tail_destination']:v['worker_result_tail_destination'] + 40] = frame[base + 40:base + 80]
        self.assertEqual(frame[v['worker_result_head_destination']:v['worker_result_head_destination'] + 24], output[:24])
        self.assertEqual(frame[v['worker_result_extra_destination']:v['worker_result_extra_destination'] + 8], output[24:32])
        self.assertEqual(struct.unpack_from('<I', frame, v['worker_result_flag_destination'])[0], output[32])
        self.assertEqual(frame[v['worker_result_tail_destination']:v['worker_result_tail_destination'] + 40], output[40:80])
        pending = bytearray(v['worker_pending_clear_offset'] + 8)
        struct.pack_into('<Q', pending, v['worker_pending_write_offset'], 123)
        old = struct.unpack_from('<Q', pending, v['worker_pending_read_offset'])[0]
        struct.pack_into('<Q', pending, v['worker_pending_clear_offset'], v['worker_pending_sentinel'])
        self.assertEqual(old, 123)
        self.assertEqual(struct.unpack_from('<Q', pending, 0x5f8)[0], 1 << 63)

    def test_invalid_stride_and_tag_joins_fail_closed(self):
        for field in ('worker_saved_callback', 'worker_reloaded_callback', 'worker_owner_argument_store',
                      'worker_argument_base', 'worker_captured_owner', 'worker_owner_body',
                      'worker_owner_guard', 'worker_result_base', 'worker_result_head_source',
                      'worker_result_word_source', 'worker_result_word_destination',
                      'worker_result_extra_source', 'worker_result_flag_source',
                      'worker_result_tail_source', 'worker_result_tail_second', 'worker_result_tail_word',
                      'worker_pending_write_offset', 'worker_pending_read_offset',
                      'worker_pending_clear_offset', 'worker_pending_sentinel',
                      'guard_slot_saved', 'guard_slot_reloaded', 'guard_slot_argument_store',
                      'wrapper_input_chunk', 'wrapper_output_chunk', 'item_slot_input',
                      'item_slot_saved', 'item_slot_reloaded', 'wrapper_count_output', 'wrapper_count_pointer', 'parent_output_base',
                      'projection_argument_cursor_store', 'projection_argument_capacity_store',
                      'projection_argument_end_store', 'projection_input_end',
                      'handler_key_head', 'handler_key_tail', 'alias_key_tail', 'alias_value_tail',
                      'handler_clock_head', 'handler_clock_tail', 'nested_clock_head',
                      'nested_value_clock_tail', 'projection_capacity_first_sib', 'projection_capacity_second_sib',
                      'item_input_stride', 'item_output_stride', 'item_tag',
                      'handler_map_rows', 'insert_element_size', 'nested_value_word',
                      'nested_result_code', 'nested_multiplier_shift', 'insert_stride_sib',
                      'handler_nested_flag', 'nested_flag_compare', 'handler_flag_address_offset',
                      'handler_flag_store_offset', 'nested_flag_stack_offset',
                      'nested_frame_size', 'nested_push_count'):
            values = dict(self.values)
            values[field] ^= 1
            with self.subTest(field=field), self.assertRaises(ValueError):
                evidence.verify_joins(values, self.transfers)

    def test_changed_direct_join_fails(self):
        rows = list(self.transfers)
        i = next(i for i, row in enumerate(rows) if row[1] == '0x548580d')
        row = list(rows[i])
        row[5] = '0x1'
        rows[i] = tuple(row)
        with self.assertRaises(ValueError):
            evidence.verify_joins(self.values, rows)

    def test_lsda_rows_within_selected_ranges(self):
        spans = {f['role']: (f['start'], f['end']) for f in self.fdes}
        self.assertGreater(len(self.unwind), 0)
        for role, _, _, start, end, landing, _, _ in self.unwind:
            lower, upper = spans[role]
            self.assertLessEqual(lower, int(start, 16))
            self.assertLessEqual(int(start, 16), int(end, 16))
            self.assertLessEqual(int(end, 16), upper)
            if landing != '-':
                self.assertTrue(lower <= int(landing, 16) < upper)

    def test_corrupted_lsda_header_is_rejected(self):
        changed = bytearray(self.data)
        fde = next(f for f in self.fdes if f['lsda'] is not None)
        off = evidence.file_offset(changed, self.sections, fde['lsda'], 1)
        changed[off] ^= 1
        with self.assertRaises(ValueError):
            evidence.lsda_rows(changed, self.sections, fde)

    def test_lsda_call_links_and_uncovered_path(self):
        links = evidence.link_unwind(self.transfers, self.unwind, self.fdes)
        call = next(r for r in links if r[1] == '0x5866042')
        self.assertEqual(call[4:6], ('covered', '0x586624f'))
        synthetic = [('row_insertion', '0x4ef55c2', '0', 'e800000000', 'rel', '0x4ef55c7', '-')]
        self.assertEqual(evidence.link_unwind(synthetic, self.unwind, self.fdes)[0][4], 'no_lsda')
        duplicated = self.unwind + [next(r for r in self.unwind
            if r[0] == 'item_loop' and int(r[3], 16) <= 0x5866042 < int(r[4], 16))]
        with self.assertRaises(ValueError):
            evidence.link_unwind(self.transfers, duplicated, self.fdes)

    def test_push_sequence_rejects_non_push_and_truncation(self):
        self.assertEqual(evidence.count_pushes(bytes.fromhex('55415741564155415453')), 6)
        for raw in (bytes.fromhex('55ff'), bytes.fromhex('41')):
            with self.assertRaises(ValueError):
                evidence.count_pushes(raw)

    def test_wrong_historical_digest_is_rejected(self):
        with self.assertRaises(ValueError):
            evidence.historical_check(b'not the historical binary')

    def test_saturating_arithmetic_boundaries(self):
        maximum = (1 << 64) - 1
        for factor in (4, 5):
            boundary = maximum // factor
            for value in (0, 1, boundary - 1, boundary, boundary + 1, maximum):
                self.assertEqual(evidence.saturating_multiply(value, factor), min(value * factor, maximum))
        for left, right in ((0, 0), (maximum, 0), (maximum, 1), (maximum - 1, 1),
                            (maximum - 1, 2), (2**63, 2**63)):
            self.assertEqual(evidence.saturating_add(left, right), min(left + right, maximum))
        for pair in ((-1, 1), (maximum + 1, 0)):
            with self.assertRaises(ValueError):
                evidence.saturating_add(*pair)
        with self.assertRaises(ValueError):
            evidence.saturating_multiply(1, 3)

    def test_parent_sort_thresholds(self):
        first = self.values['sort_first_count']
        second = self.values['sort_second_count']
        self.assertEqual((first, second), (2, 21))
        for count, want in ((0, 0), (1, 0), (2, 1), (20, 1), (21, 2), ((1 << 64) - 1, 2)):
            self.assertEqual(evidence.sorting_lane(count, first, second), want)
        with self.assertRaises(ValueError):
            evidence.sorting_lane(-1, first, second)
        with self.assertRaises(ValueError):
            evidence.sorting_lane(1, second, first)

    def test_two_selected_saturating_increments(self):
        maximum = (1 << 64) - 1
        for initial in (0, 1, maximum - 2, maximum - 1, maximum):
            first = evidence.saturating_add(initial, 1)
            second = evidence.saturating_add(first, 1)
            self.assertEqual(second, min(initial + 2, maximum))

    def test_item_tag_width_and_counter_saturation(self):
        maximum = (1 << 64) - 1
        cases = (
            (0, 9, (1, 1)),
            (2, maximum, (1, 1)),
            (1, 0, (1, 1)),
            (1, maximum - 1, (1, maximum)),
            (1, maximum, (1, maximum)),
            (0x100000001, 4, (0x100000001, 5)),
            (0x100000000, 4, (1, 1)),
        )
        for tag, count, want in cases:
            self.assertEqual(evidence.next_item_state(tag, count), want)
        with self.assertRaises(ValueError):
            evidence.next_item_state(-1, 0)

    def test_singleton_key_and_all_single_byte_mutations(self):
        original = bytes(range(20))
        replacement = bytes(range(20, 40))
        self.assertEqual(evidence.singleton_alias(original, original, replacement), replacement)
        for i in range(len(original)):
            for delta in range(1, 256):
                changed = bytearray(original)
                changed[i] ^= delta
                self.assertEqual(evidence.singleton_alias(original, bytes(changed), replacement), original)
        with self.assertRaises(ValueError):
            evidence.singleton_alias(original[:-1], original, replacement)

    def test_projection_capacity_and_u64_wrap(self):
        input_stride = self.values['projection_input_stride']
        output_stride = self.values['projection_output_stride']
        maximum = (1 << 64) - 1
        boundary = maximum // input_stride
        for cap in (0, 1, 7, 8, boundary - 1, boundary, boundary + 1, maximum):
            expected = ((cap * input_stride) & maximum) // output_stride
            self.assertEqual(evidence.projection_capacity(cap, input_stride, output_stride), expected)
        with self.assertRaises(ValueError):
            evidence.projection_capacity(-1, input_stride, output_stride)
        with self.assertRaises(ValueError):
            evidence.projection_capacity(1 << 64, input_stride, output_stride)

    def test_projection_discards_only_each_row_tail(self):
        in_stride = self.values['projection_input_stride']
        out_stride = self.values['projection_output_stride']
        rows = [bytes(((i * 31 + j) & 255) for j in range(in_stride)) for i in range(3)]
        actual = evidence.compact_rows(b''.join(rows), in_stride, out_stride)
        self.assertEqual(actual, rows[0][:out_stride] + rows[1][:out_stride] + rows[2][:out_stride])
        for i in range(len(rows)):
            changed = bytearray(b''.join(rows))
            changed[i * in_stride + out_stride] ^= 0xff
            self.assertEqual(evidence.compact_rows(changed, in_stride, out_stride), actual)
        for count in range(65):
            payload = bytes((index * 37 + count) & 255 for index in range(count * in_stride))
            reference = b''.join(payload[i:i + out_stride] for i in range(0, len(payload), in_stride))
            self.assertEqual(evidence.compact_rows(payload, in_stride, out_stride), reference)
        self.assertEqual(evidence.compact_rows(b'', in_stride, out_stride), b'')
        with self.assertRaises(ValueError):
            evidence.compact_rows(b''.join(rows)[:-1], in_stride, out_stride)
        with self.assertRaises(ValueError):
            evidence.compact_rows(rows[0], in_stride, in_stride + 1)
        with self.assertRaises(ValueError):
            evidence.compact_rows(rows[0], in_stride, 0)

    def test_generated_records_are_complete_and_stable_in_memory(self):
        files = evidence.collect(self.data)
        expected = {'functions.tsv', 'windows.tsv', 'transfers.tsv', 'operands.tsv', 'boundary-relocation.tsv',
                    'locations.tsv', 'references.tsv', 'unwind.tsv', 'unwind-links.tsv',
                    'joins.json', 'summary.json'}
        self.assertEqual(set(files), expected)
        self.assertTrue(all(content.endswith(b'\n') for content in files.values()))
        self.assertIn(evidence.SHA115.encode(), files['summary.json'])


if __name__ == '__main__':
    unittest.main()
