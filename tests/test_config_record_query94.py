"""Controls for the node 94 name-gated record-query packet."""
import copy
import math
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import config_record_query94 as target


class RecordQueryEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = target.TARGET.read_bytes()
        cls.view = target.View(cls.data)
        cls.results = target.collect(cls.data)
        _, cls.fdes = target.eh_frame_records(cls.data, cls.view.sections)
        cls.constants = cls.results['summary']['constants']
        cls.decodes = {
            name: target.decode_body(cls.view.read(start, end - start), start)
            for name, start, end, _ in target.FUNCTIONS
        }

    def mutable_view(self):
        data = bytearray(self.data)
        view = target.View(data)
        return data, view

    def make_row(self, key, threshold, tag=0):
        row = bytearray(self.constants['record_stride'])
        struct.pack_into('<Q', row, 0, tag)
        pos = self.constants['key_offset']
        row[pos:pos + self.constants['key_length']] = key
        struct.pack_into('<Q', row, self.constants['threshold_offset'], threshold)
        return bytes(row)

    def test_authenticated_artifact(self):
        target.verify_identity(self.data)
        self.assertEqual(target.DIGEST, self.results['summary']['artifact_sha256'])

    def test_truncated_artifact_is_rejected(self):
        with self.assertRaises(ValueError):
            target.verify_identity(self.data[:-1])

    def test_changed_artifact_is_rejected(self):
        data = bytearray(self.data)
        data[0] ^= 1
        with self.assertRaises(ValueError):
            target.verify_identity(data)

    def test_function_ranges_and_instruction_totals(self):
        self.assertEqual([308, 725, 586, 521, 155, 995], [x['size'] for x in self.results['functions']])
        self.assertEqual([73, 164, 120, 131, 42, 238], [x['instructions'] for x in self.results['functions']])
        self.assertEqual(3290, self.results['summary']['function_bytes'])
        self.assertEqual(768, self.results['summary']['instructions'])

    def test_decoded_instructions_cover_each_complete_fde(self):
        for name, start, end, _ in target.FUNCTIONS:
            rows = self.decodes[name]
            with self.subTest(function=name):
                self.assertEqual(start, rows[0]['va'])
                self.assertEqual(end, rows[-1]['end'])
                self.assertEqual(self.view.read(start, end - start), b''.join(r['bytes'] for r in rows))

    def test_wrong_fde_end_is_rejected(self):
        functions = list(target.FUNCTIONS)
        name, start, end, digest = functions[0]
        functions[0] = (name, start, end + 1, digest)
        with mock.patch.object(target, 'FUNCTIONS', tuple(functions)):
            with self.assertRaises(ValueError):
                target.collect(self.data)

    def test_corrupt_fde_range_is_rejected_after_identity_gate(self):
        data, view = self.mutable_view()
        fde_va = int(self.results['functions'][0]['fde'], 16)
        # This target's parsed FDE uses sdata4 for its range at record + 12.
        off = view.offset(fde_va, 16)
        size = struct.unpack_from('<i', data, off + 12)[0]
        struct.pack_into('<i', data, off + 12, size + 1)
        with mock.patch.object(target, 'verify_identity', return_value=None):
            with self.assertRaises(ValueError):
                target.collect(data)

    def test_duplicate_selected_fde_start_is_rejected(self):
        selected = next(row for row in self.fdes if row['start'] == target.FUNCTIONS[0][1])
        with mock.patch.object(target, 'eh_frame_records', return_value=({}, self.fdes + [selected])):
            with self.assertRaises(ValueError):
                target.collect(self.data)

    def test_wrong_body_hash_is_rejected(self):
        functions = list(target.FUNCTIONS)
        name, start, end, _ = functions[0]
        functions[0] = (name, start, end, '0' * 64)
        with mock.patch.object(target, 'FUNCTIONS', tuple(functions)):
            with self.assertRaises(ValueError):
                target.collect(self.data)

    def test_each_instruction_contract_rejects_a_corrupted_byte(self):
        data, view = self.mutable_view()
        for name, va, expected in target.CONTRACTS:
            off = view.offset(va, len(bytes.fromhex(expected)))
            data[off] ^= 1
            with self.subTest(name=name), self.assertRaises(ValueError):
                target.require(view, name, va, bytes.fromhex(expected))
            data[off] ^= 1

    def test_contract_table_rejects_changed_branch(self):
        data, view = self.mutable_view()
        data[view.offset(0x24c149c, 2)] ^= 1
        with self.assertRaises(ValueError):
            target.collect_contracts(view, self.decodes)

    def test_contract_at_non_instruction_boundary_is_rejected(self):
        fake = (('inside_branch', 0x24c149d, 'd2'),)
        with mock.patch.object(target, 'CONTRACTS', fake):
            with self.assertRaises(ValueError):
                target.collect_contracts(self.view, self.decodes)

    def test_duplicate_contract_is_rejected(self):
        with mock.patch.object(target, 'CONTRACTS', (target.CONTRACTS[0], target.CONTRACTS[0])):
            with self.assertRaises(ValueError):
                target.collect_contracts(self.view, self.decodes)

    def test_decoder_rejects_branch_into_operand(self):
        with self.assertRaises(ValueError):
            target.decode_body(bytes.fromhex('7501b800000000c3'), 0x1000)

    def test_decoder_accepts_branch_to_instruction_start(self):
        rows = target.decode_body(bytes.fromhex('7505b800000000c3'), 0x1000)
        self.assertEqual(0x1007, rows[0]['target'])
        self.assertEqual(3, len(rows))

    def test_decoder_rejects_incomplete_instruction(self):
        with self.assertRaises(ValueError):
            target.decode_body(bytes.fromhex('488b0500'), 0x1000)

    def test_decoder_rejects_unknown_opcode(self):
        with self.assertRaises(ValueError):
            target.decode_body(bytes.fromhex('0fff'), 0x1000)

    def test_decoder_rejects_excess_prefixes(self):
        with self.assertRaises(ValueError):
            target.decode_body(bytes.fromhex('66' * 9 + '90'), 0x1000)

    def test_unbacked_nobits_and_ambiguous_ranges_rejected(self):
        view = target.View.__new__(target.View)
        view.data = bytes(16)
        view.sections = [{'name': 'zero', 'type': 8, 'flags': 2,
                          'address': 0x1000, 'offset': 0, 'size': 8}]
        with self.assertRaises(ValueError):
            view.read(0x1000, 1)
        view.sections[0]['type'] = 1
        with self.assertRaises(ValueError):
            view.read(0x1007, 2)
        with self.assertRaises(ValueError):
            view.read(0x1000, 0)
        view.sections.append(dict(view.sections[0]))
        with self.assertRaises(ValueError):
            view.read(0x1000, 1)

    def test_relocation_identity_and_default_descriptor(self):
        relocs = {int(x['slot'], 16): x for x in self.results['relocations']}
        self.assertEqual('0x577b288', relocs[0x576e928]['addend'])
        names = {x['index']: x['text'] for x in self.results['descriptors']}
        self.assertEqual(target.EXPECTED_DESCRIPTORS, names)
        self.assertEqual(8, len(names))

    def test_prior_caller_handoff_binds_complete_label_and_target(self):
        label, instructions = target.handoff_context(self.view, self.fdes)
        self.assertEqual('small_vault_summaries_get', label['text'])
        self.assertEqual(25, label['length'])
        self.assertEqual(('65', '75'), (label['before'], label['after']))
        self.assertEqual('0x2586d80', instructions[-1]['target'])

    def test_handoff_displacement_corruption_is_rejected(self):
        data, view = self.mutable_view()
        data[view.offset(0x27e50d4, 5) + 1] ^= 1
        with self.assertRaises(ValueError):
            target.handoff_context(view, self.fdes)

    def test_handoff_label_corruption_is_rejected(self):
        data, view = self.mutable_view()
        data[view.offset(0x3f3ac6, 1)] ^= 1
        with self.assertRaises(ValueError):
            target.handoff_context(view, self.fdes)

    def test_handoff_without_enclosing_unwind_extent_is_rejected(self):
        with self.assertRaises(ValueError):
            target.handoff_context(self.view, [])

    def test_relocation_type_corruption_is_rejected(self):
        data, view = self.mutable_view()
        rec = next(x for x in self.results['relocations'] if x['slot'] == '0x576e928')
        struct.pack_into('<Q', data, int(rec['record_offset'], 16) + 8, 9)
        with self.assertRaises(ValueError):
            target.selected_relocations(view, {0x576e928})

    def test_duplicate_relocation_is_rejected(self):
        data, view = self.mutable_view()
        rows = {int(r['slot'], 16): r for r in self.results['relocations']}
        record = int(rows[0x576e8b8]['record_offset'], 16)
        struct.pack_into('<Q', data, record, 0x576e928)
        with self.assertRaises(ValueError):
            target.selected_relocations(view, {0x576e928, 0x576e8b8})

    def test_missing_relocation_is_rejected(self):
        data, view = self.mutable_view()
        rec = next(x for x in self.results['relocations'] if x['slot'] == '0x576e928')
        struct.pack_into('<Q', data, int(rec['record_offset'], 16), 0)
        with self.assertRaises(ValueError):
            target.selected_relocations(view, {0x576e928})

    def test_corrupt_descriptor_length_is_rejected(self):
        data, view = self.mutable_view()
        slot = 0x5668488
        relocs = target.selected_relocations(view, {slot})
        struct.pack_into('<Q', data, view.offset(slot + 8, 8), 33)
        with self.assertRaises(ValueError):
            target.ascii_descriptors(view, relocs, [(32, slot, False)])

    def test_corrupt_descriptor_text_is_rejected(self):
        rows = copy.deepcopy(self.results['descriptors'])
        rows[0]['text'] = 'HeavyTESTNET'
        with self.assertRaises(ValueError):
            target.check_descriptors(rows)

    def test_corrupt_descriptor_target_fails_even_when_printable(self):
        data, view = self.mutable_view()
        slot = 0x5668488
        rec = next(x for x in self.results['relocations'] if int(x['slot'], 16) == slot)
        struct.pack_into('<q', data, int(rec['record_offset'], 16) + 16, 0x218112)
        rows = target.ascii_descriptors(view, target.selected_relocations(view, {slot}), [(32, slot, False)])
        self.assertEqual('NvMainnet', rows[0]['text'])
        with self.assertRaises(ValueError):
            target.check_descriptors(rows)

    def test_cfg_rejects_changed_branch_edge(self):
        decodes = copy.deepcopy(self.decodes)
        row = next(x for x in decodes['select_next'] if x['va'] == 0x24c149c)
        row['target'] = row['end']
        with self.assertRaises(ValueError):
            target.checked_flow(decodes)

    def test_cfg_rejects_name_gate_reentering_query(self):
        decodes = copy.deepcopy(self.decodes)
        row = next(x for x in decodes['query_wrapper'] if x['va'] == 0x2586e0e)
        row['target'] = 0x2586db0
        with self.assertRaises(ValueError):
            target.checked_flow(decodes)

    def test_lsda_header_corruption_is_rejected(self):
        data, view = self.mutable_view()
        va = int(self.results['functions'][0]['lsda'], 16)
        data[view.offset(va, 1)] ^= 1
        with self.assertRaises(ValueError):
            target.parse_lsda(view, 0x2586d80, 0x2586eb4, va)

    def test_lsda_landing_corruption_is_rejected(self):
        rows = copy.deepcopy(self.results['lsda'])
        row = next(x for x in rows if int(x['start_va'], 16) <= 0x257eeef < int(x['end_va'], 16))
        row['landing_va'] = '0x257ef61'
        with self.assertRaises(ValueError):
            target.checked_failure_routes(rows)

    def test_exception_boundaries_cover_allocations_locks_and_once_calls(self):
        failures = {row['boundary']: row for row in self.results['failure_routes']}
        self.assertEqual(15, len(failures))
        self.assertEqual('0x27d5fbc', failures['locked_collector']['landing'])
        self.assertEqual('0x257ef49', failures['vector_growth']['landing'])
        self.assertEqual('0x257ef61', failures['next_after_allocation']['landing'])
        self.assertEqual('0x24c161b', failures['nested_clone']['landing'])
        self.assertEqual('0x2586e99', failures['invocation_initialization']['landing'])
        self.assertEqual('0x250f469', failures['vector_cleanup_panic']['landing'])
        self.assertEqual('0x250f4ab', failures['remaining_row_cleanup']['landing'])

    def test_name_gate_across_entire_byte_domain(self):
        accepted = {13, 14, 18, 19, 20, 21, 31}
        actual = {n for n in range(256) if target.gate_reaches_invocation_word(n, 4.0, self.constants)}
        self.assertEqual(accepted, actual)
        self.assertNotIn(32, actual)

    def test_name_gate_time_boundaries_and_nan(self):
        for value in (float('-inf'), -0.0, 0.0, math.nextafter(3.0, 0.0), 3.0, float('nan')):
            with self.subTest(value=value):
                self.assertFalse(target.gate_reaches_invocation_word(13, value, self.constants))
        for value in (math.nextafter(3.0, 4.0), 4.0, float('inf')):
            with self.subTest(value=value):
                self.assertTrue(target.gate_reaches_invocation_word(13, value, self.constants))

    def test_out_of_range_name_is_rejected_by_model(self):
        for value in (-1, 256, True, '13'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                target.gate_reaches_invocation_word(value, 4.0, self.constants)

    def test_optional_helper_flag_and_argument(self):
        self.assertEqual(self.constants['extra_flag_offset'], 0x588)
        self.assertEqual(self.constants['optional_helper_argument'], 50)
        for flag in range(256):
            with self.subTest(flag=flag):
                self.assertEqual(target.optional_helper_argument(flag, self.constants),
                                 50 if flag else None)
        for flag in (-1, 256, None, True):
            with self.subTest(invalid=flag), self.assertRaises(ValueError):
                target.optional_helper_argument(flag, self.constants)

    def test_fast_lock_low_byte_domain(self):
        for old in range(256):
            action, new = target.lock_acquisition(old, True, self.constants)
            if old & 8:
                self.assertEqual(('slow', None), (action, new))
            else:
                self.assertEqual(('fast', old + 16), (action, new))

    def test_lock_boundaries_and_competing_writer(self):
        limit = (1 << 64) - 16
        self.assertEqual(('fast', limit), target.lock_acquisition(limit - 16, True, self.constants))
        self.assertEqual(('slow', None), target.lock_acquisition(limit, True, self.constants))
        self.assertEqual(('slow', None), target.lock_acquisition(0, False, self.constants))
        for bad in (-1, 1 << 64, True):
            with self.subTest(value=bad), self.assertRaises(ValueError):
                target.lock_acquisition(bad, True, self.constants)

    def test_release_wake_exact_low_values(self):
        expected = {0x12, 0x13, 0x16, 0x17, 0x1a, 0x1b, 0x1e, 0x1f}
        wake_values = {old for old in range(256) if target.lock_release(old, self.constants)[1]}
        self.assertEqual(expected, wake_values)
        self.assertEqual(((1 << 64) - 16, False), target.lock_release(0, self.constants))
        self.assertFalse(target.lock_release((1 << 64) - 1, self.constants)[1])

    def test_row_cleanup_separates_allocation_and_tag_guards(self):
        expected = {(0, 0): (False, False), (1, 8): (True, False),
                    (2, 0): (False, True), (3, 8): (True, True),
                    ((1 << 32) + 1, 1): (True, False)}
        for (tag, length), result in expected.items():
            with self.subTest(tag=tag, length=length):
                self.assertEqual(result, target.cleanup_row_paths(tag, length, self.constants))

    def test_vector_backing_guard_uses_capacity_not_length(self):
        self.assertEqual((False, 0), target.cleanup_vector_backing(0, self.constants))
        self.assertEqual((True, 120), target.cleanup_vector_backing(1, self.constants))
        self.assertEqual((True, 480), target.cleanup_vector_backing(4, self.constants))
        # This deliberately corrupt synthetic capacity wraps the machine product.
        self.assertEqual((True, 0), target.cleanup_vector_backing(1 << 61, self.constants))

    def test_cleanup_models_reject_out_of_range_words(self):
        for value in (-1, 1 << 64, True):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    target.cleanup_row_paths(value, 0, self.constants)
                with self.assertRaises(ValueError):
                    target.cleanup_vector_backing(value, self.constants)

    def test_corrupt_cleanup_guard_is_rejected(self):
        data, view = self.mutable_view()
        data[view.offset(0x250c2d2, 2)] ^= 1
        with self.assertRaises(ValueError):
            target.collect_contracts(view, self.decodes)

    def test_unsigned_threshold_includes_equality(self):
        key = b'A' * 20
        rows = [self.make_row(key, 4), self.make_row(key, 5)]
        self.assertEqual((1, 2), target.select_record(rows, 0, 0, key, 5, self.constants))
        high = self.make_row(key, 1 << 63)
        self.assertEqual((0, 1), target.select_record([high], 0, 0, key, (1 << 63) - 1, self.constants))

    def test_active_key_filter_bypasses_threshold_comparison(self):
        key_a, key_b = b'A' * 20, b'B' * 20
        rows = [self.make_row(key_a, 1), self.make_row(key_b, 100)]
        self.assertEqual((0, 1), target.select_record(rows, 0, 1, key_a, 99, self.constants))
        self.assertEqual((1, 2), target.select_record(rows, 0, 0, key_a, 99, self.constants))

    def test_other_flag_bits_do_not_enable_key_filter(self):
        key = b'A' * 20
        rows = [self.make_row(key, 1), self.make_row(key, 100)]
        for flag in range(0, 256, 2):
            self.assertEqual((1, 2), target.select_record(rows, 0, flag, key, 99, self.constants))
        for flag in range(1, 256, 2):
            self.assertEqual((0, 1), target.select_record(rows, 0, flag, key, 99, self.constants))

    def test_key_comparison_covers_all_twenty_bytes(self):
        key = b'A' * 20
        for offset in range(20):
            other = bytearray(key)
            other[offset] ^= 1
            rows = [self.make_row(other, 100), self.make_row(key, 0)]
            self.assertEqual((1, 2), target.select_record(rows, 0, 1, key, 0, self.constants))

    def test_no_match_advances_cursor_to_end(self):
        key = b'A' * 20
        rows = [self.make_row(key, 1), self.make_row(key, 2)]
        self.assertEqual((None, 2), target.select_record(rows, 0, 0, key, 3, self.constants))
        self.assertEqual((None, 2), target.select_record(rows, 2, 0, key, 0, self.constants))
        self.assertEqual((None, 0), target.select_record([], 0, 1, key, 0, self.constants))

    def test_matched_sentinel_advances_cursor_but_stops_collection(self):
        key = b'A' * 20
        for tag in (3, (1 << 32) + 3):
            rows = [self.make_row(key, 5, tag), self.make_row(key, 6)]
            self.assertEqual((0, 1), target.select_record(rows, 0, 1, key, 0, self.constants))
            self.assertEqual(([], 1, 'selected_sentinel'),
                             target.collect_synthetic(rows, 0, 1, key, 0, self.constants))

    def test_collection_keeps_order_and_stops_at_exhaustion(self):
        key_a, key_b = b'A' * 20, b'B' * 20
        rows = [self.make_row(key_a, 4), self.make_row(key_b, 100), self.make_row(key_a, 5)]
        self.assertEqual(([0, 2], 3, 'exhausted'),
                         target.collect_synthetic(rows, 0, 1, key_a, 999, self.constants))

    def test_start_after_first_does_not_revisit_it(self):
        key = b'A' * 20
        rows = [self.make_row(key, 1), self.make_row(key, 5)]
        self.assertEqual((1, 2), target.select_record(rows, 1, 1, key, 0, self.constants))

    def test_invalid_synthetic_inputs_are_rejected(self):
        key = b'A' * 20
        row = self.make_row(key, 5)
        bad_cases = [([row], -1, 0, key, 0), ([row], 2, 0, key, 0),
                     ([row[:-1]], 0, 0, key, 0), ([row], 0, 256, key, 0),
                     ([row], 0, 0, key[:-1], 0), ([row], 0, 0, 'A' * 20, 0),
                     ([row], 0, 0, key, -1), ([row], 0, 0, key, 1 << 64)]
        for args in bad_cases:
            with self.subTest(args=args[1:]), self.assertRaises(ValueError):
                target.select_record(*args, self.constants)

    def test_selected_record_does_not_mutate_input_fixture(self):
        key = b'A' * 20
        rows = [self.make_row(key, 5)]
        before = rows[:]
        target.select_record(rows, 0, 1, key, 999, self.constants)
        self.assertEqual(before, rows)

    def test_retained_evidence_matches_fresh_generation(self):
        retained = target.ROOT / 'research/work-items/RE-015-name-gated-records-94'
        with tempfile.TemporaryDirectory() as directory:
            produced = Path(directory)
            target.generate(self.data, produced)
            for path in sorted(produced.iterdir()):
                with self.subTest(file=path.name):
                    self.assertEqual(path.read_bytes(), (retained / path.name).read_bytes())


if __name__ == '__main__':
    unittest.main()
