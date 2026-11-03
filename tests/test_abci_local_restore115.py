"""Byte-backed controls for the selected node 115 local-state restore path."""
from contextlib import contextmanager
import csv
import io
import json
import mmap
import unittest

from tools import abci_local_restore115 as subject


class LocalStateRestoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.handle = subject.TARGET.open('rb')
        cls.data = mmap.mmap(cls.handle.fileno(), 0, access=mmap.ACCESS_COPY)
        cls.generated = subject.analyse(cls.data)
        cls.sections, table = subject.unwind_index(cls.data)
        _, fdes = subject.eh_frame_records(cls.data, cls.sections)
        wanted = {start for _, start, _, _ in subject.FDE_SPECS}
        cls.table = [row for row in table if row['start'] in wanted]
        cls.fdes = [row for row in fdes if row['start'] in wanted]
        _, cls.selected = subject.check_fdes(cls.data, cls.sections, cls.table, cls.fdes)

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.handle.close()

    @contextmanager
    def flip(self, offset):
        original = self.data[offset]
        try:
            self.data[offset] = original ^ 1
            yield
        finally:
            self.data[offset] = original

    def test_digest_and_selected_denominators(self):
        subject.checked_digest(self.data, subject.SHA115)
        summary = json.loads(self.generated['summary.json'])
        self.assertEqual(summary['artifact_sha256'], subject.SHA115)
        self.assertEqual(summary['selected_counts'], {
            'dispatch.tsv': 21, 'fdes.tsv': 15, 'key-descriptor.tsv': 1, 'literals.tsv': 12,
            'locations.tsv': 4, 'model-cases.tsv': 21, 'operands.tsv': 69,
            'references.tsv': 11, 'relocations.tsv': 4, 'transfers.tsv': 119, 'unwind-links.tsv': 34, 'unwind-sites.tsv': 365,
            'windows.tsv': 56,
        })

    def test_wrong_capture_is_refused_before_parsing(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            subject.analyse(b'\x7fELF\x02\x01')
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            subject.checked_digest(b'not a historical capture', subject.SHA94)

    def test_file_mapping_rejects_nobits_and_unmapped(self):
        bss = next(s for s in self.sections if s['name'] == '.bss' and s['type'] == 8)
        with self.assertRaises(ValueError):
            subject.file_offset(self.data, self.sections, bss['address'], 1)
        with self.assertRaises(ValueError):
            subject.file_offset(self.data, self.sections, (1 << 64) - 1, 2)
        with self.assertRaises(ValueError):
            subject.file_offset(self.data, self.sections, -1, 1)
        with self.assertRaises(ValueError):
            subject.file_offset(self.data, self.sections, 0, 0)

    def test_file_mapping_rejects_ambiguous_sections(self):
        section = next(s for s in self.sections if s['flags'] & 4 and s['size'] and s['type'] != 8)
        with self.assertRaises(ValueError):
            subject.file_offset(self.data, self.sections + [dict(section)], section['address'], 1, True)

    def test_mutated_capture_and_window_are_refused(self):
        off = subject.file_offset(self.data, self.sections, 0x2cc1aa6, 1, True)
        with self.flip(off):
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                subject.checked_digest(self.data, subject.SHA115)
            with self.assertRaisesRegex(ValueError, 'instruction window'):
                subject.check_windows(self.data, self.sections)

    def test_direct_call_displacement_mutation_is_refused(self):
        spec = next(s for s in subject.TRANSFER_SPECS if s[0] == 'read_state')
        off = subject.file_offset(self.data, self.sections, spec[1], 5, True)
        with self.flip(off + 1):
            with self.assertRaisesRegex(ValueError, 'unexpected target'):
                subject.decode_transfer(self.data, self.sections, *spec)

    def test_unexpected_branch_opcode_is_refused(self):
        spec = next(s for s in subject.TRANSFER_SPECS if s[0] == 'freeze_tag_other')
        off = subject.file_offset(self.data, self.sections, spec[1], 2, True)
        with self.flip(off):
            with self.assertRaisesRegex(ValueError, 'opcode'):
                subject.decode_transfer(self.data, self.sections, *spec)

    def test_indirect_call_slot_displacement_mutation_is_refused(self):
        spec = next(s for s in subject.TRANSFER_SPECS if s[0] == 'materializer_prior_boundary')
        off = subject.file_offset(self.data, self.sections, spec[1], 6, True)
        with self.flip(off + 2):
            with self.assertRaisesRegex(ValueError, 'unexpected target'):
                subject.decode_transfer(self.data, self.sections, *spec)

    def test_wrong_field_operand_is_refused(self):
        off = subject.file_offset(self.data, self.sections, 0x2cc1aa6, 7, True)
        with self.flip(off + 2):
            with self.assertRaisesRegex(ValueError, 'freeze_tag'):
                subject.check_operands(self.data, self.sections)

    def test_wrong_dispatch_cell_is_refused(self):
        off = subject.file_offset(self.data, self.sections, 0x60bcf8, 4)
        with self.flip(off):
            with self.assertRaisesRegex(ValueError, 'future_entry'):
                subject.check_tables(self.data, self.sections)

    def test_wrong_relocation_type_is_refused(self):
        rows = subject.check_relocations(self.data, self.sections)
        row = next(r for r in rows if r[0] == 'local_state_location')
        with self.flip(int(row[3], 16) + 8):
            with self.assertRaisesRegex(ValueError, 'local_state_location'):
                subject.check_relocations(self.data, self.sections)

    def test_wrong_relocation_addend_is_refused(self):
        rows = subject.check_relocations(self.data, self.sections)
        row = next(r for r in rows if r[0] == 'materializer_prior_boundary')
        with self.flip(int(row[3], 16) + 16):
            with self.assertRaisesRegex(ValueError, 'materializer_prior_boundary'):
                subject.check_relocations(self.data, self.sections)

    def test_wrong_location_line_is_refused(self):
        off = subject.file_offset(self.data, self.sections, 0x644de70, 24)
        with self.flip(off + 16):
            with self.assertRaisesRegex(ValueError, 'local_state'):
                subject.check_locations(self.data, self.sections)

    def test_wrong_reference_displacement_is_refused(self):
        spec = next(s for s in subject.REFERENCE_SPECS if s[0] == 'cache_key_descriptor')
        off = subject.file_offset(self.data, self.sections, spec[1], 7, True)
        with self.flip(off + 3):
            with self.assertRaisesRegex(ValueError, 'cache_key_descriptor'):
                subject.decode_reference(self.data, self.sections, *spec)

    def test_wrong_key_descriptor_length_is_refused(self):
        off = subject.file_offset(self.data, self.sections, 0x644dae0, 16)
        with self.flip(off + 8):
            with self.assertRaisesRegex(ValueError, 'descriptor'):
                subject.check_key_descriptor(self.data, self.sections)

    def test_wrong_literal_is_refused(self):
        off = subject.file_offset(self.data, self.sections, 0x60eb53, 10)
        with self.flip(off):
            with self.assertRaisesRegex(ValueError, 'cache_key'):
                subject.check_literals(self.data, self.sections)

    def test_changed_fde_range_is_refused(self):
        future = next(row for row in self.fdes if row['start'] == 0x2cc1120)
        off = subject.file_offset(self.data, self.sections, future['fde'], 16)
        with self.flip(off + 12):
            _, altered = subject.eh_frame_records(self.data, self.sections)
            wanted = {start for _, start, _, _ in subject.FDE_SPECS}
            subset = [row for row in altered if row['start'] in wanted]
            with self.assertRaisesRegex(ValueError, 'FDE extent'):
                subject.check_fdes(self.data, self.sections, self.table, subset)

    def test_lsda_encoding_corruption_is_refused(self):
        future = next(fde for name, fde in self.selected if name == 'future')
        off = subject.file_offset(self.data, self.sections, future['lsda'], 1)
        with self.flip(off):
            with self.assertRaisesRegex(ValueError, 'LSDA base encoding'):
                subject.check_lsdas(self.data, self.sections, [('future', future)])

    def test_freeze_guard_unsigned_boundaries(self):
        self.assertEqual(subject.freeze_decision(0, 3, 3), 'skip_tag')
        self.assertEqual(subject.freeze_decision(1, 3, 2), 'past_assert')
        self.assertEqual(subject.freeze_decision(1, 3, 4), 'future_skip')
        self.assertEqual(subject.freeze_decision(1, 3, 3), 'equal_reset')
        self.assertEqual(subject.freeze_decision(0x100000001, 0, 0), 'equal_reset')
        self.assertEqual(subject.freeze_decision(1, 0, subject.MAX64), 'future_skip')
        self.assertEqual(subject.freeze_decision(1, subject.MAX64, 0), 'past_assert')
        for bad in (-1, 1 << 64, True):
            with self.assertRaises(ValueError):
                subject.freeze_decision(1, bad, 0)

    def test_saturating_increment(self):
        self.assertEqual(subject.saturated_increment(0), 1)
        self.assertEqual(subject.saturated_increment(subject.MAX64 - 1), subject.MAX64)
        self.assertEqual(subject.saturated_increment(subject.MAX64), subject.MAX64)
        for bad in (-1, 1 << 64, True):
            with self.assertRaises(ValueError):
                subject.saturated_increment(bad)

    def test_exact_cache_key_and_all_single_byte_mutations(self):
        key = b'abci_state'
        self.assertEqual(subject.selected_suffix(key), 'rmp')
        self.assertEqual(subject.selected_suffix(key[:-1]), 'json')
        self.assertEqual(subject.selected_suffix(key + b'x'), 'json')
        for i in range(len(key)):
            for byte in range(256):
                if byte != key[i]:
                    self.assertEqual(subject.selected_suffix(key[:i] + bytes([byte]) + key[i+1:]), 'json')
        with self.assertRaises(ValueError):
            subject.selected_suffix('abci_state')

    def test_json_trailing_whitespace_all_byte_values(self):
        self.assertEqual({x for x in range(256) if subject.whitespace_byte(x)}, {9, 10, 13, 32})
        with self.assertRaises(ValueError):
            subject.whitespace_byte(256)

    def test_child_dispatch_and_result_field_joins(self):
        text = self.generated['operands.tsv'].decode('utf-8')
        rows = list(csv.DictReader(io.StringIO(text), delimiter='\t'))
        values = {row['name']: int(row['value'], 16) for row in rows}
        self.assertEqual(values['parent_child_state_store'] - values['parent_child_base'],
                         values['future_dispatch_byte'])
        self.assertEqual(values['parent_child_state_zero'], 0)
        self.assertEqual(values['parent_result_pointer_stack'] - values['parent_result_temp'],
                         values['output_state_offset'])
        self.assertEqual(values['choice_high_bit'] + values['choice_high_bit_increment'],
                         0x8000000000000001)
        self.assertEqual(values['reset_source_sequence'], values['reset_incremented_word'])

    def test_tag_classifier_fallback_and_adjacent_values(self):
        self.assertEqual(subject.selection_class(0x8000000000000003), 'context_fallback')
        self.assertEqual(subject.selection_class(0x8000000000000002), 'context_fallback')
        self.assertEqual(subject.selection_class(0x8000000000000001), 'other')
        self.assertEqual(subject.selection_class(0x8000000000000004), 'other')
        self.assertEqual(subject.selection_class(0), 'context_fallback')
        with self.assertRaises(ValueError):
            subject.selection_class(-1)

    def test_fallback_edges_and_error_terminals(self):
        transfers = {row[0]: row for row in subject.check_transfers(self.data, self.sections)}
        self.assertEqual(transfers['fallback_context_mode'][-1], '0x2cc1f06')
        self.assertEqual(transfers['fallback_to_shuffle'][-1], '0x2cc48a0')
        for name in ('fallback_alloc_error_terminal', 'fallback_input_error_terminal', 'fallback_bounds_terminal'):
            self.assertEqual(transfers[name][-1], '0x2cc7f3b')
        spec = next(s for s in subject.TRANSFER_SPECS if s[0] == 'fallback_to_shuffle')
        off = subject.file_offset(self.data, self.sections, spec[1], 5, True)
        with self.flip(off + 1):
            with self.assertRaisesRegex(ValueError, 'unexpected target'):
                subject.decode_transfer(self.data, self.sections, *spec)

    def test_time_gate_modular_boundaries(self):
        self.assertEqual(subject.time_selection(0), 'conversion_call')
        self.assertEqual(subject.time_selection(0x20c49ba5e353f8), 'default_first')
        self.assertEqual(subject.time_selection(0xa8bfffffffff), 'conversion_call')
        self.assertEqual(subject.time_selection(0xa8c000000000), 'default_second')
        self.assertEqual(subject.time_selection(0xffff573ffffeae80), 'default_second')
        self.assertEqual(subject.time_selection(0xffff573ffffeae81), 'conversion_call')
        with self.assertRaises(ValueError):
            subject.time_selection(1 << 64)

    def test_candidate_order_signed_first_unsigned_rest(self):
        self.assertFalse(subject.candidate_ge((0xffffffff, 0xffffffff, 0xffffffff), (0, 0, 0)))
        self.assertTrue(subject.candidate_ge((0, 0, 0), (0xffffffff, 0xffffffff, 0xffffffff)))
        self.assertTrue(subject.candidate_ge((1, 0xffffffff, 0), (1, 0, 0)))
        self.assertFalse(subject.candidate_ge((1, 1, 0), (1, 1, 1)))
        self.assertTrue(subject.candidate_ge((1, 1, 1), (1, 1, 1)))
        with self.assertRaises(ValueError):
            subject.candidate_ge((1, 2), (1, 2, 3))
        with self.assertRaises(ValueError):
            subject.candidate_ge((1, 2, -1), (1, 2, 3))

    def test_parent_unexpected_result_failure_path(self):
        transfers = {row[0]: row for row in subject.check_transfers(self.data, self.sections)}
        self.assertEqual(transfers['parent_unexpected_result_error'][-1], '0x2cbfc40')
        self.assertEqual(transfers['parent_unexpected_result_terminal'][-1], '0x2cbf001')
        self.assertEqual(subject.bytes_at(self.data, self.sections, 0x2cbfc74, 2, True), b'\x0f\x0b')
        self.assertEqual(subject.bytes_at(self.data, self.sections, 0x2cbf001, 2, True), b'\x0f\x0b')
        locations = {row[0]: row for row in subject.check_locations(self.data, self.sections)}
        self.assertEqual(locations['parent_error'][-2:], [355, 17])
        rows = list(csv.DictReader(io.StringIO(self.generated['unwind-links.tsv'].decode()), delimiter='\t'))
        error = next(row for row in rows if row['transfer_name'] == 'parent_error_format')
        self.assertEqual(error['landing_va'], '0x2cbfc76')

    def test_binary_cleanup_table_groups(self):
        rows = subject.check_tables(self.data, self.sections)
        targets = [int(row[6], 16) for row in rows if row[0] == 'binary_error_cleanup']
        self.assertEqual(targets, [0x26a4076, 0x26a4076, 0x26a409f, 0x26a409f,
                                   0x26a409f, 0x26a4084, 0x26a4084])

    def test_unwind_links_protected_calls_and_landings(self):
        rows = list(csv.DictReader(io.StringIO(self.generated['unwind-links.tsv'].decode()), delimiter='\t'))
        links = {row['transfer_name']: row for row in rows}
        self.assertEqual(links['read_state']['landing_va'], '0x2cc464a')
        self.assertEqual(links['binary_decode']['landing_va'], '0x26a38f0')
        self.assertEqual(links['reset_child_a']['landing_va'], '0x2cc4332')
        self.assertEqual(links['reset_child_a']['landing_va'], links['reset_child_b']['landing_va'])
        self.assertEqual(links['reset_child_a']['action'], '0')
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            transfer = next(row for row in subject.check_transfers(self.data, self.sections) if row[0] == 'read_state')
            lsda = subject.check_lsdas(self.data, self.sections, self.selected)
            overlap = [row for row in lsda if row[0] == 'future' and int(row[4], 16) <= 0x2cc1249 < int(row[5], 16)][0]
            subject.link_unwind([transfer], [overlap, overlap])

    def test_selected_unwind_includes_binary_reader_cleanup(self):
        rows = subject.check_lsdas(self.data, self.sections, self.selected)
        reader = [row for row in rows if row[0] == 'path_reader']
        self.assertTrue(any(int(row[4], 16) <= 0x26a38aa < int(row[5], 16) and row[6] for row in reader))
        self.assertTrue(any(row[0] == 'future' and row[6] for row in rows))


if __name__ == '__main__':
    unittest.main()
