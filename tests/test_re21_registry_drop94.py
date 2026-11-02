"""Offline controls for selected node 94 registry cleanup evidence."""
import csv
import io
import json
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import re21_registry_drop94 as re21


class RegistryDropTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Absence is an error: the admitted validation environment has the input.
        cls.target = re21.TARGET.read_bytes()
        cls.sections = re21.sections(cls.target)
        cls.files = re21.extract(cls.target)
        cls.root = ROOT / 'research' / 'work-items' / 'RE-021-blake2b-registry-drop-94'

    def rows(self, filename):
        return list(csv.DictReader(io.StringIO(self.files[filename].decode('ascii')), delimiter='\t'))

    def body(self, start):
        end = re21.FUNCTIONS[start][0]
        return re21.read_va(self.target, self.sections, start, end - start, executable=True)

    def test_target_digest(self):
        self.assertEqual(re21.digest(self.target), re21.TARGET_SHA256)

    def test_wrong_digest_rejected(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            re21.verify_digest(b'not the captured target')

    def test_corrupt_input_is_rejected_before_elf_parsing(self):
        with patch.object(re21, 'sections', side_effect=AssertionError('parsed before digest')):
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                re21.extract(b'not the captured target')

    def test_each_generated_file_matches_retained_evidence(self):
        for name, expected in self.files.items():
            with self.subTest(name=name):
                self.assertEqual((self.root / name).read_bytes(), expected)

    def test_summary_denominator_and_no_execution(self):
        summary = json.loads(self.files['summary.json'])
        self.assertEqual(summary['selected_fde_count'], len(re21.FUNCTIONS))
        self.assertEqual(summary['selected_code_bytes'], 2742)
        self.assertEqual(summary['lsda_tables'], 12)
        self.assertFalse(summary['captured_execution'])

    def test_bss_is_not_file_backed(self):
        bss = next(s for s in self.sections if s['name'] == '.bss')
        self.assertEqual(bss['type'], 8)
        with self.assertRaises(ValueError):
            re21.file_offset(self.sections, bss['address'], 1)

    def test_address_outside_sections_rejected(self):
        with self.assertRaises(ValueError):
            re21.file_offset(self.sections, 0, 1)

    def test_reject_empty_and_negative_ranges(self):
        with self.assertRaises(ValueError):
            re21.file_offset(self.sections, 0x4e95310, 0)
        with self.assertRaises(ValueError):
            re21.file_offset(self.sections, -1, 1)

    def test_reject_cross_section_range(self):
        sec = {'type': 1, 'flags': 6, 'address': 0x1000, 'size': 8, 'offset': 0}
        with self.assertRaises(ValueError):
            re21.file_offset([sec], 0x1007, 2)

    def test_reject_ambiguous_va(self):
        a = {'type': 1, 'flags': 6, 'address': 0x1000, 'size': 8, 'offset': 0}
        b = {'type': 1, 'flags': 6, 'address': 0x1000, 'size': 8, 'offset': 20}
        with self.assertRaises(ValueError):
            re21.file_offset([a, b], 0x1000, 1)

    def test_reject_nonexecutable_code_read(self):
        sec = {'type': 1, 'flags': 2, 'address': 0x1000, 'size': 8, 'offset': 0}
        with self.assertRaises(ValueError):
            re21.file_offset([sec], 0x1000, 1, executable=True)

    def test_corrupted_instruction_bytes_fail_pin(self):
        sec = {'type': 1, 'flags': 6, 'address': 0x1000, 'size': 4, 'offset': 0}
        expected = bytes.fromhex('4883f802')
        self.assertEqual(re21.checked_pin(expected, [sec], 0x1000, expected), expected)
        damaged = expected[:-1] + bytes([expected[-1] ^ 1])
        with self.assertRaisesRegex(ValueError, 'predicate'):
            re21.checked_pin(damaged, [sec], 0x1000, expected)

    def test_empty_pin_rejected(self):
        with self.assertRaises(ValueError):
            re21.checked_pin(b'', [], 0, b'')

    def test_layout_operands_are_read_from_instruction_bytes(self):
        rows = {r['site_va']: r for r in self.rows('operands.tsv')}
        self.assertEqual(rows['0x4e9531e']['decoded_value'], '8')
        self.assertEqual(rows['0x4e95335']['decoded_value'], '24')
        self.assertEqual(rows['0x4e95389']['decoded_value'], '-768')
        self.assertEqual(rows['0x4e95451']['decoded_value'], '-48')
        self.assertEqual(rows['0x4e9d109']['decoded_value'], '48')

    def test_operand_extractor_rejects_out_of_bounds(self):
        with self.assertRaisesRegex(ValueError, 'outside'):
            re21.operand_value(bytes.fromhex('488b4708'), 3, 2, False)
        with self.assertRaises(ValueError):
            re21.operand_value(bytes.fromhex('488b4708'), -1, 1, False)

    def test_lea_scale_is_decoded_and_wrong_register_rejected(self):
        self.assertEqual(re21.same_register_lea_factor(bytes.fromhex('488d0440')), 3)
        self.assertEqual(re21.same_register_lea_factor(bytes.fromhex('488d04b6')), 5)
        with self.assertRaisesRegex(ValueError, 'same register'):
            re21.same_register_lea_factor(bytes.fromhex('488d0441'))

    def test_relocation_type_and_addend(self):
        rows = re21.relocations(self.target, self.sections)
        self.assertEqual(re21.relative_relocation(rows, 0x57733e0, 0x4e9e470)['info'], 8)
        with self.assertRaises(ValueError):
            re21.relative_relocation(rows, 0x57733e0, 0x4e9e471)
        altered = {0x57733e0: dict(rows[0x57733e0], info=6)}
        with self.assertRaises(ValueError):
            re21.relative_relocation(altered, 0x57733e0, 0x4e9e470)

    def test_missing_relocation_rejected(self):
        with self.assertRaises(ValueError):
            re21.relative_relocation({}, 0x57733e0, 0x4e9e470)

    def test_relocation_with_symbol_index_is_not_relative(self):
        rows = {0x57733e0: {'info': (1 << 32) | 8, 'addend': 0x4e9e470}}
        with self.assertRaises(ValueError):
            re21.relative_relocation(rows, 0x57733e0, 0x4e9e470)

    def test_duplicate_relocation_slot_rejected(self):
        record = struct.pack('<QQq', 0x1000, 8, 0x2000)
        secs = [
            {'name': '.rela.dyn', 'type': 4, 'flags': 2, 'address': 1, 'offset': 0, 'size': 24},
            {'name': '.rela.plt', 'type': 4, 'flags': 2, 'address': 2, 'offset': 24, 'size': 24},
        ]
        with self.assertRaisesRegex(ValueError, 'duplicate relocation'):
            re21.relocations(record + record, secs)

    def test_unwind_plt_relocation_and_symbol(self):
        row = json.loads(self.files['unwind-import.json'])
        self.assertEqual(row['symbol_name'], '_Unwind_Resume')
        self.assertEqual(row['plt_va'], '0x5660110')
        self.assertEqual(row['slot_va'], '0x5778db0')

    def test_corrupt_plt_opcode_rejected(self):
        with self.assertRaises(ValueError):
            re21.plt_slot(bytes.fromhex('ff159a8c1100'), 0x5660110)
        with self.assertRaises(ValueError):
            re21.plt_slot(b'\xff\x25', 0x5660110)

    def test_unwind_wrong_relocation_rejected(self):
        rows = re21.relocations(self.target, self.sections)
        rows[0x5778db0] = dict(rows[0x5778db0], info=8)
        with self.assertRaisesRegex(ValueError, 'PLT relocation'):
            re21.unwind_import(self.target, self.sections, rows)

    def test_unwind_wrong_dynamic_symbol_rejected(self):
        plt = bytes.fromhex('ff259a8c1100')
        symbols = bytes(24) + struct.pack('<I', 1) + bytes(20)
        strings = b'\0wrong_name\0'
        data = plt + symbols + strings
        secs = [
            {'name': '.plt', 'type': 1, 'flags': 6, 'address': 0x5660110,
             'offset': 0, 'size': len(plt)},
            {'name': '.dynsym', 'type': 11, 'flags': 2, 'address': 1,
             'offset': len(plt), 'size': len(symbols)},
            {'name': '.dynstr', 'type': 3, 'flags': 2, 'address': 2,
             'offset': len(plt) + len(symbols), 'size': len(strings)},
        ]
        rel = {0x5778db0: {'section': '.rela.plt', 'info': (1 << 32) | 7,
                            'file_offset': 0, 'raw': ''}}
        with self.assertRaisesRegex(ValueError, 'unexpected unwind import'):
            re21.unwind_import(data, secs, rel)

    def test_unsupported_opcode_rejected(self):
        with self.assertRaises(ValueError):
            re21.walk(b'\x0f\xff')

    def test_truncated_instruction_rejected(self):
        with self.assertRaises(ValueError):
            re21.walk(b'\xe8\x00')

    def test_branch_into_instruction_rejected(self):
        with self.assertRaisesRegex(ValueError, 'instruction interior'):
            re21.walk(b'\xeb\xff\xc3')

    def test_control_decision_precedence(self):
        self.assertEqual([re21.model_tag(i) for i in (0, 1, 2, 3)],
                         ['no_value_cleanup', 'no_value_cleanup',
                          'atomic_primary_decrement', 'virtual_payload_cleanup'])

    def test_high_tag_bits_show_two_distinct_comparison_widths(self):
        # These are malformed synthetic tags, not claimed target values.
        self.assertEqual(re21.model_tag(0x100000002), 'atomic_primary_decrement')
        self.assertEqual(re21.model_tag(0x100000000), 'virtual_payload_cleanup')

    def test_tag_outside_word_rejected_by_model(self):
        for tag in (-1, 1 << 64, True):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                re21.model_tag(tag)

    def test_primary_count_last_reference(self):
        self.assertEqual(re21.model_counter(1), (0, True))
        self.assertEqual(re21.model_counter(2), (1, False))

    def test_zero_counter_wraps_in_synthetic_projection(self):
        self.assertEqual(re21.model_counter(0), ((1 << 64) - 1, False))

    def test_counter_input_bounds(self):
        for n in (-1, 1 << 64, False):
            with self.subTest(n=n), self.assertRaises(ValueError):
                re21.model_counter(n)

    def test_occupied_control_scan_across_group_boundary(self):
        controls = bytearray([0xff] * 32)
        for index, value in ((0, 0), (15, 0x7f), (16, 0x42), (31, 1)):
            controls[index] = value
        controls[7] = 0x80
        controls[8] = 0xfe
        self.assertEqual(re21.model_control_scan(bytes(controls), 4), [0, 15, 16, 31])

    def test_control_scan_stops_after_declared_count(self):
        controls = bytes([0, 1] + [0xff] * 14)
        self.assertEqual(re21.model_control_scan(controls, 1), [0])
        self.assertEqual(re21.model_control_scan(controls, 0), [])

    def test_control_scan_rejects_synthetic_shortage(self):
        with self.assertRaisesRegex(ValueError, 'exhausted'):
            re21.model_control_scan(bytes([0xff] * 16), 1)
        with self.assertRaises(ValueError):
            re21.model_control_scan(bytes(15), 1)

    def test_map_and_set_backing_geometry(self):
        self.assertEqual(re21.model_backing(3, 48), (192, 212))
        self.assertEqual(re21.model_backing(7, 48), (384, 408))
        self.assertEqual(re21.model_backing(3, 20), (80, 100))
        self.assertEqual(re21.model_backing(7, 20), (160, 184))
        self.assertEqual(re21.model_backing(15, 20), (320, 352))

    def test_invalid_map_geometry_rejected(self):
        for mask in (0, 2, 8, -1, 1 << 60):
            with self.subTest(mask=mask), self.assertRaises(ValueError):
                re21.model_backing(mask, 48)
        with self.assertRaises(ValueError):
            re21.model_backing(7, 24)

    def test_secondary_allocation_geometry(self):
        self.assertEqual(re21.model_secondary_layout(0, 1), 16)
        self.assertEqual(re21.model_secondary_layout(1, 8), 24)
        self.assertEqual(re21.model_secondary_layout(17, 16), 48)
        self.assertEqual(re21.model_secondary_layout(33, 32), 64)

    def test_payload_offset_and_allocation_round_up(self):
        for exponent in range(15):
            alignment = 1 << exponent
            self.assertEqual(re21.model_payload_offset(alignment), max(16, alignment))
            for size in (0, 1, 15, 16, 17, 255):
                a = max(8, alignment)
                expected = ((size + 16 + a - 1) // a) * a
                self.assertEqual(re21.model_secondary_layout(size, alignment), expected)

    def test_payload_offset_model_rejects_nonpower_alignment(self):
        for alignment in (0, 3, -1):
            with self.subTest(alignment=alignment), self.assertRaises(ValueError):
                re21.model_payload_offset(alignment)

    def test_invalid_secondary_alignment_rejected_by_model(self):
        for align in (0, 3, -1):
            with self.subTest(align=align), self.assertRaises(ValueError):
                re21.model_secondary_layout(4, align)

    def test_fde_end_and_file_offsets(self):
        for row in self.rows('functions.tsv'):
            start = int(row['start_va'], 16)
            self.assertEqual(int(row['end_va_exclusive'], 16), re21.FUNCTIONS[start][0])
            self.assertEqual(int(row['file_offset'], 16),
                             re21.file_offset(self.sections, start, int(row['size']), executable=True))

    def test_fde_join_rejects_missing_and_duplicate_records(self):
        queries = {0x1000: (0x1005, 'example')}
        fde = {'start': 0x1000, 'end': 0x1005, 'fde': 0x2000}
        index = [{'start': 0x1000, 'fde': 0x2000}]
        self.assertEqual(re21.select_fdes([fde], index, queries)[0x1000], fde)
        with self.assertRaisesRegex(ValueError, 'missing or duplicated'):
            re21.select_fdes([], index, queries)
        with self.assertRaisesRegex(ValueError, 'missing or duplicated'):
            re21.select_fdes([fde, fde], index, queries)

    def test_fde_join_rejects_changed_bounds_and_pointer(self):
        queries = {0x1000: (0x1005, 'example')}
        fde = {'start': 0x1000, 'end': 0x1006, 'fde': 0x2000}
        index = [{'start': 0x1000, 'fde': 0x2000}]
        with self.assertRaisesRegex(ValueError, 'extent'):
            re21.select_fdes([fde], index, queries)
        fde['end'] = 0x1005
        with self.assertRaisesRegex(ValueError, 'index mismatch'):
            re21.select_fdes([fde], [{'start': 0x1000, 'fde': 0x2001}], queries)

    def test_fde_join_rejects_duplicate_index(self):
        queries = {0x1000: (0x1005, 'example')}
        fde = {'start': 0x1000, 'end': 0x1005, 'fde': 0x2000}
        index = [{'start': 0x1000, 'fde': 0x2000}] * 2
        with self.assertRaisesRegex(ValueError, 'duplicate selected unwind'):
            re21.select_fdes([fde], index, queries)

    def test_original_address_nine_anchor(self):
        row = json.loads(self.files['address-anchor.json'])
        self.assertEqual(row['tag'], 0)
        self.assertEqual(bytes.fromhex(row['address_raw']), bytes(19) + b'\x09')
        self.assertEqual(re21.model_tag(row['tag']), 'no_value_cleanup')

    def test_aggregate_to_map_and_set_edges(self):
        rows = self.rows('transfers.tsv')
        pairs = {(r['site_va'], r['relative_target_va']) for r in rows}
        self.assertIn(('0x4e98b67', '0x4e95310'), pairs)
        self.assertIn(('0x4e98bc0', '0x4e952d0'), pairs)

    def test_prior_caller_boundaries_resolve_from_call_bytes(self):
        rows = self.rows('prior-boundary-calls.tsv')
        self.assertEqual(len(rows), len(re21.BOUNDARY_CALLS))
        for row in rows:
            site = int(row['call_va'], 16)
            target = re21.rel32_call_target(bytes.fromhex(row['raw']), site)
            self.assertEqual(target, int(row['target_va'], 16))
            self.assertIn(target, re21.FUNCTIONS)

    def test_bad_boundary_call_opcode_or_displacement(self):
        with self.assertRaises(ValueError):
            re21.rel32_call_target(bytes.fromhex('e974b9ffff'), 0x4e99997)
        original = bytes.fromhex('e874b9ffff')
        changed = original[:-1] + bytes([original[-1] ^ 1])
        self.assertNotEqual(re21.rel32_call_target(original, 0x4e99997),
                            re21.rel32_call_target(changed, 0x4e99997))

    def test_indirect_primary_release_slot_resolves(self):
        rows = self.rows('transfers.tsv')
        matches = [r for r in rows if r['site_va'] == '0x4e953d1']
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]['rip_target_va'], '0x57733e0')
        self.assertEqual(matches[0]['relative_relocation_addend'], '0x4e9e470')
        self.assertEqual(matches[0]['scope'], 'selected_entry')

    def test_unwind_release_edge_is_bound(self):
        rows = self.rows('exception-edges.tsv')
        self.assertIn(('0x4e9e498', '0x4e9e4f2', '0'),
                      {(r['call_va'], r['landing_va'], r['action']) for r in rows})
        self.assertIn(('0x4e98b67', '0x4e98bb6', '0'),
                      {(r['call_va'], r['landing_va'], r['action']) for r in rows})

    def test_primary_release_call_has_no_local_landing_in_map(self):
        rows = self.rows('exception-calls.tsv')
        matches = [r for r in rows if r['call_va'] == '0x4e953d1']
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]['relocation_addend'], '0x4e9e470')
        self.assertEqual(matches[0]['landing_va'], '')
        self.assertEqual(matches[0]['action'], '0')

    def test_cleanup_during_unwind_has_separate_landing(self):
        rows = self.rows('exception-edges.tsv')
        self.assertIn(('0x4e9d20c', '0x4e9d23a', '1'),
                      {(r['call_va'], r['landing_va'], r['action']) for r in rows})

    def test_four_cleanup_bodies_agree_only_after_resolved_masks(self):
        rows = self.rows('cleanup-comparison.tsv')
        self.assertEqual(len(rows), 4)
        self.assertEqual(len({r['raw_sha256'] for r in rows}), 4)
        self.assertEqual(len({r['masked_sha256'] for r in rows}), 1)
        self.assertEqual([int(r['masked_fields']) for r in rows], [4] * 4)

    def test_corrupt_relocation_displacement_not_masked_away(self):
        start = 0x4e9bb90
        body = bytearray(self.body(start))
        body[0x4e9bbbe - start] ^= 1
        with self.assertRaisesRegex(ValueError, 'RIP target'):
            re21.normalize_drop(bytes(body), start)

    def test_mask_cannot_swap_two_otherwise_allowed_slots(self):
        start = 0x4e9bb90
        body = bytearray(self.body(start))
        call_site = start + 0x2c
        wrong_but_known_slot = 0x576e010
        struct.pack_into('<i', body, 0x2e, wrong_but_known_slot - (call_site + 6))
        with self.assertRaisesRegex(ValueError, 'RIP target'):
            re21.normalize_drop(bytes(body), start)

    def test_mask_cannot_hide_changed_unwind_call(self):
        start = 0x4e9bb90
        body = bytearray(self.body(start))
        body[0xa7] ^= 1
        with self.assertRaisesRegex(ValueError, 'relative call'):
            re21.normalize_drop(bytes(body), start)

    def test_nonmasked_corruption_changes_comparison(self):
        start = 0x4e9bb90
        original = self.body(start)
        masked, _ = re21.normalize_drop(original, start)
        mutated = bytearray(original)
        # Different but still decodable register-save prefix.
        mutated[0] ^= 1
        altered, _ = re21.normalize_drop(bytes(mutated), start)
        self.assertNotEqual(masked, altered)

    def test_lsda_record_parser_and_corruption(self):
        raw = bytes.fromhex('ffff010400010200')
        sec = {'name': '.gcc_except_table', 'type': 1, 'flags': 2,
               'address': 0x2000, 'offset': 0, 'size': len(raw)}
        fde = {'start': 0x1000, 'end': 0x1003, 'lsda': 0x2000}
        row = re21.lsda_records(raw, [sec], fde)
        self.assertEqual(row['entries'][0]['landing_va'], '0x1002')
        bad = bytes([0]) + raw[1:]
        with self.assertRaisesRegex(ValueError, 'LPStart'):
            re21.lsda_records(bad, [sec], fde)

    def test_lsda_outside_function_rejected(self):
        raw = bytes.fromhex('ffff010400010400')
        sec = {'name': '.gcc_except_table', 'type': 1, 'flags': 2,
               'address': 0x2000, 'offset': 0, 'size': len(raw)}
        fde = {'start': 0x1000, 'end': 0x1003, 'lsda': 0x2000}
        with self.assertRaisesRegex(ValueError, 'landing outside'):
            re21.lsda_records(raw, [sec], fde)

    def test_lsda_length_cannot_extend_beyond_section(self):
        raw = bytes.fromhex('ffff010500010200')
        sec = {'name': '.gcc_except_table', 'type': 1, 'flags': 2,
               'address': 0x2000, 'offset': 0, 'size': len(raw)}
        fde = {'start': 0x1000, 'end': 0x1003, 'lsda': 0x2000}
        with self.assertRaisesRegex(ValueError, 'call-site extent'):
            re21.lsda_records(raw, [sec], fde)

    def test_truncated_uleb_rejected(self):
        with self.assertRaises(ValueError):
            re21.uleb(b'\x80', 0, 1)

    def test_expected_input_never_skips(self):
        self.assertTrue(re21.TARGET.is_file())


if __name__ == '__main__':
    unittest.main()
