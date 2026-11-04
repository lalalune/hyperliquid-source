"""Offline target-grounded controls for the selected node-115 ABCI path."""

import csv
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import abci_preflight_result115 as subject
from elf_index import sections
from fde_extents import eh_frame_records


class BinaryEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.BINARY.read_bytes()
        subject.verify_digest(cls.data)
        cls.secs = sections(cls.data)

    def test_real_digest(self):
        subject.verify_digest(self.data)

    def test_bad_hash_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            subject.verify_digest(self.data, '0' * 64)

    def test_historical_comparison_rejects_unverified_input(self):
        with self.assertRaisesRegex(ValueError, 'historical node size or SHA-256'):
            subject.historical_crosscheck(self.data, b'not the historical ELF')

    def test_truncated_input_does_not_create_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'missing'
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                subject.generate(memoryview(self.data)[:-1], output)
            self.assertFalse(output.exists())

    def test_bad_digest_does_not_create_output(self):
        data = bytearray(self.data)
        data[-1] ^= 1
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'bad'
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                subject.generate(data, output)
            self.assertFalse(output.exists())

    def test_missing_nobits_and_ambiguous_mapping_rejected(self):
        sec = {'type': 1, 'flags': 6, 'address': 0x100, 'offset': 0, 'size': 4, 'name': '.text'}
        bss = {'type': 8, 'flags': 6, 'address': 0x100, 'offset': 0, 'size': 4, 'name': '.bss'}
        self.assertEqual(subject.file_offset(b'abcd', [sec, bss], 0x100, 4, True), (0, '.text'))
        with self.assertRaises(ValueError):
            subject.file_offset(b'abcd', [bss], 0x100, 1)
        with self.assertRaises(ValueError):
            subject.file_offset(b'abcd', [sec, dict(sec)], 0x100, 1)
        for va, size in ((0xff, 1), (0x104, 1), (0x103, 2), (0x100, 0), (-1, 1)):
            with self.subTest(va=va, size=size), self.assertRaises(ValueError):
                subject.file_offset(b'abcd', [sec], va, size)

    def test_real_bss_is_not_file_data(self):
        bss = next(s for s in self.secs if s['name'] == '.bss')
        self.assertEqual(bss['type'], 8)
        with self.assertRaises(ValueError):
            subject.file_offset(self.data, self.secs, bss['address'], 1)

    def test_selected_windows_reject_edge_and_middle_corruptions(self):
        extents = {start: end for _, start, end in subject.FUNCTIONS}
        for spec in subject.WINDOWS:
            label, owner, start, end, _ = spec
            fde = {'start': owner, 'end': extents[owner]}
            original = subject.checked_window(self.data, self.secs, spec, fde)
            fake = {'type': 1, 'flags': 6, 'address': start, 'offset': 0,
                    'size': len(original), 'name': '.text'}
            for index in sorted({0, len(original) // 2, len(original) - 1}):
                damaged = bytearray(original)
                damaged[index] ^= 1
                with self.subTest(window=label, index=index), self.assertRaisesRegex(ValueError, 'window mismatch'):
                    subject.checked_window(damaged, [fake], spec, fde)

    def test_window_outside_fde_is_rejected(self):
        spec = subject.WINDOWS[0]
        _, owner, _, end, _ = spec
        with self.assertRaisesRegex(ValueError, 'outside'):
            subject.checked_window(self.data, self.secs, spec, {'start': owner, 'end': end - 1})

    def test_every_transfer_is_decoded_and_corruption_rejected(self):
        for spec in subject.TRANSFERS:
            label, site, expected_hex, destination, kind = spec
            raw, actual_kind, actual_destination = subject.checked_transfer(self.data, self.secs, spec)
            self.assertEqual((actual_kind, actual_destination), (kind, destination), label)
            changed = bytearray(raw)
            changed[-1] ^= 1
            fake = {'type': 1, 'flags': 6, 'address': site, 'offset': 0,
                    'size': len(changed), 'name': '.text'}
            with self.subTest(transfer=label), self.assertRaisesRegex(ValueError, 'transfer bytes'):
                subject.checked_transfer(changed, [fake], spec)
            if kind in ('call', 'jmp', 'jcc', 'slot_call', 'slot_jmp'):
                self.assertNotEqual(subject.decode_transfer(site, changed)[1], destination)

    def test_unknown_transfer_encoding_rejected(self):
        for raw in (b'', b'\x90', b'\xe8\0', b'\xff\x14\0\0\0\0'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                subject.decode_transfer(0x1000, raw)

    def test_operand_decoding_and_corrupt_opcode(self):
        actual = {}
        for spec in subject.OPERANDS:
            label, site, _, _, _ = spec
            raw, actual[label] = subject.checked_operand(self.data, self.secs, spec)
            fake = {'type': 1, 'flags': 6, 'address': site, 'offset': 0,
                    'size': len(raw), 'name': '.text'}
            changed = bytearray(raw)
            changed[0] ^= 1
            with self.subTest(operand=label), self.assertRaisesRegex(ValueError, 'operand pattern'):
                subject.checked_operand(changed, [fake], spec)
        self.assertEqual(actual['owner_context'] + actual['context_state_slot'], 0xb00)
        self.assertEqual(actual['pre_counter_read'], actual['handler_counter_write'])
        self.assertEqual(actual['pre_success_read'], actual['handler_success_write'])
        self.assertEqual(actual['precheck_success_tag'], actual['handler_input_tag'])
        self.assertEqual(actual['item_output_stride'], 72)

    def test_every_operand_payload_is_in_a_pinned_window(self):
        extents = {start: end for _, start, end in subject.FUNCTIONS}
        for label, site, prefix, width, suffix in subject.OPERANDS:
            size = len(bytes.fromhex(prefix)) + width + len(bytes.fromhex(suffix))
            matches = [spec for spec in subject.WINDOWS if spec[2] <= site and site + size <= spec[3]]
            self.assertTrue(matches, label)
            spec = matches[0]
            _, owner, start, _, _ = spec
            fde = {'start': owner, 'end': extents[owner]}
            raw = subject.checked_window(self.data, self.secs, spec, fde)
            changed = bytearray(raw)
            changed[site - start + len(bytes.fromhex(prefix))] ^= 1
            fake = {'type': 1, 'flags': 6, 'address': start, 'offset': 0,
                    'size': len(changed), 'name': '.text'}
            with self.subTest(operand=label), self.assertRaisesRegex(ValueError, 'window mismatch'):
                subject.checked_window(changed, [fake], spec, fde)

    def test_literal_bytes_and_references_are_checked(self):
        for spec in subject.LITERALS:
            label, site, va, _, expected = spec
            ref, value = subject.checked_literal(self.data, self.secs, spec, len(expected))
            fake_data = bytearray(ref + value)
            fake_secs = [
                {'name': '.text', 'type': 1, 'flags': 6, 'address': site, 'offset': 0, 'size': len(ref)},
                {'name': '.rodata', 'type': 1, 'flags': 2, 'address': va, 'offset': len(ref), 'size': len(value)},
            ]
            for index in (0, 3, len(ref)):
                changed = bytearray(fake_data)
                changed[index] ^= 1
                with self.subTest(literal=label, index=index), self.assertRaises(ValueError):
                    subject.checked_literal(changed, fake_secs, spec, len(expected))
            with self.subTest(literal=label, length='short'), self.assertRaises(ValueError):
                subject.checked_literal(fake_data, fake_secs, spec, len(expected) - 1)

    def test_original_location(self):
        record = subject.read_location(self.data, self.secs)
        self.assertEqual((record['line'], record['column'], record['path']), (460, 78, 'l1/src/abci/state.rs'))
        self.assertEqual(record['record_va'], '0x64aa208')
        self.assertEqual(record['reference_va'], '0x5485129')

    @staticmethod
    def fake_location():
        data = bytearray(80)
        location, path, site = 0x64aa208, 0x443168, 0x5485129
        data[0:7] = b'\x4c\x8d\x05' + struct.pack('<i', location - site - 7)
        struct.pack_into('<QQII', data, 8, 0, 20, 460, 78)
        data[32:52] = b'l1/src/abci/state.rs'
        struct.pack_into('<QQq', data, 56, location, 8, path)
        secs = [
            {'name': '.text', 'type': 1, 'flags': 6, 'address': site, 'offset': 0, 'size': 7},
            {'name': '.data.rel.ro', 'type': 1, 'flags': 3, 'address': location, 'offset': 8, 'size': 24},
            {'name': '.rodata', 'type': 1, 'flags': 2, 'address': path, 'offset': 32, 'size': 20},
            {'name': '.rela.dyn', 'type': 4, 'flags': 2, 'address': 0x1000, 'offset': 56, 'size': 24},
        ]
        return data, secs

    def test_location_negative_controls(self):
        original, secs = self.fake_location()
        self.assertEqual(subject.read_location(original, secs)['line'], 460)
        # Distinct failures: reference opcode/displacement, path, length, line,
        # column, relocation type and relocation addend.
        for offset in (0, 3, 32, 16, 24, 28, 64, 72):
            damaged = bytearray(original)
            damaged[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                subject.read_location(damaged, secs)
        duplicated = bytearray(original) + original[56:80]
        dup_secs = [dict(s) for s in secs]
        dup_secs[-1]['size'] = 48
        with self.assertRaisesRegex(ValueError, 'exactly one'):
            subject.read_location(duplicated, dup_secs)
        no_data_secs = [dict(s) for s in secs]
        no_data_secs[1]['type'] = 8
        with self.assertRaises(ValueError):
            subject.read_location(original, no_data_secs)

    def test_real_fde_lsda_records_fit_selected_extents(self):
        _, records = eh_frame_records(self.data, self.secs)
        target = next(f for f in records if f['start'] == 0x58679a0)
        gcc = subject.section_once(self.secs, '.gcc_except_table')
        blob = self.data[gcc['offset']:gcc['offset'] + gcc['size']]
        rows = subject.parse_lsda(blob, target['lsda'] - gcc['address'], target['start'], target['end'])
        self.assertTrue(any(start <= 0x5867ade < end for start, end, _, _, _ in rows))
        self.assertTrue(all(target['start'] <= start < end <= target['end'] for start, end, _, _, _ in rows))

    def test_generator_output_and_derived_join(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / 'generated'
            result = subject.generate(self.data, out)
            summary = json.loads((out / 'summary.json').read_text())
            joins = json.loads((out / 'joins.json').read_text())
            self.assertEqual(result['fdes'], len(subject.FUNCTIONS))
            self.assertEqual(summary['selected_windows'], len(subject.WINDOWS))
            self.assertEqual(summary['selected_transfers'], len(subject.TRANSFERS))
            self.assertGreater(summary['lsda_rows'], 0)
            self.assertEqual(joins['owner_relative_state_slot'], '0xb00')
            self.assertEqual(joins['pre_and_handler_counter_offsets'], ['0xb40', '0xb48'])
            self.assertEqual(joins['pre_and_handler_equal_tag'], '0x1a2')
            self.assertEqual(joins['inline_key_item_offset'], '0x3')
            self.assertEqual(joins['tree_key_descriptor_pointer_offset'], '0x28')
            self.assertEqual(joins['tree_key_pointee_offset'], '0x20')
            self.assertEqual(joins['mode2_counter_context_pointer_offset'], '0x458')
            self.assertEqual(joins['mode2_counter_pointee_offset'], '0x10')
            with (out / 'unwind-links.tsv').open(newline='') as f:
                links = list(csv.DictReader(f, delimiter='\t'))
            precheck = next(row for row in links if row['transfer'] == 'precheck_call')
            self.assertIn(precheck['status'], ('landing', 'no_landing'))
            selected_landings = {
                'handler_location_failure': '0x5485171',
                'handler_call': '0x586794f',
                'batch_iterate': '0x5b320b3',
                'item_batch': '0x5867ce6',
                'collector_each': '0x59615a0',
                'collector_group': '0x54866da',
                'group_call': '0x5a06413',
                'precheck_call': '0x5867cce',
                'end_boundary': '0x5a0658b',
            }
            for label, landing in selected_landings.items():
                row = next(row for row in links if row['transfer'] == label)
                self.assertEqual((row['status'], row['landing_va']), ('landing', landing), label)
            destinations = {label: dest for label, _, _, dest, _ in subject.TRANSFERS}
            for label in ('handler_unwind_resume', 'item_unwind_resume', 'batch_unwind_resume',
                          'group_unwind_resume', 'result_unwind_resume', 'collect_unwind_resume',
                          'engine_unwind_resume'):
                self.assertEqual(destinations[label], 0x63f0a50)


class SyntheticControls(unittest.TestCase):
    @staticmethod
    def lsda(table):
        # Omitted LP start; indirect type encoding; uleb call-site fields.
        if len(table) > 120:
            raise ValueError('fixture too long')
        return b'\xff\x9b' + bytes([2 + len(table), 1, len(table)]) + table

    def test_lsda_valid_and_empty_landing(self):
        blob = self.lsda(bytes((0, 5, 6, 0, 6, 3, 0, 0)))
        rows = subject.parse_lsda(blob, 0, 100, 120)
        self.assertEqual(rows, [(100, 105, 106, 0, '00050600'), (106, 109, None, 0, '06030000')])

    def test_lsda_rejects_truncation_overlap_out_of_range_and_encoding(self):
        bad = [
            (b'', 100, 120),
            (b'\x00\x9b\x00\x01\x00', 100, 120),
            (b'\xff\x9b\x80', 100, 120),
            (self.lsda(bytes((0, 5, 6))), 100, 120),
            (self.lsda(bytes((0, 5, 6, 0, 4, 2, 7, 0))), 100, 120),
            (self.lsda(bytes((0, 5, 6, 0))), 100, 104),
            (self.lsda(bytes((0, 5, 21, 0))), 100, 120),
            (self.lsda(bytes((0, 0, 0, 0))), 100, 120),
        ]
        for blob, start, end in bad:
            with self.subTest(blob=blob.hex()), self.assertRaises(ValueError):
                subject.parse_lsda(blob, 0, start, end)

    def test_twenty_byte_comparison_each_byte_and_lengths(self):
        key = bytes(range(20))
        self.assertTrue(subject.same20(key, key))
        for index in range(20):
            changed = bytearray(key)
            changed[index] ^= 1
            self.assertFalse(subject.same20(key, changed), index)
        for size in (0, 19, 21):
            with self.subTest(size=size), self.assertRaises(ValueError):
                subject.same20(key, bytes(size))

    def test_precheck_failure_still_changes_first_counter(self):
        self.assertEqual(subject.selected_counter_case(1, 0x123, 0x1a2, 1, 0x1a2, 4, 7),
                         (5, 7, 'precheck_other_tag'))

    def test_both_stages_increment_in_selected_success_case(self):
        self.assertEqual(subject.selected_counter_case(1, 0x1a2, 0x1a2, 1, 0x1a2, 4, 7),
                         (6, 9, 'both_success_tags'))
        self.assertEqual(subject.selected_counter_case(1, 0x1a2, 0x1a2, 1, 0, 4, 7),
                         (6, 8, 'item_inner_other_tag'))

    def test_skip_or_failed_membership_stops_second_increment(self):
        self.assertEqual(subject.selected_counter_case(0, 0x1a2, 0x1a2, 1, 0x1a2, 4, 7),
                         (4, 7, 'precheck_skipped'))
        self.assertEqual(subject.selected_counter_case(1, 0x1a2, 0x1a2, 0, 0x1a2, 4, 7),
                         (5, 8, 'item_not_admitted'))
        self.assertEqual(subject.selected_counter_case(1, 0x1a2, 0x1a3, 1, 0x1a2, 4, 7),
                         (5, 8, 'item_other_tag'))

    def test_counter_saturation_and_bad_inputs(self):
        m = subject.U64_MAX
        self.assertEqual(subject.sat_inc(m), m)
        self.assertEqual(subject.sat_inc(m - 1), m)
        self.assertEqual(subject.sat_inc(0), 1)
        self.assertEqual(subject.selected_counter_case(1, 0x1a2, 0x1a2, 1, 0x1a2, m - 1, m),
                         (m, m, 'both_success_tags'))
        for n in (-1, m + 1):
            with self.subTest(n=n), self.assertRaises(ValueError):
                subject.sat_inc(n)

    def test_item_state_transition_uses_only_low_tag_word(self):
        self.assertEqual(subject.item_state_advance(0, 99), (1, 1))
        self.assertEqual(subject.item_state_advance(1, 99), (1, 100))
        self.assertEqual(subject.item_state_advance((1 << 32) | 1, 99), ((1 << 32) | 1, 100))
        self.assertEqual(subject.item_state_advance((1 << 32) | 2, 99), (1, 1))
        self.assertEqual(subject.item_state_advance(1, subject.U64_MAX), (1, subject.U64_MAX))
        for tag, count in ((-1, 0), (0, -1), (subject.U64_MAX + 1, 0), (0, subject.U64_MAX + 1)):
            with self.subTest(tag=tag, count=count), self.assertRaises(ValueError):
                subject.item_state_advance(tag, count)

    def test_mode2_increment_wraps_and_then_compares_when_uncontended(self):
        self.assertEqual(subject.sequential_mode2_check(5, 6), (6, True))
        self.assertEqual(subject.sequential_mode2_check(5, 7), (6, False))
        self.assertEqual(subject.sequential_mode2_check(subject.U64_MAX, 0), (0, True))
        self.assertEqual(subject.sequential_mode2_check(subject.U64_MAX, subject.U64_MAX), (0, False))
        for counter, height in ((-1, 0), (0, -1), (subject.U64_MAX + 1, 0)):
            with self.subTest(counter=counter, height=height), self.assertRaises(ValueError):
                subject.sequential_mode2_check(counter, height)

    def test_clock_comparison_is_signed_only_in_first_word(self):
        self.assertFalse(subject.clock_is_later((1, 2, 3), (1, 2, 3)))
        self.assertTrue(subject.clock_is_later((1, 2, 4), (1, 2, 3)))
        self.assertFalse(subject.clock_is_later((0xffffffff, 0, 0), (0, 0, 0)))
        self.assertTrue(subject.clock_is_later((0, 0, 0), (0xffffffff, 0xffffffff, 0xffffffff)))
        self.assertTrue(subject.clock_is_later((0, 0xffffffff, 0), (0, 0, 0xffffffff)))
        with self.assertRaises(ValueError):
            subject.clock_is_later((0, 0), (0, 0, 0))

    def test_result_change_byte_noncanonical_cases(self):
        self.assertEqual(subject.later_change(0, 0, 3, 4), 0)
        self.assertEqual(subject.later_change(0, 1, 3, 4), 1)
        self.assertEqual(subject.later_change(1, 1, 3, 3), 0)
        self.assertEqual(subject.later_change(1, 1, 3, 4), 1)
        self.assertEqual(subject.later_change(2, 0, 3, 4), 2)
        self.assertEqual(subject.later_change(0x100000000, 0, 3, 4), 0)
        with self.assertRaises(ValueError):
            subject.later_change(-1, 0, 0, 0)


if __name__ == '__main__':
    unittest.main()
