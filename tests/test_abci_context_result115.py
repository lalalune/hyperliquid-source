# SPDX-License-Identifier: MIT
"""Negative and boundary controls for the selected node 115 state handoff."""

import csv
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

from tools import abci_context_result115 as evidence


class ContextResultEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = evidence.TARGET.read_bytes()
        cls.sections = evidence.sections(cls.data)
        cls.outputs = evidence.analyze(cls.data)
        cls.layout = json.loads(cls.outputs['layout.json'])
        cls.arithmetic = json.loads(cls.outputs['arithmetic.json'])
        cls.summary = json.loads(cls.outputs['summary.json'])

    @classmethod
    def read(cls, va, size, executable=False):
        return evidence.read_va(cls.data, cls.sections, va, size, executable)

    def test_target_and_selected_fdes(self):
        self.assertEqual(self.summary['target_sha256'], evidence.SHA256)
        functions = json.loads(self.outputs['functions.json'])
        self.assertEqual(len(functions), 12)
        self.assertEqual([int(f['start_va'], 16) for f in functions],
                         [start for _, start, _ in evidence.FUNCTIONS])
        for row in functions:
            self.assertEqual(len(bytes.fromhex(row['body_hex'])), row['length'])
            self.assertEqual(int(row['end_va_exclusive'], 16) - int(row['start_va'], 16), row['length'])
            self.assertEqual(row['section'], '.text')

    def test_bad_hash_or_truncated_input_fails_before_output(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            bad = base / 'bad-node'
            out = base / 'evidence'
            bad.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                evidence.generate(bad, out)
            self.assertFalse(out.exists())
        modified = bytearray(self.data)
        modified[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            evidence.check_identity(modified)

    def test_all_windows_reject_corrupted_target_bytes(self):
        for label, _, va, hx in evidence.PINS:
            expected = bytes.fromhex(hx)
            self.assertEqual(evidence.validate_window(self.read, label, va, hx), expected)
            for pos in (0, len(expected) - 1):
                changed = bytearray(expected)
                changed[pos] ^= 1
                def changed_read(address, size, executable=False):
                    self.assertEqual((address, size, executable), (va, len(expected), True))
                    return bytes(changed)
                with self.subTest(window=label, pos=pos), self.assertRaisesRegex(ValueError, 'window mismatch'):
                    evidence.validate_window(changed_read, label, va, hx)

    def test_corrupted_real_branch_is_rejected_after_private_hash_bypass(self):
        changed = bytearray(self.data)
        off, _ = evidence.file_mapping(self.sections, 0x5a8b15f, 1, True)
        changed[off] ^= 1
        with mock.patch.object(evidence, 'check_identity'):
            with self.assertRaisesRegex(ValueError, 'window mismatch'):
                evidence.analyze(changed)

    def test_actual_fde_range_mutation_is_rejected(self):
        rows = json.loads(self.outputs['functions.json'])
        fde_va = int(next(r for r in rows if r['label'] == 'pending_drain')['fde_va'], 16)
        off, _ = evidence.file_mapping(self.sections, fde_va, 16)
        changed = bytearray(self.data)
        changed[off + 12] ^= 1
        with mock.patch.object(evidence, 'check_identity'):
            with self.assertRaisesRegex(ValueError, 'FDE extent or header mismatch'):
                evidence.analyze(changed)

    def test_select_fde_rejects_duplicate_overlap_and_header_mismatch(self):
        good = [{'start': 10, 'end': 20, 'fde': 100}]
        header = [{'start': 10, 'fde': 100, 'index': 0}]
        spec = [('test', 10, 20)]
        self.assertEqual(len(evidence.selected_fdes(good, header, spec)), 1)
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            evidence.selected_fdes(good + [dict(good[0])], header, spec)
        with self.assertRaisesRegex(ValueError, 'overlapping'):
            evidence.selected_fdes(good + [{'start': 19, 'end': 30, 'fde': 200}], header, spec)
        with self.assertRaisesRegex(ValueError, 'mismatch'):
            evidence.selected_fdes(good, [{'start': 10, 'fde': 101}], spec)
        with self.assertRaisesRegex(ValueError, 'mismatch'):
            evidence.selected_fdes([{'start': 10, 'end': 21, 'fde': 100}], header, spec)

    def test_section_file_backing_and_boundaries(self):
        row = {'name': 'code', 'type': 1, 'flags': 6, 'address': 100, 'offset': 9, 'size': 10}
        self.assertEqual(evidence.file_mapping([row], 100, 10, True), (9, 'code'))
        for address, size in ((99, 1), (109, 2), (100, 0), (-1, 1)):
            with self.subTest(address=address, size=size), self.assertRaises(ValueError):
                evidence.file_mapping([row], address, size, True)
        with self.assertRaises(ValueError):
            evidence.file_mapping([dict(row, type=8)], 100, 1, True)
        with self.assertRaises(ValueError):
            evidence.file_mapping([dict(row, flags=2)], 100, 1, True)
        with self.assertRaises(ValueError):
            evidence.file_mapping([row, dict(row, name='other')], 100, 1, True)
        with self.assertRaises(ValueError):
            evidence.unique_section([row, dict(row)], 'code')

    def test_bad_or_duplicate_relocations_are_rejected(self):
        slot = 0x64e72a0
        wanted = {slot: evidence.RELOCATION_EXPECTATIONS[slot]}
        entry = struct.pack('<QQq', slot, 8, 0x5a8b130)
        row = {'name': '.rela.dyn', 'type': 4, 'flags': 2, 'address': 0, 'offset': 0, 'size': 24}
        self.assertEqual(evidence.parse_relocations(entry, [row], wanted)[slot]['addend'], 0x5a8b130)
        for blob, section in (
            (struct.pack('<QQq', slot, 7, 0x5a8b130), row),
            (struct.pack('<QQq', slot, 8, 0x5a8b131), row),
            (entry + entry, dict(row, size=48)),
            (entry[:-1], dict(row, size=23)),
            (bytes(24), row),
        ):
            with self.subTest(blob=blob.hex()), self.assertRaises(ValueError):
                evidence.parse_relocations(blob, [section], wanted)

    def test_lsda_call_site_bounds_and_encodings(self):
        good = bytes.fromhex('ffff010401020300')
        section = {'name': '.gcc_except_table', 'type': 1, 'flags': 2,
                   'address': 200, 'offset': 0, 'size': len(good)}
        sites = evidence.lsda_sites(good, [section], 100, 110, 200)
        self.assertEqual(sites, [(4, 101, 103, 103, 0)])
        typed = bytes.fromhex('ff9b06010401020300')
        typed_section = dict(section, size=len(typed))
        self.assertEqual(evidence.lsda_sites(typed, [typed_section], 100, 110, 200),
                         [(5, 101, 103, 103, 0)])
        for bad in (bytes.fromhex('ff9b05010401020300'),
                    bytes.fromhex('00ff010401020300'),
                    bytes.fromhex('fffe010401020300'),
                    bytes.fromhex('ffff020401020300'),
                    bytes.fromhex('ffff010501020300'),
                    bytes.fromhex('ffff010401020b00'),
                    bytes.fromhex('ffff01040a020300'),
                    bytes.fromhex('ffff01080102030001020300')):
            bad_section = dict(section, size=len(bad))
            with self.subTest(bad=bad.hex()), self.assertRaises(ValueError):
                evidence.lsda_sites(bad, [bad_section], 100, 110, 200)
        with self.assertRaises(ValueError):
            evidence.lsda_sites(good, [dict(section, type=8)], 100, 110, 200)
        with self.assertRaises(ValueError):
            evidence.lsda_sites(good, [section], 100, 110, 199)

    def test_real_lsda_landing_mutation_is_rejected(self):
        changed = bytearray(self.data)
        off, _ = evidence.file_mapping(self.sections, 0x255f07, 1)
        changed[off] ^= 1
        with mock.patch.object(evidence, 'check_identity'):
            with self.assertRaisesRegex(ValueError, 'cleanup landing mismatch'):
                evidence.analyze(changed)

    def test_real_failure_landings_cover_the_relevant_calls(self):
        rows = [line.split('\t') for line in self.outputs['landings.tsv'].splitlines()[1:]]
        for label, call, target in (('callback_adapter', 0x2a929ba, '0x2a929d0'),
                                    ('pending_drain', 0x5a8b1f2, '0x5a8b3be'),
                                    ('pending_drain', 0x5a8b29a, '0x5a8b390'),
                                    ('pending_drain', 0x5a8b32b, '0x5a8b380')):
            matches = [r for r in rows if r[0] == label and int(r[3], 16) <= call < int(r[4], 16)]
            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0][5], target)

    def test_source_location_and_dynamic_copy_binding(self):
        location = json.loads(self.outputs['location.json'])
        self.assertEqual((location['source_path'], location['line'], location['column']),
                         ('l1/src/abci/state.rs', 123, 37))
        self.assertEqual(evidence.symbol_name(self.data, self.sections, 7), 'memcpy')
        with self.assertRaises(ValueError):
            evidence.symbol_name(self.data, self.sections, 1 << 31)

    def test_corrupted_location_is_rejected_after_private_hash_bypass(self):
        changed = bytearray(self.data)
        off, _ = evidence.file_mapping(self.sections, 0x64767a8 + 16, 1)
        changed[off] ^= 1
        with mock.patch.object(evidence, 'check_identity'):
            with self.assertRaisesRegex(ValueError, 'Location mismatch'):
                evidence.analyze(changed)

    def test_decoded_transfer_targets_and_out_of_range(self):
        target, raw = evidence.relative_target(self.read, 0x5a8b15e, branch=True)
        self.assertEqual((target, raw), (0x5a8b350, bytes.fromhex('0f80ec010000')))
        target, raw = evidence.relative_target(self.read, 0x2aaea4c)
        self.assertEqual(target, 0x64e72a0)
        self.assertEqual(raw[:2], bytes.fromhex('ff15'))
        with self.assertRaises(ValueError):
            evidence.relative_target(self.read, 0x5a8b15e, branch=False)
        with self.assertRaises(ValueError):
            evidence.relative_target(self.read, 0, branch=True)

    def test_context_and_closure_offsets(self):
        layout = self.layout
        self.assertEqual(layout['assembler_input_length_from_caller'], 16)
        self.assertEqual(layout['context_pointer_offset'], '0x450')
        self.assertEqual(layout['assembler_context_offset'], '0x6b0')
        self.assertEqual(layout['assembler_state_pointer_offset'], '0xb00')
        self.assertEqual(layout['future_owner_offset'], '0x838')
        self.assertEqual(layout['closure_owner_offset'], layout['drain_owner_offset'])
        self.assertEqual(layout['callback_target_va'], '0x2a92960')
        self.assertEqual(layout['callback_payload_size'], 0x718)
        self.assertEqual(layout['constructor_header_bytes'], 0x10)
        self.assertEqual(layout['drain_body_adjustment'], 0x10)
        self.assertEqual(layout['read_state_word_offset'], '0x28')
        self.assertEqual(layout['drain_pending_offset'], '0x5f8')
        self.assertEqual(layout['serializer_resps_offset'], '0x58')
        self.assertEqual(layout['serializer_resps_tag'], 2)
        self.assertEqual(layout['serializer_height_offset'], '0x80')

    def test_copy_boundaries_keep_pointer_only_when_fully_included(self):
        token = bytes.fromhex('1122334455667788')
        input_context = bytearray(0x470)
        input_context[0x450:0x458] = token
        temporary = bytearray(0x478)
        temporary[8:8 + len(input_context)] = input_context
        owner = bytearray(0xb28)
        owner[0x6a8:0x6a8 + len(temporary)] = temporary
        self.assertEqual(owner[0xb00:0xb08], token)
        truncated = bytearray(0xb28)
        truncated[0x6a8:0x6a8 + 0x45f] = temporary[:0x45f]
        self.assertNotEqual(truncated[0xb00:0xb08], token)
        future = bytearray(0x6c0)
        future[0x6a0:0x6a8] = token
        closure = bytes(future)
        self.assertEqual(closure[0x6a0:0x6a8], token)
        self.assertNotEqual(closure[0x69f:0x6a7], token)

    def test_pending_take_sets_sentinel_and_second_take_is_empty(self):
        sentinel = int(self.arithmetic['drain_empty_sentinel'], 16)
        for old in (0, 1, sentinel - 1, sentinel + 1, evidence.MASK64):
            new, should_drain = evidence.take_pending(old)
            self.assertTrue(should_drain)
            self.assertEqual(new, sentinel)
            self.assertEqual(evidence.take_pending(new), (sentinel, False))
        self.assertEqual(evidence.take_pending(sentinel), (sentinel, False))
        for old in (-1, 1 << 64):
            with self.assertRaises(ValueError):
                evidence.take_pending(old)

    def test_real_state_read_and_sentinel_instruction_corruption_fail(self):
        for va in (0x4fbd4e9, 0x4fbd5cb, 0x5a8b147):
            changed = bytearray(self.data)
            off, _ = evidence.file_mapping(self.sections, va, 1, True)
            changed[off] ^= 1
            with self.subTest(va=hex(va)), mock.patch.object(evidence, 'check_identity'):
                with self.assertRaisesRegex(ValueError, 'window mismatch'):
                    evidence.analyze(changed)

    def test_callback_cleanup_and_height_read_edges(self):
        edges = {r['label']: r for r in csv.DictReader(
            io.StringIO(self.outputs['calls.tsv']), delimiter='\t')}
        self.assertEqual(edges['callback_normal_cleanup']['target_or_slot_va'], '0x2aaea40')
        self.assertEqual(edges['callback_unwind_cleanup']['target_or_slot_va'], '0x2aaea40')
        self.assertEqual((edges['cleanup_drain']['target_or_slot_va'],
                          edges['cleanup_drain']['relocation_target']), ('0x64e72a0', '0x5a8b130'))
        self.assertEqual(edges['drain_read_height']['target_or_slot_va'], '0x4f0e990')
        self.assertEqual(edges['height_read_tail']['target_or_slot_va'], '0x4fbd410')
        self.assertEqual(edges['drain_first_encode']['target_or_slot_va'], '0x4d6d740')
        self.assertEqual(edges['drain_sink']['target_or_slot_va'], '0x595a6b0')
        self.assertEqual(edges['encode_record']['target_or_slot_va'],
                         edges['drain_first_encode']['target_or_slot_va'])
        self.assertEqual(edges['assemble_context']['ownership'], 'context')
        self.assertEqual(edges['drain_sink']['ownership'], 'selected')

    def test_bucket_division_and_saturating_subtraction(self):
        multiplier = int(self.arithmetic['roll_multiplier'], 16)
        shift = self.arithmetic['roll_shift_after_high_half']
        step = self.arithmetic['roll_bucket_step']
        self.assertEqual(multiplier * step - (1 << (64 + shift)), 432)
        self.assertLess(432, 1 << shift)
        values = [0, 1, 9999, 10000, 10001, 20000, 20001, evidence.MASK64]
        values += [(i * 98765432109876543) & evidence.MASK64 for i in range(10000)]
        for value in values:
            expected = (max(0, value - 1) // 10000) * 10000
            self.assertEqual(evidence.roll_bucket(value, multiplier, shift, step), expected)
        self.assertNotEqual(evidence.roll_bucket(10001, multiplier ^ (1 << 50), shift, step), 10000)
        with self.assertRaises(ValueError):
            evidence.roll_bucket(1 << 64, multiplier, shift, step)

    def test_disabled_sink_precedes_roll_and_boundary_comparison(self):
        a = self.arithmetic
        m, shift, step = int(a['roll_multiplier'], 16), a['roll_shift_after_high_half'], a['roll_bucket_step']
        self.assertEqual(evidence.sink_admission(1 << 63, 10001, 0, m, shift, step), ('disabled', None))
        self.assertEqual(evidence.sink_admission(0, 10000, 0, m, shift, step), ('append', 0))
        self.assertEqual(evidence.sink_admission(0, 10001, 0, m, shift, step), ('roll', 10000))
        self.assertEqual(evidence.sink_admission(0, 10001, 10000, m, shift, step), ('append', 10000))
        self.assertEqual(evidence.sink_admission((1 << 63) - 1, 10001, 0, m, shift, step)[0], 'roll')
        self.assertEqual(evidence.sink_admission((1 << 63) + 1, 10001, 0, m, shift, step)[0], 'roll')
        with self.assertRaises(ValueError):
            evidence.sink_admission(-1, 0, 0, m, shift, step)

    def test_buffer_equality_takes_fallback(self):
        self.assertEqual(evidence.buffer_route(100, 90, 9), 'copy')
        self.assertEqual(evidence.buffer_route(100, 90, 10), 'fallback')
        self.assertEqual(evidence.buffer_route(100, 90, 11), 'fallback')
        self.assertEqual(evidence.buffer_route(0, 0, 0), 'fallback')
        with self.assertRaises(ValueError):
            evidence.buffer_route(5, 6, 0)

    def test_field_names_and_error_paths_are_bound(self):
        field_lines = self.outputs['literals.tsv']
        for key in ('abci_block', 'resps', 'height'):
            self.assertIn('\t' + key + '\n', field_lines)
        self.assertIn('serializer_field_one_error', self.outputs['branches.tsv'])
        self.assertIn('encoder_serializer_ok', self.outputs['branches.tsv'])
        self.assertEqual(self.arithmetic['record_newline_byte'], 10)
        self.assertEqual((self.arithmetic['serializer_open_byte'], self.arithmetic['serializer_close_byte']),
                         (ord('{'), ord('}')))


if __name__ == '__main__':
    unittest.main()
