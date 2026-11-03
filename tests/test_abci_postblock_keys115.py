"""Static #115 post-block evidence controls; no captured binary is run."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import abci_postblock_keys115 as packet
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records


class PostblockKeysEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = packet.TARGET.read_bytes()
        cls.secs = sections(cls.data)
        cls.field_rows, cls.values = packet.select_fields(cls.data, cls.secs)

    def test_digest_and_release_are_pinned(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), packet.TARGET_SHA256)
        self.assertEqual(packet.TARGET.name, 'hl-node')
        packet.authenticate(self.data)
        with self.assertRaises(ValueError):
            packet.authenticate(b'not the captured ELF')

    def test_wrong_target_never_creates_output(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            bad, out = base / 'bad-elf', base / 'uncreated'
            bad.write_bytes(b'corrupt')
            with self.assertRaises(ValueError):
                packet.generate(bad, out)
            self.assertFalse(out.exists())

    def test_bad_historical_input_never_creates_output(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            old, out = base / 'old-bad', base / 'uncreated'
            old.write_bytes(b'wrong historical capture')
            with mock.patch.object(packet, 'collect', return_value={'summary.json': b'{}\n'}):
                with self.assertRaises(ValueError):
                    packet.generate(packet.TARGET, out, old)
            self.assertFalse(out.exists())

    def test_complete_collection_and_selected_record_counts(self):
        outputs = packet.collect(self.data)
        self.assertEqual(set(outputs), {'functions.tsv', 'windows.tsv', 'edges.tsv', 'fields.tsv',
                                        'relocations.tsv', 'exceptions.tsv', 'unwind-links.tsv',
                                        'location.json', 'summary.json'})
        summary = json.loads(outputs['summary.json'])
        self.assertEqual(summary['binary_sha256'], packet.TARGET_SHA256)
        self.assertEqual(summary['counts']['selected_new_fdes'], len(packet.FUNCTIONS))
        self.assertEqual(summary['counts']['new_windows'], sum(w[0] == 'new' for w in packet.WINDOWS))
        self.assertEqual(summary['counts']['operand_fields'], len(packet.FIELDS))
        self.assertGreater(summary['counts']['selected_calls_in_lsda_rows'], 0)
        self.assertEqual(summary['derived']['engine_result_descriptor_offset'], 0x30)
        self.assertEqual(summary['derived']['row_key_offset'], 0x118)
        self.assertEqual(summary['derived']['upper_prior_result_stride'], 0x168)
        self.assertEqual(summary['derived']['nested_keyed_result_tag'], '0x10')
        self.assertEqual(summary['derived']['nested_direct_result_tag'], '0xf')

    def test_every_selected_window_rejects_corruption(self):
        self.assertEqual(len(packet.select_windows(self.data, self.secs)), len(packet.WINDOWS))
        real = packet.read_va
        for _, label, start, _, _ in packet.WINDOWS:
            def corrupt(data, secs, va, size, executable=False, target=start):
                raw = real(data, secs, va, size, executable)
                if va == target:
                    return bytes([raw[0] ^ 1]) + raw[1:]
                return raw
            with self.subTest(label=label), mock.patch.object(packet, 'read_va', side_effect=corrupt):
                with self.assertRaises(ValueError):
                    packet.select_windows(self.data, self.secs)

    def test_every_selected_operand_rejects_corruption(self):
        real = packet.read_va
        for label, site, expected, _, _ in packet.FIELDS:
            def corrupt(data, secs, va, size, executable=False, target=site, n=len(bytes.fromhex(expected))):
                raw = real(data, secs, va, size, executable)
                if va == target and size == n:
                    return raw[:-1] + bytes([raw[-1] ^ 1])
                return raw
            with self.subTest(label=label), mock.patch.object(packet, 'read_va', side_effect=corrupt):
                with self.assertRaises(ValueError):
                    packet.select_fields(self.data, self.secs)

    def test_every_relative_transfer_rejects_changed_displacement(self):
        self.assertEqual(len(packet.select_edges(self.data, self.secs)), len(packet.EDGES))
        real = packet.read_va
        for _, label, site, _, _ in packet.EDGES:
            def corrupt(data, secs, va, size, executable=False, target=site):
                raw = real(data, secs, va, size, executable)
                if va == target and (size > 2 or (size == 2 and (0x70 <= raw[0] <= 0x7f or raw[0] == 0xeb))):
                    return raw[:-1] + bytes([raw[-1] ^ 1])
                return raw
            with self.subTest(label=label), mock.patch.object(packet, 'read_va', side_effect=corrupt):
                with self.assertRaises(ValueError):
                    packet.select_edges(self.data, self.secs)

    def test_executable_mapping_rejects_missing_ambiguous_and_nobits(self):
        data = bytes(range(16))
        sec = {'type': 1, 'flags': 4, 'address': 0x1000, 'offset': 0, 'size': len(data)}
        self.assertEqual(packet.read_va(data, [sec], 0x100f, 1, True), b'\x0f')
        for va, size in ((0x0fff, 1), (0x100f, 2), (0x1000, 0), (-1, 1), ((1 << 64) - 1, 2)):
            with self.subTest(va=va, size=size), self.assertRaises(ValueError):
                packet.file_offset(data, [sec], va, size, True)
        with self.assertRaises(ValueError):
            packet.file_offset(data, [sec, dict(sec)], 0x1000, 1, True)
        with self.assertRaises(ValueError):
            packet.file_offset(data, [dict(sec, type=8)], 0x1000, 1, True)
        with self.assertRaises(ValueError):
            packet.file_offset(data, [dict(sec, flags=2)], 0x1000, 1, True)

    def test_fde_header_matches_and_rejects_mismatches(self):
        secs, index = unwind_index(self.data)
        _, fdes = eh_frame_records(self.data, secs)
        wanted = {f[1] for f in packet.FUNCTIONS}
        selected_fdes = [f.copy() for f in fdes if f['start'] in wanted]
        selected_index = [r.copy() for r in index if r['start'] in wanted]
        self.assertEqual(len(packet.select_functions(self.data, secs, selected_index, selected_fdes)), len(wanted))
        altered = [f.copy() for f in selected_fdes]
        altered[0]['end'] += 1
        with self.assertRaises(ValueError):
            packet.select_functions(self.data, secs, selected_index, altered)
        altered_index = [r.copy() for r in selected_index]
        altered_index[0]['fde'] += 4
        with self.assertRaises(ValueError):
            packet.select_functions(self.data, secs, altered_index, selected_fdes)
        with self.assertRaises(ValueError):
            packet.select_functions(self.data, secs, selected_index + [selected_index[0]], selected_fdes)
        overlapping = selected_fdes + [dict(selected_fdes[0], start=selected_fdes[0]['start'] + 1)]
        with self.assertRaises(ValueError):
            packet.select_functions(self.data, secs, selected_index, overlapping)

    def test_relocations_reject_type_addend_duplicates_and_missing_rows(self):
        actual = packet.select_relocations(self.data, self.secs)
        self.assertEqual(len(actual), len(packet.RELOCATIONS))
        entries = [struct.pack('<QQq', slot, info, add) for _, slot, info, add in packet.RELOCATIONS]
        blob = b''.join(entries)
        sec = {'name': '.rela.dyn', 'type': 4, 'offset': 0, 'address': 0x2000, 'size': len(blob)}
        self.assertEqual(len(packet.select_relocations(blob, [sec])), len(entries))
        changed_type = bytearray(blob)
        changed_type[8] ^= 1
        with self.assertRaises(ValueError):
            packet.select_relocations(changed_type, [sec])
        changed_addend = bytearray(blob)
        changed_addend[16] ^= 1
        with self.assertRaises(ValueError):
            packet.select_relocations(changed_addend, [sec])
        duplicate = blob + entries[0]
        with self.assertRaises(ValueError):
            packet.select_relocations(duplicate, [dict(sec, size=len(duplicate))])
        missing = blob[24:]
        with self.assertRaises(ValueError):
            packet.select_relocations(missing, [dict(sec, size=len(missing))])
        with self.assertRaises(ValueError):
            packet.select_relocations(blob, [dict(sec, size=len(blob) - 1)])

    def test_location_and_reference_are_release_specific(self):
        relocs = packet.select_relocations(self.data, self.secs)
        loc = packet.location_record(self.data, self.secs, relocs)
        self.assertEqual((loc['path'], loc['line'], loc['column']), ('l1/src/abci/state.rs', 123, 37))
        secs, index = unwind_index(self.data)
        _, fdes = eh_frame_records(self.data, secs)
        owner = packet.location_owner(index, fdes)
        self.assertEqual(owner['owner_start_va'], '0x3c13520')
        changed_index = [dict(row) for row in index if row['start'] == 0x3c13520]
        changed_index[0]['fde'] += 4
        with self.assertRaises(ValueError):
            packet.location_owner(changed_index, fdes)
        bad = [dict(row) for row in relocs]
        bad[0]['addend'] = '0x1'
        with self.assertRaises(ValueError):
            packet.location_record(self.data, self.secs, bad)
        with self.assertRaises(ValueError):
            packet.verify_historical(self.data)

    def test_lsda_records_and_corrupt_header(self):
        fde = {'start': 0x5601970, 'end': 0x5601bdf, 'lsda': 0x3b66b4}
        rows = packet.lsda_rows(self.data, self.secs, fde, 'selected')
        self.assertTrue(any(int(r['start_va'], 16) <= 0x5601a06 < int(r['end_va_exclusive'], 16)
                            for r in rows))
        changed = bytearray(self.data)
        off = packet.file_offset(changed, self.secs, fde['lsda'], 2)
        changed[off] ^= 1
        with self.assertRaises(ValueError):
            packet.lsda_rows(changed, self.secs, fde, 'selected')
        bad = dict(fde, lsda=0xffffffffffffffff)
        with self.assertRaises(ValueError):
            packet.lsda_rows(self.data, self.secs, bad, 'selected')

    def test_pointer_joins_fail_closed(self):
        prologue = packet.read_va(self.data, self.secs, 0x55f4760, 10, True)
        joined = packet.derived(self.values, prologue)
        self.assertEqual((joined['row_key_offset'], joined['result_stride']), (0x118, 0x130))
        for field in ('expanded_key_suffix_stack', 'compact_root_group_offset',
                      'root_capture_state_offset', 'nested_flag_stack_offset', 'upper_cleanup_stack',
                      'cleanup_row_stride', 'late_saved_count_stack', 'expanded_row_key_last',
                      'engine_late_cell_stack', 'late_compact_call_state',
                      'cleanup_second_tail_stride', 'cleanup_first_tail_pointer',
                      'upper_prior_count_stack', 'late_accum_pointer',
                      'late_body_result_count', 'upper_prior_row_stride'):
            altered = dict(self.values)
            altered[field] += 1
            with self.subTest(field=field), self.assertRaises(ValueError):
                packet.derived(altered, prologue)
        altered = dict(self.values)
        altered['nested_direct_result_tag'] = altered['nested_keyed_result_tag']
        with self.assertRaises(ValueError):
            packet.derived(altered, prologue)
        with self.assertRaises(ValueError):
            packet.derived(self.values, b'\0' + prologue[1:])

    def test_special_key_is_all_22_only_on_both_conditions(self):
        word = 0x0123456789abcdef
        expected_regular = b'\x20' + b'\0' * 11 + bytes.fromhex('0123456789abcdef')
        self.assertEqual(packet.key_model(self.values, 1, word, word), b'\x22' * 20)
        self.assertEqual(packet.key_model(self.values, 0x100000001, word, word), b'\x22' * 20)
        self.assertEqual(packet.key_model(self.values, 0, word, word), expected_regular)
        self.assertEqual(packet.key_model(self.values, 1, word - 1, word), expected_regular)
        self.assertNotEqual(expected_regular, expected_regular[::-1])
        for bit in range(64):
            self.assertEqual(packet.key_model(self.values, 1, word ^ (1 << bit), word), expected_regular)
        for value in (0, 1, 0xff, 0x100, (1 << 64) - 1):
            expected = b'\x20' + bytes(11) + value.to_bytes(8, 'big')
            self.assertEqual(packet.key_model(self.values, 0, 0, value), expected)
        for bad in (-1, 1 << 64):
            with self.assertRaises(ValueError):
                packet.key_model(self.values, bad, 0, 0)

    def test_counter_width_and_saturation(self):
        maximum = (1 << 64) - 1
        self.assertEqual(packet.counter_model(1, maximum), (1, maximum))
        self.assertEqual(packet.counter_model(1, maximum - 1), (1, maximum))
        self.assertEqual(packet.counter_model(1, 0), (1, 1))
        self.assertEqual(packet.counter_model(0x100000001, 12), (0x100000001, 13))
        self.assertEqual(packet.counter_model(0x100000000, maximum), (1, 1))
        with self.assertRaises(ValueError):
            packet.counter_model(0, -1)

    def test_ring_count_only_equals_division_on_valid_aligned_spans(self):
        width = self.values['ring_element_bytes']
        inverse = self.values['ring_divisor_inverse']
        for n in (0, 1, 2, 3, 127, 65535, ((1 << 64) - 1) // width):
            span = n * width
            self.assertEqual(packet.ring_count_model(span, inverse), n)
        self.assertNotEqual(packet.ring_count_model(64, inverse), 64 // width)
        with self.assertRaises(ValueError):
            packet.ring_count_model(1 << 64, inverse)

    def test_result_cleanup_boundaries(self):
        val = self.values
        self.assertEqual(val['upper_cleanup_stack'] - val['upper_engine_result_stack'],
                         val['engine_return_field_offset'])
        self.assertEqual(val['expanded_result_stride'], val['cleanup_row_stride'])
        self.assertEqual(val['cleanup_row_inner_offset'], val['expanded_row_result_first'])
        self.assertEqual(val['expanded_row_key_last'] + 4, 0x12c)
        self.assertLess(val['expanded_row_key_last'] + 4, val['expanded_result_stride'])
        self.assertEqual(val['expanded_zero_flag'], 0)
        self.assertEqual(val['compact_zero_flag'], 0)
        self.assertEqual(val['cleanup_first_tail_stride'], 0x68)
        self.assertEqual(val['cleanup_second_tail_stride'], 0x68)
        self.assertEqual(val['cleanup_first_tail_inner'], 8)
        self.assertEqual(val['cleanup_second_tail_allocation'], 0x30)


if __name__ == '__main__':
    unittest.main()
