"""Static controls for the node 115 checkpoint evidence extractor."""
import csv
import io
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock

from tools import abci_loader_checkpoint115 as probe


class CheckpointEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = probe.TARGET.read_bytes()
        cls.files = probe.collect(cls.data)
        cls.secs = probe.sections(cls.data)
        cls.joins = probe.make_joins(cls.data, cls.secs)

    def test_authentication_rejects_different_input(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            probe.authenticate(b'not the captured binary')

    def test_wrong_input_does_not_create_output_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            bad_input = base / 'bad-node'
            bad_input.write_bytes(b'wrong digest')
            output = base / 'evidence'
            with mock.patch.object(probe, 'TARGET', bad_input), mock.patch.object(sys, 'argv', ['extract', '--out', str(output)]):
                with self.assertRaisesRegex(ValueError, 'SHA-256'):
                    probe.main()
            self.assertFalse(output.exists())

    def test_every_selected_window_rejects_corruption(self):
        for label, start, end, _ownership, expected in probe.WINDOWS:
            with self.subTest(label=label):
                _, raw = probe.read_va(self.data, self.secs, start, end - start)
                probe.check_window(raw, expected)
                altered = bytearray(raw)
                altered[len(altered) // 2] ^= 1
                with self.assertRaises(ValueError):
                    probe.check_window(altered, expected)

    def test_shorter_window_rejected(self):
        _, start, end, _, expected = probe.WINDOWS[0]
        _, raw = probe.read_va(self.data, self.secs, start, end - start)
        with self.assertRaises(ValueError):
            probe.check_window(raw[:-1], expected)

    def test_selected_direct_and_indirect_transfers(self):
        rows = list(csv.DictReader(io.StringIO(self.files['transfers.tsv'].decode()), delimiter='\t'))
        table = {r['label']: r for r in rows}
        for label, target in {
            'parent_checkpoint_boundary': '0x64e7438',
            'startup_to_compact_dispatch': '0x4e4a740',
            'compact_capture_plain': '0x4e4a960',
            'compact_route_call': '0x50dd9d0',
            'compact_binary_encode': '0x5480950',
            'expanded_mismatch': '0x5a0793f',
            'expanded_dispatch_plain': '0x4e35c10',
            'expanded_binary_encode': '0x5481900',
            'startup_result_boundary': '0x64ebf70',
        }.items():
            with self.subTest(label=label):
                self.assertEqual(table[label]['target_va'], target)
        self.assertEqual(table['parent_checkpoint_boundary']['ownership'], 'context')
        self.assertEqual(table['startup_to_compact_dispatch']['ownership'], 'new')

    def test_relative_decoding_handles_signed_offsets(self):
        self.assertEqual(probe.decode_transfer(0x100, bytes.fromhex('e8fbffffff')),
                         ('call_rel32', 5, 0x100))
        self.assertEqual(probe.decode_transfer(0x100, bytes.fromhex('75fe')),
                         ('jcc_rel8_5', 2, 0x100))
        self.assertEqual(probe.decode_transfer(0x200, bytes.fromhex('ff1504000000')),
                         ('call_rip_slot', 6, 0x20a))

    def test_truncated_and_invalid_transfer_rejected(self):
        for raw in (b'', b'\xe8', b'\x0f\x85\x00', b'\xff\x15', b'\x90\x90\x90\x90\x90\x90'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                probe.decode_transfer(0x100, raw)

    def test_corrupted_branch_fails_window_pin(self):
        label, start, end, _, expected = next(w for w in probe.WINDOWS if w[0] == 'startup_mode_gate')
        _, raw = probe.read_va(self.data, self.secs, start, end - start)
        changed = bytearray(raw)
        changed[0x5a6de25 - start + 2] ^= 1
        with self.assertRaises(ValueError):
            probe.check_window(changed, expected)

    def test_nobits_does_not_supply_file_bytes(self):
        data = b'abcdefgh'
        no_bytes = dict(name='.bss', type=8, flags=3, address=0x100, offset=0, size=8)
        file_bytes = dict(name='.data', type=1, flags=3, address=0x100, offset=0, size=8)
        with self.assertRaises(ValueError):
            probe.read_va(data, [no_bytes], 0x100, 1)
        self.assertEqual(probe.read_va(data, [no_bytes, file_bytes], 0x103, 2), (3, b'de'))

    def test_ambiguous_mapping_is_rejected(self):
        one = dict(name='.a', type=1, flags=2, address=0x100, offset=0, size=4)
        two = dict(name='.b', type=1, flags=2, address=0x100, offset=4, size=4)
        with self.assertRaises(ValueError):
            probe.read_va(b'abcdefgh', [one, two], 0x100, 1)

    def test_outside_and_invalid_ranges_rejected(self):
        one = dict(name='.a', type=1, flags=2, address=0x100, offset=0, size=4)
        for va, size in ((0xff, 1), (0x103, 2), (0x104, 1), (0x100, 0), (-1, 1)):
            with self.subTest(va=va, size=size), self.assertRaises(ValueError):
                probe.read_va(b'abcd', [one], va, size)

    def test_missing_and_duplicate_sections_rejected(self):
        sec = dict(name='.wanted', type=1, flags=2, address=0x100, offset=0, size=4)
        for secs in ([], [sec, sec], [dict(sec, type=8)]):
            with self.subTest(secs=secs), self.assertRaises(ValueError):
                probe.unique_section(secs, '.wanted')

    def test_relative_relocation_decoding(self):
        row = struct.pack('<QQq', 0x10, 8, 0x100)
        sec = {'offset': 0, 'size': len(row)}
        got = probe.relative_relocations(row, sec, {0x10})
        self.assertEqual(got[0x10], (0x100, 0, row))

    def test_relocation_rejects_duplicate_bad_type_and_missing(self):
        row = struct.pack('<QQq', 0x10, 8, 0x100)
        bad = struct.pack('<QQq', 0x10, 7, 0x100)
        for data, wanted in ((row + row, {0x10}), (bad, {0x10}), (row, {0x11}), (row[:-1], {0x10})):
            with self.subTest(data_length=len(data), wanted=wanted), self.assertRaises(ValueError):
                probe.relative_relocations(data, {'offset': 0, 'size': len(data)}, wanted)

    def test_two_elf_relative_anchors_resolve(self):
        rows = list(csv.DictReader(io.StringIO(self.files['relocations.tsv'].decode()), delimiter='\t'))
        self.assertEqual([(r['slot_va'], r['addend']) for r in rows],
                         [('0x64e1050', '0x154abf0'), ('0x64e7438', '0x5a6dd30'), ('0x64ebf70', '0x595ac30')])

    def test_location_records_match_release_and_columns(self):
        rows = list(csv.DictReader(io.StringIO(self.files['locations.tsv'].decode()), delimiter='\t'))
        self.assertEqual([(r['line'], r['column']) for r in rows], [('123', '37'), ('151', '17'), ('151', '35')])
        self.assertTrue(all(r['path_suffix'] == 'l1/src/abci/state.rs' for r in rows))

    def test_bad_location_operand_is_rejected(self):
        with self.assertRaises(ValueError):
            probe.lea_target(self.data, self.secs, 0x4e4a99b, (bytes.fromhex('488d15'),))

    def test_context_extents_are_not_claimed(self):
        rows = list(csv.DictReader(io.StringIO(self.files['functions.tsv'].decode()), delimiter='\t'))
        starts = {r['start_va'] for r in rows}
        self.assertEqual(len(starts), 13)
        self.assertFalse({'0x2cb6500', '0x3c13520', '0x5a04e40', '0x5a06600', '0x38c2e00'} & starts)

    def test_selected_fde_rejects_nonadjacent_overlaps(self):
        fdes = [dict(start=10, end=100, fde=1), dict(start=20, end=30, fde=2),
                dict(start=50, end=60, fde=3)]
        with self.assertRaises(ValueError):
            probe.validate_selected_fde_overlap(fdes, {3})
        probe.validate_selected_fde_overlap([fdes[1], fdes[2]], {3})
        with self.assertRaises(ValueError):
            probe.validate_selected_fde_overlap(fdes, {4})

    def test_mode_flag_all_byte_values(self):
        for value in range(256):
            self.assertEqual(probe.mode_result(value), 0 if value == 2 else 1)

    def test_config_marker_and_empty_are_distinct(self):
        sentinel = 1 << 63
        self.assertEqual(probe.config_model(sentinel, 0, False), ('marker_sentinel', sentinel, None, sentinel))
        self.assertEqual(probe.config_model(0, 0, False), ('empty', 0, 1, 0))
        for marker in (sentinel - 1, sentinel + 1, (1 << 64) - 1):
            self.assertEqual(probe.config_model(marker, 0, False)[0], 'empty')

    def test_config_copy_and_allocation_failure(self):
        sentinel = 1 << 63
        self.assertEqual(probe.config_model(0, 7, True), ('allocated_after_copy', 7, None, 7))
        self.assertEqual(probe.config_model(0, 7, False), ('allocation_failure', None, None, None))
        self.assertEqual(probe.config_model(0, sentinel, True), ('length_sentinel_after_copy', sentinel, None, sentinel))
        for invalid in (-1, 1 << 64, True):
            with self.subTest(value=invalid), self.assertRaises(ValueError):
                probe.config_model(invalid, 0, True)

    def test_startup_branch_order_and_flag_does_not_prove_a_write(self):
        self.assertEqual(probe.startup_model(2, True, False, False, False), ('format_failure', None))
        self.assertEqual(probe.startup_model(2, False, False, True, True), ('mode_bypass', 0))
        self.assertEqual(probe.startup_model(1, False, True, True, True), ('config_bypass', 1))
        self.assertEqual(probe.startup_model(1, False, False, True, False), ('router_failure', None))
        self.assertEqual(probe.startup_model(1, False, False, False, True), ('followup_failure', None))
        self.assertEqual(probe.startup_model(1, False, False, False, False), ('selected_normal', 1))

    def test_mode_rejects_non_byte_and_boolean(self):
        for value in (-1, 256, True, '2'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                probe.mode_result(value)

    def test_shortcut_is_exact_not_prefix_or_casefold(self):
        target = bytes.fromhex('2f6465762f6e756c6c')
        self.assertEqual(probe.route_model(target, 0, b''), 'shortcut')
        self.assertEqual(probe.route_model(target + b'x', 0, b''), 'text')
        self.assertEqual(probe.route_model(target[:-1], 0, b''), 'text')
        self.assertEqual(probe.route_model(target.upper(), 0, b''), 'text')

    def test_suffix_case_variants_and_tag(self):
        for c in (b'rmp', b'rmP', b'rMp', b'rMP', b'Rmp', b'RmP', b'RMp', b'RMP'):
            with self.subTest(c=c):
                self.assertEqual(probe.route_model(b'x', 9, b'a.' + c), 'binary')
                self.assertEqual(probe.route_model(b'x', 8, b'a.' + c), 'text')

    def test_component_suffix_boundary_cases(self):
        for component in (b'', b'.', b'..', b'.rmp', b'rmp', b'a.rmp.', b'a.rmps', b'a.r\xffp'):
            with self.subTest(component=component):
                self.assertEqual(probe.route_model(b'x', 9, component), 'text')
        self.assertEqual(probe.route_model(b'x', 9, b'archive.v1.rmp'), 'binary')

    def test_comparison_checks_every_byte(self):
        base = bytes(range(32))
        self.assertEqual(probe.compare_mask(base, base), 0xffff)
        for i in range(32):
            other = bytearray(base)
            other[i] ^= 1
            with self.subTest(index=i):
                self.assertEqual(probe.compare_mask(base, other), 0xffff ^ (1 << (i % 16)))

    def test_comparison_rejects_wrong_width(self):
        for left, right in ((b'', bytes(32)), (bytes(31), bytes(32)), (bytes(32), bytes(33))):
            with self.subTest(left=len(left), right=len(right)), self.assertRaises(ValueError):
                probe.compare_mask(left, right)

    def test_pointer_height_and_flag_projection(self):
        self.assertEqual(self.joins['pointer_word_relative_to_parent_result'], '0x380')
        self.assertEqual(self.joins['parent_mode_source_offset'], '0xb20')
        self.assertEqual(self.joins['parent_mode_saved_offset'], '0x2a19')
        self.assertEqual(self.joins['compact_mismatch_context_cell_offset'], '0x450')
        self.assertEqual(self.joins['compact_mismatch_cell_stack_offset'], '0xe8')
        self.assertEqual(self.joins['result_record_height_offset'], '0x68')
        self.assertEqual(self.joins['config_marker_offset'], '0x100')
        self.assertEqual(self.joins['config_pointer_offset'], '0x108')
        self.assertEqual(self.joins['config_length_offset'], '0x110')
        self.assertEqual(self.joins['capture_member_offset'], '0x1108')
        self.assertEqual(self.joins['expanded_capture_member_offset'], '0x1c78')
        self.assertEqual(self.joins['result_record_flag_offset'], '0x70')
        self.assertEqual(self.joins['record_stack_argument_offset'], '0x140')
        self.assertEqual(self.joins['later_copy_stages'][-1]['height'], '0x780')
        self.assertEqual(self.joins['later_copy_stages'][-1]['flag'], '0x788')

    def test_copy_projection_bounds(self):
        self.assertEqual(probe.map_copy(12, 10, 30, 5, 3), 32)
        for args in ((9, 10, 30, 5, 1), (14, 10, 30, 5, 2), (10, 10, 30, 5, 0), (-1, 0, 0, 2, 1)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                probe.map_copy(*args)

    def test_corrupted_height_operand_rejected(self):
        original = probe.read_va
        def corrupted(data, secs, va, length):
            off, raw = original(data, secs, va, length)
            if va == 0x5a6e038:
                raw = bytes(raw[:-1]) + bytes([raw[-1] ^ 1])
            return off, raw
        with mock.patch.object(probe, 'read_va', side_effect=corrupted):
            with self.assertRaises(ValueError):
                probe.make_joins(self.data, self.secs)

    def test_corrupted_mode_projection_rejected(self):
        original = probe.read_va
        def corrupted(data, secs, va, length):
            off, raw = original(data, secs, va, length)
            if va == 0x2cb7959:
                raw = raw[:-1] + bytes([raw[-1] ^ 1])
            return off, raw
        with mock.patch.object(probe, 'read_va', side_effect=corrupted):
            with self.assertRaisesRegex(ValueError, 'mode save-to-argument'):
                probe.make_joins(self.data, self.secs)

    def test_corrupted_mismatch_cell_projection_rejected(self):
        original = probe.read_va
        def corrupted(data, secs, va, length):
            off, raw = original(data, secs, va, length)
            if va == 0x5a0610f:
                raw = raw[:-1] + bytes([raw[-1] ^ 1])
            return off, raw
        with mock.patch.object(probe, 'read_va', side_effect=corrupted):
            with self.assertRaisesRegex(ValueError, 'mismatch state-cell'):
                probe.make_joins(self.data, self.secs)

    def test_lsda_valid_row(self):
        data = bytes([0xff, 0xff, 1, 4, 0, 2, 1, 0])
        sec = dict(name='.gcc_except_table', type=1, flags=2, address=0x1000, offset=0, size=len(data))
        fde = dict(start=0x2000, end=0x2010, lsda=0x1000)
        rows = probe.parse_lsda(data, [sec], fde)
        self.assertEqual(rows, [(4, 0x2000, 0x2002, 0x2001, 0, bytes([0, 2, 1, 0]))])
        self.assertEqual(probe.select_callsite(rows, 0x2000, 2), rows[0])

    def test_lsda_rejects_truncated_and_unsupported(self):
        for data in (bytes([0xff, 0xff, 1, 5, 0, 2, 1, 0]), bytes([0xff, 0xff, 2, 0]),
                     bytes([0xff, 0xff, 1, 4, 15, 2, 1, 0])):
            sec = dict(name='.gcc_except_table', type=1, flags=2, address=0x1000, offset=0, size=len(data))
            fde = dict(start=0x2000, end=0x2010, lsda=0x1000)
            with self.subTest(data=data), self.assertRaises(ValueError):
                probe.parse_lsda(data, [sec], fde)

    def test_lsda_crossing_and_duplicate_are_rejected(self):
        row = (0, 0x100, 0x104, 0x102, 0, b'')
        with self.assertRaises(ValueError):
            probe.select_callsite([row], 0x103, 2)
        with self.assertRaises(ValueError):
            probe.select_callsite([row, row], 0x100, 1)
        self.assertIsNone(probe.select_callsite([row], 0x105, 1))

    def test_historical_wrong_digest_rejected(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            probe.verify_historical(b'not the historical artifact')

    def test_output_does_not_contain_internal_absolute_path_prefixes(self):
        forbidden = [bytes([47]) + name for name in (b'tmp', b'mnt', b'srv', b'home', b'root', b'opt')]
        for name, content in self.files.items():
            for term in forbidden:
                with self.subTest(file=name, term=term):
                    self.assertNotIn(term, content)


if __name__ == '__main__':
    unittest.main()
