"""Target-grounded negative controls for the static scheduled-cancel packet."""
from contextlib import contextmanager
import mmap
from pathlib import Path
import struct
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import abci_cancel_root94 as packet
import elf_index
import fde_extents


class ScheduledCancelEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = packet.BINARY.open('rb')
        cls.data = mmap.mmap(cls.source.fileno(), 0, access=mmap.ACCESS_COPY)
        packet.verify_digest(cls.data)
        cls.secs, cls.entries = elf_index.unwind_index(cls.data)
        _, cls.records = fde_extents.eh_frame_records(cls.data, cls.secs)
        cls.ranges = packet.bind_extents(cls.data, cls.secs, cls.entries, cls.records)

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.source.close()

    @contextmanager
    def changed_offset(self, offset, replacement):
        old = self.data[offset:offset + len(replacement)]
        self.data[offset:offset + len(replacement)] = replacement
        try:
            yield
        finally:
            self.data[offset:offset + len(replacement)] = old

    @contextmanager
    def changed_byte(self, va, delta=1):
        _, offset = packet.file_offset(self.data, self.secs, va, 1)
        with self.changed_offset(offset, bytes([self.data[offset] ^ delta])):
            yield

    def test_artifact_digest_and_corruption(self):
        packet.verify_digest(self.data)
        with self.changed_offset(0, b'X'):
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                packet.verify_digest(self.data)

    def test_authentication_precedes_elf_parse(self):
        with mock.patch.object(packet, 'unwind_index', side_effect=AssertionError('parsed before authentication')):
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                packet.generate(b'bad')

    def test_fde_records_and_index_are_bound(self):
        self.assertEqual(len(self.ranges), 34)
        chosen = next(r for r in self.records if r['start'] == 0x30b8fe0)
        altered = [dict(r) if r is chosen else r for r in self.records]
        victim = next(r for r in altered if r['start'] == 0x30b8fe0)
        victim['fde'] += 4
        with self.assertRaisesRegex(ValueError, 'unwind index'):
            packet.bind_extents(self.data, self.secs, self.entries, altered)
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            packet.bind_extents(self.data, self.secs, self.entries, self.records + [chosen])

    def test_file_mapping_rejects_nobits_bounds_and_ambiguity(self):
        data = b'abcdefgh'
        real = {'type': 1, 'flags': 4, 'address': 0x100, 'offset': 0, 'size': 8, 'name': 'text'}
        nobits = {'type': 8, 'flags': 4, 'address': 0x100, 'offset': 0, 'size': 8, 'name': 'bss'}
        self.assertEqual(packet.file_offset(data, [real, nobits], 0x102, 2, True)[1], 2)
        with self.assertRaises(ValueError):
            packet.file_offset(data, [nobits], 0x102, 2)
        with self.assertRaises(ValueError):
            packet.file_offset(data, [real], 0x107, 2)
        with self.assertRaises(ValueError):
            packet.file_offset(data, [real, dict(real)], 0x102, 1)
        with self.assertRaises(ValueError):
            packet.file_offset(data, [real], -1, 1)

    def test_selected_windows_reject_code_mutation(self):
        self.assertEqual(len(packet.check_windows(self.data, self.secs, self.ranges)), 105)
        with self.changed_byte(0x30b91b2):
            with self.assertRaisesRegex(ValueError, 'changed window'):
                packet.check_windows(self.data, self.secs, self.ranges)

    def test_relative_edge_rejects_changed_opcode_and_displacement(self):
        rows = packet.collect_edges(self.data, self.secs, self.ranges)
        edge = next(row for row in rows if row[0] == 'map_value_to_cancel')
        self.assertEqual(edge[-1], '0x30b8fe0')
        with self.changed_byte(0x3022491):
            with self.assertRaisesRegex(ValueError, 'transfer'):
                packet.collect_edges(self.data, self.secs, self.ranges)
        with self.changed_byte(0x3022492):
            with self.assertRaisesRegex(ValueError, 'destination'):
                packet.collect_edges(self.data, self.secs, self.ranges)

    def test_conditional_rejects_changed_condition_and_destination(self):
        rows = packet.collect_branches(self.data, self.secs, self.ranges)
        cases = {row[0]: row for row in rows}
        self.assertEqual(cases['value_duplicate_t'][-2], '0x30b9610')
        self.assertEqual(cases['value_duplicate_n'][-2], '0x30b9607')
        with self.changed_byte(0x30b91c6):
            with self.assertRaises(ValueError):
                packet.collect_branches(self.data, self.secs, self.ranges)
        with self.changed_byte(0x30b91c7):
            with self.assertRaisesRegex(ValueError, 'destination'):
                packet.collect_branches(self.data, self.secs, self.ranges)

    def test_named_reference_and_literal_corruption(self):
        packet.collect_leas(self.data, self.secs, self.ranges)
        packet.collect_literals(self.data, self.secs)
        with self.changed_byte(0x343203e):
            with self.assertRaisesRegex(ValueError, 'LEA destination'):
                packet.collect_leas(self.data, self.secs, self.ranges)
        with self.changed_byte(0x57cfe9):
            with self.assertRaisesRegex(ValueError, 'literal'):
                packet.collect_literals(self.data, self.secs)

    def test_duplicate_key_inline_store_overlap(self):
        rows = packet.inline_duplicate_keys(self.data, self.secs, self.ranges)
        self.assertEqual([row[-1] for row in rows], ['duplicate key'] * 4)
        with self.changed_byte(0x363f210):
            with self.assertRaises(ValueError):
                packet.inline_duplicate_keys(self.data, self.secs, self.ranges)

    def test_dispatch_table_rejects_altered_target(self):
        rows = packet.entry_table(self.data, self.secs, self.ranges)
        self.assertEqual(len(rows), 33)
        self.assertEqual(rows[0][-1], '0x363efa0')
        self.assertEqual(rows[-1][-1], '0x363f0a6')
        with self.changed_byte(0x59224c):
            with self.assertRaises(ValueError):
                packet.entry_table(self.data, self.secs, self.ranges)

    def test_type_formatter_relocation_and_duplicate(self):
        _, _, _, off = packet.relative_relocation(self.data, self.secs, 0x56dd068, 0x3432030)
        with self.changed_offset(off + 8, struct.pack('<Q', 1)):
            with self.assertRaisesRegex(ValueError, 'relative relocation'):
                packet.relative_relocation(self.data, self.secs, 0x56dd068, 0x3432030)
        # A second record with the same offset must not silently replace the first.
        other = off + 24
        with self.changed_offset(other, struct.pack('<Q', 0x56dd068)):
            with self.assertRaisesRegex(ValueError, 'ambiguous'):
                packet.relative_relocation(self.data, self.secs, 0x56dd068, 0x3432030)

    def test_presence_count_and_order_boundaries(self):
        for count in (0, 1, (1 << 64) - 1):
            for tag in (0, 1, (1 << 32) - 1):
                expected = int(count != 0) + int(tag != 0)
                self.assertEqual(packet.field_count(count, tag), expected)
                self.assertEqual(packet.fields(count, tag),
                                 (['t'] if tag else []) + (['n'] if count else []))
        for count, tag in ((-1, 0), (1 << 64, 0), (0, -1), (0, 1 << 32)):
            with self.assertRaises(ValueError):
                packet.field_count(count, tag)

    def test_seen_flag_is_not_the_value(self):
        self.assertEqual(packet.event_model(('t-null',)), ('accepted', 0, 0))
        self.assertEqual(packet.event_model(('t-null', 't-null'))[0], 'duplicate-t')
        self.assertEqual(packet.event_model(('n-zero', 'n-nonzero'))[0], 'duplicate-n')
        self.assertEqual(packet.event_model(('n-nonzero', 't-present')),
                         ('accepted', 1, 1))
        self.assertEqual(packet.event_model(('unknown',))[0], 'delegate-unknown')
        with self.assertRaises(ValueError):
            packet.event_model(('made-up-event',))

    def test_fixed_twenty_byte_key_handoff(self):
        # Buffer-size immediates are checked in both independent input paths.
        self.assertEqual(packet.take(self.data, self.secs, 0x324f68f, 9, True),
                         bytes.fromhex('48c744241814000000'))
        self.assertEqual(packet.take(self.data, self.secs, 0x30486ce, 9, True),
                         bytes.fromhex('48c744241814000000'))
        with self.changed_byte(0x324f694):
            with self.assertRaisesRegex(ValueError, 'changed window'):
                packet.check_windows(self.data, self.secs, self.ranges)

    def test_fixarray_assuming_successful_children(self):
        self.assertEqual(packet.fixarray_model(0), ('default', 'default', 0, 9))
        self.assertEqual(packet.fixarray_model(1), ('delegate', 'default', 0, 9))
        self.assertEqual(packet.fixarray_model(2), ('delegate', 'delegate', 0, 9))
        self.assertEqual(packet.fixarray_model(3), ('delegate', 'delegate', 1, 4))
        self.assertEqual(packet.fixarray_model(15), ('delegate', 'delegate', 13, 4))
        for n in (-1, 16):
            with self.assertRaises(ValueError):
                packet.fixarray_model(n)

    def test_rmp_nested_null_and_duplicate_path_mutation(self):
        cases = {row[0]: row for row in packet.collect_branches(self.data, self.secs, self.ranges)}
        self.assertEqual(cases['rmp_nil'][-2], '0x2a6ea23')
        self.assertEqual(cases['rmp_duplicate_t'][-2], '0x2c71e6b')
        self.assertEqual(cases['rmp_duplicate_n'][-2], '0x2c72532')
        with self.changed_byte(0x2c71dfa):
            with self.assertRaises(ValueError):
                packet.collect_branches(self.data, self.secs, self.ranges)
        with self.changed_byte(0x2a6e9a7):
            with self.assertRaisesRegex(ValueError, 'changed window'):
                packet.check_windows(self.data, self.secs, self.ranges)

    def test_rmp_fixed_key_and_field_boundary(self):
        self.assertEqual(packet.take(self.data, self.secs, 0x2d3b55b, 12, True),
                         bytes.fromhex('48c78424e000000014000000'))
        refs = {row[0]: row for row in packet.collect_leas(self.data, self.secs, self.ranges)}
        self.assertEqual(refs['rmp_outer_field_boundary'][1], 'prior-boundary')
        self.assertEqual(refs['rmp_outer_field_boundary'][-1], '0x578cd2')
        with self.changed_byte(0x2d3b563):
            with self.assertRaisesRegex(ValueError, 'changed window'):
                packet.check_windows(self.data, self.secs, self.ranges)

    def test_rmp_duplicate_map_key_rejects_mutation(self):
        with self.changed_byte(0x3679f04):
            with self.assertRaises(ValueError):
                packet.inline_duplicate_keys(self.data, self.secs, self.ranges)

    def test_map_key_buffer_and_user_type(self):
        self.assertEqual(packet.take(self.data, self.secs, 0x2a72bc5, 9, True),
                         bytes.fromhex('48c744245014000000'))
        refs = {row[0]: row for row in packet.collect_leas(self.data, self.secs, self.ranges)}
        self.assertEqual(refs['rmp_key_type_name'][-1], '0x20a020')
        self.assertEqual(packet.take(self.data, self.secs, 0x20a020, 4), b'User')
        with self.changed_byte(0x2a72bca):
            with self.assertRaisesRegex(ValueError, 'changed window'):
                packet.check_windows(self.data, self.secs, self.ranges)

    def test_writer_indirect_slots_and_relocations(self):
        rows, relocs = packet.collect_helper_relocations(self.data, self.secs, self.ranges)
        self.assertEqual([row[-2] for row in rows], ['0x151f240', '0x15204a0', '0x29ed380'])
        self.assertEqual(len(relocs), 3)
        with self.changed_byte(0x43e362b):
            with self.assertRaisesRegex(ValueError, 'indirect slot'):
                packet.collect_helper_relocations(self.data, self.secs, self.ranges)
        with self.changed_offset(relocs[1][3] + 8, struct.pack('<Q', 1)):
            with self.assertRaisesRegex(ValueError, 'relative relocation'):
                packet.collect_helper_relocations(self.data, self.secs, self.ranges)

    def test_time_separator_and_failure_guard(self):
        self.assertEqual(packet.take(self.data, self.secs, 0x43e3641, 5, True),
                         bytes.fromhex('be54000000'))
        cases = {row[0]: row for row in packet.collect_branches(self.data, self.secs, self.ranges)}
        self.assertEqual(cases['time_separator_error'][-2], '0x43e36c8')
        with self.changed_byte(0x43e3642):
            with self.assertRaisesRegex(ValueError, 'changed window'):
                packet.check_windows(self.data, self.secs, self.ranges)

    def test_shared_key_hex_input_width_and_binding(self):
        self.assertEqual(packet.take(self.data, self.secs, 0x43f579b, 10, True),
                         bytes.fromhex('be2a000000b914000000'))
        cases = {row[0]: row for row in packet.collect_branches(self.data, self.secs, self.ranges)}
        self.assertEqual(cases['key_hex_write_failure'][-2], '0x43f57c8')
        with self.changed_byte(0x43f57a1):
            with self.assertRaisesRegex(ValueError, 'changed window'):
                packet.check_windows(self.data, self.secs, self.ranges)

    def test_summary_reports_selected_not_whole_node_counts(self):
        outputs = packet.generate(self.data)
        self.assertIn(b'"functions": 34', outputs['summary.json'])
        self.assertIn(b'not complete function boundaries', outputs['summary.json'])
        self.assertIn(b't-null,t-null\tduplicate-t', outputs['reader-cases.tsv'])
        self.assertEqual(len(outputs), 14)


if __name__ == '__main__':
    unittest.main()
