"""Static target and negative controls for the scheduled-cancel state packet."""

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
import abci_cancel_state115 as study


class ScheduledCancelStudy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = study.TARGET.read_bytes()
        cls.secs, table = study.unwind_index(cls.data)
        _, fdes = study.eh_frame_records(cls.data, cls.secs)
        selected = {start for _, start, _ in study.FUNCTIONS}
        cls.table = [row for row in table if row['start'] in selected]
        cls.fdes = [row for row in fdes if row['start'] in selected]
        cls.relocs = study.relative_relocations(cls.data, cls.secs)
        del table, fdes
        cls.files = study.collect(cls.data)

    def test_authenticated_target_and_bad_digest(self):
        self.assertEqual(study.digest_checked(self.data, study.TARGET_SHA256), study.TARGET_SHA256)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            study.digest_checked(self.data, '0' * 64)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            study.compare_historical(b'wrong historical artifact', self.data)

    def test_invalid_input_does_not_create_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            bad = base / 'bad-elf'
            bad.write_bytes(b'not the authenticated node')
            out = base / 'out'
            with mock.patch.object(study, 'TARGET', bad):
                with self.assertRaisesRegex(ValueError, 'SHA-256'):
                    study.main(['--out', str(out)])
            self.assertFalse(out.exists())

    def test_selected_file_mapping_rejects_nobits_overlap_and_range(self):
        blob = bytes(range(16))
        section = {'name': '.text', 'address': 100, 'size': 8, 'offset': 2, 'type': 1}
        self.assertEqual(study.read_va(blob, [section], 103, 3), bytes([5, 6, 7]))
        for va, size in ((99, 1), (107, 2), (100, 0), (-1, 1), ((1 << 64) - 1, 2)):
            with self.subTest(va=va, size=size), self.assertRaises(ValueError):
                study.mapped_offset(blob, [section], va, size)
        with self.assertRaises(ValueError):
            study.mapped_offset(blob, [dict(section, type=8)], 100, 1)
        with self.assertRaises(ValueError):
            study.mapped_offset(blob, [section, dict(section)], 100, 1)
        with self.assertRaises(ValueError):
            study.mapped_offset(blob, [dict(section, offset=15)], 100, 2)

    def test_selected_fde_ranges_and_uniqueness(self):
        rows = study.selected_functions(self.data, self.secs, self.table, self.fdes)
        self.assertEqual(len(rows), len(study.FUNCTIONS))
        with self.assertRaisesRegex(ValueError, 'FDE extent'):
            study.selected_functions(self.data, self.secs, self.table, self.fdes[:-1])
        with self.assertRaisesRegex(ValueError, 'FDE extent'):
            study.selected_functions(self.data, self.secs, self.table, self.fdes + [self.fdes[0]])
        with self.assertRaisesRegex(ValueError, 'uniquely indexed'):
            study.selected_functions(self.data, self.secs, self.table + [self.table[0]], self.fdes)
        changed = list(self.fdes)
        changed[0] = dict(changed[0], end=changed[0]['end'] + 1)
        with self.assertRaisesRegex(ValueError, 'FDE extent'):
            study.selected_functions(self.data, self.secs, self.table, changed)

    def test_window_and_transfer_negative_controls(self):
        for label, va, hx in study.WINDOWS:
            expected = bytes.fromhex(hx)
            with self.subTest(window=label):
                actual = study.read_va(self.data, self.secs, va, len(expected))
                study.exact_window(actual, expected)
                damaged = bytearray(actual)
                damaged[len(damaged) // 2] ^= 1
                with self.assertRaisesRegex(ValueError, 'window mismatch'):
                    study.exact_window(damaged, expected)
        for label, va, hx, target in study.EDGES + study.BRANCHES:
            expected = bytes.fromhex(hx)
            with self.subTest(transfer=label):
                actual = study.read_va(self.data, self.secs, va, len(expected))
                study.validate_transfer(va, actual, expected, target)
                with self.assertRaisesRegex(ValueError, 'target mismatch'):
                    study.validate_transfer(va, actual, expected, target + 1)
        with self.assertRaisesRegex(ValueError, 'unsupported'):
            study.decode_transfer(0, b'\x90')

    def test_corrupt_instruction_rejected_even_with_digest_updated(self):
        label, va, hx = next(row for row in study.WINDOWS if row[0] == 'ctx_json_duplicate')
        offset, _ = study.mapped_offset(self.data, self.secs, va, len(bytes.fromhex(hx)))
        damaged = bytearray(self.data)
        damaged[offset] ^= 1
        with mock.patch.object(study, 'TARGET_SHA256', hashlib.sha256(damaged).hexdigest()):
            with self.assertRaisesRegex(ValueError, 'window mismatch'):
                study.collect(damaged)

    def test_corrupt_real_descriptor_relocation_with_digest_updated(self):
        record_offset = self.relocs[0x649c7d0][0][3]
        damaged = bytearray(self.data)
        damaged[record_offset + 16] ^= 1
        with mock.patch.object(study, 'TARGET_SHA256', hashlib.sha256(damaged).hexdigest()):
            with self.assertRaisesRegex(ValueError, 'unexpected relative relocation'):
                study.collect(damaged)

    def test_scope_marks_previously_owned_context(self):
        self.assertEqual(study.evidence_scope(0x3efdb57, 5), 'prior-boundary')
        self.assertEqual(study.evidence_scope(0x4d9df91, 8), 'prior-boundary')
        self.assertEqual(study.evidence_scope(0x3d38b00, 8), 'new')
        end = next(end for role, _, end in study.FUNCTIONS if role == 'root_value_visitor')
        self.assertEqual(study.evidence_scope(end - 1, 2), 'prior-boundary')

    def test_relative_relocation_validation(self):
        record = struct.pack('<QQq', 0x1000, 8, 0x2000)
        sec = {'name': '.rela.dyn', 'type': 4, 'offset': 0, 'size': len(record)}
        relocs = study.relative_relocations(record, [sec])
        self.assertEqual(study.selected_relocation(relocs, 0x1000, 0x2000), (8, 0, 0x2000, 0))
        for modified in ({}, {0x1000: [(8, 0, 0x2000, 0)] * 2},
                         {0x1000: [(6, 0, 0x2000, 0)]},
                         {0x1000: [(8, 1, 0x2000, 0)]},
                         {0x1000: [(8, 0, 0x2001, 0)]}):
            with self.subTest(modified=modified), self.assertRaises(ValueError):
                study.selected_relocation(modified, 0x1000, 0x2000)
        with self.assertRaises(ValueError):
            study.relative_relocations(record, [dict(sec, size=23)])
        with self.assertRaises(ValueError):
            study.relative_relocations(record, [sec, sec])

    def test_memcmp_import_binding_and_bad_symbols(self):
        slot = 0x64dfb50
        row = study.imported_symbol(self.data, self.secs, self.relocs, slot, b'memcmp')
        self.assertEqual(row[6], 'memcmp')
        with self.assertRaises(ValueError):
            study.imported_symbol(self.data, self.secs, self.relocs, slot, b'other')
        malformed = dict(self.relocs)
        malformed[slot] = self.relocs[slot] * 2
        with self.assertRaises(ValueError):
            study.imported_symbol(self.data, self.secs, malformed, slot, b'memcmp')
        malformed[slot] = [(8, 12, 0, self.relocs[slot][0][3])]
        with self.assertRaises(ValueError):
            study.imported_symbol(self.data, self.secs, malformed, slot, b'memcmp')
        short_sym = [dict(s, size=24) if s['name'] == '.dynsym' else s for s in self.secs]
        with self.assertRaises(ValueError):
            study.imported_symbol(self.data, short_sym, self.relocs, slot, b'memcmp')

    def test_location_pointer_and_records(self):
        loc = study.read_location(self.data, self.secs, self.relocs, 0x64767a8)
        self.assertEqual((loc['line'], loc['column'], loc['source_length']), (123, 37, 20))
        bad = dict(self.relocs)
        kind, symbol, _, off = bad[0x64767a8][0]
        bad[0x64767a8] = [(kind, symbol, 0, off)]
        with self.assertRaises(ValueError):
            study.read_location(self.data, self.secs, bad, 0x64767a8)
        with self.assertRaises(ValueError):
            study.read_location(self.data, self.secs, {}, 0x64767a8)

    def test_json_table_integrity_and_bounds(self):
        base = 0x7b3f00
        raw = study.read_va(self.data, self.secs, base, 33 * 4)
        digest = hashlib.sha256(raw).hexdigest()
        rows = study.decode_dispatch(raw, base, 0x5b, digest)
        self.assertEqual((int(rows[0][-1], 16), int(rows[32][-1], 16)), (0x3c74293, 0x3c743e8))
        with self.assertRaises(ValueError):
            study.decode_dispatch(raw[:-1], base, 0x5b, digest)
        damaged = bytearray(raw)
        damaged[0] ^= 1
        with self.assertRaises(ValueError):
            study.decode_dispatch(damaged, base, 0x5b, digest)
        struct.pack_into('<i', damaged, 0, 0x7fffffff)
        with self.assertRaisesRegex(ValueError, 'outside FDE'):
            study.decode_dispatch(damaged, base, 0x5b, hashlib.sha256(damaged).hexdigest())

    def test_marker_dispatch_boundaries(self):
        def kind(n):
            return study.marker_kind(n, 0x80, 0x90, 0xa0, 15)
        self.assertEqual(kind(0x7f), ('other', None))
        self.assertEqual(kind(0x80), ('fixed-map', 0))
        self.assertEqual(kind(0x8f), ('fixed-map', 15))
        self.assertEqual(kind(0x90), ('fixed-array', 0))
        self.assertEqual(kind(0x9f), ('fixed-array', 15))
        self.assertEqual(kind(0xa0), ('other', None))
        self.assertEqual(sum(kind(i)[0] == 'fixed-map' for i in range(256)), 16)
        self.assertEqual(sum(kind(i)[0] == 'fixed-array' for i in range(256)), 16)
        for invalid in (-1, 256, True):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                kind(invalid)

    def test_sort_and_duplicate_boundaries(self):
        plan = lambda n, duplicate=False: study.map_plan(n, duplicate, 21, 64)
        self.assertEqual(plan(0), ('none', 'compact'))
        self.assertEqual(plan(1), ('none', 'compact'))
        self.assertEqual(plan(2), ('direct-helper', 'compact'))
        self.assertEqual(plan(20), ('direct-helper', 'compact'))
        self.assertEqual(plan(21), ('indirect-helper', 'compact'))
        self.assertEqual(plan(64), ('indirect-helper', 'compact'))
        self.assertEqual(plan(65), ('indirect-helper', 'large-helper'))
        self.assertEqual(plan(65, True), ('indirect-helper', 'duplicate-error'))
        for n, duplicate in ((1, True), (-1, False), (1 << 64, False), (2, 1)):
            with self.subTest(n=n, duplicate=duplicate), self.assertRaises(ValueError):
                plan(n, duplicate)
        key = bytes(range(20))
        self.assertTrue(study.adjacent_equal(key, key))
        for i in range(20):
            altered = bytearray(key)
            altered[i] ^= 1
            self.assertFalse(study.adjacent_equal(key, bytes(altered)))
        with self.assertRaises(ValueError):
            study.adjacent_equal(key, b'short')

    def test_writer_predicates_and_omission(self):
        self.assertEqual(study.writer_choice(0, 0), (0, ''))
        self.assertEqual(study.writer_choice(0, 1), (1, 't'))
        self.assertEqual(study.writer_choice(1, 0), (1, 'n'))
        self.assertEqual(study.writer_choice((1 << 64) - 1, (1 << 32) - 1), (2, 'tn'))
        for count, tag in ((-1, 0), (1 << 64, 0), (0, -1), (0, 1 << 32), (True, 0)):
            with self.subTest(count=count, tag=tag), self.assertRaises(ValueError):
                study.writer_choice(count, tag)

    def test_clone_allocation_and_node_boundaries(self):
        limit = 0x2aaaaaaaaaaaaaa
        self.assertEqual(limit, ((1 << 63) - 1) // 48)
        self.assertEqual(study.clone_count_case(0, limit, 48), ('zero-size', 0))
        self.assertEqual(study.clone_count_case(1, limit, 48), ('allocate', 48))
        self.assertEqual(study.clone_count_case(limit, limit, 48), ('allocate', limit * 48))
        self.assertEqual(study.clone_count_case(limit + 1, limit, 48), ('size-error', None))
        for invalid in (-1, 1 << 64, True):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                study.clone_count_case(invalid, limit, 48)
        self.assertEqual(study.node_insert_case(10, 11), 'write')
        self.assertEqual(study.node_insert_case(11, 11), 'full-error')
        self.assertEqual(study.node_insert_case(65535, 11), 'full-error')
        for invalid in (-1, 65536, True):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                study.node_insert_case(invalid, 11)

    def test_clone_representation_guards(self):
        marker = 1 << 63
        self.assertEqual(study.clone_representation(0, 1, 0, marker), 'compact')
        self.assertEqual(study.clone_representation(marker + 1, 1, 0, marker), 'compact')
        self.assertEqual(study.clone_representation(marker, 0, 0, marker), 'empty-tree')
        self.assertEqual(study.clone_representation(marker, 0, 8, marker), 'empty-tree')
        self.assertEqual(study.clone_representation(marker, 1, 0, marker), 'missing-tree-pointer')
        self.assertEqual(study.clone_representation(marker, 1, 8, marker), 'tree')
        for args in ((-1, 0, 0, marker), (marker, -1, 0, marker),
                     (marker, 0, 1 << 64, marker), (True, 0, 0, marker)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                study.clone_representation(*args)

    def test_copy_projection_and_outside_controls(self):
        self.assertEqual(study.project_range(16, 16, 0x2798, 0x2488, 32), 0x2488)
        self.assertEqual(study.project_range(0, 0, 0x27a8, 0x2488, 32), 0x2488)
        first = study.project_range(0x4088, 0x9820, 0x2780, 0x4060 + 0x2488, 32)
        second = study.project_range(0x97f8, 0x1098, 0x27a8, first, 32)
        self.assertEqual((first, second), (0xbc80, 0x3520))
        self.assertEqual(study.project_range(0x1098, 0, 0x27a8, second, 32), 0x2488)
        self.assertEqual(study.project_range(16, 32, 64, 16, 64), 32)
        for case in ((16, 16, 64, 15, 1), (16, 16, 64, 79, 2),
                     (0, 0, 1, 0, 0), ((1 << 64) - 1, 0, 2, 0, 1),
                     (0, (1 << 64) - 1, 2, 0, 1), (True, 0, 1, 0, 1)):
            with self.subTest(case=case), self.assertRaises(ValueError):
                study.project_range(*case)

    def test_seen_flags_are_independent_of_default_values(self):
        self.assertEqual(study.field_events([]), ('ok', 0, 0))
        self.assertEqual(study.field_events([('t', 0), ('t', 1)])[0], 'duplicate-t')
        self.assertEqual(study.field_events([('n', 0), ('n', 1)])[0], 'duplicate-n')
        self.assertEqual(study.field_events([('n', 7), ('t', 1)]), ('ok', 7, 1))
        for events in ([('x', 0)], [('t', 1 << 32)], [('n', 1 << 64)], [('n', -1)]):
            with self.subTest(events=events), self.assertRaises(ValueError):
                study.field_events(events)

    def test_generated_evidence_and_layout(self):
        expected = {'functions.tsv', 'windows.tsv', 'transfers.tsv', 'branches.tsv',
                    'relocations.tsv', 'imports.tsv', 'literals.tsv', 'json-dispatch.tsv',
                    'marker-cases.tsv', 'map-cases.tsv', 'writer-cases.tsv',
                    'field-events.tsv', 'clone-cases.tsv', 'clone-mode-cases.tsv', 'node-cases.tsv',
                    'layout.json', 'summary.json'}
        self.assertEqual(set(self.files), expected)
        summary = json.loads(self.files['summary.json'])
        layout = json.loads(self.files['layout.json'])
        self.assertEqual(summary['binary_sha256'], study.TARGET_SHA256)
        self.assertEqual(summary['selected_fde_count'], len(study.FUNCTIONS))
        self.assertEqual(layout['state_snapshot_offset'], '0x4b18')
        self.assertEqual(layout['state_root_capture_offset'], '0x4b18')
        self.assertEqual(layout['json_visitor_result_field_offset'], '0x2488')
        self.assertEqual(layout['binary_visitor_result_field_offset'], '0x2488')
        self.assertEqual(layout['binary_parent_result_field_offset'], '0x2488')
        self.assertEqual(layout['json_exchange_payload_field_offset'], '0x2488')
        self.assertEqual(layout['materialize_input_field_offset'], '0x2488')
        self.assertEqual(layout['materialize_output_field_offset'], '0x3fa8')
        self.assertEqual(layout['clone_input_field_offset'], '0x3fa8')
        self.assertEqual(layout['clone_output_field_offset'], '0x3fa8')
        staging = int(layout['expanded_staging_field_offset'], 16)
        base = int(layout['expanded_staging_base'], 16)
        self.assertEqual(staging - base, int(layout['state_snapshot_offset'], 16))
        self.assertEqual((layout['pair_stride_bytes'], layout['pair_value_offset']), (48, 24))
        self.assertIn('root_field_visit\tprior-boundary\t', self.files['relocations.tsv'])
        self.assertIn('allocation_slot\tprior-boundary\t', self.files['relocations.tsv'])
        self.assertIn('prior-boundary\t0x64dfb50\t', self.files['imports.tsv'])
        self.assertIn('ctx_json_value\tprior-boundary\t', self.files['transfers.tsv'])


if __name__ == '__main__':
    unittest.main()
