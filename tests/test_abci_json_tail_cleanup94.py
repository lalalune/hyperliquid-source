"""Target-bound and corruption controls for the selected JSON cleanup path."""

from contextlib import contextmanager
import mmap
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import abci_json_tail_cleanup94 as subject
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records


class TailCleanupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # The artifact is required. A missing or unreadable capture is a failure.
        cls.file = subject.BINARY.open('rb')
        cls.data = mmap.mmap(cls.file.fileno(), 0, access=mmap.ACCESS_COPY)
        cls.result = subject.collect(cls.data)
        cls.secs, all_index = unwind_index(cls.data)
        _cies, all_fdes = eh_frame_records(cls.data, cls.secs)
        cls.index = [r for r in all_index if r['start'] in subject.FRAMES]
        cls.fdes = [r for r in all_fdes if r['start'] in subject.FRAMES]
        cls.frames = {f['start']: f for f in cls.fdes}
        cls.mask = cls.result['operands']['tail_allowed_mask']['value']
        cls.maximum = cls.result['operands']['tail_max_byte']['value']
        cls.newline = cls.result['operands']['location_newline']['value']
        cls.line = cls.result['operands']['location_initial_line']['value']

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.file.close()

    @contextmanager
    def patched_offset(self, off, replacement):
        before = self.data[off:off + len(replacement)]
        self.data[off:off + len(replacement)] = replacement
        try:
            yield
        finally:
            self.data[off:off + len(replacement)] = before

    @contextmanager
    def flipped_va(self, va, offset=0):
        off, _ = subject.map_offset(self.secs, va + offset, 1)
        with self.patched_offset(off, bytes([self.data[off] ^ 1])):
            yield

    def test_target_identity_and_changed_binary(self):
        self.assertEqual(subject.digest(self.data), subject.SHA256)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            subject.verify_digest(b'not the target')
        with self.flipped_va(0x2ff8b70):
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                subject.verify_digest(self.data)

    def test_fde_extent_and_index_witnesses(self):
        selected = subject.validate_frames(self.data, self.secs, self.index, self.fdes)
        self.assertEqual(len(selected), 8)
        self.assertEqual(selected[0x2ff8b70]['end'], 0x2ff9627)
        self.assertEqual(selected[0x3bbf380]['end'] - 0x3bbf380, 345)
        body = {f['start_va']: f for f in self.result['functions']}
        self.assertEqual(body['0x2fe2fe0']['ownership'], 'prior_boundary')
        self.assertNotIn('raw_bytes', body['0x2fe2fe0'])
        self.assertIn('raw_bytes', body['0x2ff8b70'])

    def test_actual_fde_range_corruption(self):
        va = self.frames[0x3bbd260]['fde'] + 12
        with self.flipped_va(va):
            _cies, fdes = eh_frame_records(self.data, self.secs)
            with self.assertRaisesRegex(ValueError, 'FDE/index mismatch'):
                subject.validate_frames(self.data, self.secs, self.index, fdes)

    def test_actual_unwind_index_displacement_corruption(self):
        row = next(r for r in self.index if r['start'] == 0x3bbd260)
        hdr = next(s for s in self.secs if s['name'] == '.eh_frame_hdr')
        offset = hdr['offset'] + 12 + row['index'] * 8 + 4
        with self.patched_offset(offset, bytes([self.data[offset] ^ 1])):
            with self.assertRaises(ValueError):
                _sections, changed = unwind_index(self.data)
                subject.validate_frames(self.data, self.secs, changed, self.fdes)

    def test_missing_duplicate_and_wrong_index_are_rejected(self):
        first = self.index[0]
        with self.assertRaisesRegex(ValueError, 'missing or duplicate'):
            subject.validate_frames(self.data, self.secs, self.index + [first], self.fdes)
        wrong = [dict(r) for r in self.index]
        wrong[0]['fde'] += 4
        with self.assertRaisesRegex(ValueError, 'FDE/index mismatch'):
            subject.validate_frames(self.data, self.secs, wrong, self.fdes)
        with self.assertRaisesRegex(ValueError, 'missing or duplicate'):
            subject.validate_frames(self.data, self.secs, self.index, self.fdes[:-1])

    def test_body_byte_corruption_in_every_selected_frame(self):
        for start in subject.FRAMES:
            with self.subTest(start=hex(start)), self.flipped_va(start):
                with self.assertRaisesRegex(ValueError, 'FDE bytes'):
                    subject.validate_frames(self.data, self.secs, self.index, self.fdes)

    def test_section_mapping_rejects_nobits_ambiguity_and_bad_ranges(self):
        section = {'type': 1, 'flags': 2, 'size': 16, 'address': 0x1000,
                   'offset': 24, 'name': 'synthetic'}
        self.assertEqual(subject.map_offset([section], 0x1008, 4), (32, 'synthetic'))
        nobits = dict(section, type=8)
        for bad, va, size in [([nobits], 0x1008, 4), ([section], 0x100f, 2),
                              ([section, dict(section)], 0x1008, 4),
                              ([section], -1, 4), ([section], 0x1008, 0),
                              ([section], (1 << 64) - 1, 2)]:
            with self.subTest(va=va, size=size):
                with self.assertRaises(ValueError):
                    subject.map_offset(bad, va, size)

    def test_complete_selected_windows_reject_edge_mutations(self):
        self.assertEqual(len(subject.extract_windows(self.data, self.secs)), 14)
        for start, end, role, _pin in subject.WINDOWS:
            for va in (start, end - 1):
                with self.subTest(role=role, va=hex(va)), self.flipped_va(va):
                    with self.assertRaisesRegex(ValueError, 'window changed'):
                        subject.extract_windows(self.data, self.secs)

    def test_every_branch_opcode_and_displacement_is_pinned(self):
        self.assertEqual(len(subject.extract_branches(self.data, self.secs)), 37)
        for site, raw, target, role in subject.BRANCHES:
            for byte_index in (0, len(bytes.fromhex(raw)) - 1):
                with self.subTest(site=hex(site), byte_index=byte_index), self.flipped_va(site, byte_index):
                    with self.assertRaises(ValueError):
                        subject.branch_one(self.data, self.secs, site, raw, target, role)
        with self.assertRaises(ValueError):
            subject.branch_one(self.data, self.secs, 0x2fe3099, '771d', 0x2fe30b9, 'bad target')

    def test_selected_transfers_and_mutated_displacements(self):
        got = {e['site_va']: e for e in subject.extract_edges(self.data, self.secs)}
        self.assertEqual(got['0x2fe30de']['target_va'], '0x2ff8b70')
        self.assertEqual(got['0x2fe310d']['target_va'], '0x2ff8b70')
        self.assertEqual(got['0x3005f30']['target_va'], '0x3bbe610')
        self.assertEqual(got['0x3bbd290']['target_va'], '0x3bbf380')
        for site, form, _target, _role in subject.EDGES:
            width = 5 if form in ('e8', 'e9') else 6
            for index in (0, width - 1):
                with self.subTest(site=hex(site), index=index), self.flipped_va(site, index):
                    with self.assertRaises(ValueError):
                        subject.extract_edges(self.data, self.secs)

    def test_operand_witnesses_and_every_immediate_mutation(self):
        vals = {k: v['value'] for k, v in self.result['operands'].items()}
        expected = {'copy_size': 0x1fc8, 'tail_max_byte': 0x20, 'tail_error_code': 22,
                    'outer_a_stride': 0x138, 'outer_b_stride': 0xd8,
                    'group_stride': 0x2f0, 'nested_stride': 0xd8,
                    'group_child_stride': 0x30, 'item_inner_stride': 0xf8,
                    'item_skip_tag': 2, 'item_count_from_pointer': -8}
        self.assertEqual({key: vals[key] for key in expected}, expected)
        for _name, site, _raw, at, _width, _signed in subject.OPERANDS:
            with self.subTest(site=hex(site)), self.flipped_va(site, at):
                with self.assertRaisesRegex(ValueError, 'operand instruction changed'):
                    subject.extract_operands(self.data, self.secs)

    def test_layout_from_distinct_nested_vectors(self):
        layout = self.result['layout']
        vectors = {row['name']: row for row in layout['vectors']}
        self.assertEqual((vectors['state_groups']['capacity_offset'], vectors['state_groups']['pointer_offset'],
                          vectors['state_groups']['count_offset'], vectors['state_groups']['stride_bytes']),
                         (0x5b8, 0x5c0, 0x5c8, 0x2f0))
        self.assertEqual((vectors['state_outer_a']['capacity_offset'], vectors['state_outer_a']['stride_bytes']),
                         (0x1848, 0x138))
        self.assertEqual((vectors['state_outer_b']['capacity_offset'], vectors['state_outer_b']['stride_bytes']),
                         (0x1860, 0xd8))
        self.assertEqual((vectors['outer_a_nested']['capacity_offset'], vectors['outer_a_nested']['stride_bytes']),
                         (0, 0xd8))
        self.assertEqual(layout['group_child_release_multiplier'], 0x30)
        self.assertEqual(layout['embedded_field_offsets'], [0x80, 0x98])
        self.assertEqual(layout['tagged_item'], {'row_stride': 0xf8, 'tag_offset': 0, 'skip_tag': 2,
                                                 'size_offset': 0x50, 'pointer_offset': 0x58, 'element_size': 8})

    def test_layout_rejects_mismatched_loop_and_release_size(self):
        operands = {k: dict(v) for k, v in self.result['operands'].items()}
        operands['group_child_release_shift']['value'] += 1
        with self.assertRaisesRegex(ValueError, 'multipliers disagree'):
            subject.derive_layout(operands, self.result['edges'])
        operands = {k: dict(v) for k, v in self.result['operands'].items()}
        operands['item_embedded_stride']['value'] = 0
        with self.assertRaisesRegex(ValueError, 'loop bounds'):
            subject.derive_layout(operands, self.result['edges'])

    def test_existing_factory_slot_is_a_boundary(self):
        edges = {e['site_va']: e for e in subject.extract_edges(self.data, self.secs)}
        self.assertEqual(edges['0x2fe3309']['target_va'], '0x576ef80')
        self.assertEqual(edges['0x2fe3309']['role'], 'prior located-error slot boundary')

    def test_lsda_rows_and_selected_landings(self):
        lsdas = {a: subject.parse_lsda(self.data, self.secs, f) for a, f in self.frames.items()}
        witnesses = {w['site_va']: w for w in subject.unwind_witnesses(lsdas)}
        self.assertEqual(len(witnesses), 13)
        self.assertEqual(witnesses['0x2fe30c9']['landing_va'], '0x2fe3105')
        self.assertEqual(witnesses['0x2fe30de']['landing_va'], '0x2fe311a')
        self.assertEqual(witnesses['0x2fe310d']['action'], 1)
        self.assertEqual(witnesses['0x3005f30']['landing_va'], '0x3006132')
        self.assertEqual(witnesses['0x3bbd290']['landing_va'], '0x3bbd30a')
        self.assertEqual(sum(len(x['rows']) for x in lsdas.values()), 97)

    def test_lsda_header_and_table_corruption(self):
        for start, frame in self.frames.items():
            va = frame['lsda']
            for off in (0, 5):
                with self.subTest(start=hex(start), offset=off), self.flipped_va(va, off):
                    with self.assertRaises(ValueError):
                        subject.parse_lsda(self.data, self.secs, frame)

    def test_missing_or_wrong_unwind_witness_is_rejected(self):
        lsdas = {a: subject.parse_lsda(self.data, self.secs, f) for a, f in self.frames.items()}
        row = next(r for r in lsdas[0x2fe2fe0]['rows'] if r['landing_va'] == '0x2fe3105')
        row['landing_va'] = '0x2fe3106'
        with self.assertRaisesRegex(ValueError, 'witness mismatch'):
            subject.unwind_witnesses(lsdas)

    def test_paired_functions_raw_and_explicitly_masked(self):
        pair = subject.masked_pair(self.data, self.secs)
        self.assertFalse(pair['raw_equal'])
        self.assertEqual(pair['different_raw_bytes'], 35)
        self.assertEqual(len(pair['raw_differences']), 35)
        self.assertTrue(all(row['inside_mask'] for row in pair['raw_differences']))
        self.assertTrue(pair['normalized_equal'])
        self.assertEqual(pair['masked_byte_count'], 56)
        self.assertEqual(len(pair['masks']), 14)
        self.assertEqual(pair['masks'][0]['target_va'], '0x33f5270')
        with self.flipped_va(0x3bb9d50):
            with self.assertRaisesRegex(ValueError, 'normalized paired'):
                subject.masked_pair(self.data, self.secs)

    def test_paired_relative_targets_are_not_blindly_masked(self):
        for offset in subject.MASK_SITES:
            first = 0x3bb9d50 + offset
            # Pick a displacement byte, not the opcode.
            b = subject.read_va(self.data, self.secs, first, 3)
            field = 1 if b[0] in (0xe8, 0xe9) else 2 if b[:2] in (b'\xff\x15', b'\xff\x25') else 3
            with self.subTest(offset=hex(offset)), self.flipped_va(first, field):
                with self.assertRaisesRegex(ValueError, 'relative targets differ'):
                    subject.masked_pair(self.data, self.secs)
        # Even a coordinated target change in both bodies is rejected by its pinned target.
        with self.flipped_va(0x3bb9d50 + 0x31, 1), self.flipped_va(0x3bbf380 + 0x31, 1):
            with self.assertRaisesRegex(ValueError, 'relative targets differ'):
                subject.masked_pair(self.data, self.secs)

    def test_all_suffix_bytes_against_independent_expected_set(self):
        accepted = set()
        for value in range(256):
            outcome = subject.scan_suffix(bytes([value]), 0, self.mask, self.maximum)
            if outcome['status'] == 'accept':
                accepted.add(value)
            else:
                self.assertEqual((outcome['cursor'], outcome['byte']), (0, value))
        self.assertEqual(accepted, {9, 10, 13, 32})
        self.assertEqual(sum(row['accepted'] for row in self.result['suffix_cases']), 4)

    def test_suffix_cursor_and_first_failure(self):
        cases = [(b'', 0, 'accept', 0, None),
                 (b' \n\r\t', 0, 'accept', 4, None),
                 (b'  X ', 0, 'reject', 2, 88),
                 (b'!\n', 1, 'accept', 2, None),
                 (b'\xc2\xa0', 0, 'reject', 0, 194)]
        for data, cursor, status, end, value in cases:
            with self.subTest(data=data, cursor=cursor):
                actual = subject.scan_suffix(data, cursor, self.mask, self.maximum)
                self.assertEqual((actual['status'], actual['cursor'], actual['byte']), (status, end, value))
        for bad in (-1, 2, True):
            with self.assertRaises(ValueError):
                subject.scan_suffix(b'x', bad, self.mask, self.maximum)
        with self.assertRaises(ValueError):
            subject.scan_suffix(b'x', 0, self.mask, 64)

    def test_location_counts_bytes_and_newlines(self):
        cases = [(b'', 0, (1, 0)), (b'abcX', 3, (1, 4)),
                 (b'\r\nX', 2, (2, 1)), (b'\nA?', 2, (2, 2)),
                 (b'\xc3\xa9!', 2, (1, 3)), (b'abc', 100, (1, 3))]
        for data, cursor, expected in cases:
            with self.subTest(data=data, cursor=cursor):
                self.assertEqual(subject.locate_error(data, cursor, self.newline, self.line), expected)
        for bad in (-1, 1 << 64, (1 << 64) - 1, True):
            with self.assertRaises(ValueError):
                subject.locate_error(b'a', bad, self.newline, self.line)

    def test_render_is_deterministic_and_has_only_generated_files(self):
        one = subject.render(self.result)
        two = subject.render(self.result)
        self.assertEqual(one, two)
        self.assertEqual(set(one), {'functions.json', 'windows.tsv', 'branches.tsv', 'edges.tsv',
                                    'operands.tsv', 'layout.json', 'unwind.json', 'unwind.tsv',
                                    'normalized-pair.json', 'suffix-byte-cases.tsv', 'summary.json'})
        self.assertTrue(all(b'\r' not in value for value in one.values()))


if __name__ == '__main__':
    unittest.main()
