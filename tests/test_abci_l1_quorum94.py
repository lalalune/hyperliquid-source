import csv
import hashlib
import io
import json
import mmap
from pathlib import Path
import tempfile
import unittest

from tools import abci_l1_quorum94 as evidence


class QuorumEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.handle = evidence.TARGET.open('rb')
        cls.data = mmap.mmap(cls.handle.fileno(), 0, access=mmap.ACCESS_COPY)
        cls.image = evidence.Image(cls.data)
        cls.files = evidence.collect(cls.data)
        cls.fdes = {f['start']: f for f in evidence.selected_fdes(cls.image)}
        cls.keys = evidence.decode_keys(cls.image)

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.handle.close()

    def mutate(self, va, index=0, value=1):
        offset = self.image.offset(va, index + 1) + index
        original = self.data[offset]
        self.data[offset] = original ^ value
        self.addCleanup(self.data.__setitem__, offset, original)

    def test_target_identity_and_missing_artifact_is_not_skipped(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), evidence.SHA256)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'wrong'
            target = Path(directory) / 'out'
            source.write_bytes(b'wrong target')
            with self.assertRaises(evidence.EvidenceError):
                evidence.generate(source, target)
            self.assertFalse(target.exists())
            with self.assertRaises(FileNotFoundError):
                evidence.generate(source.with_name('absent'), target)

    def test_digest_corruption_rejected(self):
        self.mutate(0x1e84d50)
        with self.assertRaisesRegex(evidence.EvidenceError, 'digest'):
            evidence.authenticate(self.data)

    def test_twenty_two_actual_fde_records_and_body_hashes(self):
        rows = list(csv.DictReader(io.StringIO(self.files['functions.tsv'].decode()), delimiter='\t'))
        self.assertEqual(len(rows), 22)
        self.assertEqual(len(self.fdes), 22)
        for row in rows:
            start = int(row['start_va'], 16)
            end = int(row['end_va_exclusive'], 16)
            self.assertEqual(end, self.fdes[start]['end'])
            raw = self.image.read(start, end - start)
            self.assertEqual(row['body_hex'], raw.hex())
            self.assertEqual(hashlib.sha256(raw).hexdigest(), row['body_sha256'])

    def test_corrupt_fde_range_rejected(self):
        fde = self.fdes[0x1e84d50]
        self.mutate(fde['fde'], 12)
        with self.assertRaises((evidence.EvidenceError, ValueError)):
            evidence.selected_fdes(self.image)

    def test_corrupt_fde_body_rejected(self):
        self.mutate(0x1e84d50)
        with self.assertRaisesRegex(evidence.EvidenceError, 'body changed'):
            evidence.selected_fdes(self.image)

    def test_each_window_detects_corruption(self):
        for name, site, expected in evidence.WINDOW_PINS:
            off = self.image.offset(site, 1)
            saved = self.data[off]
            self.data[off] ^= 1
            try:
                with self.subTest(name=name):
                    with self.assertRaises(evidence.EvidenceError):
                        evidence.checked(self.image, site, expected)
            finally:
                self.data[off] = saved

    def test_every_selected_branch_and_displacement_is_pinned(self):
        for site, raw_hex, target in evidence.BRANCH_PINS:
            raw = bytes.fromhex(raw_hex)
            cond, fallthrough, taken = evidence.branch(self.image, site, raw_hex, target)
            self.assertTrue(0 <= cond <= 15)
            self.assertEqual(fallthrough, site + len(raw))
            self.assertEqual(taken, target)
            for index in (0, len(raw) - 1):
                off = self.image.offset(site, len(raw)) + index
                saved = self.data[off]
                self.data[off] ^= 1
                try:
                    with self.subTest(site=hex(site), index=index):
                        with self.assertRaises(evidence.EvidenceError):
                            evidence.branch(self.image, site, raw_hex, target)
                finally:
                    self.data[off] = saved

    def test_every_selected_call_and_displacement_is_pinned(self):
        for site, raw_hex, target in evidence.CALL_PINS:
            self.assertEqual(evidence.call(self.image, site, raw_hex, target), target)
            for index in (0, 4):
                off = self.image.offset(site, 5) + index
                saved = self.data[off]
                self.data[off] ^= 1
                try:
                    with self.subTest(site=hex(site), index=index):
                        with self.assertRaises(evidence.EvidenceError):
                            evidence.call(self.image, site, raw_hex, target)
                finally:
                    self.data[off] = saved

    def test_selected_path_edges_and_result_guards(self):
        calls = {site: target for site, _, target in evidence.CALL_PINS}
        for source, dest in {
            0x2fe73a8: 0x31210a0,
            0x31215c2: 0x3b45940,
            0x3b45964: 0x31a1020,
            0x312154a: 0x308d1a0,
            0x308d25b: 0x340f760,
            0x340f810: 0x303eaa0,
            0x303ed25: 0x31888c0,
            0x281aa10: 0x1e84d50,
            0x1e84df5: 0x2326ea0,
            0x1e84e37: 0x1e43a90,
            0x1e43c79: 0x1de0be0,
            0x1de0d6a: 0x1e84540,
            0x4ae37c0: 0x48c8ba0,
            0x48c8c87: 0x440a800,
        }.items():
            self.assertEqual(calls[source], dest)
        targets = {site: target for site, _, target in evidence.BRANCH_PINS}
        self.assertEqual(targets[0x31212f0], 0x312260a)
        self.assertEqual(targets[0x3188c9d], 0x3189ae9)
        self.assertEqual(targets[0x1e84e04], 0x1e84e97)

    def test_key_names_and_all_single_byte_mutations(self):
        groups = {
            'outer': ['tracker', 'quorum_l1_hashes', 'highest_quorum_height'],
            'row': ['l1_hash', 'hot_user_to_signature', 'hard_voter_to_signature'],
        }
        for group, expected in groups.items():
            records = [r for r in self.keys if r['group'] == group]
            self.assertEqual([r['name'] for r in records], expected)
            for name in expected:
                original = name.encode()
                self.assertEqual(evidence.classify(original, records), name)
                self.assertIsNone(evidence.classify(original + b'X', records))
                self.assertIsNone(evidence.classify(original[:-1], records))
                for i, byte in enumerate(original):
                    for replacement in range(256):
                        if replacement == byte:
                            continue
                        altered = original[:i] + bytes([replacement]) + original[i+1:]
                        self.assertIsNone(evidence.classify(altered, records))

    def test_corrupt_key_comparison_and_rodata_are_rejected(self):
        cmp_site = 0x31212b3
        self.mutate(cmp_site, 3)
        with self.assertRaises(evidence.EvidenceError):
            evidence.decode_keys(self.image)

    def test_corrupt_overlapping_key_literal_is_rejected(self):
        site = self.keys[0]['pieces'][0]['data_va']
        self.mutate(site)
        with self.assertRaises(evidence.EvidenceError):
            evidence.decode_keys(self.image)

    def test_tracker_dispatch_and_optional_hsc_completion(self):
        rows, tables = evidence.tracker_dispatch(self.image)
        self.assertEqual([(r[0], r[1]) for r in rows], [(0, 'name'), (1, 'hsc'), (2, 'i')])
        self.assertEqual(len(tables), 2)
        self.assertEqual(rows[2][5], 0x31a1c8f)
        cases = evidence.tracker_presence_cases()
        self.assertEqual(cases[0][1], 'missing:name')
        self.assertEqual(cases[1][1], 'missing:i')
        self.assertEqual(cases[5][1:], ('complete', 'two_zero_words'))
        self.assertEqual(cases[7][1:], ('complete', 'present_child_words'))

    def test_changed_tracker_literal_and_dispatch_are_rejected(self):
        self.mutate(0x5a7e6a)
        with self.assertRaises(evidence.EvidenceError):
            evidence.tracker_dispatch(self.image)

    def test_changed_tracker_table_is_rejected(self):
        self.mutate(0x57cb10)
        with self.assertRaises(evidence.EvidenceError):
            evidence.tracker_dispatch(self.image)

    def test_hsc_fields_duplicate_and_missing_paths(self):
        rows = evidence.hsc_dispatch(self.image)
        self.assertEqual([r[0] for r in rows], ['q', 'i'])
        self.assertEqual([r[1] for r in rows], [0, 8])
        self.assertEqual([r[3] for r in rows], [0x3087600, 0x3087600])
        self.assertEqual([r[5] for r in rows], [0x30e77e2, 0x30e77eb])
        self.assertEqual([r[7] for r in rows], [0x30e76ac, 0x30e76b5])
        self.assertEqual([r[1] for r in evidence.hsc_presence_cases()],
                         ['missing:q', 'missing:i', 'missing:q', 'complete'])

    def test_changed_hsc_key_is_rejected(self):
        self.mutate(0x30e730a, 2)
        with self.assertRaises(evidence.EvidenceError):
            evidence.hsc_dispatch(self.image)

    def test_changed_hsc_child_is_rejected(self):
        self.mutate(0x30e7474, 4)
        with self.assertRaises(evidence.EvidenceError):
            evidence.hsc_dispatch(self.image)

    def test_diagnostic_names_are_loaded_from_file_bytes(self):
        rows = evidence.diagnostic_links(self.image)
        self.assertEqual(len(rows), 9)
        self.assertEqual([r[3] for r in rows[-4:]], ['q', 'i', 'q', 'i'])
        self.mutate(0x57e76c)
        with self.assertRaises(evidence.EvidenceError):
            evidence.diagnostic_links(self.image)

    def test_diagnostic_templates_and_corruption(self):
        rows = evidence.diagnostic_templates(self.image)
        self.assertEqual(len(rows), 7)
        self.assertEqual([r[4] for r in rows[-2:]], ['missing field `', 'duplicate field `'])
        self.mutate(0x1df8f3, 1)
        with self.assertRaises(evidence.EvidenceError):
            evidence.diagnostic_templates(self.image)

    def test_changed_tracker_default_mask_is_rejected(self):
        self.mutate(0x31a1d5b, 4)
        with self.assertRaises(evidence.EvidenceError):
            evidence.tracker_dispatch(self.image)

    def test_writer_names_offsets_and_child_calls(self):
        rows = evidence.writer_fields(self.image, self.keys)
        expected = {
            'low': [('tracker', 0), ('quorum_l1_hashes', 0x40), ('highest_quorum_height', 0x58)],
            'shared': [('tracker', 0), ('quorum_l1_hashes', 0x40), ('highest_quorum_height', 0x58)],
            'json': [('tracker', 0), ('quorum_l1_hashes', 0x40), ('highest_quorum_height', 0x58)],
            'tracker': [('name', 8), ('hsc', 0x18), ('i', 0x28)],
            'value': [('l1_hash', 0), ('hot_user_to_signature', 0x20),
                      ('hard_voter_to_signature', 0x38)],
        }
        for group, items in expected.items():
            self.assertEqual([(r['name'], r['source_offset']) for r in rows if r['group'] == group], items)

    def test_changed_writer_offset_is_rejected(self):
        self.mutate(0x1e84e2b, 3)
        with self.assertRaises(evidence.EvidenceError):
            evidence.writer_fields(self.image, self.keys)

    def test_changed_shared_writer_offset_is_rejected(self):
        self.mutate(0x48c8c7b, 3)
        with self.assertRaises(evidence.EvidenceError):
            evidence.writer_fields(self.image, self.keys)

    def test_all_three_copy_stages_preserve_the_96_bytes(self):
        rows = evidence.transfer_rows(self.image)
        self.assertEqual(len(rows), 18)
        for index in range(6):
            local, visitor, materializer = rows[index], rows[6 + index], rows[12 + index]
            self.assertEqual(local[4], visitor[3])
            self.assertEqual(visitor[4], materializer[3])
            self.assertEqual(materializer[4], 0x35b0 + index * 16)
            self.assertEqual((local[5], visitor[5], materializer[5]), (16, 16, 16))

    def test_changed_copy_register_and_displacement_rejected(self):
        va = 0x2ff3678
        off = self.image.offset(va, 8)
        old = self.data[off + 2]
        self.data[off + 2] = 0x8c
        try:
            with self.assertRaisesRegex(evidence.EvidenceError, 'register mismatch'):
                evidence.transfer_rows(self.image)
        finally:
            self.data[off + 2] = old
        self.mutate(va, 4)
        with self.assertRaises(evidence.EvidenceError):
            evidence.transfer_rows(self.image)

    def test_two_row_descriptors_and_thunk_targets(self):
        rows, relocs = evidence.decode_tables(self.image)
        self.assertEqual([(r['lane'], r['row']) for r in rows], [('low', 36), ('shared', 36)])
        self.assertEqual([r['closure'] for r in rows], [0x281a9c0, 0x4ae3770])
        self.assertEqual([r['writer'] for r in rows], [0x1e84d50, 0x48c8ba0])
        self.assertEqual(len(relocs), 3)

    def test_low_hash_capture_connects_field_and_descriptor(self):
        rows, _ = evidence.decode_tables(self.image)
        self.assertEqual(evidence.low_hash_capture(self.image, rows),
                         (0x35b0, 0x240, 0x248, 0x56bdeb8, 0x208))
        self.mutate(0x2756f48, 3)
        with self.assertRaises(evidence.EvidenceError):
            evidence.low_hash_capture(self.image, rows)

    def test_low_hash_capture_rejects_wrong_saved_argument(self):
        rows, _ = evidence.decode_tables(self.image)
        self.mutate(0x27561c7, 4)
        with self.assertRaises(evidence.EvidenceError):
            evidence.low_hash_capture(self.image, rows)

    def test_hash_writer_named_mode_and_corruption(self):
        rows = evidence.hash_writer_configs(self.image)
        self.assertEqual([(r[0], r[3], r[4], r[5]) for r in rows], [
            ('low', 0x1000400, 1, 0), ('shared', 0x1000400, 1, 0),
        ])
        self.mutate(0x281a9f5, 7)
        with self.assertRaises(evidence.EvidenceError):
            evidence.hash_writer_configs(self.image)

    def test_both_output_wrappers_bind_state_field_and_name(self):
        rows = evidence.output_wrappers(self.image)
        self.assertEqual([(r[0], r[2], r[6], r[7]) for r in rows], [
            ('binary', 0x35b0, 'lhvt', 0x1e84d50),
            ('json', 0x35b0, 'lhvt', 0x1e84ee0),
        ])
        self.mutate(0x27b29fc, 1)
        with self.assertRaises(evidence.EvidenceError):
            evidence.output_wrappers(self.image)

    def test_output_wrapper_rejects_changed_enclosing_name(self):
        _, name = evidence.named_literal(self.image, 0x27b29d1, 0x27b29d8)
        self.assertEqual(name, 'lhvt')
        name_va, _ = evidence.named_literal(self.image, 0x27b29d1, 0x27b29d8)
        self.mutate(name_va)
        with self.assertRaises(evidence.EvidenceError):
            evidence.output_wrappers(self.image)

    def test_default_initializer_and_all_twelve_words(self):
        _, relocs = evidence.decode_tables(self.image)
        literal, rows, calls = evidence.default_path(self.image, relocs)
        self.assertEqual(literal, b'lhv')
        self.assertEqual([r[1] for r in rows], list(range(0, 96, 8)))
        self.assertEqual([r[3] for r in rows], [
            '3', 'allocation_result', '3', '0', '0', '0',
            'unspecified_stack_word', '0', '0', '8', '0', '0',
        ])
        self.assertEqual([(r[1], r[3], r[4]) for r in calls], [
            (0x2ff3618, 0x5770e30, 0x3a054e0),
            (0x3a054ff, 0x576dfd8, None),
            (0x3a05566, 0x576dfb8, None),
        ])
        targets = {site: target for site, _, target in evidence.BRANCH_PINS}
        self.assertEqual(targets[0x2ff360e], 0x2ff3620)
        self.assertEqual(targets[0x3a05508], 0x3a0555c)

    def test_default_initializer_detects_corrupt_literal(self):
        _, relocs = evidence.decode_tables(self.image)
        self.mutate(0x3a0550e, 3)
        with self.assertRaises(evidence.EvidenceError):
            evidence.default_path(self.image, relocs)

    def test_default_initializer_detects_corrupt_indirect_call(self):
        _, relocs = evidence.decode_tables(self.image)
        self.mutate(0x2ff3618, 2)
        with self.assertRaises(evidence.EvidenceError):
            evidence.default_path(self.image, relocs)

    def test_default_initializer_rejects_wrong_relocation(self):
        _, relocs = evidence.decode_tables(self.image)
        altered = [dict(row) for row in relocs]
        next(r for r in altered if r['slot'] == 0x5770e30)['addend'] ^= 1
        with self.assertRaises(evidence.EvidenceError):
            evidence.default_path(self.image, altered)

    def test_changed_relocation_type_is_rejected(self):
        _, relocs = evidence.decode_tables(self.image)
        off = relocs[0]['entry_offset'] + 8
        before = self.data[off]
        self.data[off] ^= 1
        self.addCleanup(self.data.__setitem__, off, before)
        with self.assertRaises(evidence.EvidenceError):
            evidence.relative_relocations(self.image, {relocs[0]['slot']: relocs[0]['addend']})

    def test_duplicate_relocation_is_rejected(self):
        _, relocs = evidence.decode_tables(self.image)
        sec = self.image.section('.rela.dyn')
        off = sec['offset']
        old = bytes(self.data[off:off + 24])
        self.data[off:off + 24] = self.data[relocs[0]['entry_offset']:relocs[0]['entry_offset'] + 24]
        self.addCleanup(self.data.__setitem__, slice(off, off + 24), old)
        with self.assertRaisesRegex(evidence.EvidenceError, 'duplicate'):
            evidence.relative_relocations(self.image, {relocs[0]['slot']: relocs[0]['addend']})

    def test_changed_descriptor_thunk_is_rejected(self):
        self.mutate(0x1e64890, 4)
        with self.assertRaises(evidence.EvidenceError):
            evidence.decode_tables(self.image)

    def test_nobits_unmapped_and_ambiguous_ranges_are_rejected(self):
        bss = next(s for s in self.image.sections if s['name'] == '.bss' and s['type'] == 8)
        with self.assertRaises(evidence.EvidenceError):
            self.image.read(bss['address'], 1)
        for address, size in ((-1, 1), (0xffffffffffffffff, 1), (0x1e84d50, 0)):
            with self.subTest(address=address, size=size):
                with self.assertRaises(evidence.EvidenceError):
                    self.image.offset(address, size)
        clone = object.__new__(evidence.Image)
        clone.data = self.data
        source = next(s for s in self.image.sections if s['name'] == '.text')
        clone.sections = [dict(source), dict(source)]
        with self.assertRaises(evidence.EvidenceError):
            clone.offset(0x1e84d50, 1)
        clone.sections = [dict(source, type=8)]
        with self.assertRaises(evidence.EvidenceError):
            clone.offset(0x1e84d50, 1)

    def test_lsda_range_and_selected_landing(self):
        fde = self.fdes[0x1e43a90]
        header, rows = evidence.lsda_rows(self.image, fde)
        self.assertIsNotNone(header)
        row = next(r for r in rows if r['start'] <= 0x1e43b49 + 4 < r['end'])
        self.assertEqual(row['landing'], 0x1e43cea)
        self.assertEqual(row['action'], 0)
        self.assertTrue(all(fde['start'] <= r['start'] <= r['end'] <= fde['end'] for r in rows))

    def test_corrupt_lsda_encoding_is_rejected(self):
        fde = self.fdes[0x1e43a90]
        self.mutate(fde['lsda'])
        with self.assertRaises(evidence.EvidenceError):
            evidence.lsda_rows(self.image, fde)

    def test_stride_and_count_boundaries(self):
        strides, shift = evidence.stride_cases(self.image)
        self.assertEqual({r[3] for r in strides}, {88})
        self.assertEqual(shift, 32)
        self.assertEqual(((1 << shift) - 1) >> shift, 0)
        self.assertEqual((1 << shift) >> shift, 1)

    def test_changed_stride_is_rejected(self):
        self.mutate(0x340f7c5, 3)
        with self.assertRaises(evidence.EvidenceError):
            evidence.stride_cases(self.image)

    def test_map_and_sequence_marker_cases(self):
        self.assertEqual(evidence.marker_cases(self.image), [(0, 0x93), (1, 0x83)])
        self.mutate(0x1e84a6f)
        with self.assertRaises(evidence.EvidenceError):
            evidence.marker_cases(self.image)

    def test_synthetic_presence_cases_are_ordered_and_labeled(self):
        rows = list(csv.DictReader(io.StringIO(self.files['cases.tsv'].decode()), delimiter='\t'))
        outer = [r for r in rows if r['group'] == 'outer' and r['case'] == 'presence']
        self.assertEqual(len(outer), 8)
        self.assertEqual(outer[0]['result'], 'missing:tracker')
        self.assertEqual(outer[1]['result'], 'missing:quorum_l1_hashes')
        self.assertEqual(outer[3]['result'], 'missing:highest_quorum_height')
        self.assertEqual(outer[7]['result'], 'complete')

    def test_summary_counts_are_selected_evidence_not_coverage(self):
        summary = json.loads(self.files['summary.json'])
        self.assertEqual(summary['selected_fdes'], 22)
        self.assertEqual(summary['selected_key_names'], 6)
        self.assertEqual(summary['tracker_key_names'], 3)
        self.assertEqual(summary['hsc_key_names'], 2)
        self.assertEqual(summary['diagnostic_names'], 9)
        self.assertEqual(summary['diagnostic_templates'], 7)
        self.assertEqual(summary['copy_lanes'], 18)
        self.assertEqual(summary['relative_relocations'], 3)
        self.assertEqual(summary['default_words'], 12)
        self.assertEqual(summary['output_wrappers'], 2)
        self.assertEqual(summary['hash_writer_configs'], 2)
        self.assertIn('not a complete call graph', summary['limitations'])


if __name__ == '__main__':
    unittest.main()
