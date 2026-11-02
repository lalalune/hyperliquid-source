"""Byte accounting controls: actual differences, target separation and no double counting."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import struct
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from byte_progress import compare, fraction, load_coverage, summarize
from catalogue import project_bytes, render_dependency_progress, render_readme_progress
from test_research_tools import fixture


class ByteArithmeticTests(unittest.TestCase):
    def test_raw_and_relocation_qualified_are_separate(self):
        field = {'offset': 4, 'width': 4, 'kind': 2, 'addend': -4}
        row = compare(b'abcd0000', b'abcd1234', [field])
        self.assertEqual((row['raw_equal_bytes'], row['bytes']), (4, 8))
        self.assertFalse(row['raw_equal'])
        self.assertTrue(row['relocation_qualified'])
        changed = compare(b'xbcd0000', b'abcd1234', [field])
        self.assertFalse(changed['relocation_qualified'])
        self.assertEqual(changed['non_relocation_difference_offsets'], [0])

    def test_invalid_masks_and_length_mismatch_cannot_improve_score(self):
        field = {'offset': 4, 'width': 4, 'kind': 2, 'addend': -4}
        for fields in [[field, field], [{**field, 'offset': 6}], [{**field, 'kind': 1}],
                       [{**field, 'width': 8}], [{**field, 'addend': 0}]]:
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                compare(b'abcd0000', b'abcd1234', fields)
        for a, b in [(b'', b''), (b'ab', b'a')]:
            with self.assertRaises(ValueError):
                compare(a, b, [])

    def test_weight_by_bytes_instead_of_averaging_window_percentages(self):
        rows = [compare(b'a', b'a', []), compare(b'x' * 9, b'y' * 9, [])]
        result = summarize(rows)
        self.assertEqual(fraction(result['raw_equal_bytes'], result['bytes']), '1/10 (10.00%)')
        self.assertEqual(fraction(result['raw_equal_windows'], result['windows']), '1/2 (50.00%)')
        self.assertEqual(fraction(0, 0), 'Unmeasured')


class ByteRegistryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'provenance').mkdir()
        data = fixture()
        data[256:288] = b'abcdefgh' * 4
        self.data = bytes(data)
        self.sha = lambda b: hashlib.sha256(b).hexdigest()
        manifest = []
        for target in ('node94', 'node115'):
            (self.root / target).write_bytes(self.data)
            manifest.append({'path': target, 'size': len(self.data), 'sha256': self.sha(self.data)})
        (self.root / 'provenance/artifacts.json').write_text(json.dumps({'files': manifest}))
        (self.root / 'source.bin').write_bytes(b'abcdefgh')
        self.components = [{'id': 'foundation', 'artifact': 'node94'}, {'id': 'visor', 'artifact': 'visor'}]
        self.window = dict(id='first', component='foundation', target='node94', start=256, end=264,
                           evidence='source.bin',
                           target_body_sha256=self.sha(b'abcdefgh'),
                           source={'path': 'source.bin', 'encoding': 'binary', 'offset': 0,
                                   'body_sha256': self.sha(b'abcdefgh')})
        self.registry = dict(schema_version=1, targets={t: {'path': t, 'sha256': self.sha(self.data)}
                                                      for t in ('node94', 'node115')},
                             evidence_sha256={'source.bin': self.sha(b'abcdefgh')}, windows=[self.window])

    def load(self):
        (self.root / 'registry.json').write_text(json.dumps(self.registry))
        return load_coverage(self.root, 'registry.json', self.components)

    def test_same_address_on_separate_targets_is_not_project_double_credit(self):
        self.registry['windows'].append({**self.window, 'id': 'later-release', 'target': 'node115'})
        result = self.load()
        self.assertEqual(result['totals']['node115']['bytes'], 8)
        self.assertEqual(project_bytes(self.components, result)['bytes'], 8)
        self.assertEqual(result['components']['visor']['windows'], 0)

    def test_overlapping_windows_and_duplicate_ids_rejected(self):
        for second in [{**self.window}, {**self.window, 'id': 'overlap', 'start': 260, 'end': 268}]:
            self.registry['windows'] = [self.window, second]
            with self.assertRaises(ValueError):
                self.load()

    def test_dependency_window_is_counted_once_outside_component_progress(self):
        self.window['dependency'] = 'rust-core'
        result = self.load()
        self.assertEqual(result['components']['foundation']['bytes'], 0)
        self.assertEqual(result['totals']['node94']['bytes'], 8)
        self.assertEqual(result['dependencies']['node94']['rust-core']['bytes'], 8)
        self.assertEqual(project_bytes(self.components, result)['bytes'], 8)
        self.window['dependency'] = 'unreviewed-library'
        with self.assertRaisesRegex(ValueError, 'dependency attribution'):
            self.load()

    def test_changed_target_and_evidence_are_rejected(self):
        (self.root / 'node94').write_bytes(self.data[:-1])
        with self.assertRaisesRegex(ValueError, 'target identity'):
            self.load()
        (self.root / 'node94').write_bytes(self.data)
        (self.root / 'source.bin').write_bytes(b'abcdxfgh')
        with self.assertRaisesRegex(ValueError, 'evidence digest'):
            self.load()

    def test_unmapped_and_cross_component_target_rejected(self):
        self.window['start'], self.window['end'] = 0, 8
        with self.assertRaisesRegex(ValueError, 'executable section'):
            self.load()
        self.window.update(start=256, end=264, component='visor', target='node115')
        with self.assertRaisesRegex(ValueError, 'another target'):
            self.load()

    def test_truncated_source_rejected_even_if_whole_file_rehashed(self):
        (self.root / 'source.bin').write_bytes(b'abc')
        self.registry['evidence_sha256']['source.bin'] = self.sha(b'abc')
        self.window['source']['body_sha256'] = self.sha(b'abc')
        with self.assertRaisesRegex(ValueError, 'comparison extent'):
            self.load()

    def unequal_candidate(self, source=b'abcdefghXY'):
        (self.root / 'source.bin').write_bytes(source)
        self.registry['evidence_sha256']['source.bin'] = self.sha(source)
        self.window.update(comparison_mode='extent-mismatch', dependency='mio',
                           label='Source-built listener candidate', source_kind='licensed-source build')
        self.window['source'].update(length=len(source), body_sha256=self.sha(source))

    def test_unequal_complete_extents_are_registered_without_aligned_byte_credit(self):
        for source in (b'abcdefghXY', b'abc'):
            with self.subTest(source=source):
                self.unequal_candidate(source)
                result = self.load()
                self.assertEqual(result['windows'], [])
                self.assertEqual(result['totals']['node94'], summarize([]))
                self.assertEqual(project_bytes(self.components, result), summarize([]))
                row, = result['extent_mismatches']
                self.assertEqual((row['target_bytes'], row['source_bytes']), (8, len(source)))
                self.assertEqual(row['status'], 'unmatched-extent')
                self.assertIsNone(row['aligned_byte_comparison'])
                self.assertNotIn('raw_equal_bytes', row)
                self.assertNotIn('equal_non_relocation_bytes', row)
                self.assertEqual(row['source']['body_sha256'], self.sha(source))
                text = '\n'.join(render_dependency_progress(result))
                self.assertIn('Unmatched candidates with different extents', text)
                self.assertIn(f'| 8 | {len(source)} | Unmatched; no aligned-byte comparison |', text)

    def test_unequal_candidate_does_not_change_existing_aligned_totals(self):
        self.unequal_candidate()
        aligned = {**self.window, 'id': 'aligned', 'start': 264, 'end': 272,
                   'comparison_mode': 'offset-aligned', 'dependency': 'rust-core',
                   'source': {**self.window['source'], 'length': 8, 'body_sha256': self.sha(b'abcdefgh')}}
        self.registry['windows'].append(aligned)
        result = self.load()
        self.assertEqual(result['totals']['node94'], summarize([compare(b'abcdefgh', b'abcdefgh', [])]))
        self.assertEqual(len(result['windows']), 1)
        self.assertEqual(len(result['extent_mismatches']), 1)
        self.assertEqual(set(result['dependencies']['node94']), {'rust-core'})

    def test_unequal_source_tail_is_authenticated_even_if_prefix_matches(self):
        self.unequal_candidate()
        changed = b'abcdefghXZ'
        (self.root / 'source.bin').write_bytes(changed)
        self.registry['evidence_sha256']['source.bin'] = self.sha(changed)
        with self.assertRaisesRegex(ValueError, 'Source body digest'):
            self.load()

    def test_unequal_candidate_cannot_inject_unmeasured_aligned_metrics(self):
        self.unequal_candidate()
        for key, value in {'bytes': 8, 'raw_equal_bytes': 8, 'relocation_bytes': 0,
                           'non_relocation_bytes': 8, 'equal_non_relocation_bytes': 8,
                           'raw_difference_offsets': [], 'non_relocation_difference_offsets': []}.items():
            self.window[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'cannot supply aligned-byte metrics'):
                self.load()
            del self.window[key]

    def test_unequal_mode_requires_explicit_positive_in_bounds_extent(self):
        self.unequal_candidate()
        del self.window['source']['length']
        with self.assertRaisesRegex(ValueError, 'explicit source length'):
            self.load()
        for length in (0, -1, True, 10.0, '10', 11):
            self.window['source']['length'] = length
            with self.subTest(length=length), self.assertRaisesRegex(ValueError, 'source comparison extent'):
                self.load()
        self.window['source']['length'] = 10
        self.window['source']['offset'] = 1
        with self.assertRaisesRegex(ValueError, 'source comparison extent'):
            self.load()

    def test_mode_cannot_hide_equal_lengths_or_unapproved_relocation_masks(self):
        self.unequal_candidate(b'abcdefgh')
        with self.assertRaisesRegex(ValueError, 'requires unequal extents'):
            self.load()
        self.unequal_candidate()
        self.window['relocations'] = {'path': 'source.bin', 'pointer': []}
        with self.assertRaisesRegex(ValueError, 'no shared relocation mask'):
            self.load()
        del self.window['relocations']
        self.window['comparison_mode'] = 'unreviewed-mode'
        with self.assertRaisesRegex(ValueError, 'comparison mode'):
            self.load()
        del self.window['comparison_mode']
        with self.assertRaisesRegex(ValueError, 'comparison extent'):
            self.load()

    def test_unequal_hex_source_extent_uses_decoded_bytes_and_offset(self):
        self.unequal_candidate()
        source = b'XXabcdefghYYY'
        encoded = source.hex().encode('ascii')
        (self.root / 'source.bin').write_bytes(encoded)
        self.registry['evidence_sha256']['source.bin'] = self.sha(encoded)
        self.window['source'].update(encoding='hex', offset=2, length=11,
                                     body_sha256=self.sha(source[2:]))
        result = self.load()
        self.assertEqual(result['extent_mismatches'][0]['source_bytes'], 11)

    def test_unequal_candidates_still_reject_duplicate_target_intervals(self):
        self.unequal_candidate()
        self.registry['windows'].append({**self.window, 'id': 'second-candidate'})
        with self.assertRaisesRegex(ValueError, 'Overlapping target windows'):
            self.load()

    def test_equal_length_legacy_output_does_not_gain_extent_mismatch_records(self):
        self.assertNotIn('extent_mismatches', self.load())

    def test_external_registry_or_evidence_is_not_read(self):
        self.registry['evidence_sha256']['../outside.bin'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'external byte evidence'):
            self.load()

    def test_unpinned_comparison_evidence_rejected(self):
        self.window['evidence'] = 'unreviewed.json'
        with self.assertRaisesRegex(ValueError, 'hash-pinned'):
            self.load()

    def test_duplicate_registry_key_rejected(self):
        path = self.root / 'registry.json'
        path.write_text('{"schema_version": 1, "schema_version": 2}')
        with self.assertRaisesRegex(ValueError, 'Duplicate key'):
            load_coverage(self.root, path.name, self.components)

    def test_non_text_executable_window_does_not_inflate_text_coverage(self):
        # Make .eh_frame_hdr executable in the synthetic ELF; its bytes must
        # still not contribute to a denominator measured only over .text.
        data = bytearray(self.data)
        struct.pack_into('<Q', data, 512 + 3 * 64 + 8, 6)
        (self.root / 'node94').write_bytes(data)
        manifest_path = self.root / 'provenance/artifacts.json'
        manifest = json.loads(manifest_path.read_text())
        manifest['files'][0]['sha256'] = self.sha(data)
        manifest_path.write_text(json.dumps(manifest))
        self.registry['targets']['node94']['sha256'] = self.sha(data)
        self.window.update(start=0x200, end=0x208)
        with self.assertRaisesRegex(ValueError, '.text coverage denominator'):
            self.load()


class ActualByteProgressTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.components = json.loads((ROOT / 'research/components.json').read_text())['components']
        cls.coverage = load_coverage(ROOT, 'research/byte-windows.json', cls.components)

    def test_actual_captures_and_retained_compiled_sources(self):
        stats = self.coverage['totals']['node94']
        self.assertEqual((stats['raw_equal_bytes'], stats['bytes']), (4781, 4873))
        self.assertEqual((stats['raw_equal_windows'], stats['relocation_qualified_windows'], stats['windows']), (5, 10, 10))
        self.assertEqual(self.coverage['totals']['node115']['windows'], 3)
        self.assertEqual(self.coverage['targets']['node94']['text_bytes'], 70370352)
        self.assertEqual(self.coverage['targets']['node94']['other_executable_bytes'], 4504)
        self.assertEqual(self.coverage['targets']['visor']['text_bytes'], 5150272)
        self.assertEqual(self.coverage['totals']['visor']['windows'], 0)
        self.assertTrue(all(row['windows'] == 0 for row in self.coverage['components'].values()))
        self.assertEqual(self.coverage['dependencies']['node94']['rust-core']['bytes'], 2060)
        self.assertEqual(sum(row['bytes'] for row in self.coverage['dependencies']['node94'].values()), 4873)

    def test_byte_progress_does_not_complete_module_gates(self):
        progress = json.loads((ROOT / 'research/progress.json').read_text())
        before = copy.deepcopy(progress)
        output = render_readme_progress(self.components, progress, self.coverage)
        self.assertEqual(progress, before)
        self.assertIn('0.00% (0/92 accepted gates; 0/23 components complete)', output)
        self.assertIn('0.00% (0/4 accepted gates; 0/1 components complete)', output)
        self.assertIn('1,968/2,060 (95.53%)', output)
        self.assertIn('0.00692%', output)
        self.assertIn('| 0/4 | 0% | 0 | 0 |', output)
        self.assertIn('not 0% correct', output)
        self.assertNotIn('N/A', output)

    def test_division_two_published_candidates_count_one_interval(self):
        windows = [row for row in self.coverage['windows']
                   if row['id'] == 'node94-u128-division']
        self.assertEqual(len(windows), 1)
        self.assertEqual(windows[0]['source_kind'], 'published-artifact')
        self.assertEqual(windows[0]['dependency'], 'compiler-builtins')
        self.assertEqual(windows[0]['bytes'], 198)
        self.assertTrue(windows[0]['raw_equal'])
        self.assertEqual(windows[0]['relocation_bytes'], 0)

    def test_remainder_published_artifact_counts_one_interval(self):
        windows = [row for row in self.coverage['windows']
                   if row['id'] == 'node94-u128-remainder']
        self.assertEqual(len(windows), 1)
        self.assertEqual(windows[0]['source_kind'], 'published-artifact')
        self.assertEqual(windows[0]['bytes'], 197)
        self.assertTrue(windows[0]['raw_equal'])
        self.assertEqual(windows[0]['relocation_bytes'], 0)

    def test_actual_mio_candidate_preserves_full_unequal_extents_without_credit(self):
        row, = [r for r in self.coverage['extent_mismatches']
                if r['id'] == 'node94-mio-listener-bind']
        self.assertEqual((row['target_bytes'], row['source_bytes']), (305, 364))
        self.assertEqual((row['start'], row['end']), (0x3cd6690, 0x3cd67c1))
        self.assertEqual(row['source']['length'], 364)
        self.assertEqual(row['dependency'], 'mio')
        self.assertFalse(row['raw_equal'])
        self.assertFalse(row['relocation_qualified'])
        self.assertIsNone(row['aligned_byte_comparison'])
        self.assertNotIn(row['id'], {r['id'] for r in self.coverage['windows']})
        self.assertEqual(self.coverage['components']['transport'], summarize([]))
        self.assertNotIn('mio', self.coverage['dependencies']['node94'])


if __name__ == '__main__':
    unittest.main()
