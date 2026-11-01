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
from catalogue import project_bytes, render_readme_progress
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
        self.assertEqual(fraction(0, 0), 'N/A')


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
        self.assertEqual((stats['raw_equal_bytes'], stats['bytes']), (5648, 5756))
        self.assertEqual((stats['raw_equal_windows'], stats['relocation_qualified_windows'], stats['windows']), (4, 10, 10))
        self.assertEqual(self.coverage['totals']['node115']['windows'], 3)
        self.assertEqual(self.coverage['targets']['node94']['text_bytes'], 70370352)

    def test_byte_progress_does_not_complete_module_gates(self):
        progress = json.loads((ROOT / 'research/progress.json').read_text())
        before = copy.deepcopy(progress)
        output = render_readme_progress(self.components, progress, self.coverage)
        self.assertEqual(progress, before)
        self.assertIn('0.00% (0/24)', output)
        self.assertIn('5,648/5,756 (98.12%)', output)
        self.assertIn('0.00818%', output)
        self.assertIn('| Node #94 | 0/4 | 0% | N/A | N/A | N/A |', output)
        self.assertIn('not 0% correct', output)

    def test_string_pad_primary_is_a_separate_published_artifact_window(self):
        windows = [row for row in self.coverage['windows']
                   if row['id'] == 'node94-formatter-string-pad']
        self.assertEqual(len(windows), 1)
        row = windows[0]
        self.assertEqual((row['start'], row['end']), (0x1573450, 0x1573889))
        self.assertEqual(row['source_kind'], 'published-artifact')
        self.assertEqual((row['bytes'], row['raw_equal_bytes'], row['relocation_bytes']),
                         (1081, 1065, 16))
        self.assertFalse(row['raw_equal'])
        self.assertTrue(row['relocation_qualified'])

    def test_remainder_published_artifact_counts_one_interval(self):
        windows = [row for row in self.coverage['windows']
                   if row['id'] == 'node94-u128-remainder']
        self.assertEqual(len(windows), 1)
        self.assertEqual(windows[0]['source_kind'], 'published-artifact')
        self.assertEqual(windows[0]['bytes'], 197)
        self.assertTrue(windows[0]['raw_equal'])
        self.assertEqual(windows[0]['relocation_bytes'], 0)


if __name__ == '__main__':
    unittest.main()
