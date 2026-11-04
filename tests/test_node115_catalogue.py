"""Controls for target exclusivity and honest progress accounting."""
import copy
import errno
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import byte_progress
import catalogue


class CatalogueTests(unittest.TestCase):
    def setUp(self):
        self.components = json.loads((ROOT / 'research/components.json').read_text())['components']
        self.progress = json.loads((ROOT / 'research/progress.json').read_text())

    def test_all_scope_is_node115_with_no_unearned_gates(self):
        self.assertEqual(len(self.components), 23)
        self.assertEqual({c['artifact'] for c in self.components}, {'node115'})
        catalogue.validate_progress(self.components, self.progress, ROOT)
        self.assertEqual(catalogue.progress_totals(self.components, self.progress), (0, 92))

    def test_completed_gate_requires_evidence(self):
        progress = copy.deepcopy(self.progress)
        progress['components'][self.components[0]['id']]['gates']['built'] = True
        with self.assertRaisesRegex(ValueError, 'Completed gates require reviewed evidence'):
            catalogue.validate_progress(self.components, progress, ROOT)

    def test_old_target_cannot_enter_generated_scope(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'research').mkdir()
            components = copy.deepcopy(self.components)
            components[0]['artifact'] = 'node94'
            (root / 'research/components.json').write_text(json.dumps({'components': components}))
            (root / 'research/progress.json').write_text(json.dumps(self.progress))
            with self.assertRaisesRegex(ValueError, 'Only node115'):
                catalogue.generate(root)

    def stage_registry(self, folder):
        root = Path(folder)
        registry = json.loads((ROOT / 'research/byte-windows.json').read_text())
        paths = set(registry['evidence_sha256']) | {'research/byte-windows.json', 'provenance/artifacts.json'}
        paths |= {t['path'] for t in registry['targets'].values()}
        for path in paths:
            dest = root / path
            dest.parent.mkdir(parents=True, exist_ok=True)
            # Copies of small records can be mutated without changing originals;
            # the large, immutable input is linked and never written here.
            # A hard link fails when the staging directory is on another
            # filesystem (EXDEV, e.g. a tmpfs TMPDIR); copy in that case.
            if path.startswith('artifacts/'):
                try:
                    os.link(ROOT / path, dest)
                except OSError as error:
                    if error.errno != errno.EXDEV:
                        raise
                    shutil.copyfile(ROOT / path, dest)
            else:
                dest.write_bytes((ROOT / path).read_bytes())
        return root, registry

    def test_dependency_bytes_do_not_count_as_first_party(self):
        coverage = byte_progress.load_coverage(ROOT, 'research/byte-windows.json', self.components)
        self.assertEqual(set(coverage['targets']), {'node115'})
        self.assertEqual(coverage['totals']['node115']['windows'], 7884)
        self.assertEqual(coverage['totals']['node115']['bytes'], 5313802)
        self.assertTrue(all(row['windows'] == 0 for row in coverage['components'].values()))

    def test_wrong_owner_target_and_changed_evidence_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root, registry = self.stage_registry(folder)
            components = copy.deepcopy(self.components)
            first_owner = registry['windows'][0]['component']
            next(c for c in components if c['id'] == first_owner)['artifact'] = 'node94'
            with self.assertRaisesRegex(ValueError, 'belongs to another target'):
                byte_progress.load_coverage(root, 'research/byte-windows.json', components)
            evidence = next(iter(registry['evidence_sha256']))
            with (root / evidence).open('ab') as stream:
                stream.write(b'corruption')
            with self.assertRaisesRegex(ValueError, 'Byte evidence digest changed'):
                byte_progress.load_coverage(root, 'research/byte-windows.json', self.components)

    def test_rustc_195_std_windows_are_relocation_qualified_dependencies(self):
        coverage = byte_progress.load_coverage(ROOT, 'research/byte-windows.json', self.components)
        rows = [r for r in coverage['windows'] if r['id'].startswith('node115-std-')]
        self.assertEqual(len(rows), 306)
        self.assertTrue(all(r['relocation_qualified'] for r in rows))
        self.assertEqual({r['dependency'] for r in rows},
                         {'rust-core', 'rust-std', 'rust-alloc', 'compiler-builtins'})
        remainder, = [r for r in rows if r['start'] == 0x63efd70]
        self.assertTrue(remainder['raw_equal'])
        self.assertEqual(remainder['bytes'], 197)

    def test_plt32_and_displaced_pc32_fields_mask_only_their_four_bytes(self):
        for field in ({'offset': 4, 'width': 4, 'kind': 4, 'addend': -4},
                      {'offset': 4, 'width': 4, 'kind': 2, 'addend': 52}):
            with self.subTest(field=field):
                row = byte_progress.compare(b'abcd0000', b'abcd1234', [field])
                self.assertEqual(row['relocation_bytes'], 4)
                self.assertTrue(row['relocation_qualified'])
                changed = byte_progress.compare(b'xbcd0000', b'abcd1234', [field])
                self.assertFalse(changed['relocation_qualified'])
        for field in ({'offset': 4, 'width': 4, 'kind': 1, 'addend': 0},
                      {'offset': 4, 'width': 4, 'kind': 2, 'addend': None},
                      {'offset': 4, 'width': 8, 'kind': 4, 'addend': -4}):
            with self.subTest(field=field), self.assertRaises(ValueError):
                byte_progress.compare(b'abcd0000', b'abcd1234', [field])

    def test_vendored_crate_windows_are_own_crate_dependencies(self):
        coverage = byte_progress.load_coverage(ROOT, 'research/byte-windows.json', self.components)
        rows = [r for r in coverage['windows'] if r['id'].startswith('node115-vendor-')]
        rust = [r for r in rows if r['dependency'] == 'vendored-crates']
        native = [r for r in rows if r['dependency'] == 'native-libraries']
        self.assertEqual((len(rust), sum(r['bytes'] for r in rust)), (309, 153433))
        self.assertEqual((len(native), sum(r['bytes'] for r in native)), (7265, 5053810))
        self.assertEqual(len(rust) + len(native), len(rows))
        self.assertTrue(all(r['relocation_qualified'] for r in rows))
        self.assertTrue(all(row['windows'] == 0 for row in coverage['components'].values()))
    def test_relocation_field_rejections_cannot_widen_credit(self):
        field = {'offset': 4, 'width': 4, 'kind': 2, 'addend': -4}
        cases = ([field, {**field, 'offset': 6}],          # overlapping fields
                 [{**field, 'offset': 5}],                 # runs past the end
                 [{**field, 'offset': -1}],                # negative offset
                 [{**field, 'addend': True}],              # bool is not an integer addend
                 [{**field, 'kind': 24}], [{**field, 'kind': 26}],
                 [{**field, 'offset': 0}, field])          # every byte masked
        for fields in cases:
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                byte_progress.compare(b'abcd0000', b'abcd1234', fields)

    def test_census_relocation_pointer_must_name_the_window_record(self):
        with tempfile.TemporaryDirectory() as folder:
            root, registry = self.stage_registry(folder)
            windows = [w for w in registry['windows'] if (w.get('relocations') or {}).get('pointer', [None])[0] == 'records']
            first, second = windows[0], next(w for w in windows[1:]
                                               if w['relocations']['path'] == windows[0]['relocations']['path'])
            first['relocations'] = dict(second['relocations'])
            (root / 'research/byte-windows.json').write_text(json.dumps(registry))
            with self.assertRaisesRegex(ValueError, 'Relocation record belongs to another window'):
                byte_progress.load_coverage(root, 'research/byte-windows.json', self.components)

    def test_gotpcrelx_relaxation_requires_the_exact_psabi_rewrite(self):
        mov = b'\x48\x8b\x05\x00\x00\x00\x00\x90'
        lea = b'\x48\x8d\x05\x11\x22\x33\x44\x90'
        row = {'offset': 3, 'width': 4, 'kind': 42, 'addend': -4, 'relaxation': 'gotpcrelx-mov-lea'}
        result = byte_progress.compare(mov, lea, [row])
        self.assertTrue(result['relocation_qualified'])
        self.assertFalse(result['raw_equal'])
        self.assertEqual(result['relocation_bytes'], 5)  # field plus the rewritten opcode
        untagged = {k: v for k, v in row.items() if k != 'relaxation'}
        self.assertFalse(byte_progress.compare(mov, lea, [untagged])['relocation_qualified'])
        call = b'\xff\x15\x00\x00\x00\x00\x90'
        relaxed_call = b'\x67\xe8\x01\x02\x03\x04\x90'
        self.assertTrue(byte_progress.compare(call, relaxed_call, [
            {'offset': 2, 'width': 4, 'kind': 41, 'addend': -4, 'relaxation': 'gotpcrelx-call'}])['relocation_qualified'])
        changed_modrm = b'\x48\x8d\x0d\x11\x22\x33\x44\x90'
        for source, target, bad in ((mov, lea, {**row, 'kind': 9}),          # not a GOTPCRELX site
                                    (mov, lea, {**row, 'relaxation': 'x'}),  # unknown rewrite
                                    (mov, lea, {**row, 'relaxation': 'gotpcrelx-call'}),
                                    (lea, lea, row),                          # source is not mov
                                    (mov, mov, row)):                         # target not relaxed
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                byte_progress.compare(source, target, [bad])
        with self.assertRaises(ValueError):  # the ModRM is not part of the rewrite
            byte_progress.compare(mov, changed_modrm, [row])
        not_rip = b'\x48\x8b\x44\x00\x00\x00\x00\x90'
        with self.assertRaises(ValueError):  # mov reg,[rax+rax] is not a GOT load
            byte_progress.compare(not_rip, b'\x48\x8d\x44\x00\x00\x00\x00\x90', [row])
        with self.assertRaises(ValueError):  # call relaxation is a kind-41 site only
            byte_progress.compare(call, relaxed_call, [
                {'offset': 2, 'width': 4, 'kind': 42, 'addend': -4, 'relaxation': 'gotpcrelx-call'}])

    def test_census_relaxed_match_uses_the_comparator_rule(self):
        sys.path.insert(0, str(ROOT / 'research/work-items/RE-002-node115-std-census'))
        sys.path.insert(0, str(ROOT / 'research/work-items/RE-002-node115-vendor-census'))
        import vendor_census
        self.assertIs(vendor_census.RELAXATIONS, byte_progress.RELAXATIONS)
        mov = b'\x48\x8b\x05\x00\x00\x00\x00\x90'
        lea = b'\x48\x8d\x05\x11\x22\x33\x44\x90'
        mask = set(range(3, 7))
        self.assertEqual(vendor_census.relaxed_match(mov, lea, [(3, 42, -4)], mask), {3: 'gotpcrelx-mov-lea'})
        self.assertIsNone(vendor_census.relaxed_match(mov, lea, [(3, 9, -4)], mask))           # not GOTPCRELX
        self.assertIsNone(vendor_census.relaxed_match(mov, lea[:-1] + b'\x91', [(3, 42, -4)], mask))
        self.assertIsNone(vendor_census.relaxed_match(mov, lea, [(3, 42, -4)], mask | {1}))    # overlap

    def test_multi_copy_windows_are_native_and_fully_explained(self):
        census = json.loads((ROOT / 'research/work-items/RE-002-node115-vendor-census/census.json').read_text())
        multi = [r for r in census['records'] if r.get('identical_copies')]
        self.assertTrue(multi)
        self.assertTrue(all(r['native'] for r in multi))
        self.assertTrue(all(r['distinct_functions_explaining_copies'] >= r['identical_copies'] for r in multi))
        self.assertTrue(all(r['end'] - r['start'] >= 64 and r['identical_copies'] <= 32 for r in multi))
        by_body = {}
        for r in multi:
            by_body.setdefault(r['source_body_sha256'], set()).add(r['start'])
        self.assertTrue(all(len(v) >= 2 for v in by_body.values()))


if __name__ == '__main__':
    unittest.main()
