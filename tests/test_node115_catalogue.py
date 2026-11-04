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
        self.assertEqual(coverage['totals']['node115']['windows'], 4)
        self.assertEqual(coverage['totals']['node115']['bytes'], 2940)
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


if __name__ == '__main__':
    unittest.main()
