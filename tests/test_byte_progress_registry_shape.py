"""Malformed byte-registry and artifact-manifest shapes fail closed.

load_coverage dereferences the two JSON documents it loads — the byte
registry and provenance/artifacts.json — so a record that is missing a
field the function reads must meet the module's ValueError diagnostics,
not escape as a raw KeyError or TypeError. The sibling loaders
(artifacts.load_manifest, verify_imports.verify) validate the records
they load the same way. Staging idiom follows test_node115_catalogue.py.
"""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import byte_progress

COMPONENTS = json.loads((ROOT / 'research/components.json').read_text())['components']
REGISTRY = json.loads((ROOT / 'research/byte-windows.json').read_text())


class RegistryShapeTests(unittest.TestCase):
    def stage(self, folder):
        root = Path(folder)
        registry = copy.deepcopy(REGISTRY)
        paths = set(registry['evidence_sha256']) | {'research/byte-windows.json',
                                                  'provenance/artifacts.json'}
        paths |= {t['path'] for t in registry['targets'].values()}
        for path in paths:
            dest = root / path
            dest.parent.mkdir(parents=True, exist_ok=True)
            if path.startswith('artifacts/'):
                try:
                    os.link(ROOT / path, dest)
                except OSError:
                    dest.write_bytes((ROOT / path).read_bytes())
            else:
                dest.write_bytes((ROOT / path).read_bytes())
        return root, registry

    def load(self, root):
        return byte_progress.load_coverage(root, 'research/byte-windows.json', COMPONENTS)

    def assert_registry_rejected(self, mutate, message):
        with tempfile.TemporaryDirectory(dir=ROOT) as folder:
            root, registry = self.stage(folder)
            mutate(registry)
            (root / 'research/byte-windows.json').write_text(json.dumps(registry))
            with self.assertRaisesRegex(ValueError, message):
                self.load(root)

    def assert_manifest_rejected(self, mutate, message):
        with tempfile.TemporaryDirectory(dir=ROOT) as folder:
            root, _ = self.stage(folder)
            path = root / 'provenance/artifacts.json'
            manifest = json.loads(path.read_text())
            mutate(manifest)
            path.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, message):
                self.load(root)

    def test_missing_schema_version_is_invalid_registry(self):
        self.assert_registry_rejected(lambda r: r.pop('schema_version'),
                                      'Invalid byte registry')

    def test_missing_evidence_index_is_invalid_registry(self):
        self.assert_registry_rejected(lambda r: r.pop('evidence_sha256'),
                                      'Invalid byte registry')

    def test_missing_targets_is_invalid_registry(self):
        self.assert_registry_rejected(lambda r: r.pop('targets'),
                                      'Invalid byte registry')

    def test_target_record_missing_digest_is_invalid_registry(self):
        self.assert_registry_rejected(lambda r: r['targets']['node115'].pop('sha256'),
                                      'Invalid byte registry')

    def test_target_record_not_a_record_is_invalid_registry(self):
        self.assert_registry_rejected(lambda r: r['targets'].update(node115='x'),
                                      'Invalid byte registry')

    def test_target_outside_artifact_manifest_is_named(self):
        self.assert_registry_rejected(
            lambda r: r['targets']['node115'].update(path='research/byte-windows.json'),
            'missing from the artifact manifest')

    def test_manifest_record_missing_path_is_invalid_manifest(self):
        self.assert_manifest_rejected(lambda m: m['files'][0].pop('path'),
                                      'Invalid artifact manifest')

    def test_manifest_records_missing_digest_are_invalid_manifest(self):
        self.assert_manifest_rejected(
            lambda m: [f.pop('sha256') for f in m['files']],
            'Invalid artifact manifest')

    def test_manifest_records_missing_size_are_invalid_manifest(self):
        self.assert_manifest_rejected(
            lambda m: [f.pop('size') for f in m['files']],
            'Invalid artifact manifest')

    def test_manifest_without_files_is_invalid_manifest(self):
        self.assert_manifest_rejected(lambda m: m.pop('files'),
                                      'Invalid artifact manifest')

    def test_wrong_schema_version_keeps_its_own_diagnostic(self):
        self.assert_registry_rejected(lambda r: r.update(schema_version=2),
                                      'Unknown byte registry schema')

    def test_non_integer_schema_version_keeps_its_own_diagnostic(self):
        self.assert_registry_rejected(lambda r: r.update(schema_version='1'),
                                      'Unknown byte registry schema')


if __name__ == '__main__':
    unittest.main()
