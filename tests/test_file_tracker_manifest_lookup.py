"""Synthetic-manifest controls for file_tracker_init_static.generate lookup.

generate() resolves the node #94 artifact with a manifest lookup before any
binary is read, so these tests patch the module's ROOT at a tmp manifest and
never need the real (LFS-pointer) binary: a manifest without the entry, one
without a files key, and one with a path-less entry must all fail closed with
the tool's ValueError contract, like every other malformed input generate()
rejects, instead of a raw StopIteration/KeyError traceback.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import file_tracker_init_static as file_tracker


def stage(manifest):
    tmp = Path(tempfile.mkdtemp())
    (tmp / 'provenance').mkdir()
    (tmp / 'provenance/artifacts.json').write_text(json.dumps(manifest))
    return tmp


class FileTrackerManifestLookupTests(unittest.TestCase):
    def setUp(self):
        self._root = file_tracker.ROOT

    def tearDown(self):
        file_tracker.ROOT = self._root

    def test_missing_entry_fails_closed(self):
        file_tracker.ROOT = stage({'files': [{'path': 'artifacts/node/115/hl-node',
                                              'size': 1, 'sha256': 'x'}]})
        with self.assertRaisesRegex(ValueError, 'No provenance/artifacts.json entry'):
            file_tracker.generate(Path('/tmp/fake-hl-node'), Path('/tmp/fake-out'))

    def test_manifest_without_files_key_fails_closed(self):
        file_tracker.ROOT = stage({'other': []})
        with self.assertRaisesRegex(ValueError, 'Invalid artifact manifest'):
            file_tracker.generate(Path('/tmp/fake-hl-node'), Path('/tmp/fake-out'))

    def test_entry_without_path_fails_closed(self):
        file_tracker.ROOT = stage({'files': [{'size': 1, 'sha256': 'x'}]})
        with self.assertRaisesRegex(ValueError, 'Invalid artifact record'):
            file_tracker.generate(Path('/tmp/fake-hl-node'), Path('/tmp/fake-out'))

    def test_present_entry_passes_lookup_to_artifact_check(self):
        file_tracker.ROOT = stage({'files': [{'path': 'artifacts/node/94/hl-node',
                                              'size': 1, 'sha256': 'x'}]})
        with self.assertRaisesRegex(ValueError, 'Missing artifact'):
            file_tracker.generate(Path('/tmp/fake-hl-node'), Path('/tmp/fake-out'))


if __name__ == '__main__':
    unittest.main()
