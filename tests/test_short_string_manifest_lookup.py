"""Synthetic-manifest controls for short_string_static.generate lookup.

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
import short_string_static as short_string


def stage(manifest):
    tmp = Path(tempfile.mkdtemp())
    (tmp / 'provenance').mkdir()
    (tmp / 'provenance/artifacts.json').write_text(json.dumps(manifest))
    return tmp


class ShortStringManifestLookupTests(unittest.TestCase):
    def setUp(self):
        self._root = short_string.ROOT

    def tearDown(self):
        short_string.ROOT = self._root

    def test_missing_entry_fails_closed(self):
        short_string.ROOT = stage({'files': [{'path': 'artifacts/node/115/hl-node',
                                              'size': 1, 'sha256': 'x'}]})
        with self.assertRaisesRegex(ValueError, 'No provenance/artifacts.json entry'):
            short_string.generate(Path('/tmp/fake-hl-node'), Path('/tmp/fake-out'))

    def test_manifest_without_files_key_fails_closed(self):
        short_string.ROOT = stage({'other': []})
        with self.assertRaisesRegex(ValueError, 'Invalid artifact manifest'):
            short_string.generate(Path('/tmp/fake-hl-node'), Path('/tmp/fake-out'))

    def test_entry_without_path_fails_closed(self):
        short_string.ROOT = stage({'files': [{'size': 1, 'sha256': 'x'}]})
        with self.assertRaisesRegex(ValueError, 'Invalid artifact record'):
            short_string.generate(Path('/tmp/fake-hl-node'), Path('/tmp/fake-out'))

    def test_present_entry_passes_lookup_to_artifact_check(self):
        short_string.ROOT = stage({'files': [{'path': 'artifacts/node/94/hl-node',
                                              'size': 1, 'sha256': 'x'}]})
        with self.assertRaisesRegex(ValueError, 'Missing artifact'):
            short_string.generate(Path('/tmp/fake-hl-node'), Path('/tmp/fake-out'))


if __name__ == '__main__':
    unittest.main()
