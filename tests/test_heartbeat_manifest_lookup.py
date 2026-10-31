"""Synthetic-manifest controls for heartbeat_status.run lookup.

run() resolves the node #94 artifact with a manifest lookup before any
binary is read, so these tests patch the module's ROOT at a tmp manifest and
never need the real (LFS-pointer) binary: a manifest without the entry, one
without a files key, and one with a path-less entry must all fail closed with
the tool's ValueError contract, like every other malformed input run()
rejects, instead of a raw StopIteration/KeyError traceback.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import heartbeat_status as heartbeat


def stage(manifest):
    tmp = Path(tempfile.mkdtemp())
    (tmp / 'provenance').mkdir()
    (tmp / 'provenance/artifacts.json').write_text(json.dumps(manifest))
    return tmp


class HeartbeatManifestLookupTests(unittest.TestCase):
    def setUp(self):
        self._root = heartbeat.ROOT

    def tearDown(self):
        heartbeat.ROOT = self._root

    def test_missing_entry_fails_closed(self):
        heartbeat.ROOT = stage({'files': [{'path': 'artifacts/node/115/hl-node',
                                           'size': 1, 'sha256': 'x'}]})
        with self.assertRaisesRegex(ValueError, 'No provenance/artifacts.json entry'):
            heartbeat.run(Path('/tmp/fake-hl-node'), Path('/tmp/fake-out'))

    def test_manifest_without_files_key_fails_closed(self):
        heartbeat.ROOT = stage({'other': []})
        with self.assertRaisesRegex(ValueError, 'Invalid artifact manifest'):
            heartbeat.run(Path('/tmp/fake-hl-node'), Path('/tmp/fake-out'))

    def test_entry_without_path_fails_closed(self):
        heartbeat.ROOT = stage({'files': [{'size': 1, 'sha256': 'x'}]})
        with self.assertRaisesRegex(ValueError, 'Invalid artifact record'):
            heartbeat.run(Path('/tmp/fake-hl-node'), Path('/tmp/fake-out'))

    def test_present_entry_passes_lookup_to_artifact_check(self):
        heartbeat.ROOT = stage({'files': [{'path': 'artifacts/node/94/hl-node',
                                           'size': 1, 'sha256': 'x'}]})
        with self.assertRaisesRegex(ValueError, 'Missing artifact'):
            heartbeat.run(Path('/tmp/fake-hl-node'), Path('/tmp/fake-out'))


if __name__ == '__main__':
    unittest.main()
