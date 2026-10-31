import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import rea


class TargetManifestFieldTests(unittest.TestCase):
    def setUp(self):
        self._root = rea.ROOT
        self._config = rea.CONFIG
        self._tmp = Path(tempfile.mkdtemp())
        (self._tmp / 'provenance').mkdir()
        (self._tmp / 'artifacts/x').mkdir(parents=True)
        self._data = b'fake-node-bytes'
        (self._tmp / 'artifacts/x/hl-node').write_bytes(self._data)
        self._digest = hashlib.sha256(self._data).hexdigest()
        rea.ROOT = self._tmp
        config = dict(self._config)
        config['targets'] = {'x': 'artifacts/x/hl-node'}
        rea.CONFIG = config

    def tearDown(self):
        rea.ROOT = self._root
        rea.CONFIG = self._config

    def _write_manifest(self, entry):
        (self._tmp / 'provenance/artifacts.json').write_text(
            json.dumps({'files': [entry]}))

    def test_target_with_manifest_entry_missing_sha256_fails_closed(self):
        self._write_manifest({'path': 'artifacts/x/hl-node', 'size': len(self._data)})
        with self.assertRaisesRegex(ValueError, 'missing sha256'):
            rea.target('x')

    def test_target_with_manifest_entry_missing_size_fails_closed(self):
        self._write_manifest({'path': 'artifacts/x/hl-node', 'sha256': self._digest})
        with self.assertRaisesRegex(ValueError, 'missing size'):
            rea.target('x')

    def test_target_with_manifest_entry_missing_sha256_fails_closed_via_main(self):
        self._write_manifest({'path': 'artifacts/x/hl-node', 'size': len(self._data)})
        with self.assertRaisesRegex(ValueError, 'missing sha256'):
            rea.main(['target', 'x'])

    def test_complete_manifest_entry_still_resolves(self):
        self._write_manifest({'path': 'artifacts/x/hl-node', 'size': len(self._data),
                              'sha256': self._digest})
        row = rea.target('x')
        self.assertEqual(row['path'], str(self._tmp / 'artifacts/x/hl-node'))
        self.assertEqual(row['sha256'], self._digest)
        self.assertEqual(row['provider_id'], self._config['provider'])


if __name__ == '__main__':
    unittest.main()
