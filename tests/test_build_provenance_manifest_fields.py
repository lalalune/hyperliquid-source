import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import build_provenance as bp


class ManifestFieldsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'provenance').mkdir()
        self.patch = mock.patch.object(bp, 'ROOT', self.root)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def write_manifest(self, manifest):
        (self.root / 'provenance/artifacts.json').write_text(json.dumps(manifest))

    def test_entry_missing_size_or_sha256_is_value_error(self):
        for entry in ({'path': 'artifacts/node/94/hl-node', 'sha256': 'a'},
                      {'path': 'artifacts/node/94/hl-node', 'size': 1}):
            with self.subTest(entry=entry):
                artifact = self.root / 'artifacts/node/94/hl-node'
                artifact.parent.mkdir(parents=True, exist_ok=True)
                artifact.write_bytes(b'x')
                self.write_manifest({'files': [entry]})
                with self.assertRaisesRegex(ValueError, 'is missing'):
                    bp.record('94')

    def test_valid_lookup_reaches_artifact_check(self):
        self.write_manifest({'files': [{'path': 'artifacts/node/94/hl-node',
                                        'sha256': 'a', 'size': 1}]})
        with self.assertRaisesRegex(ValueError, 'Missing artifact'):
            bp.record('94')


if __name__ == '__main__':
    unittest.main()
