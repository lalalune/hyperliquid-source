import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('artifacts', Path(__file__).resolve().parents[1] / 'tools/artifacts.py')
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


class ArtifactsManifestTypeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'provenance').mkdir()

    def run_main(self, manifest):
        (self.root / 'provenance/artifacts.json').write_text(json.dumps(manifest))
        with patch.object(a, 'ROOT', self.root), \
             patch.object(a, 'verify_signatures'), \
             patch.object(a, 'verify_pinned_pairs'), \
             patch.object(sys, 'argv', ['artifacts.py', 'verify']):
            a.main()

    def test_non_mapping_manifest_rejected(self):
        for bad in ([{'path': 'node', 'size': 4, 'sha256': '0' * 64}], 'files'):
            with self.assertRaises(ValueError):
                self.run_main(bad)

    def test_valid_manifest_passes(self):
        data = b'good'
        (self.root / 'node').write_bytes(data)
        item = {'path': 'node', 'size': len(data),
                'sha256': hashlib.sha256(data).hexdigest()}
        self.run_main({'files': [item], 'signing_fingerprint': 'X'})


if __name__ == '__main__':
    unittest.main()
