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


class ArtifactsPathTypeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'provenance').mkdir()

    def write_manifest(self, manifest):
        (self.root / 'provenance/artifacts.json').write_text(json.dumps(manifest))

    def test_non_string_path_rejected_by_load_manifest(self):
        for bad in (123, True, None, ['node'], {'x': 1}):
            with self.subTest(path=bad):
                self.write_manifest({'files': [{'path': bad, 'size': 4, 'sha256': 'x'}]})
                with self.assertRaises(ValueError):
                    a.load_manifest(self.root)

    def test_non_string_path_rejected_by_main(self):
        for bad in (123, True, None, ['node'], {'x': 1}):
            with self.subTest(path=bad):
                self.write_manifest({'files': [{'path': bad, 'size': 4, 'sha256': 'x'}],
                                       'signing_fingerprint': 'X'})
                with patch.object(a, 'ROOT', self.root), \
                     patch.object(a, 'verify_signatures'), \
                     patch.object(a, 'verify_pinned_pairs'), \
                     patch.object(sys, 'argv', ['artifacts.py', 'verify']):
                    with self.assertRaises(ValueError):
                        a.main()

    def test_missing_path_still_rejected(self):
        self.write_manifest({'files': [{'size': 4, 'sha256': 'x'}]})
        with self.assertRaises(ValueError):
            a.load_manifest(self.root)

    def test_valid_manifest_passes(self):
        data = b'good'
        (self.root / 'node').write_bytes(data)
        item = {'path': 'node', 'size': len(data),
                'sha256': hashlib.sha256(data).hexdigest()}
        self.write_manifest({'files': [item], 'signing_fingerprint': 'X'})
        manifest = a.load_manifest(self.root)
        self.assertEqual(manifest['files'], [item])
        with patch.object(a, 'ROOT', self.root), \
             patch.object(a, 'verify_signatures'), \
             patch.object(a, 'verify_pinned_pairs'), \
             patch.object(sys, 'argv', ['artifacts.py', 'verify']):
            a.main()


if __name__ == '__main__':
    unittest.main()
