import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('artifacts', Path(__file__).resolve().parents[1] / 'tools/artifacts.py')
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.item = {'path': 'bin/node', 'size': 4, 'sha256': hashlib.sha256(b'good').hexdigest(),
                     'recovery_url': 'https://example.invalid/artifact'}

    def test_tamper_same_size_rejected(self):
        p = self.root / 'node'
        p.write_bytes(b'evil')
        with self.assertRaises(ValueError):
            a.check(p, self.item)

    def test_failed_download_does_not_publish_partial(self):
        source = self.root / 'source'
        source.write_bytes(b'evil')
        self.item['recovery_url'] = source.as_uri()
        with self.assertRaises(ValueError):
            a.fetch_one(self.root, self.item)
        self.assertFalse((self.root / self.item['path']).exists())
        self.assertFalse(list(self.root.rglob('*.part')))

    def test_valid_download_and_existing_file_no_network(self):
        source = self.root / 'source'
        source.write_bytes(b'good')
        self.item['recovery_url'] = source.as_uri()
        a.fetch_one(self.root, self.item)
        a.check(self.root / self.item['path'], self.item)
        with patch.object(a.urllib.request, 'urlopen', side_effect=AssertionError('network')):
            a.fetch_one(self.root, self.item)

    def test_missing_pinned_reference_names_the_fix(self):
        with self.assertRaises(ValueError) as caught:
            a.verify_pinned_pairs(self.root)
        self.assertIn('git submodule update --init --recursive', str(caught.exception))

    def test_pinned_reference_mismatch_rejected(self):
        for left, right in a.PAIRS:
            for relative in (left, right):
                (self.root / relative).parent.mkdir(parents=True, exist_ok=True)
                (self.root / relative).write_bytes(b'good')
        a.verify_pinned_pairs(self.root)
        (self.root / a.PAIRS[0][1]).write_bytes(b'evil')
        with self.assertRaises(ValueError):
            a.verify_pinned_pairs(self.root)

    def write_manifest(self, text):
        manifest = self.root / 'provenance/artifacts.json'
        manifest.parent.mkdir(parents=True, exist_ok=True)
        manifest.write_text(text)

    def test_manifest_duplicate_key_rejected(self):
        sha = self.item['sha256']
        self.write_manifest(
            '{"signing_fingerprint": "X", "files": [{"path": "bin/node", "size": 4, '
            f'"sha256": "{sha}", "sha256": "{sha}"}}]}}')
        with self.assertRaises(ValueError):
            a.load_manifest(self.root)

    def test_manifest_duplicate_path_rejected(self):
        sha = self.item['sha256']
        self.write_manifest(
            '{"signing_fingerprint": "X", "files": ['
            f'{{"path": "bin/node", "size": 4, "sha256": "{sha}"}}, '
            f'{{"path": "bin/node", "size": 4, "sha256": "{sha}"}}]}}')
        with self.assertRaises(ValueError):
            a.load_manifest(self.root)

    def test_manifest_loads_and_item_lookup(self):
        sha = self.item['sha256']
        self.write_manifest(
            '{"signing_fingerprint": "X", "files": ['
            f'{{"path": "bin/node", "size": 4, "sha256": "{sha}"}}]}}')
        manifest = a.load_manifest(self.root)
        self.assertEqual(manifest['files'][0]['sha256'], sha)
        self.assertEqual(a.manifest_item(self.root, 'bin/node')['size'], 4)

    def test_corrupt_existing_file_not_overwritten(self):
        p = self.root / self.item['path']
        p.parent.mkdir()
        p.write_bytes(b'evil')
        with self.assertRaises(ValueError):
            a.fetch_one(self.root, self.item)
        self.assertEqual(p.read_bytes(), b'evil')
