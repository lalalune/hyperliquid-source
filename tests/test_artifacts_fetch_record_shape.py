import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest


spec = importlib.util.spec_from_file_location('artifacts', Path(__file__).resolve().parents[1] / 'tools/artifacts.py')
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


class FetchRecordShapeTests(unittest.TestCase):
    """fetch_one/fetch_all validate the item record before dereferencing it.

    load_manifest guarantees only 'path'; the fetch path also dereferences
    'size' (the download cap) and hands the record to check() ('size' and
    'sha256'), so a record missing a field — or not a record at all — used
    to escape as a raw KeyError/TypeError, including past fetch_all's
    per-item failure net. The module's diagnostic for a bad record is
    ValueError('Invalid artifact record'), as in check()/load_manifest().
    """

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'source'
        self.source.write_bytes(b'good')
        self.sha = hashlib.sha256(b'good').hexdigest()
        self.url = self.source.as_uri()
        self.good = {'path': 'bin/node', 'size': 4, 'sha256': self.sha,
                     'recovery_url': self.url}

    def test_fetch_one_missing_size_refused_before_download(self):
        item = {'path': 'bin/node', 'sha256': self.sha, 'recovery_url': self.url}
        with self.assertRaisesRegex(ValueError, 'Invalid artifact record'):
            a.fetch_one(self.root, item)
        self.assertFalse((self.root / 'bin/node').exists())
        self.assertFalse(list(self.root.rglob('*.part')))

    def test_fetch_one_missing_path_refused(self):
        item = {'size': 4, 'sha256': self.sha, 'recovery_url': self.url}
        with self.assertRaisesRegex(ValueError, 'Invalid artifact record'):
            a.fetch_one(self.root, item)

    def test_fetch_one_missing_sha256_refused_before_download(self):
        item = {'path': 'bin/node', 'size': 4, 'recovery_url': self.url}
        with self.assertRaisesRegex(ValueError, 'Invalid artifact record'):
            a.fetch_one(self.root, item)
        self.assertFalse((self.root / 'bin/node').exists())

    def test_fetch_one_non_record_refused(self):
        for bad in (None, 'bin/node', 4):
            with self.assertRaisesRegex(ValueError, 'Invalid artifact record'):
                a.fetch_one(self.root, bad)

    def test_fetch_all_aggregates_malformed_and_recovers_rest(self):
        bad = {'path': 'bin/bad', 'sha256': self.sha, 'recovery_url': self.url}
        with self.assertRaises(ValueError) as caught:
            a.fetch_all(self.root, {'files': [bad, dict(self.good)]})
        self.assertIn('bin/bad', str(caught.exception))
        self.assertIn('Invalid artifact record', str(caught.exception))
        a.check(self.root / 'bin/node', self.good)

    def test_fetch_all_names_pathless_record_without_key_error(self):
        bad = {'size': 4, 'sha256': self.sha, 'recovery_url': self.url}
        with self.assertRaises(ValueError) as caught:
            a.fetch_all(self.root, {'files': [bad, dict(self.good)]})
        self.assertIn('Invalid artifact record', str(caught.exception))
        a.check(self.root / 'bin/node', self.good)

    def test_fetch_all_aggregates_non_record(self):
        with self.assertRaises(ValueError) as caught:
            a.fetch_all(self.root, {'files': [None, dict(self.good)]})
        self.assertIn('Invalid artifact record', str(caught.exception))
        a.check(self.root / 'bin/node', self.good)

    def test_fetch_all_valid_manifest_unchanged(self):
        a.fetch_all(self.root, {'files': [dict(self.good)]})
        a.check(self.root / 'bin/node', self.good)


if __name__ == '__main__':
    unittest.main()
