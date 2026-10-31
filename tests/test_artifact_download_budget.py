"""Synthetic controls for the manifest-declared artifact download size budget."""
from contextlib import contextmanager
import hashlib
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    'artifacts', Path(__file__).resolve().parents[1] / 'tools/artifacts.py')
artifacts = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(artifacts)


class ChunkResponse:
    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.read_sizes = []

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self, size):
        self.read_sizes.append(size)
        if not self.chunks:
            raise AssertionError('read after the supplied response chunks')
        return self.chunks.pop(0)


class DownloadBudgetTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.item = {
            'path': 'bin/node',
            'size': 4,
            'sha256': hashlib.sha256(b'good').hexdigest(),
            'recovery_url': 'https://example.invalid/artifact',
        }

    @property
    def target(self):
        return self.root / self.item['path']

    def assert_no_partial_file(self):
        self.assertFalse(self.target.exists())
        self.assertEqual(list(self.root.rglob('*.part')), [])

    @contextmanager
    def download(self, chunks):
        response = ChunkResponse(chunks)
        writes = []
        named_tempfile = tempfile.NamedTemporaryFile

        @contextmanager
        def recording_file(*args, **kwargs):
            with named_tempfile(*args, **kwargs) as file:
                def write(block):
                    writes.append(bytes(block))
                    return file.write(block)

                yield SimpleNamespace(name=file.name, write=write)

        with patch.object(artifacts.urllib.request, 'urlopen', return_value=response) as urlopen:
            with patch.object(artifacts.tempfile, 'NamedTemporaryFile', recording_file):
                yield response, writes
            urlopen.assert_called_once_with(self.item['recovery_url'], timeout=120)

    def test_first_chunk_overflow_aborts_without_a_write_or_extra_read(self):
        with self.download([b'good!']) as (response, writes):
            with self.assertRaisesRegex(ValueError, 'exceeds manifest size'):
                artifacts.fetch_one(self.root, self.item)
        self.assertEqual(writes, [])
        self.assertEqual(response.read_sizes, [1024 * 1024])
        self.assert_no_partial_file()

    def test_valid_prefix_then_extra_byte_aborts_before_overflow_write(self):
        with self.download([b'go', b'od', b'!']) as (response, writes):
            with self.assertRaisesRegex(ValueError, 'exceeds manifest size'):
                artifacts.fetch_one(self.root, self.item)
        self.assertEqual(writes, [b'go', b'od'])
        self.assertEqual(response.read_sizes, [1024 * 1024] * 3)
        self.assert_no_partial_file()

    def test_empty_valid_response_is_published(self):
        self.item['size'] = 0
        self.item['sha256'] = hashlib.sha256(b'').hexdigest()
        with self.download([b'']) as (response, writes):
            artifacts.fetch_one(self.root, self.item)
        self.assertEqual(writes, [])
        self.assertEqual(response.read_sizes, [1024 * 1024])
        self.assertEqual(self.target.read_bytes(), b'')
        self.assertEqual(list(self.root.rglob('*.part')), [])

    def test_empty_budget_rejects_nonempty_response(self):
        self.item['size'] = 0
        self.item['sha256'] = hashlib.sha256(b'').hexdigest()
        with self.download([b'x']) as (response, writes):
            with self.assertRaisesRegex(ValueError, 'exceeds manifest size'):
                artifacts.fetch_one(self.root, self.item)
        self.assertEqual(writes, [])
        self.assertEqual(response.read_sizes, [1024 * 1024])
        self.assert_no_partial_file()

    def test_exact_size_irregular_chunks_keep_final_verification(self):
        with self.download([b'g', b'oo', b'd', b'']) as (response, writes):
            artifacts.fetch_one(self.root, self.item)
        self.assertEqual(writes, [b'g', b'oo', b'd'])
        self.assertEqual(response.read_sizes, [1024 * 1024] * 4)
        self.assertEqual(self.target.read_bytes(), b'good')
        self.assertEqual(list(self.root.rglob('*.part')), [])

    def test_short_body_fails_final_size_check_and_cleans_up(self):
        with self.download([b'goo', b'']) as (response, writes):
            with self.assertRaisesRegex(ValueError, 'size/SHA-256 mismatch'):
                artifacts.fetch_one(self.root, self.item)
        self.assertEqual(writes, [b'goo'])
        self.assertEqual(response.read_sizes, [1024 * 1024] * 2)
        self.assert_no_partial_file()

    def test_wrong_hash_fails_final_check_and_cleans_up(self):
        with self.download([b'evil', b'']) as (response, writes):
            with self.assertRaisesRegex(ValueError, 'size/SHA-256 mismatch'):
                artifacts.fetch_one(self.root, self.item)
        self.assertEqual(writes, [b'evil'])
        self.assertEqual(response.read_sizes, [1024 * 1024] * 2)
        self.assert_no_partial_file()

    def test_existing_valid_and_corrupt_targets_never_fetch(self):
        self.target.parent.mkdir(parents=True)
        with patch.object(artifacts.urllib.request, 'urlopen', side_effect=AssertionError('network')):
            self.target.write_bytes(b'good')
            artifacts.fetch_one(self.root, self.item)
            self.target.write_bytes(b'evil')
            with self.assertRaisesRegex(ValueError, 'size/SHA-256 mismatch'):
                artifacts.fetch_one(self.root, self.item)
        self.assertEqual(self.target.read_bytes(), b'evil')
        self.assertEqual(list(self.root.rglob('*.part')), [])


if __name__ == '__main__':
    unittest.main()
