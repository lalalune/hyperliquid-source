import hashlib


import importlib.util


from pathlib import Path


import tempfile


import unittest


from unittest.mock import patch


spec = importlib.util.spec_from_file_location('artifacts', Path(__file__).resolve().parents[1] / 'tools/artifacts.py')


a = importlib.util.module_from_spec(spec)


spec.loader.exec_module(a)


import http.client


import json


import sys


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

    def test_corrupt_existing_file_not_overwritten(self):
        p = self.root / self.item['path']
        p.parent.mkdir()
        p.write_bytes(b'evil')
        with self.assertRaises(ValueError):
            a.fetch_one(self.root, self.item)
        self.assertEqual(p.read_bytes(), b'evil')

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

    def test_fetch_continues_past_unrecoverable_item(self):
        # Manifest order puts node/115 (no recovery URL) before node/94.
        source = self.root / 'source'
        source.write_bytes(b'good')
        first = dict(self.item, path='bin/first', recovery_url=None)
        second = dict(self.item, path='bin/second', recovery_url=source.as_uri())
        (self.root / 'provenance').mkdir()
        (self.root / 'provenance/artifacts.json').write_text(
            json.dumps({'signing_fingerprint': 'unused', 'files': [first, second]}))
        real_urlopen = a.urllib.request.urlopen

        def local_only(url, *args, **kwargs):  # never reach a real recovery URL
            if not url.startswith('file:'):
                raise AssertionError(f'network fetch attempted: {url}')
            return real_urlopen(url, *args, **kwargs)

        with patch.object(a, 'ROOT', self.root), \
                patch.object(a.urllib.request, 'urlopen', local_only), \
                patch.object(sys, 'argv', ['artifacts.py', 'fetch']), \
                self.assertRaises(ValueError) as caught:
            a.main()
        self.assertIn('No upstream recovery URL', str(caught.exception))
        self.assertIn('bin/first', str(caught.exception))
        self.assertNotIn('bin/second', str(caught.exception))
        a.check(self.root / 'bin/second', second)

    def test_fetch_continues_past_download_errors(self):
        source = self.root / 'source'
        source.write_bytes(b'good')
        items = [dict(self.item, path=f'bin/{name}', recovery_url=f'https://example.invalid/{name}')
                 for name in ('url', 'http', 'read')]
        items.append(dict(self.item, path='bin/last', recovery_url=source.as_uri()))
        real_urlopen = a.urllib.request.urlopen
        errors = {'url': a.urllib.error.URLError('down'),
                  'http': http.client.BadStatusLine('garbage'),
                  'read': http.client.IncompleteRead(b'')}

        def fake(url, *args, **kwargs):
            if url.startswith('file:'):
                return real_urlopen(url, *args, **kwargs)
            raise errors[url.rsplit('/', 1)[1]]

        with patch.object(a.urllib.request, 'urlopen', fake), self.assertRaises(ValueError) as caught:
            a.fetch_all(self.root, {'files': items})
        for name in ('bin/url', 'bin/http', 'bin/read'):
            self.assertIn(name, str(caught.exception))
        a.check(self.root / 'bin/last', items[-1])
        self.assertFalse(list(self.root.rglob('*.part')))

    def test_lfs_pointer_is_named_and_not_overwritten(self):
        p = self.root / self.item['path']
        p.parent.mkdir()
        pointer = ('version https://git-lfs.github.com/spec/v1\n'
                   f"oid sha256:{self.item['sha256']}\nsize {self.item['size']}\n").encode()
        p.write_bytes(pointer)
        with self.assertRaisesRegex(ValueError, 'Git LFS pointer, not the artifact'):
            a.check(p, self.item)
        with self.assertRaisesRegex(ValueError, 'Git LFS pointer'):
            a.fetch_one(self.root, self.item)
        self.assertEqual(p.read_bytes(), pointer)
        other = dict(self.item, sha256='0' * 64)
        with self.assertRaisesRegex(ValueError, 'size/SHA-256 mismatch'):
            a.check(p, other)
        for bad in (pointer.replace(b'size 4', b'size 5'),
                    pointer.replace(b'version https://git-lfs.github.com/spec/v1\n', b''),
                    pointer + b'x' * 1024):
            p.write_bytes(bad)
            with self.assertRaisesRegex(ValueError, 'size/SHA-256 mismatch'):
                a.check(p, self.item)

    def test_malformed_artifact_record_rejected(self):
        p = self.root / 'node'
        p.write_bytes(b'good')
        for bad in ({'size': 4}, {'sha256': self.item['sha256']}, None):
            with self.assertRaises(ValueError):
                a.check(p, bad)

    def test_manifest_entry_missing_path_rejected(self):
        manifest = {'files': [{'size': 4, 'sha256': '0' * 64}], 'signing_fingerprint': 'X'}
        (self.root / 'provenance').mkdir()
        (self.root / 'provenance/artifacts.json').write_text(json.dumps(manifest))
        with patch.object(a, 'ROOT', self.root), \
             patch.object(a, 'verify_signatures'), \
             patch.object(a, 'verify_pinned_pairs'), \
             patch.object(sys, 'argv', ['artifacts.py', 'verify']):
            with self.assertRaises(ValueError):
                a.main()

    def test_main_missing_files_key_rejected(self):
        manifest_dir = self.root / 'provenance'
        manifest_dir.mkdir()
        (manifest_dir / 'artifacts.json').write_text('{}')
        with patch.object(a, 'ROOT', self.root), patch.object(sys, 'argv', ['artifacts.py', 'verify']):
            with self.assertRaises(ValueError):
                a.main()

    def test_main_empty_files_list_passes_guard(self):
        manifest_dir = self.root / 'provenance'
        manifest_dir.mkdir()
        (manifest_dir / 'artifacts.json').write_text('{"files": [], "signing_fingerprint": "unused"}')
        with patch.object(a, 'ROOT', self.root), patch.object(sys, 'argv', ['artifacts.py', 'verify']), \
                patch.object(a, 'verify_signatures'), patch.object(a, 'verify_pinned_pairs'):
            a.main()

    def test_main_missing_signing_fingerprint_rejected(self):
        manifest_dir = self.root / 'provenance'
        manifest_dir.mkdir()
        (manifest_dir / 'artifacts.json').write_text('{"files": []}')
        with patch.object(a, 'ROOT', self.root), patch.object(sys, 'argv', ['artifacts.py', 'verify']):
            with self.assertRaises(ValueError):
                a.main()

    def test_main_files_and_fingerprint_pass_guard(self):
        manifest_dir = self.root / 'provenance'
        manifest_dir.mkdir()
        (manifest_dir / 'artifacts.json').write_text('{"files": [], "signing_fingerprint": "unused"}')
        with patch.object(a, 'ROOT', self.root), patch.object(sys, 'argv', ['artifacts.py', 'verify']), \
                patch.object(a, 'verify_signatures'), patch.object(a, 'verify_pinned_pairs'):
            a.main()

    def _signature_root(self):
        for rel in ['node/94/hl-node', 'node/115/hl-node', 'visor/captured/hl-visor']:
            for suffix in ('', '.asc'):
                p = self.root / 'artifacts' / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.with_name(p.name + suffix).write_bytes(b'x')
        (self.root / 'artifacts/keys').mkdir(parents=True, exist_ok=True)
        (self.root / 'artifacts/keys/pub_key.asc').write_bytes(b'key')
        self.signature_manifest = {
            'signing_fingerprint': 'A' * 40,
            'files': [{'path': p.relative_to(self.root).as_posix()}
                      for p in (self.root / 'artifacts').rglob('*') if p.is_file()],
        }

    def _fake_gpg(self, extra=''):
        fingerprint = 'A' * 40

        def run(command, **kwargs):
            if '--import' in command:
                return a.subprocess.CompletedProcess(command, 0, '', '')
            stdout = f'[GNUPG:] VALIDSIG {fingerprint} 2026-01-01 1 0 4 0 1 8 00 {fingerprint}\n'
            if extra and command[-1].endswith('node/94/hl-node'):
                stdout += extra + '\n'
            return a.subprocess.CompletedProcess(command, 0, stdout, '')
        return run

    def test_valid_signature_accepted(self):
        self._signature_root()
        with patch.object(a.subprocess, 'run', side_effect=self._fake_gpg()):
            a.verify_signatures(self.root, self.signature_manifest)

    def test_revoked_key_signature_rejected(self):
        self._signature_root()
        with patch.object(a.subprocess, 'run',
                          side_effect=self._fake_gpg('[GNUPG:] REVKEYSIG DEADBEEF Test')):
            with self.assertRaises(ValueError) as caught:
                a.verify_signatures(self.root, self.signature_manifest)
        self.assertIn('not currently valid', str(caught.exception))

    def test_expired_key_signature_rejected(self):
        self._signature_root()
        with patch.object(a.subprocess, 'run',
                          side_effect=self._fake_gpg('[GNUPG:] KEYEXPIRED 1')):
            with self.assertRaises(ValueError):
                a.verify_signatures(self.root, self.signature_manifest)

    def _broken_gpg(self):
        def run(command, **kwargs):
            if '--import' in command:
                return a.subprocess.CompletedProcess(command, 0, '', '')
            raise a.subprocess.CalledProcessError(1, command, stderr='gpg: BAD signature\n')
        return run

    def test_bad_signature_failure_reported_as_one_line(self):
        self._signature_root()
        with patch.object(a.subprocess, 'run', side_effect=self._broken_gpg()), \
                self.assertRaises(ValueError) as caught:
            a.verify_signatures(self.root, self.signature_manifest)
        message = str(caught.exception)
        self.assertIn('GPG verification failed', message)
        self.assertIn('BAD signature', message)
