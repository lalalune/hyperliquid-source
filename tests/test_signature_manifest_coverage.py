"""Detached-signature verification must cover every artifact the manifest records."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import artifacts

ROOT = Path(__file__).resolve().parents[1]
KEY = 'artifacts/keys/pub_key.asc'
FINGERPRINT = 'CF2C2EA3DC3E8F042A55FB6503254A9349F1820B'
OTHER_FINGERPRINT = '0000000000000000000000000000000000000000'


def record(path):
    return {'path': path, 'size': 1, 'sha256': '0' * 64}


def manifest(*paths):
    return {'signing_fingerprint': FINGERPRINT, 'files': [record(path) for path in sorted(set(paths))]}


def fake_run(commands, valid_fingerprint=FINGERPRINT):
    def run(command, **kwargs):
        commands.append(command)
        stdout = ''
        if '--verify' in command:
            stdout = ('[GNUPG:] NEWSIG\n'
                      f'[GNUPG:] VALIDSIG {valid_fingerprint} 2026-10-28 0 4 0 1 10 00 {valid_fingerprint}\n')
        return subprocess.CompletedProcess(command, 0, stdout, '')
    return run


class SignatureCoverageTests(unittest.TestCase):
    def verify(self, data, valid_fingerprint=FINGERPRINT):
        root = Path(tempfile.gettempdir()) / 'hl-signature-coverage-root'
        commands = []
        with mock.patch.object(artifacts.subprocess, 'run', fake_run(commands, valid_fingerprint)):
            artifacts.verify_signatures(root, data)
        return root, commands

    @staticmethod
    def verified(commands):
        return [command for command in commands if '--verify' in command]

    def test_every_manifest_signature_is_verified(self):
        data = manifest(
            KEY,
            'artifacts/node/94/hl-node', 'artifacts/node/94/hl-node.asc',
            'artifacts/node/116/hl-node', 'artifacts/node/116/hl-node.asc',
            'artifacts/node/116/node_metadata.json',
            'artifacts/visor/captured/hl-visor', 'artifacts/visor/captured/hl-visor.asc')
        root, commands = self.verify(data)
        rows = self.verified(commands)
        self.assertEqual([Path(command[-1]) for command in rows],
                         [root / 'artifacts/node/116/hl-node',
                          root / 'artifacts/node/94/hl-node',
                          root / 'artifacts/visor/captured/hl-visor'])
        self.assertEqual([Path(command[-2]) for command in rows],
                         [root / 'artifacts/node/116/hl-node.asc',
                          root / 'artifacts/node/94/hl-node.asc',
                          root / 'artifacts/visor/captured/hl-visor.asc'])
        self.assertEqual(len(rows), 3)

    def test_manifest_addition_is_covered_without_editing_the_module(self):
        base = manifest(KEY, 'artifacts/node/94/hl-node', 'artifacts/node/94/hl-node.asc')
        _, before = self.verify(base)
        added = manifest(KEY, 'artifacts/node/94/hl-node', 'artifacts/node/94/hl-node.asc',
                         'artifacts/node/116/hl-node', 'artifacts/node/116/hl-node.asc')
        _, after = self.verify(added)
        self.assertEqual(len(self.verified(before)), 1)
        self.assertEqual(len(self.verified(after)), 2)

    def test_signature_without_signed_artifact_fails_closed(self):
        data = manifest(KEY, 'artifacts/node/94/hl-node.asc')
        with self.assertRaisesRegex(ValueError, 'Detached signature without a signed artifact'):
            self.verify(data)

    def test_binary_without_signature_fails_closed(self):
        data = manifest(KEY, 'artifacts/node/94/hl-node')
        with self.assertRaisesRegex(ValueError, 'Artifact without a detached signature'):
            self.verify(data)

    def test_manifest_without_any_signature_fails_closed(self):
        data = manifest(KEY, 'artifacts/node/94/node_metadata.json')
        with self.assertRaisesRegex(ValueError, 'records no detached signatures'):
            self.verify(data)

    def test_wrong_fingerprint_is_still_rejected(self):
        data = manifest(KEY, 'artifacts/node/94/hl-node', 'artifacts/node/94/hl-node.asc')
        with self.assertRaisesRegex(ValueError, 'Expected signing fingerprint not found'):
            self.verify(data, valid_fingerprint=OTHER_FINGERPRINT)

    def test_committed_manifest_covers_the_captured_binaries(self):
        data = json.loads((ROOT / 'provenance/artifacts.json').read_text())
        self.assertEqual(artifacts.signature_pairs(data), [
            ('artifacts/node/115/hl-node', 'artifacts/node/115/hl-node.asc'),
            ('artifacts/node/94/hl-node', 'artifacts/node/94/hl-node.asc'),
            ('artifacts/visor/captured/hl-visor', 'artifacts/visor/captured/hl-visor.asc'),
        ])


if __name__ == '__main__':
    unittest.main()
