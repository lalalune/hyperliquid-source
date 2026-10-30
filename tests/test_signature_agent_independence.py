"""Real GPG verification of pinned captures must not need a secret-key agent."""
import contextlib
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import artifacts

GPG = os.environ.get('HL_GPG_TEST_BINARY') or shutil.which('gpg')
MATERIALIZED = (ROOT / 'artifacts/node/94/hl-node').stat().st_size == 91774280


@unittest.skipUnless(GPG and MATERIALIZED, 'requires native GnuPG and materialized captures')
class SignatureAgentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='hl-signature-agent-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.tools = self.root / 'tools'
        self.tools.mkdir()
        # Actual GPG, with its documented --agent-program option pointing at an
        # absent helper. This models gpg-agent unavailable in an offline sandbox;
        # no signature/key/result is fabricated and GPG is never mocked.
        launcher = self.tools / 'gpg'
        launcher.write_text('#!/bin/sh\nexec ' + shlex.quote(str(Path(GPG).resolve())) +
                            ' --agent-program ' + shlex.quote(str(self.root / 'no-agent')) + ' "$@"\n')
        launcher.chmod(0o755)
        self.environment = patch.dict(os.environ, {'PATH': str(self.tools) + os.pathsep + os.environ.get('PATH', '')})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.fingerprint = json.loads((ROOT / 'provenance/artifacts.json').read_text())['signing_fingerprint']

    def test_all_three_real_signatures_verify_without_an_agent(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            artifacts.verify_signatures(ROOT, self.fingerprint)
        self.assertEqual(output.getvalue().count('Valid signature:'), 3)
        self.assertFalse((self.root / 'no-agent').exists())

    def test_wrong_expected_fingerprint_is_rejected(self):
        with self.assertRaises(ValueError):
            artifacts.verify_signatures(ROOT, '0' * 40)

    def test_actual_capture_corruption_is_rejected(self):
        # Copy the public key plus the first real capture/signature into a
        # disposable layout. One capture byte is changed
        # only in this owned copy; all repository evidence stays unchanged.
        root = self.root / 'evidence'
        key = root / 'artifacts/keys/pub_key.asc'
        key.parent.mkdir(parents=True)
        shutil.copyfile(ROOT / 'artifacts/keys/pub_key.asc', key)
        binary = root / 'artifacts/node/94/hl-node'
        binary.parent.mkdir(parents=True)
        shutil.copyfile(ROOT / 'artifacts/node/94/hl-node', binary)
        shutil.copyfile(ROOT / 'artifacts/node/94/hl-node.asc', binary.with_name('hl-node.asc'))
        with binary.open('r+b') as stream:
            stream.seek(32)
            value = stream.read(1)[0]
            stream.seek(32)
            stream.write(bytes([value ^ 1]))
        with self.assertRaises(subprocess.CalledProcessError) as failure:
            artifacts.verify_signatures(root, self.fingerprint)
        self.assertIn('BADSIG', failure.exception.stdout)


if __name__ == '__main__':
    unittest.main()
