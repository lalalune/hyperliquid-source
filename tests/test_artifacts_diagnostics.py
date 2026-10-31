import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parents[1]


class ArtifactsDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'tools').mkdir()
        shutil.copy(REPO_ROOT / 'tools/artifacts.py', self.root / 'tools/artifacts.py')
        (self.root / 'provenance').mkdir()

    def _write_manifest(self, files):
        (self.root / 'provenance/artifacts.json').write_text(
            json.dumps({'files': files, 'signing_fingerprint': 'unused'}))

    def _run_verify(self):
        return subprocess.run(
            [sys.executable, str(self.root / 'tools/artifacts.py'), 'verify'],
            capture_output=True, text=True, timeout=60)

    def test_missing_artifact_reported_as_one_line(self):
        self._write_manifest([{'path': 'artifacts/node/94/hl-node', 'size': 4,
                               'sha256': hashlib.sha256(b'good').hexdigest()}])
        result = self._run_verify()
        self.assertEqual(result.returncode, 1)
        self.assertNotIn('Traceback', result.stderr)
        self.assertEqual(result.stderr.strip().splitlines(),
                         [f'artifacts: Missing artifact: {self.root}/artifacts/node/94/hl-node'])

    def test_mismatched_artifact_reported_as_one_line(self):
        target = self.root / 'artifacts/node/94/hl-node'
        target.parent.mkdir(parents=True)
        target.write_bytes(b'evil')
        self._write_manifest([{'path': 'artifacts/node/94/hl-node', 'size': 4,
                               'sha256': hashlib.sha256(b'good').hexdigest()}])
        result = self._run_verify()
        self.assertEqual(result.returncode, 1)
        self.assertNotIn('Traceback', result.stderr)
        self.assertEqual(result.stderr.strip().splitlines(),
                         [f'artifacts: Artifact size/SHA-256 mismatch: {target}'])


if __name__ == '__main__':
    unittest.main()
