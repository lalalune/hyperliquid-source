import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import verify_imports


class VerifyImportsManifestFileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.sub = self.root / 'refs/sub'
        self.sub.mkdir(parents=True)
        self.git('init', '-q')
        self.git('config', 'user.email', 't@example.invalid')
        self.git('config', 'user.name', 't')
        (self.sub / 'file').write_text('x')
        self.git('add', 'file')
        self.git('commit', '-q', '-m', 'one')
        self.commit = self.git('rev-parse', 'HEAD')
        (self.root / 'provenance').mkdir()

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.sub), *args], text=True).strip()

    def write_manifests(self, with_imports=True, with_sources=True):
        if with_imports:
            (self.root / 'provenance/imports.json').write_text(json.dumps({'files': []}))
        if with_sources:
            (self.root / 'provenance/sources.json').write_text(
                json.dumps({'repositories': [{'path': 'refs/sub', 'commit': self.commit}]}))

    def test_missing_imports_manifest_rejected(self):
        self.write_manifests(with_imports=False)
        with self.assertRaises(ValueError) as caught:
            verify_imports.verify(self.root)
        self.assertIn('Missing manifest: provenance/imports.json', str(caught.exception))

    def test_missing_sources_manifest_rejected(self):
        self.write_manifests(with_sources=False)
        with self.assertRaises(ValueError) as caught:
            verify_imports.verify(self.root)
        self.assertIn('Missing manifest: provenance/sources.json', str(caught.exception))

    def test_both_manifests_present_passes(self):
        self.write_manifests()
        with contextlib.redirect_stdout(io.StringIO()):
            verify_imports.verify(self.root)


if __name__ == '__main__':
    unittest.main()
