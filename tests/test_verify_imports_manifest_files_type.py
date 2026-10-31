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


class VerifyImportsFilesTypeTests(unittest.TestCase):
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
        (self.root / 'provenance/sources.json').write_text(
            json.dumps({'repositories': [{'path': 'refs/sub', 'commit': self.commit}]}))

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.sub), *args], text=True).strip()

    def verify_with_files(self, files_value):
        (self.root / 'provenance/imports.json').write_text(json.dumps({'files': files_value}))
        with contextlib.redirect_stdout(io.StringIO()):
            verify_imports.verify(self.root)

    def test_dict_files_rejected(self):
        with self.assertRaises(ValueError) as caught:
            self.verify_with_files({'a': 1})
        self.assertIn('Invalid import manifest', str(caught.exception))

    def test_int_files_rejected(self):
        with self.assertRaises(ValueError) as caught:
            self.verify_with_files(123)
        self.assertIn('Invalid import manifest', str(caught.exception))

    def test_list_files_passes(self):
        self.verify_with_files([])


if __name__ == '__main__':
    unittest.main()
