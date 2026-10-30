import contextlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import verify_imports


class VerifyImportsTests(unittest.TestCase):
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
        (self.root / 'provenance/imports.json').write_text(json.dumps({'files': []}))
        self.sources = self.root / 'provenance/sources.json'
        self.write_source(self.commit)

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.sub), *args], text=True).strip()

    def write_source(self, commit):
        self.sources.write_text(json.dumps({'repositories': [{'path': 'refs/sub', 'commit': commit}]}))

    def test_clean_pin_passes(self):
        with contextlib.redirect_stdout(io.StringIO()):
            verify_imports.verify(self.root)

    def test_missing_submodule_names_the_fix(self):
        shutil.rmtree(self.sub)
        self.sub.mkdir()
        with self.assertRaises(ValueError) as caught:
            verify_imports.verify(self.root)
        self.assertIn('Missing pinned source: refs/sub', str(caught.exception))
        self.assertIn('git submodule update --init --recursive', str(caught.exception))

    def test_commit_mismatch_rejected(self):
        self.write_source('0' * 40)
        with self.assertRaises(ValueError) as caught:
            verify_imports.verify(self.root)
        self.assertIn('Source commit mismatch', str(caught.exception))

    def test_modified_reference_rejected(self):
        (self.sub / 'file').write_text('y')
        with self.assertRaises(ValueError) as caught:
            verify_imports.verify(self.root)
        self.assertIn('Modified source reference', str(caught.exception))

    def test_missing_git_binary_is_a_message(self):
        with patch.object(verify_imports.subprocess, 'check_output', side_effect=FileNotFoundError('git')):
            with self.assertRaises(ValueError) as caught:
                verify_imports.verify(self.root)
        self.assertIn('Unreadable pinned source', str(caught.exception))


class RepositoryManifestCoverageTests(unittest.TestCase):
    def test_every_retained_import_is_pinned(self):
        # Retained evidence that `make verify` must hash-check: the tracked
        # files, or outside a git checkout a walk that skips what .gitignore
        # ignores in these trees (.DS_Store, __pycache__, *.py[cod]).
        root = Path(__file__).resolve().parents[1]
        tops = ('research/imported', 'research/upstream-docs', 'tools/legacy')
        try:
            listed = subprocess.run(['git', '-C', str(root), 'ls-files', '-z', '--', *tops],
                                    capture_output=True, check=True).stdout.decode()
            retained = {p for p in listed.split('\0') if p}
        except (OSError, subprocess.CalledProcessError):
            retained = {p.relative_to(root).as_posix()
                        for top in tops for p in (root / top).rglob('*')
                        if p.is_file() and '__pycache__' not in p.parts
                        and p.name != '.DS_Store' and p.suffix not in ('.pyc', '.pyo', '.pyd')}
        pinned = {item['path'] for item in
                  json.loads((root / 'provenance/imports.json').read_text())['files']}
        self.assertEqual(sorted(retained - pinned), [])
        self.assertEqual(sorted(pinned - retained), [])
