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

    def test_hidden_untracked_source_is_rejected(self):
        self.git('config', 'status.showUntrackedFiles', 'no')
        with contextlib.redirect_stdout(io.StringIO()):
            verify_imports.verify(self.root)
        (self.sub / 'unexpected.rs').write_text('// Extra source, not in the pinned commit.\n')
        # The user's display preference hides a file that source scans can read.
        self.assertEqual(self.git('status', '--porcelain'), '')
        with self.assertRaisesRegex(ValueError, 'Modified source reference: refs/sub'):
            verify_imports.verify(self.root)

    def check_index_flag(self, flag):
        self.git('update-index', '--' + flag, '--', 'file')
        with contextlib.redirect_stdout(io.StringIO()):
            verify_imports.verify(self.root)
        index = (self.sub / '.git/index').read_bytes()
        marker = self.git('ls-files', '-v', '--', 'file')
        (self.sub / 'file').write_text('y')
        self.assertEqual(self.git('status', '--porcelain', '--untracked-files=all'), '')
        with self.assertRaisesRegex(ValueError, 'Modified source reference: refs/sub'):
            verify_imports.verify(self.root)
        self.assertEqual((self.sub / '.git/index').read_bytes(), index)
        self.assertEqual(self.git('ls-files', '-v', '--', 'file'), marker)
        (self.sub / 'file').unlink()
        with self.assertRaisesRegex(ValueError, 'Modified source reference: refs/sub'):
            verify_imports.verify(self.root)
        (self.sub / 'file').write_text('x')
        with contextlib.redirect_stdout(io.StringIO()):
            verify_imports.verify(self.root)
        self.assertEqual(self.git('ls-files', '-v', '--', 'file'), marker)

    def test_assume_unchanged_does_not_hide_modified_source(self):
        self.check_index_flag('assume-unchanged')

    def test_skip_worktree_does_not_hide_modified_source(self):
        self.check_index_flag('skip-worktree')

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
