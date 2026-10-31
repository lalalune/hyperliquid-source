import importlib.util
import json
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest

TOOLS = Path(__file__).resolve().parents[1] / 'tools'


def load_verify_imports():
    spec = importlib.util.spec_from_file_location('artifacts', TOOLS / 'artifacts.py')
    artifacts = importlib.util.module_from_spec(spec)
    sys.modules['artifacts'] = artifacts
    spec.loader.exec_module(artifacts)
    spec = importlib.util.spec_from_file_location('verify_imports', TOOLS / 'verify_imports.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


vi = load_verify_imports()


def make_git_repo(path):
    subprocess.run(['git', 'init', '-q', str(path)], check=True)
    subprocess.run(['git', '-C', str(path), 'config', 'user.email', 'test@example.invalid'],
                   check=True)
    subprocess.run(['git', '-C', str(path), 'config', 'user.name', 'Test'], check=True)
    (path / 'f.txt').write_text('x')
    subprocess.run(['git', '-C', str(path), 'add', '.'], check=True)
    subprocess.run(['git', '-C', str(path), 'commit', '-qm', 'init'], check=True)
    return subprocess.run(['git', '-C', str(path), 'rev-parse', 'HEAD'],
                          check=True, text=True, capture_output=True).stdout.strip()


class VerifyImportsRepoRecordTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'provenance').mkdir()
        (self.root / 'provenance' / 'imports.json').write_text(
            json.dumps({'files': []}))

    def _write_sources(self, repositories):
        (self.root / 'provenance' / 'sources.json').write_text(
            json.dumps({'repositories': repositories}))

    def test_repo_missing_path_rejected(self):
        self._write_sources([{'commit': '0' * 40}])
        with self.assertRaises(ValueError):
            vi.verify(self.root)

    def test_non_dict_repo_rejected(self):
        self._write_sources(['refs/repo'])
        with self.assertRaises(ValueError):
            vi.verify(self.root)

    def test_repo_missing_commit_rejected(self):
        repo_dir = self.root / 'refs' / 'repo'
        repo_dir.mkdir(parents=True)
        make_git_repo(repo_dir)
        self._write_sources([{'path': 'refs/repo'}])
        with self.assertRaises(ValueError):
            vi.verify(self.root)

    def test_valid_repo_still_verifies(self):
        repo_dir = self.root / 'refs' / 'repo'
        repo_dir.mkdir(parents=True)
        commit = make_git_repo(repo_dir)
        self._write_sources([{'path': 'refs/repo', 'commit': commit}])
        vi.verify(self.root)


if __name__ == '__main__':
    unittest.main()
