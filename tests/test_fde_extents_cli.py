import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

POINTER = (b'version https://git-lfs.github.com/spec/v1\n'
           b'oid sha256:0000000000000000000000000000000000000000000000000000000000\n'
           b'size 1\n')


def stage_tree(root):
    """Copy the CLI and its helpers into a scratch tree whose pinned
    artifacts are unresolved LFS pointers, as in a fresh clone."""
    (root / 'tools').mkdir(parents=True)
    for name in ('fde_extents.py', 'elf_index.py', 'artifacts.py'):
        (root / 'tools' / name).write_bytes((ROOT / 'tools' / name).read_bytes())
    manifest = json.loads((ROOT / 'provenance' / 'artifacts.json').read_text())
    (root / 'provenance').mkdir()
    (root / 'provenance' / 'artifacts.json').write_text(json.dumps(manifest))
    return {item['path'] for item in manifest['files']}


def run_cli(root, release):
    return subprocess.run(
        [sys.executable, str(root / 'tools' / 'fde_extents.py'),
         '--release', release, '--output-dir', str(root / 'out')],
        capture_output=True, text=True)


class FdeExtentsCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.pinned = stage_tree(self.root)

    def place_pointer(self, rel):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(POINTER)

    def assert_one_line_diagnostic(self, proc):
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(proc.stdout, '')
        lines = proc.stderr.splitlines()
        self.assertEqual(len(lines), 1, proc.stderr)
        self.assertTrue(lines[0].startswith('fde_extents: '), lines[0])
        self.assertNotIn('Traceback', proc.stderr)

    def test_release_94_pointer_artifact(self):
        rel = 'artifacts/node/94/hl-node'
        self.assertIn(rel, self.pinned)
        self.place_pointer(rel)
        self.assert_one_line_diagnostic(run_cli(self.root, '94'))

    def test_release_115_missing_artifact(self):
        rel = 'artifacts/node/115/hl-node'
        self.assertIn(rel, self.pinned)
        proc = run_cli(self.root, '115')
        self.assert_one_line_diagnostic(proc)
        self.assertIn('Missing artifact', proc.stderr)


if __name__ == '__main__':
    unittest.main()
