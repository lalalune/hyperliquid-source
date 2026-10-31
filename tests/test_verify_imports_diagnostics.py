import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / 'tools'


def stage_root(missing_imports=True, missing_provenance=False):
    """Stage a minimal tree whose verify_imports.py computes ROOT from __file__."""
    tmp = tempfile.TemporaryDirectory()
    root = Path(tmp.name)
    tools = root / 'tools'
    tools.mkdir()
    shutil.copy(TOOLS / 'verify_imports.py', tools / 'verify_imports.py')
    shutil.copy(TOOLS / 'artifacts.py', tools / 'artifacts.py')
    if not missing_provenance:
        prov = root / 'provenance'
        prov.mkdir()
        if missing_imports:
            (prov / 'imports.json').write_text(json.dumps(
                {'files': [{'path': 'research/imported/gone.txt',
                            'size': 1, 'sha256': '0' * 64}]}))
        else:
            (prov / 'imports.json').write_text(json.dumps({'files': []}))
        (prov / 'sources.json').write_text(json.dumps({'repositories': []}))
    return tmp, root


def run_cli(root):
    proc = subprocess.run(
        [sys.executable, str(root / 'tools' / 'verify_imports.py')],
        capture_output=True, text=True, timeout=60)
    return proc.returncode, proc.stderr


class VerifyImportsDiagnosticsTests(unittest.TestCase):
    def test_missing_artifact_is_one_line(self):
        tmp, root = stage_root()
        with tmp:
            rc, err = run_cli(root)
        self.assertEqual(rc, 1)
        self.assertNotIn('Traceback', err)
        self.assertEqual(len(err.strip().splitlines()), 1)
        self.assertTrue(err.startswith('verify_imports: Missing artifact: '))

    def test_missing_provenance_is_one_line(self):
        tmp, root = stage_root(missing_provenance=True)
        with tmp:
            rc, err = run_cli(root)
        self.assertEqual(rc, 1)
        self.assertNotIn('Traceback', err)
        self.assertEqual(len(err.strip().splitlines()), 1)
        self.assertTrue(err.startswith('verify_imports: '))

    def test_clean_pin_still_passes(self):
        tmp, root = stage_root(missing_imports=False)
        with tmp:
            proc = subprocess.run(
                [sys.executable, str(root / 'tools' / 'verify_imports.py')],
                capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 0)
        self.assertIn('Verified 0 imported files', proc.stdout)


if __name__ == '__main__':
    unittest.main()
