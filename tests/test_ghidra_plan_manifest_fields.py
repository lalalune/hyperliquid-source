"""Staged-tree tests for the manifest-entry fields gap in ghidra_plan.

On base, ghidra_plan resolves the release entry and hands it straight to
artifacts.check(), which reads item['size'] and item['sha256'] with bare
subscripts. A present entry missing either field therefore dies with a raw
KeyError traceback instead of the script's SystemExit one-line contract
(its Ghidra-missing and existing-project errors are SystemExit messages).
With the fix the entry is validated before check() and the missing
field(s) are named.

The script parses arguments at import time, so the tests run it as a
subprocess inside a staged repo root: the three tool files it imports,
a synthetic manifest, a dummy artifact file, and a fake GHIDRA_HOME.
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RELATIVE = 'artifacts/node/94/hl-node'


def stage(entry, artifact=b''):
    tmp = Path(tempfile.mkdtemp(prefix='ghidra-plan-fields-'))
    (tmp / 'tools').mkdir()
    for name in ('artifacts.py', 'doctor.py', 'ghidra_plan.py'):
        shutil.copy(ROOT / 'tools' / name, tmp / 'tools' / name)
    (tmp / 'provenance').mkdir()
    (tmp / 'provenance' / 'artifacts.json').write_text(
        json.dumps({'files': [entry]}), encoding='utf-8')
    artifact_path = tmp / RELATIVE
    artifact_path.parent.mkdir(parents=True)
    artifact_path.write_bytes(artifact)
    ghidra = tmp / 'ghidra'
    (ghidra / 'support').mkdir(parents=True)
    (ghidra / 'support' / 'analyzeHeadless').touch()
    return tmp, ghidra


def run_plan(tmp, ghidra):
    env = dict(os.environ, GHIDRA_HOME=str(ghidra))
    return subprocess.run(
        [sys.executable, str(tmp / 'tools/ghidra_plan.py'), '--release', '94'],
        capture_output=True, text=True, env=env)


class GhidraPlanManifestFieldsTests(unittest.TestCase):
    def assert_fails_closed(self, entry, artifact, message):
        tmp, ghidra = stage(entry, artifact)
        try:
            result = run_plan(tmp, ghidra)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('Traceback', result.stderr)
        self.assertEqual(result.stderr.strip(), message)

    def test_missing_sha256_fails_closed(self):
        self.assert_fails_closed(
            {'path': RELATIVE, 'size': 0},
            b'',
            f'provenance/artifacts.json entry for {RELATIVE} is missing sha256')

    def test_missing_size_fails_closed(self):
        self.assert_fails_closed(
            {'path': RELATIVE, 'sha256': 'x' * 64},
            b'',
            f'provenance/artifacts.json entry for {RELATIVE} is missing size')

    def test_missing_both_names_both_fields(self):
        self.assert_fails_closed(
            {'path': RELATIVE},
            b'',
            f'provenance/artifacts.json entry for {RELATIVE} is missing size, sha256')

    def test_complete_entry_still_plans(self):
        artifact = b'node94-stand-in'
        entry = {'path': RELATIVE, 'size': len(artifact),
                 'sha256': hashlib.sha256(artifact).hexdigest()}
        tmp, ghidra = stage(entry, artifact)
        try:
            result = run_plan(tmp, ghidra)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Static import plan only', result.stdout)
        self.assertIn(entry['sha256'][:12], result.stdout)


if __name__ == '__main__':
    unittest.main()
