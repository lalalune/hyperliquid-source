"""Synthetic-manifest controls for ghidra_plan's artifact lookup.

ghidra_plan.py is a top-level script (it parses arguments and resolves the
artifact at import), so these tests stage a copy of tools/ in a tmp tree and
run the script as a subprocess with a fake GHIDRA_HOME (a directory holding
support/analyzeHeadless, which is all locate_ghidra requires). The staged
manifest is therefore the one the script reads, and no real (LFS-pointer)
binary is ever needed: a manifest without the entry, one without a files
list, a non-object manifest, and one with a path-less entry must all fail
closed with the script's clean SystemExit message — like its GHIDRA_HOME and
existing-project errors — instead of a raw StopIteration/KeyError traceback.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TOOLS = REPO / 'tools'


def stage(manifest):
    tmp = Path(tempfile.mkdtemp())
    (tmp / 'tools').mkdir()
    (tmp / 'provenance').mkdir()
    for name in ('ghidra_plan.py', 'artifacts.py', 'doctor.py'):
        shutil.copy(TOOLS / name, tmp / 'tools' / name)
    (tmp / 'provenance/artifacts.json').write_text(json.dumps(manifest))
    ghidra = tmp / 'fake-ghidra'
    (ghidra / 'support').mkdir(parents=True)
    (ghidra / 'support/analyzeHeadless').write_text('')
    return tmp, ghidra


def run_plan(tmp, ghidra):
    env = dict(os.environ, GHIDRA_HOME=str(ghidra))
    return subprocess.run(
        [sys.executable, str(tmp / 'tools/ghidra_plan.py'), '--release', '94'],
        capture_output=True, text=True, env=env)


class GhidraPlanManifestLookupTests(unittest.TestCase):
    def assert_fails_closed(self, manifest, message):
        tmp, ghidra = stage(manifest)
        result = run_plan(tmp, ghidra)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('Traceback', result.stderr)
        self.assertEqual(result.stderr.strip(), message)

    def test_missing_entry_fails_closed(self):
        self.assert_fails_closed(
            {'files': [{'path': 'artifacts/node/115/hl-node',
                        'size': 1, 'sha256': 'x'}]},
            'No provenance/artifacts.json entry for artifacts/node/94/hl-node')

    def test_manifest_without_files_list_fails_closed(self):
        self.assert_fails_closed(
            {'other': []},
            'Invalid artifact manifest: provenance/artifacts.json must be an object with a files list')

    def test_non_object_manifest_fails_closed(self):
        self.assert_fails_closed(
            [{'path': 'artifacts/node/94/hl-node', 'size': 1, 'sha256': 'x'}],
            'Invalid artifact manifest: provenance/artifacts.json must be an object with a files list')

    def test_entry_without_path_fails_closed(self):
        self.assert_fails_closed(
            {'files': [{'size': 1, 'sha256': 'x'}]},
            'Invalid artifact record in provenance/artifacts.json: entry without path')

    def test_present_entry_passes_lookup_to_artifact_check(self):
        tmp, ghidra = stage(
            {'files': [{'path': 'artifacts/node/94/hl-node',
                        'size': 1, 'sha256': 'x'}]})
        result = run_plan(tmp, ghidra)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Missing artifact', result.stderr)


if __name__ == '__main__':
    unittest.main()
