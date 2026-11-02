"""Synthetic-manifest controls for rea_smoke's artifact lookup.

rea_smoke.py is a top-level script, so these tests stage a copy of tools/
in a tmp tree and run the script as a subprocess. Two external inputs are
staged, not the code under test: a synthetic manifest, and a stub rea.py
that answers `--version` with the staged config's version. The stub stands
in for the pinned REA package, which is absent on this VM (rea.py --version
fails with 'Pinned REA package is absent' before the lookup), and is the
only reason the lookup is otherwise unreachable here; rea_smoke.py itself
is copied unmodified. With that harness, a manifest without the entry, one
without a files list, a non-object manifest, and one with a path-less
entry must all fail closed with the script's clean SystemExit message —
like its version and operation errors — instead of a raw
StopIteration/KeyError traceback.
"""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TOOLS = REPO / 'tools'
CONFIG = {'version': '6.8.0',
          'targets': {'115': 'artifacts/node/115/hl-node'}}


def stage(manifest):
    tmp = Path(tempfile.mkdtemp())
    (tmp / 'tools').mkdir()
    (tmp / 'provenance').mkdir()
    (tmp / 'config').mkdir()
    for name in ('rea_smoke.py', 'artifacts.py'):
        shutil.copy(TOOLS / name, tmp / 'tools' / name)
    (tmp / 'tools/rea.py').write_text(
        "import sys\nif '--version' in sys.argv: print('6.8.0')\n")
    (tmp / 'config/rea.json').write_text(json.dumps(CONFIG))
    (tmp / 'provenance/artifacts.json').write_text(json.dumps(manifest))
    return tmp


def run_smoke(tmp):
    try:
        return subprocess.run(
            [sys.executable, str(tmp / 'tools/rea_smoke.py')],
            capture_output=True, text=True)
    finally:
        shutil.rmtree(tmp)


class ReaSmokeManifestLookupTests(unittest.TestCase):
    def assert_fails_closed(self, manifest, message):
        result = run_smoke(stage(manifest))
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('Traceback', result.stderr)
        self.assertEqual(result.stderr.strip(), message)

    def test_missing_entry_fails_closed(self):
        self.assert_fails_closed(
            {'files': [{'path': 'artifacts/node/other/hl-node',
                        'size': 1, 'sha256': 'x'}]},
            'No provenance/artifacts.json entry for artifacts/node/115/hl-node')

    def test_manifest_without_files_list_fails_closed(self):
        self.assert_fails_closed(
            {'other': []},
            'Invalid artifact manifest')

    def test_non_object_manifest_fails_closed(self):
        self.assert_fails_closed(
            [{'path': 'artifacts/node/115/hl-node', 'size': 1, 'sha256': 'x'}],
            'Invalid artifact manifest')

    def test_entry_without_path_fails_closed(self):
        self.assert_fails_closed(
            {'files': [{'size': 1, 'sha256': 'x'}]},
            'Invalid artifact record')

    def test_present_entry_passes_lookup_to_artifact_check(self):
        result = run_smoke(stage(
            {'files': [{'path': 'artifacts/node/115/hl-node',
                        'size': 1, 'sha256': 'x'}]}))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Missing artifact', result.stderr)


if __name__ == '__main__':
    unittest.main()
