"""Staged-tree tests for the manifest-entry fields gap in rea_smoke.

On base, rea_smoke resolves each release entry and hands it straight to
artifacts.check(), which reads item['size'] and item['sha256'] with bare
subscripts. A present entry missing either field therefore dies with a raw
KeyError traceback instead of the script's SystemExit one-line contract
(its version and operation errors are SystemExit messages). With the fix
the entry is validated before check() and the missing field(s) are named.

The script shells out to tools/rea.py for --version, and the pinned REA
package is absent on this VM, so the harness stages a stub rea.py that
answers --version with the staged config version. The stub stands in for
the absent REA package only; rea_smoke.py itself is copied unmodified.
"""
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = '9.9.9-test'
STUB = (
    "import sys\n"
    "if sys.argv[1:] == ['--version']:\n"
    f"    print({VERSION!r})\n"
    "else:\n"
    "    raise SystemExit('stub rea.py answers --version only')\n"
)


def stage(entry94, entry115, artifact94=b'', artifact115=b''):
    tmp = Path(tempfile.mkdtemp(prefix='rea-smoke-fields-'))
    (tmp / 'tools').mkdir()
    for name in ('artifacts.py', 'rea_smoke.py'):
        shutil.copy(ROOT / 'tools' / name, tmp / 'tools' / name)
    (tmp / 'tools' / 'rea.py').write_text(STUB, encoding='utf-8')
    (tmp / 'config').mkdir()
    (tmp / 'config' / 'rea.json').write_text(json.dumps({
        'version': VERSION,
        'targets': {'94': 'artifacts/node/94/hl-node',
                    '115': 'artifacts/node/115/hl-node'}}), encoding='utf-8')
    (tmp / 'provenance').mkdir()
    (tmp / 'provenance' / 'artifacts.json').write_text(
        json.dumps({'files': [entry94, entry115]}), encoding='utf-8')
    for release, artifact in (('94', artifact94), ('115', artifact115)):
        path = tmp / f'artifacts/node/{release}/hl-node'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(artifact)
    return tmp


def run_smoke(tmp):
    return subprocess.run(
        [sys.executable, str(tmp / 'tools/rea_smoke.py')],
        capture_output=True, text=True)


def complete_entry(release, artifact):
    return {'path': f'artifacts/node/{release}/hl-node',
            'size': len(artifact),
            'sha256': hashlib.sha256(artifact).hexdigest()}


class ReaSmokeManifestFieldsTests(unittest.TestCase):
    def assert_fails_closed(self, entry94, entry115, message):
        tmp = stage(entry94, entry115)
        try:
            result = run_smoke(tmp)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('Traceback', result.stderr)
        self.assertEqual(result.stderr.strip(), message)

    def test_missing_sha256_fails_closed(self):
        self.assert_fails_closed(
            {'path': 'artifacts/node/94/hl-node', 'size': 0},
            complete_entry('115', b''),
            'provenance/artifacts.json entry for artifacts/node/94/hl-node'
            ' is missing sha256')

    def test_missing_size_fails_closed(self):
        self.assert_fails_closed(
            {'path': 'artifacts/node/94/hl-node', 'sha256': 'x' * 64},
            complete_entry('115', b''),
            'provenance/artifacts.json entry for artifacts/node/94/hl-node'
            ' is missing size')

    def test_missing_both_names_both_fields(self):
        self.assert_fails_closed(
            {'path': 'artifacts/node/94/hl-node'},
            complete_entry('115', b''),
            'provenance/artifacts.json entry for artifacts/node/94/hl-node'
            ' is missing size, sha256')

    def test_complete_entries_pass_fields_to_check(self):
        # Both entries complete: the run must get past the fields guard
        # and fail later, at the artifact check / REA inspection stage,
        # not at a fields KeyError. The stub rea.py answers --version
        # only, so the inspect-rust-binary call is where it stops.
        tmp = stage(complete_entry('94', b'node94-stand-in'),
                    complete_entry('115', b'node115-stand-in'),
                    b'node94-stand-in', b'node115-stand-in')
        try:
            result = run_smoke(tmp)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("KeyError: 'size'", result.stderr)
        self.assertNotIn("KeyError: 'sha256'", result.stderr)


if __name__ == '__main__':
    unittest.main()
