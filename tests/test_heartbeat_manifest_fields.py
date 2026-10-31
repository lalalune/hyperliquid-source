"""Patched-ROOT tests for the manifest-entry fields gap in heartbeat run.

On base, run() resolves its release entry and hands it straight to
artifacts.check(), which reads item['size'] and item['sha256'] with bare
subscripts. A present entry missing either field therefore dies with a raw
KeyError instead of the tool's ValueError contract (every other malformed
input in run() raises ValueError). With the fix the entry is validated
before check() and the missing field(s) are named.

The manifest lives under the module's ROOT, so the tests point ROOT at a
temporary tree holding a synthetic manifest and a dummy binary. The
fields failure fires inside check(), before any binary parsing, so no
captured binary is needed; the complete-entry case only has to reach past
the guard (downstream parsing of the dummy binary then fails closed with
its own ValueError).
"""
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import heartbeat_status as hb

RELATIVE = 'artifacts/node/94/hl-node'


def run_with(entry, artifact=b''):
    tmp = Path(tempfile.mkdtemp(prefix='heartbeat-fields-'))
    (tmp / 'provenance').mkdir()
    (tmp / 'provenance' / 'artifacts.json').write_text(
        json.dumps({'files': [entry]}), encoding='utf-8')
    binary = tmp / 'hl-node'
    binary.write_bytes(artifact)
    with mock.patch.object(hb, 'ROOT', tmp):
        return hb.run(binary, tmp / 'out')


class HeartbeatManifestFieldsTests(unittest.TestCase):
    def test_missing_sha256_fails_closed(self):
        with self.assertRaisesRegex(
                ValueError,
                f'provenance/artifacts.json entry for {RELATIVE} is missing sha256'):
            run_with({'path': RELATIVE, 'size': 0})

    def test_missing_size_fails_closed(self):
        with self.assertRaisesRegex(
                ValueError,
                f'provenance/artifacts.json entry for {RELATIVE} is missing size'):
            run_with({'path': RELATIVE, 'sha256': 'x' * 64})

    def test_missing_both_names_both_fields(self):
        with self.assertRaisesRegex(
                ValueError,
                f'provenance/artifacts.json entry for {RELATIVE} is missing size, sha256'):
            run_with({'path': RELATIVE})

    def test_complete_entry_passes_fields_to_check(self):
        artifact = b'node94-stand-in'
        entry = {'path': RELATIVE, 'size': len(artifact),
                 'sha256': hashlib.sha256(artifact).hexdigest()}
        # check() passes, so the failure must come from downstream binary
        # parsing as a ValueError — never a fields KeyError.
        with self.assertRaises(ValueError):
            run_with(entry, artifact)


if __name__ == '__main__':
    unittest.main()
