"""The RE-001 readelf crosscheck must verify the binary it parses.

Its report carries the pinned binary_sha256 from the fde_extents summary;
before this gate the script ran readelf on whatever bytes sat at the
artifact path, so a frame-neutral tamper (appended bytes) still produced
identical=true under the stale pinned digest.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / 'research/work-items/RE-001-fde-extents/readelf_crosscheck.py'
BINARY = b'\x7fELF-crosscheck-fixture'

STUB_READELF = """#!/usr/bin/env python3
import sys
if '--version' in sys.argv:
    print('GNU readelf (stub) 0.0')
elif '-SW' in sys.argv:
    print('  [ 1] .eh_frame PROGBITS 0000000000001000 001000 000100 00 A 0 0 8')
else:
    print('')
"""


class ReadelfCrosscheckTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        script_dir = self.root / 'research/work-items/RE-001-fde-extents'
        script_dir.mkdir(parents=True)
        (script_dir / 'readelf_crosscheck.py').write_text(SCRIPT.read_text())
        tools_dir = self.root / 'tools'
        tools_dir.mkdir()
        (tools_dir / 'artifacts.py').write_text(
            (REPO / 'tools/artifacts.py').read_text())
        self.binary = self.root / 'artifacts/node/94/hl-node'
        self.binary.parent.mkdir(parents=True)
        self.binary.write_bytes(BINARY)
        digest = hashlib.sha256(BINARY).hexdigest()
        (self.root / 'provenance').mkdir()
        (self.root / 'provenance/artifacts.json').write_text(json.dumps(
            {'files': [{'path': 'artifacts/node/94/hl-node',
                        'size': len(BINARY), 'sha256': digest}]}))
        index = self.root / 'work/index'
        index.mkdir(parents=True)
        (index / 'node-94-fde.json').write_text(json.dumps(
            {'binary_sha256': digest, 'cie_records': 0}))
        (index / 'node-94-fde.tsv').write_text('start_va\tend_va\tfde_va\n')
        self.readelf = self.root / 'readelf-stub'
        self.readelf.write_text(STUB_READELF)
        self.readelf.chmod(0o755)
        self.script = script_dir / 'readelf_crosscheck.py'

    def run_crosscheck(self):
        return subprocess.run(
            [sys.executable, str(self.script), '--release', '94',
             '--readelf', str(self.readelf)],
            capture_output=True, text=True)

    def test_pinned_binary_crosschecks(self):
        result = self.run_crosscheck()
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report['identical'])
        self.assertEqual(report['binary_sha256'],
                         hashlib.sha256(BINARY).hexdigest())

    def test_tampered_binary_rejected_before_readelf(self):
        with self.binary.open('ab') as handle:
            handle.write(b'TAMPERED')
        result = self.run_crosscheck()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Artifact size/SHA-256 mismatch', result.stderr)
        self.assertNotIn('identical', result.stdout)


if __name__ == '__main__':
    unittest.main()
