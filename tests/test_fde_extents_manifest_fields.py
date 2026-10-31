"""Manifest-entry field guard in fde_extents main(); synthetic manifest, no target execution."""
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import fde_extents as fe


REL = 'artifacts/node/94/hl-node'


class FdeExtentsManifestFieldsTests(unittest.TestCase):
    def run_main(self, entry):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / 'provenance').mkdir()
        (root / 'provenance' / 'artifacts.json').write_text(
            json.dumps({'files': [entry]}))
        # The artifact must exist so check() reaches the field reads
        # instead of failing earlier with 'Missing artifact'.
        art = root / 'artifacts' / 'node' / '94'
        art.mkdir(parents=True)
        (art / 'hl-node').write_bytes(b'\x00' * 64)
        with patch.object(fe, 'ROOT', root), patch.object(
                sys, 'argv', ['fde_extents.py', '--release', '94',
                              '--output-dir', str(root / 'out')]):
            fe.main()

    def test_missing_sha256_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'missing sha256'):
            self.run_main({'path': REL, 'size': 64})

    def test_missing_size_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'missing size'):
            self.run_main({'path': REL, 'sha256': 'x' * 64})

    def test_missing_both_fields_names_both(self):
        with self.assertRaisesRegex(ValueError, 'missing size/sha256'):
            self.run_main({'path': REL})

    def test_valid_entry_passes_validation(self):
        data = b'\x00' * 64
        # check() passes, so the failure moves downstream to a ValueError
        # contract error (ELF parsing of the dummy binary) instead of a
        # KeyError from the field guard.
        with self.assertRaises(ValueError):
            self.run_main({'path': REL, 'size': len(data),
                           'sha256': hashlib.sha256(data).hexdigest()})


if __name__ == '__main__':
    unittest.main()
