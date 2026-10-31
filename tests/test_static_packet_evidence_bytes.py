"""Static packet tools must emit byte-identical evidence on every host.

Two fast generators stand in for the shared write path: cguard (4 files) and
file_tracker (4 files). Before the newline pin they produced CRLF on Windows and
the committed observed/ files could not be reproduced.
"""
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import cguard_consistency_static as cguard  # noqa: E402
import file_tracker_init_static as file_tracker  # noqa: E402

ARTIFACT = ROOT / 'artifacts/node/94/hl-node'
CASES = (
    (cguard, 'RE-001-cguard-consistency-94'),
    (file_tracker, 'RE-001-file-tracker-init-94'),
)


@unittest.skipUnless(shutil.which('readelf') and shutil.which('objdump'),
                     'GNU binutils required')
@unittest.skipUnless(ARTIFACT.exists(), 'captured node #94 not present')
class EvidenceBytes(unittest.TestCase):
    def test_regenerated_packet_matches_committed_bytes(self):
        for module, item in CASES:
            with self.subTest(item=item), tempfile.TemporaryDirectory() as tmp:
                out = Path(tmp)
                module.generate(ARTIFACT.resolve(), out)
                committed = ROOT / 'research/work-items' / item / 'observed'
                names = sorted(p.name for p in committed.iterdir() if p.is_file())
                self.assertTrue(names, item)
                for name in names:
                    self.assertEqual((out / name).read_bytes(), (committed / name).read_bytes(),
                                     f'{item}/{name}')


if __name__ == '__main__':
    unittest.main()
