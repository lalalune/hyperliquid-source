"""constants_scan must emit byte-identical committed evidence on every host.

The reference tree is unlicensed and not committed. Set HL_REFERENCE_ROOT to a
local copy of the pinned can1357-hl tree to run this outside a submodule
checkout; CI uses the pinned submodule.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import constants_scan as cs  # noqa: E402

REF_ROOT = Path(os.environ.get('HL_REFERENCE_ROOT', ROOT / 'references/can1357-hl'))
AWS = REF_ROOT / 'global_constants/aws_name.rs'
CONFIG = REF_ROOT / 'global_constants/static_config.rs'
ARTIFACT = ROOT / 'artifacts/node/94/hl-node'
PACKET = ROOT / 'research/work-items/constants'


@unittest.skipUnless(AWS.is_file() and CONFIG.is_file(), 'pinned reference source not available')
@unittest.skipUnless(ARTIFACT.exists(), 'captured node #94 not present')
class EvidenceBytes(unittest.TestCase):
    def test_regenerated_outputs_match_committed_bytes(self):
        saved = (cs.REFERENCE, cs.REFERENCE_CONFIG, sys.argv)
        cs.REFERENCE, cs.REFERENCE_CONFIG = AWS, CONFIG
        try:
            with tempfile.TemporaryDirectory() as tmp:
                sys.argv = ['constants_scan.py', '--release', '94', '--out', tmp]
                cs.main()
                for name in ('constants.json', 'strings.tsv', 'xrefs.tsv'):
                    self.assertEqual((Path(tmp) / name).read_bytes(),
                                     (PACKET / name).read_bytes(), name)
        finally:
            cs.REFERENCE, cs.REFERENCE_CONFIG, sys.argv = saved


if __name__ == '__main__':
    unittest.main()
