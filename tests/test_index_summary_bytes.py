"""Committed index/progress summaries must be byte-identical when regenerated.

Both writers used Path.write_text, so Windows produced CRLF copies that no
longer matched the committed summary files or their recorded hashes.
"""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import elf_index  # noqa: E402
import fde_extents  # noqa: E402

ARTIFACT = ROOT / 'artifacts/node/94/hl-node'


@unittest.skipUnless(ARTIFACT.exists(), 'captured node #94 not present')
class SummaryBytes(unittest.TestCase):
    def test_fde_summary_matches_committed_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            prefix = Path(tmp) / 'node-94-fde'
            fde_extents.generate(ARTIFACT, prefix)
            self.assertEqual(prefix.with_suffix('.json').read_bytes(),
                             (ROOT / 'research/work-items/RE-001-fde-extents/node-94-fde-summary.json').read_bytes())

    def test_unwind_summary_matches_committed_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            prefix = Path(tmp) / 'node-94-unwind'
            elf_index.generate(ARTIFACT, prefix)
            self.assertEqual(prefix.with_suffix('.json').read_bytes(),
                             (ROOT / 'research/work-items/RE-000-readiness/node-94-unwind.json').read_bytes())


if __name__ == '__main__':
    unittest.main()
