"""Missing manifest-identity entry in truncated_debug_static.generate()."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import truncated_debug_static as tds

REL = 'artifacts/node/94/hl-node'


class TruncatedDebugIdentityTests(unittest.TestCase):
    def run_generate(self, manifest):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / 'provenance').mkdir()
        (root / 'provenance/artifacts.json').write_text(json.dumps(manifest))
        with patch.object(tds, 'ROOT', root):
            tds.generate(root / 'node', root / 'out')

    def test_missing_identity_entry_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'No provenance/artifacts.json entry'):
            self.run_generate({'files': [{'path': 'artifacts/node/115/hl-node',
                                          'size': 1, 'sha256': 'x'}]})

    def test_present_entry_reaches_artifact_check(self):
        # The lookup itself succeeds; the artifact is absent in the tmp root,
        # so artifacts.check() raises its own ValueError, not a lookup error.
        with self.assertRaisesRegex(ValueError, 'Missing artifact'):
            self.run_generate({'files': [{'path': REL, 'size': 1, 'sha256': 'x'}]})


if __name__ == '__main__':
    unittest.main()
