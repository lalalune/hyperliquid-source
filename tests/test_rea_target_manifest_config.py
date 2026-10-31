import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import rea


class TargetManifestConfigTests(unittest.TestCase):
    def setUp(self):
        self._config = dict(rea.CONFIG)

    def tearDown(self):
        rea.CONFIG = self._config

    def test_target_without_manifest_entry_fails_closed(self):
        rea.CONFIG = dict(self._config)
        rea.CONFIG['targets'] = {'x': 'artifacts/nope/hl-node'}
        with self.assertRaisesRegex(ValueError, 'has no provenance/artifacts.json entry'):
            rea.target('x')

    def test_target_without_manifest_entry_fails_closed_via_main(self):
        rea.CONFIG = dict(self._config)
        rea.CONFIG['targets'] = {'x': 'artifacts/nope/hl-node'}
        with self.assertRaisesRegex(ValueError, 'has no provenance/artifacts.json entry'):
            rea.main(['target', 'x'])

    def test_present_manifest_entry_still_resolves(self):
        with patch.object(rea, 'check'):
            row = rea.target('94')
        self.assertEqual(row['path'], str(rea.ROOT / 'artifacts/node/94/hl-node'))
        self.assertEqual(row['sha256'], '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f')
        self.assertEqual(row['provider_id'], 'ghidra')


if __name__ == '__main__':
    unittest.main()
