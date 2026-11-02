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
            row = rea.target('115')
        self.assertEqual(row['path'], str(rea.ROOT / 'artifacts/node/115/hl-node'))
        self.assertEqual(row['sha256'], 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301')
        self.assertEqual(row['provider_id'], 'ghidra')


if __name__ == '__main__':
    unittest.main()
