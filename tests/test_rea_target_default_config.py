import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import rea


class TargetDefaultConfigTests(unittest.TestCase):
    def setUp(self):
        self._config = dict(rea.CONFIG)

    def tearDown(self):
        rea.CONFIG = self._config

    def test_missing_default_target_fails_closed(self):
        rea.CONFIG = {k: v for k, v in self._config.items() if k != 'default_target'}
        with self.assertRaisesRegex(ValueError, 'missing default_target'):
            rea.main(['target'])

    def test_explicit_target_still_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'Unknown target'):
            rea.main(['target', 'nope'])

    def test_present_default_target_resolves(self):
        seen = []
        with patch.object(rea, 'target', side_effect=lambda name: seen.append(name) or {'path': 'x', 'sha256': 'y', 'provider_id': 'z'}):
            rea.main(['target'])
        self.assertEqual(seen, ['94'])


if __name__ == '__main__':
    unittest.main()
