import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import rea


class TargetBranchConfigTests(unittest.TestCase):
    def setUp(self):
        self._config = dict(rea.CONFIG)

    def tearDown(self):
        rea.CONFIG = self._config

    def test_missing_targets_fails_closed(self):
        rea.CONFIG = {k: v for k, v in self._config.items() if k != 'targets'}
        with self.assertRaisesRegex(ValueError, 'missing targets'):
            rea.main(['target', '94'])

    def test_unknown_target_still_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'Unknown target'):
            rea.main(['target', 'nope'])


if __name__ == '__main__':
    unittest.main()
