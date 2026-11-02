import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import rea


class TargetTargetsConfigTests(unittest.TestCase):
    def setUp(self):
        self._config = dict(rea.CONFIG)

    def tearDown(self):
        rea.CONFIG = self._config

    def test_missing_targets_fails_closed(self):
        # Open #359 guards only main()'s target branch; target() itself is
        # also called directly (rea_mcp_check's native smoke) and still hit
        # the bare CONFIG['targets'] subscript with a raw KeyError.
        rea.CONFIG = {k: v for k, v in self._config.items() if k != 'targets'}
        with self.assertRaisesRegex(ValueError, 'missing targets'):
            rea.target('115')

    def test_missing_targets_fails_closed_with_check_stubbed(self):
        # The guard must fire before the artifact check so the failure is
        # closed on any artifact state, mirroring #366's provider guard.
        rea.CONFIG = {k: v for k, v in self._config.items() if k != 'targets'}
        with patch.object(rea, 'check', lambda *args: None):
            with self.assertRaises(ValueError):
                rea.target('115')

    def test_present_targets_still_builds_row(self):
        with patch.object(rea, 'check', lambda *args: None):
            row = rea.target('115')
        self.assertEqual(row['provider_id'], 'ghidra')
        self.assertEqual(row['sha256'], 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301')


if __name__ == '__main__':
    unittest.main()
