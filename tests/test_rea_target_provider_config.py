import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import rea


class TargetProviderConfigTests(unittest.TestCase):
    def setUp(self):
        self._config = dict(rea.CONFIG)

    def tearDown(self):
        rea.CONFIG = self._config

    def test_missing_provider_fails_closed(self):
        rea.CONFIG = {k: v for k, v in self._config.items() if k != 'provider'}
        with self.assertRaisesRegex(ValueError, 'missing provider'):
            rea.target('115')

    def test_missing_provider_fails_closed_with_check_stubbed(self):
        # With the artifact check stubbed out, base reaches the bare
        # CONFIG['provider'] subscript and raises KeyError instead of the
        # ValueError every other launcher failure gets; the guard must fire
        # before the check so the failure is closed on any artifact state.
        rea.CONFIG = {k: v for k, v in self._config.items() if k != 'provider'}
        with patch.object(rea, 'check', lambda *args: None):
            with self.assertRaises(ValueError):
                rea.target('115')

    def test_present_provider_still_builds_row(self):
        with patch.object(rea, 'check', lambda *args: None):
            row = rea.target('115')
        self.assertEqual(row['provider_id'], 'ghidra')
        self.assertEqual(row['sha256'], 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301')


if __name__ == '__main__':
    unittest.main()
