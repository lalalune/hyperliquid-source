import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import rea


class ProfileDisabledAnalyzersConfigTests(unittest.TestCase):
    def setUp(self):
        self._config = dict(rea.CONFIG)

    def tearDown(self):
        rea.CONFIG = self._config

    def _run_with_profile(self, profile):
        rea.CONFIG = dict(self._config)
        rea.CONFIG['profiles'] = {'p': profile}
        env = {}
        with patch.object(rea, 'find_node', return_value=Path('/tmp/node')), \
                patch.object(rea, 'environment', return_value=env):
            rea.main(['--profile', 'p', '--help'])
        return env

    def test_missing_disabled_analyzers_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'missing disabled_analyzers'):
            self._run_with_profile({})

    def test_unknown_profile_still_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'Unknown REA profile'):
            rea.main(['--profile', 'nope', '--help'])

    def test_present_disabled_analyzers_still_applied(self):
        # The pinned package is absent on this environment, so main stops at
        # the package check after the env assignment; the env dict proves the
        # profile key was applied.
        env = {}
        rea.CONFIG = dict(self._config)
        rea.CONFIG['profiles'] = {'p': {'disabled_analyzers': ['A', 'B']}}
        with patch.object(rea, 'find_node', return_value=Path('/tmp/node')), \
                patch.object(rea, 'environment', return_value=env):
            with self.assertRaisesRegex(ValueError, 'Pinned REA package is absent'):
                rea.main(['--profile', 'p', '--help'])
        self.assertEqual(env['REA_GHIDRA_DISABLED_ANALYZERS'], 'A,B')


if __name__ == '__main__':
    unittest.main()
