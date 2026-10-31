import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import harness_plan as hp


class FixturesContainerTypeTests(unittest.TestCase):
    def _protocol(self):
        return {'fixture_identity_fields': ['fixture_id', 'target_sha256']}

    def _doc(self, fixtures):
        return {'task_id': 'RE-003', 'fixtures': fixtures}

    def test_dict_fixtures_rejected(self):
        with self.assertRaisesRegex(ValueError, 'fixtures must be a list'):
            hp.validate_fixtures(
                self._doc({'a': {'fixture_id': 'a', 'target_sha256': '0' * 64}}),
                self._protocol())

    def test_str_fixtures_rejected(self):
        with self.assertRaisesRegex(ValueError, 'fixtures must be a list'):
            hp.validate_fixtures(self._doc('abc'), self._protocol())

    def test_int_fixtures_rejected(self):
        with self.assertRaisesRegex(ValueError, 'fixtures must be a list'):
            hp.validate_fixtures(self._doc(123), self._protocol())

    def test_list_fixtures_still_validated(self):
        by_id = hp.validate_fixtures(
            self._doc([{'fixture_id': 'a', 'target_sha256': '0' * 64}]),
            self._protocol())
        self.assertIn('a', by_id)


if __name__ == '__main__':
    unittest.main()
