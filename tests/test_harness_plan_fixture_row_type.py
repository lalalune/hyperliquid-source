import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import harness_plan as hp

PROTOCOL = {'fixture_identity_fields': ['fixture_id', 'target_sha256']}
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'


def _doc(rows):
    return {'task_id': 'RE-003', 'fixtures': rows}


class FixtureRowTypeTests(unittest.TestCase):
    def test_list_row_rejected(self):
        with self.assertRaises(ValueError):
            hp.validate_fixtures(_doc([['fixture_id']]), PROTOCOL)

    def test_string_row_rejected(self):
        with self.assertRaises(ValueError):
            hp.validate_fixtures(_doc(['x']), PROTOCOL)

    def test_int_row_rejected(self):
        with self.assertRaises(ValueError):
            hp.validate_fixtures(_doc([5]), PROTOCOL)

    def test_none_row_rejected(self):
        with self.assertRaises(ValueError):
            hp.validate_fixtures(_doc([None]), PROTOCOL)

    def test_dict_row_missing_field_still_rejected(self):
        with self.assertRaises(ValueError):
            hp.validate_fixtures(_doc([{'fixture_id': 'f1'}]), PROTOCOL)

    def test_valid_dict_row_accepted(self):
        by_id = hp.validate_fixtures(
            _doc([{'fixture_id': 'f1', 'target_sha256': DIGEST}]), PROTOCOL)
        self.assertIn('f1', by_id)


if __name__ == '__main__':
    unittest.main()
