import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import harness_plan as hp


def _request(fixture_ids):
    return {
        'request_id': 'r1',
        'component_id': 'c',
        'bounded_question': 'q',
        'target_release': '94',
        'target_sha256': hp.KNOWN_TARGET_DIGESTS['94'],
        'fixture_ids': fixture_ids,
        'declared_side_effects': [],
        'network': 'deny',
        'execute_target': False,
        'approval_present': False,
    }


class FixtureIdTypeTests(unittest.TestCase):
    def test_list_fixture_id_rejected(self):
        with self.assertRaises(ValueError):
            hp.validate_request(_request([['x']]), {})

    def test_dict_fixture_id_rejected(self):
        with self.assertRaises(ValueError):
            hp.validate_request(_request([{'x': 1}]), {})

    def test_unknown_string_fixture_id_rejected(self):
        with self.assertRaises(ValueError):
            hp.validate_request(_request(['nope']), {})

    def test_valid_string_fixture_id_passes_gate(self):
        fixtures = {'f1': {'target_sha256': hp.KNOWN_TARGET_DIGESTS['94'],
                           'declared_side_effects': []}}
        plan = hp.validate_request(_request(['f1']), fixtures)
        self.assertEqual(plan['status'], 'planned')


if __name__ == '__main__':
    unittest.main()
