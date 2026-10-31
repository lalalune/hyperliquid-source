import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import harness_plan as hp


class RequestSideEffectTypeTests(unittest.TestCase):
    def _request(self, effects):
        return {
            'request_id': 're003-side-effect-type-001',
            'component_id': 'harness',
            'bounded_question': 'Validate side-effect entry types without executing a target',
            'target_release': '94',
            'target_sha256': hp.KNOWN_TARGET_DIGESTS['94'],
            'fixture_ids': ['fx1'],
            'declared_side_effects': effects,
            'network': 'deny',
            'execute_target': False,
            'approval_present': False,
        }

    def _fixtures(self):
        return {'fx1': {
            'target_sha256': hp.KNOWN_TARGET_DIGESTS['94'],
            'declared_side_effects': [],
        }}

    def test_list_effect_rejected(self):
        with self.assertRaisesRegex(ValueError, 'declared_side_effects entries must be strings'):
            hp.validate_request(self._request([['writes_fixture_output']]), self._fixtures())

    def test_dict_effect_rejected(self):
        with self.assertRaisesRegex(ValueError, 'declared_side_effects entries must be strings'):
            hp.validate_request(self._request([{'effect': 'writes_fixture_output'}]), self._fixtures())

    def test_int_effect_rejected(self):
        with self.assertRaisesRegex(ValueError, 'declared_side_effects entries must be strings'):
            hp.validate_request(self._request([1]), self._fixtures())

    def test_string_effects_still_planned(self):
        plan = hp.validate_request(
            self._request(['writes_fixture_output']), self._fixtures())
        self.assertEqual(plan['status'], 'planned')
        self.assertEqual(plan['declared_side_effects'], ['writes_fixture_output'])


if __name__ == '__main__':
    unittest.main()
