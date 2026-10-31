import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import harness_plan as hp


ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-003-harness-design'


class DuplicateFixtureIdsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        protocol = hp.load_json(PACKET / 'protocol.json')
        cls.fixtures = hp.validate_fixtures(
            hp.load_json(PACKET / 'fixture-identities.json'), protocol
        )

    def _request(self):
        return hp.load_json(PACKET / 'examples' / 'plan-only.json')

    def test_duplicate_fixture_id_rejected(self):
        req = self._request()
        req['fixture_ids'] = ['syn-94-pos-equal-window-v1',
                              'syn-94-pos-equal-window-v1']
        with self.assertRaisesRegex(ValueError, 'duplicate fixture_id'):
            hp.validate_request(req, self.fixtures)

    def test_single_fixture_still_planned(self):
        plan = hp.validate_request(self._request(), self.fixtures)
        self.assertEqual(plan['status'], 'planned')
        self.assertEqual(plan['fixture_ids'],
                         ['syn-94-pos-equal-window-v1'])

    def test_two_distinct_fixtures_still_planned(self):
        req = self._request()
        req['fixture_ids'] = ['syn-94-pos-equal-window-v1',
                              'syn-94-neg-corrupt-byte-v1']
        plan = hp.validate_request(req, self.fixtures)
        self.assertEqual(plan['status'], 'planned')
        self.assertEqual(plan['fixture_ids'], req['fixture_ids'])


if __name__ == '__main__':
    unittest.main()
