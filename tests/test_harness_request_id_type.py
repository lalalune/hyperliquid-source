"""harness_plan must reject a non-string request_id with ValueError.

Sibling of open #350 (non-string fixture_id) and #342 (non-string
target_release) in the same function: validate_request passes
request['request_id'] to approval_covers(), which tests
``request_id in text`` against APPROVAL.md, so a list/dict/int/None id
escapes main()'s ValueError-only rejection handler as TypeError whenever
an approval file exists, instead of the clean rejected result every
other malformed request gets.
"""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import harness_plan as hp


ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-003-harness-design'


class RequestIdTypeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        protocol = hp.load_json(PACKET / 'protocol.json')
        cls.fixtures = hp.validate_fixtures(
            hp.load_json(PACKET / 'fixture-identities.json'), protocol
        )

    def _request(self, request_id):
        req = hp.load_json(PACKET / 'examples/plan-only.json')
        req['request_id'] = request_id
        return req

    def _assert_rejected(self, request_id):
        with tempfile.TemporaryDirectory() as tmp:
            approval = Path(tmp) / 'APPROVAL.md'
            approval.write_text('authorized\n', encoding='utf-8')
            with mock.patch.object(hp, 'APPROVAL_PATH', approval):
                with self.assertRaisesRegex(ValueError, 'request_id must be a string'):
                    hp.validate_request(self._request(request_id), self.fixtures)

    def test_list_request_id_rejected(self):
        self._assert_rejected(['re003-plan-only-001'])

    def test_dict_request_id_rejected(self):
        self._assert_rejected({'id': 're003-plan-only-001'})

    def test_int_request_id_rejected(self):
        self._assert_rejected(42)

    def test_none_request_id_rejected(self):
        self._assert_rejected(None)

    def test_string_request_id_still_plans(self):
        plan = hp.validate_request(self._request('re003-plan-only-001'), self.fixtures)
        self.assertEqual(plan['status'], 'planned')
        self.assertEqual(plan['request_id'], 're003-plan-only-001')


if __name__ == '__main__':
    unittest.main()
