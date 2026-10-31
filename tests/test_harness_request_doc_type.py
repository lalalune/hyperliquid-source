"""harness_plan must reject a non-dict request document with ValueError.

Sibling of open #515 (non-dict protocol document) and #490 (non-dict
fixtures document) in the same packet flow: validate_request() runs
its missing-fields membership test and then string subscripts with no
document-type gate, so an int/None request escapes as TypeError at the
membership test and a list holding all required field names escapes as
TypeError at the first subscript, instead of the ValueError every other
malformed request shape raises.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import harness_plan as hp


ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-003-harness-design'


class RequestDocTypeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        protocol = hp.load_json(PACKET / 'protocol.json')
        cls.fixtures = hp.validate_fixtures(
            hp.load_json(PACKET / 'fixture-identities.json'), protocol
        )

    def test_int_request_rejected(self):
        with self.assertRaisesRegex(ValueError, 'request must be a mapping'):
            hp.validate_request(5, self.fixtures)

    def test_none_request_rejected(self):
        with self.assertRaisesRegex(ValueError, 'request must be a mapping'):
            hp.validate_request(None, self.fixtures)

    def test_list_holding_required_keys_rejected(self):
        with self.assertRaisesRegex(ValueError, 'request must be a mapping'):
            hp.validate_request(list(hp.REQUIRED_REQUEST_FIELDS), self.fixtures)

    def test_real_request_still_plans(self):
        plan = hp.validate_request(
            hp.load_json(PACKET / 'examples/plan-only.json'), self.fixtures
        )
        self.assertEqual(plan['status'], 'planned')

    def test_dict_missing_fields_still_rejected(self):
        with self.assertRaisesRegex(ValueError, 'request missing fields'):
            hp.validate_request({}, self.fixtures)


if __name__ == '__main__':
    unittest.main()
