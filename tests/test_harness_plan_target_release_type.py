"""harness_plan must reject a non-string target_release with ValueError.

Sibling of open #151 (duplicate keys in harness_plan JSON inputs) and the
catalogue/artifacts fail-closed fixes: validate_request checks
``release not in KNOWN_TARGET_DIGESTS``, but dict membership hashes its
operand, so a list/dict target_release escapes main()'s ValueError-only
rejection handler as TypeError instead of the clean rejected JSON every
other malformed request gets.
"""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import harness_plan as hp


ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-003-harness-design'


class TargetReleaseTypeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        protocol = hp.load_json(PACKET / 'protocol.json')
        cls.fixtures = hp.validate_fixtures(
            hp.load_json(PACKET / 'fixture-identities.json'), protocol
        )
        cls.base = hp.load_json(PACKET / 'examples/plan-only.json')

    def _request(self, release):
        req = dict(self.base)
        req['target_release'] = release
        return req

    def test_list_target_release_rejected(self):
        with self.assertRaisesRegex(ValueError, 'unknown target_release'):
            hp.validate_request(self._request(['94']), self.fixtures)

    def test_dict_target_release_rejected(self):
        with self.assertRaisesRegex(ValueError, 'unknown target_release'):
            hp.validate_request(self._request({'release': '94'}), self.fixtures)

    def test_unknown_string_release_still_rejected(self):
        with self.assertRaisesRegex(ValueError, 'unknown target_release'):
            hp.validate_request(self._request('999'), self.fixtures)

    def test_valid_plan_only_still_accepted(self):
        plan = hp.validate_request(self._request('94'), self.fixtures)
        self.assertEqual(plan['status'], 'planned')


if __name__ == '__main__':
    unittest.main()
