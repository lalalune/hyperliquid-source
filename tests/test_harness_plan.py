import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import harness_plan as hp


ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-003-harness-design'


class ProtocolPacketTests(unittest.TestCase):
    def test_protocol_and_fixtures_validate(self):
        protocol = hp.load_json(PACKET / 'protocol.json')
        hp.validate_protocol(protocol)
        fixtures = hp.validate_fixtures(hp.load_json(PACKET / 'fixture-identities.json'), protocol)
        self.assertIn('syn-94-pos-equal-window-v1', fixtures)
        self.assertGreaterEqual(len(protocol['positive_controls']), 1)
        self.assertGreaterEqual(len(protocol['negative_controls']), 1)

    def test_check_packet_ok(self):
        self.assertEqual(hp.main(['--check']), 0)

    def test_approval_file_must_not_be_committed(self):
        self.assertFalse((PACKET / 'APPROVAL.md').exists())


class RequestGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        protocol = hp.load_json(PACKET / 'protocol.json')
        cls.fixtures = hp.validate_fixtures(
            hp.load_json(PACKET / 'fixture-identities.json'), protocol
        )

    def _load(self, name):
        return hp.load_json(PACKET / 'examples' / name)

    def test_plan_only_accepted(self):
        plan = hp.validate_request(self._load('plan-only.json'), self.fixtures)
        self.assertEqual(plan['status'], 'planned')
        self.assertFalse(plan['execute_target'])

    def test_execute_without_approval_rejected(self):
        with self.assertRaisesRegex(ValueError, 'execute_target requires APPROVAL'):
            hp.validate_request(self._load('deny-execute.json'), self.fixtures)

    def test_network_allow_without_approval_rejected(self):
        with self.assertRaisesRegex(ValueError, 'network allow requires APPROVAL'):
            hp.validate_request(self._load('deny-network.json'), self.fixtures)

    def test_wrong_digest_fixture_rejected(self):
        with self.assertRaisesRegex(ValueError, 'does not match request digest'):
            hp.validate_request(self._load('deny-wrong-digest.json'), self.fixtures)

    def test_cli_rejects_execute_example(self):
        self.assertEqual(
            hp.main(['--request', str(PACKET / 'examples/deny-execute.json')]),
            2,
        )

    def test_cli_accepts_plan_only_example(self):
        self.assertEqual(
            hp.main(['--request', str(PACKET / 'examples/plan-only.json')]),
            0,
        )

    def test_target_digest_mismatch_rejected(self):
        req = self._load('plan-only.json')
        req['target_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'target_sha256 does not match'):
            hp.validate_request(req, self.fixtures)

    def test_unknown_fixture_rejected(self):
        req = self._load('plan-only.json')
        req['fixture_ids'] = ['does-not-exist']
        with self.assertRaisesRegex(ValueError, 'unknown fixture_id'):
            hp.validate_request(req, self.fixtures)

    def test_approval_present_but_file_missing_rejected(self):
        req = self._load('plan-only.json')
        req['approval_present'] = True
        with self.assertRaisesRegex(ValueError, 'APPROVAL.md does not cover'):
            hp.validate_request(req, self.fixtures)

    def test_even_with_approval_tool_refuses_execute(self):
        req = self._load('deny-execute.json')
        req['approval_present'] = True
        with tempfile.TemporaryDirectory() as tmp:
            approval = Path(tmp) / 'APPROVAL.md'
            approval.write_text(
                f'authorized request_id={req["request_id"]}\n', encoding='utf-8'
            )
            with mock.patch.object(hp, 'APPROVAL_PATH', approval):
                with self.assertRaisesRegex(ValueError, 'plan-only and refuses'):
                    hp.validate_request(req, self.fixtures)

    def _fixtures_with_effect(self, effect='writes_fixture_output'):
        import copy
        fixtures = copy.deepcopy(self.fixtures)
        fid = 'syn-94-pos-equal-window-v1'
        fixtures[fid]['declared_side_effects'] = [effect]
        return fixtures, fid

    def test_omitted_fixture_effects_rejected(self):
        fixtures, fid = self._fixtures_with_effect()
        req = self._load('plan-only.json')
        req['fixture_ids'] = [fid]
        req['declared_side_effects'] = []
        with self.assertRaisesRegex(
            ValueError, r"omits selected fixture effects: \['writes_fixture_output'\]"
        ):
            hp.validate_request(req, fixtures)

    def test_underdeclared_fixture_effects_rejected(self):
        import copy
        fixtures = copy.deepcopy(self.fixtures)
        fid = 'syn-94-pos-equal-window-v1'
        fixtures[fid]['declared_side_effects'] = [
            'writes_fixture_output',
            'touches_workdir',
        ]
        req = self._load('plan-only.json')
        req['fixture_ids'] = [fid]
        req['declared_side_effects'] = ['writes_fixture_output']
        with self.assertRaisesRegex(
            ValueError, r"omits selected fixture effects: \['touches_workdir'\]"
        ):
            hp.validate_request(req, fixtures)

    def test_exact_fixture_effect_cover_accepted(self):
        fixtures, fid = self._fixtures_with_effect()
        req = self._load('plan-only.json')
        req['fixture_ids'] = [fid]
        req['declared_side_effects'] = ['writes_fixture_output']
        plan = hp.validate_request(req, fixtures)
        self.assertEqual(plan['status'], 'planned')
        self.assertEqual(plan['declared_side_effects'], ['writes_fixture_output'])

    def test_denial_text_does_not_cover_network_allow(self):
        req = self._load('deny-network.json')
        req['approval_present'] = True
        with tempfile.TemporaryDirectory() as tmp:
            approval = Path(tmp) / 'APPROVAL.md'
            approval.write_text(
                f"request_id={req['request_id']} is unauthorized\n",
                encoding='utf-8',
            )
            with mock.patch.object(hp, 'APPROVAL_PATH', approval):
                with self.assertRaisesRegex(ValueError, 'APPROVAL.md does not cover'):
                    hp.validate_request(req, self.fixtures)

    def test_other_request_approval_does_not_cover_network_allow(self):
        req = self._load('deny-network.json')
        req['approval_present'] = True
        with tempfile.TemporaryDirectory() as tmp:
            approval = Path(tmp) / 'APPROVAL.md'
            approval.write_text(
                f"authorized request_id={req['request_id']}-extended\n",
                encoding='utf-8',
            )
            with mock.patch.object(hp, 'APPROVAL_PATH', approval):
                with self.assertRaisesRegex(ValueError, 'APPROVAL.md does not cover'):
                    hp.validate_request(req, self.fixtures)

    def test_genuine_approval_still_covers_network_allow(self):
        req = self._load('deny-network.json')
        req['approval_present'] = True
        with tempfile.TemporaryDirectory() as tmp:
            approval = Path(tmp) / 'APPROVAL.md'
            approval.write_text(
                f"authorized request_id={req['request_id']}\n",
                encoding='utf-8',
            )
            with mock.patch.object(hp, 'APPROVAL_PATH', approval):
                plan = hp.validate_request(req, self.fixtures)
        self.assertEqual(plan['status'], 'planned')
        self.assertEqual(plan['network'], 'allow')

    def test_superset_fixture_effect_cover_accepted(self):
        fixtures, fid = self._fixtures_with_effect()
        req = self._load('plan-only.json')
        req['fixture_ids'] = [fid]
        req['declared_side_effects'] = ['writes_fixture_output', 'extra_declared']
        plan = hp.validate_request(req, fixtures)
        self.assertEqual(plan['status'], 'planned')
        self.assertEqual(
            plan['declared_side_effects'],
            ['writes_fixture_output', 'extra_declared'],
        )


if __name__ == '__main__':
    unittest.main()
