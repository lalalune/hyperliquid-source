"""Synthetic controls for strict booleans in the plan-only RE-003 schema."""
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import harness_plan as hp  # noqa: E402


TARGET_SHA256 = hp.KNOWN_TARGET_DIGESTS['94']
BAD_VALUES = (None, 0, 1, -1, 0.0, 1.0, '', 'true', [], ['true'], {}, {'value': True})


def protocol():
    return {
        'schema_version': 1,
        'task_id': 'RE-003',
        'execution_default': 'denied',
        'requires_execution_approval': True,
        'isolation': {'network': 'deny'},
        'fixture_identity_fields': ['fixture_id', 'target_sha256'],
        'positive_controls': ['synthetic-pass'],
        'negative_controls': ['synthetic-fail'],
        'request_fields': list(hp.REQUIRED_REQUEST_FIELDS),
        'acceptance_checklist': ['synthetic'],
    }


def fixtures_doc():
    return {
        'task_id': 'RE-003',
        'fixtures': [{'fixture_id': 'synthetic-94', 'target_sha256': TARGET_SHA256}],
    }


def request():
    return {
        'request_id': 'synthetic-request',
        'component_id': 'foundation',
        'bounded_question': 'Does the plan-only schema reject coercible flags?',
        'target_release': '94',
        'target_sha256': TARGET_SHA256,
        'fixture_ids': ['synthetic-94'],
        'declared_side_effects': [],
        'network': 'deny',
        'execute_target': False,
        'approval_present': False,
    }


class HarnessBooleanFieldsTests(unittest.TestCase):
    def setUp(self):
        self.fixtures = hp.validate_fixtures(fixtures_doc(), protocol())

    def test_execute_target_rejects_non_bool_values_before_approval_lookup(self):
        for value in BAD_VALUES:
            with self.subTest(value=value):
                row = request()
                row['execute_target'] = value
                with mock.patch.object(hp, 'approval_covers') as covers:
                    with self.assertRaisesRegex(ValueError, 'execute_target must be a boolean'):
                        hp.validate_request(row, self.fixtures)
                    covers.assert_not_called()

    def test_approval_present_rejects_non_bool_values_before_approval_lookup(self):
        for value in BAD_VALUES:
            with self.subTest(value=value):
                row = request()
                row['approval_present'] = value
                with mock.patch.object(hp, 'approval_covers') as covers:
                    with self.assertRaisesRegex(ValueError, 'approval_present must be a boolean'):
                        hp.validate_request(row, self.fixtures)
                    covers.assert_not_called()

    def test_protocol_requires_literal_true(self):
        for value in (*BAD_VALUES, False):
            with self.subTest(value=value):
                row = protocol()
                row['requires_execution_approval'] = value
                with self.assertRaisesRegex(ValueError, 'requires_execution_approval must be true'):
                    hp.validate_protocol(row)
        hp.validate_protocol(protocol())

    def test_missing_request_fields_keep_original_error_precedence(self):
        row = request()
        del row['execute_target']
        del row['approval_present']
        row['target_release'] = 'unknown'
        with mock.patch.object(hp, 'approval_covers') as covers:
            with self.assertRaises(ValueError) as caught:
                hp.validate_request(row, self.fixtures)
            covers.assert_not_called()
        self.assertEqual(
            str(caught.exception),
            "request missing fields: ['execute_target', 'approval_present']",
        )

    def test_missing_protocol_field_keeps_original_error_precedence(self):
        row = protocol()
        del row['requires_execution_approval']
        row['task_id'] = 'wrong'
        with self.assertRaises(ValueError) as caught:
            hp.validate_protocol(row)
        self.assertEqual(
            str(caught.exception),
            "protocol.json missing fields: ['requires_execution_approval']",
        )

    def test_boolean_controls_preserve_plan_only_and_approval_rules(self):
        row = request()
        with mock.patch.object(hp, 'approval_covers', return_value=False) as covers:
            plan = hp.validate_request(row, self.fixtures)
        self.assertEqual(plan['status'], 'planned')
        self.assertIs(plan['execute_target'], False)
        covers.assert_called_once_with(row['request_id'])

        row['approval_present'] = True
        with mock.patch.object(hp, 'approval_covers', return_value=False):
            with self.assertRaisesRegex(ValueError, 'APPROVAL.md does not cover'):
                hp.validate_request(row, self.fixtures)
        with mock.patch.object(hp, 'approval_covers', return_value=True):
            self.assertEqual(hp.validate_request(row, self.fixtures)['status'], 'planned')

        row['approval_present'] = False
        row['execute_target'] = True
        with mock.patch.object(hp, 'approval_covers', return_value=False):
            with self.assertRaisesRegex(ValueError, 'execute_target requires APPROVAL'):
                hp.validate_request(row, self.fixtures)
        with mock.patch.object(hp, 'approval_covers', return_value=True):
            with self.assertRaisesRegex(ValueError, 'plan-only and refuses to spawn'):
                hp.validate_request(row, self.fixtures)

    def test_network_approval_rule_is_unchanged(self):
        row = request()
        row['network'] = 'allow'
        with mock.patch.object(hp, 'approval_covers', return_value=False):
            with self.assertRaisesRegex(ValueError, 'network allow requires APPROVAL'):
                hp.validate_request(row, self.fixtures)
        with mock.patch.object(hp, 'approval_covers', return_value=True):
            self.assertEqual(hp.validate_request(row, self.fixtures)['network'], 'allow')

    def test_cli_rejects_numeric_flags_with_json_result(self):
        for field in ('execute_target', 'approval_present'):
            for value in (0, 1):
                with self.subTest(field=field, value=value):
                    row = request()
                    row[field] = value
                    output = io.StringIO()
                    with mock.patch.object(
                        hp, 'load_json', side_effect=[protocol(), fixtures_doc(), row]
                    ) as load:
                        with mock.patch.object(hp, 'approval_covers') as covers:
                            with redirect_stdout(output):
                                code = hp.main(['--request', 'synthetic.json'])
                            covers.assert_not_called()
                        self.assertEqual(load.call_count, 3)
                    self.assertEqual(code, 2)
                    result = json.loads(output.getvalue())
                    self.assertEqual(result['status'], 'rejected')
                    self.assertEqual(result['reason'], f'{field} must be a boolean')


if __name__ == '__main__':
    unittest.main()
