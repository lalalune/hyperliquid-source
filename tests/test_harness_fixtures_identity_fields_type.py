import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import harness_plan as hp


ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-003-harness-design'

DIGEST = 'a' * 64


def _row():
    return {
        'fixture_id': 'f1',
        'kind': 'k',
        'target_release': '94',
        'target_sha256': DIGEST,
        'payload_sha256': DIGEST,
        'declared_side_effects': [],
        'positive_or_negative': 'positive',
        'notes': '',
    }


def _doc():
    return {'task_id': 'RE-003', 'fixtures': [_row()]}


def _protocol(fields):
    return {'fixture_identity_fields': fields}


class FixtureIdentityFieldsTypeTests(unittest.TestCase):
    def test_non_list_fields_rejected(self):
        for fields in (42, None, {'fixture_id': 1, 'target_sha256': 1}):
            with self.subTest(fields=fields):
                with self.assertRaisesRegex(
                    ValueError, 'fixture_identity_fields must be a list'
                ):
                    hp.validate_fixtures(_doc(), _protocol(fields))

    def test_string_fields_rejected(self):
        with self.assertRaisesRegex(
            ValueError, 'fixture_identity_fields must be a list'
        ):
            hp.validate_fixtures(_doc(), _protocol('fixture_id'))

    def test_list_fields_still_validate(self):
        by_id = hp.validate_fixtures(
            _doc(),
            _protocol(['fixture_id', 'target_sha256']),
        )
        self.assertEqual(list(by_id), ['f1'])

    def test_real_packet_still_validates(self):
        protocol = hp.load_json(PACKET / 'protocol.json')
        hp.validate_protocol(protocol)
        fixtures = hp.validate_fixtures(
            hp.load_json(PACKET / 'fixture-identities.json'), protocol
        )
        self.assertIn('syn-94-pos-equal-window-v1', fixtures)


if __name__ == '__main__':
    unittest.main()
