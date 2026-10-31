import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import harness_plan as hp


ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-003-harness-design'

DIGEST = 'a' * 64


def _doc(rows):
    return {'task_id': 'RE-003', 'fixtures': rows}


def _protocol(fields):
    return {'fixture_identity_fields': fields}


class RequiredRowKeysTests(unittest.TestCase):
    def test_row_missing_fixture_id_rejected(self):
        # The protocol's identity-fields list omits fixture_id, so the
        # listed-fields check passes and the row reaches the unconditional
        # row['fixture_id'] subscript.
        with self.assertRaisesRegex(
            ValueError, 'missing fixture_id or target_sha256'
        ):
            hp.validate_fixtures(
                _doc([{'target_sha256': DIGEST}]),
                _protocol(['target_sha256']),
            )

    def test_row_missing_target_sha256_rejected(self):
        with self.assertRaisesRegex(
            ValueError, 'missing fixture_id or target_sha256'
        ):
            hp.validate_fixtures(
                _doc([{'fixture_id': 'f1'}]),
                _protocol(['fixture_id']),
            )

    def test_listed_key_still_rejected_by_missing_check(self):
        with self.assertRaisesRegex(ValueError, 'missing'):
            hp.validate_fixtures(
                _doc([{'target_sha256': DIGEST}]),
                _protocol(['fixture_id', 'target_sha256']),
            )

    def test_complete_row_still_validates(self):
        by_id = hp.validate_fixtures(
            _doc([{'fixture_id': 'f1', 'target_sha256': DIGEST}]),
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
