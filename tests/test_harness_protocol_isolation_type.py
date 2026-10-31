"""Non-dict isolation in harness_plan validate_protocol must fail closed."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))

import harness_plan as hp


def base_protocol():
    return {
        'schema_version': 1,
        'task_id': 'RE-003',
        'execution_default': 'denied',
        'requires_execution_approval': True,
        'isolation': {'network': 'deny'},
        'fixture_identity_fields': ['fixture_id', 'target_sha256'],
        'positive_controls': ['p'],
        'negative_controls': ['n'],
        'request_fields': list(hp.REQUIRED_REQUEST_FIELDS),
        'acceptance_checklist': ['a'],
    }


class ProtocolIsolationTypeTests(unittest.TestCase):
    def test_non_dict_isolation_rejected(self):
        for isolation in ('deny', ['deny'], 0, None):
            with self.subTest(isolation=isolation):
                protocol = base_protocol()
                protocol['isolation'] = isolation
                with self.assertRaisesRegex(ValueError, 'isolation must be a dict'):
                    hp.validate_protocol(protocol)

    def test_dict_isolation_still_validates(self):
        hp.validate_protocol(base_protocol())

    def test_dict_isolation_wrong_network_still_rejected(self):
        protocol = base_protocol()
        protocol['isolation'] = {'network': 'allow'}
        with self.assertRaisesRegex(
            ValueError, 'isolation.network must default to deny'
        ):
            hp.validate_protocol(protocol)


if __name__ == '__main__':
    unittest.main()
