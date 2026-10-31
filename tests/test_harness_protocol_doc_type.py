"""harness_plan must reject a non-dict protocol document with ValueError.

Sibling of open #490 (non-dict fixtures document) in the same packet
flow: validate_protocol() runs its missing-fields membership test and
then .get() calls with no document-type gate, so an int/None protocol
document escapes as TypeError and a list holding all required field
names escapes as AttributeError, instead of the ValueError every other
malformed protocol shape raises.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import harness_plan as hp


ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-003-harness-design'

REQUIRED = [
    'schema_version',
    'task_id',
    'execution_default',
    'requires_execution_approval',
    'isolation',
    'fixture_identity_fields',
    'positive_controls',
    'negative_controls',
    'request_fields',
    'acceptance_checklist',
]


class ProtocolDocTypeTests(unittest.TestCase):
    def test_int_protocol_rejected(self):
        with self.assertRaisesRegex(ValueError, 'protocol.json must be a mapping'):
            hp.validate_protocol(5)

    def test_none_protocol_rejected(self):
        with self.assertRaisesRegex(ValueError, 'protocol.json must be a mapping'):
            hp.validate_protocol(None)

    def test_list_holding_required_keys_rejected(self):
        with self.assertRaisesRegex(ValueError, 'protocol.json must be a mapping'):
            hp.validate_protocol(list(REQUIRED))

    def test_real_protocol_still_validates(self):
        protocol = hp.load_json(PACKET / 'protocol.json')
        hp.validate_protocol(protocol)

    def test_dict_missing_fields_still_rejected(self):
        with self.assertRaisesRegex(ValueError, 'protocol.json missing fields'):
            hp.validate_protocol({})


if __name__ == '__main__':
    unittest.main()
