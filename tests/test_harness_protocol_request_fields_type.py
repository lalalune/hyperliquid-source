import copy
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import harness_plan as hp


ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-003-harness-design'


class RequestFieldsTypeTests(unittest.TestCase):
    def setUp(self):
        self.protocol = hp.load_json(PACKET / 'protocol.json')

    def test_non_iterable_request_fields_rejected(self):
        # On base, an int/null request_fields escapes as TypeError from the
        # `field not in protocol['request_fields']` membership test instead
        # of the ValueError every other malformed protocol shape raises.
        for bad in (5, None):
            with self.subTest(bad=bad):
                protocol = copy.deepcopy(self.protocol)
                protocol['request_fields'] = bad
                with self.assertRaises(ValueError):
                    hp.validate_protocol(protocol)

    def test_non_list_request_fields_rejected(self):
        # A string naming every required field as substrings, or a dict
        # keyed by them, silently passes the membership loop on base even
        # though request_fields is a list of field names in the real packet.
        for bad in (
            ''.join(hp.REQUIRED_REQUEST_FIELDS),
            {field: True for field in hp.REQUIRED_REQUEST_FIELDS},
        ):
            with self.subTest(bad=type(bad).__name__):
                protocol = copy.deepcopy(self.protocol)
                protocol['request_fields'] = bad
                with self.assertRaises(ValueError):
                    hp.validate_protocol(protocol)

    def test_list_request_fields_still_validates(self):
        hp.validate_protocol(self.protocol)

    def test_list_request_fields_missing_field_still_rejected(self):
        protocol = copy.deepcopy(self.protocol)
        protocol['request_fields'] = [
            field for field in protocol['request_fields'] if field != 'network'
        ]
        with self.assertRaises(ValueError):
            hp.validate_protocol(protocol)


if __name__ == '__main__':
    unittest.main()
