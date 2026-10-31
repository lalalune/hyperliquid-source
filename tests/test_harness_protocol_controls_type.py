import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import harness_plan as hp


ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-003-harness-design'


class ProtocolControlsTypeTests(unittest.TestCase):
    def _protocol(self, **overrides):
        protocol = hp.load_json(PACKET / 'protocol.json')
        protocol.update(overrides)
        return protocol

    def test_non_list_positive_controls_rejected(self):
        for bad in (5, {'id': 'pos-equal-window'}, 'pos-equal-window', None):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    hp.validate_protocol(self._protocol(positive_controls=bad))

    def test_non_list_negative_controls_rejected(self):
        for bad in (7, {'id': 'neg-corrupt-byte'}, 'neg-corrupt-byte', None):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    hp.validate_protocol(self._protocol(negative_controls=bad))

    def test_empty_controls_still_rejected(self):
        with self.assertRaises(ValueError):
            hp.validate_protocol(self._protocol(positive_controls=[]))
        with self.assertRaises(ValueError):
            hp.validate_protocol(self._protocol(negative_controls=[]))

    def test_real_packet_still_validates(self):
        hp.validate_protocol(hp.load_json(PACKET / 'protocol.json'))


if __name__ == '__main__':
    unittest.main()
