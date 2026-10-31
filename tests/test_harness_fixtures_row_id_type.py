import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import harness_plan as hp


ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-003-harness-design'


class FixturesRowIdTypeTests(unittest.TestCase):
    def _doc(self, fid):
        protocol = hp.load_json(PACKET / 'protocol.json')
        real = hp.load_json(PACKET / 'fixture-identities.json')
        row = dict(real['fixtures'][0], fixture_id=fid)
        return {'task_id': 'RE-003', 'fixtures': [row]}, protocol

    def test_non_string_row_fixture_id_rejected(self):
        for bad in (['syn-94-pos-equal-window-v1'], {'id': 'x'}, 123, None):
            with self.subTest(bad=type(bad).__name__):
                doc, protocol = self._doc(bad)
                with self.assertRaises(ValueError):
                    hp.validate_fixtures(doc, protocol)

    def test_real_document_still_validates(self):
        protocol = hp.load_json(PACKET / 'protocol.json')
        fixtures = hp.validate_fixtures(
            hp.load_json(PACKET / 'fixture-identities.json'), protocol
        )
        self.assertIn('syn-94-pos-equal-window-v1', fixtures)


if __name__ == '__main__':
    unittest.main()
