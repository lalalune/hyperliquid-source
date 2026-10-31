import copy
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import harness_plan as hp


ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-003-harness-design'


class FixturesDocTypeTests(unittest.TestCase):
    def setUp(self):
        self.protocol = hp.load_json(PACKET / 'protocol.json')
        self.fixtures_doc = hp.load_json(PACKET / 'fixture-identities.json')

    def test_non_dict_fixtures_doc_rejected(self):
        # On base, a non-dict fixtures document escapes as AttributeError
        # from the first fixtures_doc.get() call instead of the ValueError
        # every other malformed fixture-document shape raises.
        for bad in ([], 'x', 5, None):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(ValueError):
                    hp.validate_fixtures(bad, self.protocol)

    def test_dict_fixtures_doc_still_validates(self):
        by_id = hp.validate_fixtures(
            copy.deepcopy(self.fixtures_doc), self.protocol
        )
        self.assertIn('syn-94-pos-equal-window-v1', by_id)

    def test_dict_fixtures_doc_wrong_task_id_still_rejected(self):
        doc = copy.deepcopy(self.fixtures_doc)
        doc['task_id'] = 'RE-002'
        with self.assertRaises(ValueError):
            hp.validate_fixtures(doc, self.protocol)


if __name__ == '__main__':
    unittest.main()
