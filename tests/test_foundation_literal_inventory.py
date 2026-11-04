'''Run the node #115 RE-015 literal inventory checker against saved evidence.'''
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools/foundation_literal_inventory.py'
PACKET = ROOT / 'research/work-items/RE-015-node115-literal-inventory'


def load_tool():
    spec = importlib.util.spec_from_file_location('foundation_literal_inventory', TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class LiteralInventoryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load_tool()
        cls.derived = cls.tool.derive()

    def test_evidence_matches_pinned_bytes(self):
        recorded = self.tool.load_evidence()
        self.assertEqual([], self.tool.compare(recorded, self.derived))

    def test_literal_identity_and_count(self):
        literal = self.derived['literal']
        self.assertEqual('hl-node', literal['token'])
        self.assertEqual('686c2d6e6f6465', literal['token_hex'])
        self.assertEqual(7, literal['length'])
        self.assertEqual(5, literal['occurrences'])

    def test_printed_occurrences_are_rodata_without_relative_slot(self):
        printed = self.derived['literal']['printed_occurrences']
        self.assertEqual(3, len(printed))
        for record in printed:
            self.assertEqual('.rodata', record['section'])
            self.assertEqual('686c2d6e6f6465', record['bytes_hex'])
            self.assertEqual(0, record['relative_slots'])

    def test_packet_files_exist(self):
        for name in ('README.md', 'evidence.json', 'frames.txt',
                     'rodata-window.txt', 'section-table.txt'):
            self.assertTrue((PACKET / name).is_file(), name)

    def test_corruption_controls_are_rejected(self):
        self.assertGreaterEqual(self.tool.run_controls(self.derived), 8)


if __name__ == '__main__':
    unittest.main()
