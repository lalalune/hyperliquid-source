"""Verify the cold set trace against the authenticated capture."""
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import node115_cold_set_static as cold


class ColdSetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.target = (ROOT / 'artifacts/node/115/hl-node').read_bytes()

    def test_regenerate_records(self):
        packet = ROOT / 'research/work-items/RE-015-node115-cold-set-allocation'
        self.assertEqual(cold.extract(self.target), json.loads((packet / 'records.json').read_bytes()))

    def test_changed_gate_count_or_empty_path_rejected(self):
        changes = {0x474bc82: 2, 0x4743b66: 0x85, 0x4743b1b: 0}
        for address, value in changes.items():
            with self.subTest(address=hex(address)):
                offset, original = cold.read(self.target, address, 1)
                self.assertNotEqual(original[0], value)
                mutant = bytearray(self.target)
                mutant[offset] = value
                with self.assertRaisesRegex(ValueError, 'Unexpected bytes'):
                    cold.trace_cold_path(mutant)


if __name__ == '__main__':
    unittest.main()
