"""Target-grounded controls for the static 24-byte growth helper packet (no node execution)."""
import json
import sys
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import grow24_static as g24


class Grow24EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not g24.TARGET.is_file() or g24.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        cls.result = g24.inspect(g24.TARGET)

    def test_retained_record_matches_authenticated_target(self):
        record = g24.ROOT / 'research/work-items/RE-001-grow24-94/evidence.json'
        self.assertEqual(self.result, json.loads(record.read_text()))

    def test_capacity_and_stride_identities(self):
        for current in (0, 1, 2, 3, 4, 5, 100):
            self.assertEqual(max(current * 2, 4),
                             current * 2 if current * 2 >= 5 else 4)
        self.assertEqual(g24.STRIDE, g24.ELEMENT_SIZE * 3)

    def test_three_got_slots(self):
        self.assertEqual(g24.GOT_SLOTS, [0x576ea38, 0x57705a8, 0x5776410])
        census = self.result['call_census']
        self.assertEqual(census['got_slots'], 3)
        self.assertEqual(census['got_indirect_sites'], 63)
        self.assertEqual(census['entrypoint_site'], '0x4edcfd3')

    def test_sibling_link(self):
        self.assertEqual(self.result['cross_links']['sibling_helper'],
                         '0x454e5b0 (RE-001-crossroads-callees-94)')

    def test_mutation_control_body(self):
        mutated = bytearray(g24.BODY)
        mutated[50] ^= 0xFF
        with unittest.mock.patch.object(g24, 'BODY', bytes(mutated)):
            with self.assertRaises(ValueError):
                g24.analyze(g24.TARGET.read_bytes())


if __name__ == '__main__':
    unittest.main()
