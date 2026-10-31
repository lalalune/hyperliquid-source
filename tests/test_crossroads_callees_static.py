"""Target-grounded controls for the static crossroads callees packet (no node execution)."""
import json
import sys
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import crossroads_callees_static as cx


class CrossroadsCalleesEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not cx.TARGET.is_file() or cx.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        cls.result = cx.inspect(cx.TARGET)

    def test_retained_record_matches_authenticated_target(self):
        record = cx.ROOT / 'research/work-items/RE-001-crossroads-callees-94/evidence.json'
        self.assertEqual(self.result, json.loads(record.read_text()))

    def test_cell_ships_complete(self):
        cell = self.result['cell']
        self.assertEqual(cell['shipped_state'], 3)
        self.assertEqual(cell['shipped_value'], 'two zero qwords')
        self.assertEqual(cell['initializer'], '0x143ef30')
        self.assertIn('once.rs:219:20', cell['std_location'])

    def test_capacity_identity(self):
        for current in (0, 1, 2, 3, 4, 5, 100):
            doubled = current + current
            expected = doubled if doubled >= 5 else 4
            self.assertEqual(expected, max(doubled, 4))

    def test_sizes_and_census(self):
        self.assertEqual(self.result['lazy_getter']['bytes'], 107)
        self.assertEqual(self.result['growth_helper']['bytes'], 100)
        self.assertEqual(self.result['call_census']['getter_sites'], 87)
        self.assertEqual(self.result['call_census']['growth_sites'], 8)
        self.assertEqual(self.result['growth_helper']['observed_constant'], '0x168')

    def test_mutation_control_bodies(self):
        for name, const in [('GET_BODY', cx.GET_BODY), ('GROW_BODY', cx.GROW_BODY)]:
            mutated = bytearray(const)
            mutated[len(mutated) // 2] ^= 0xFF
            with unittest.mock.patch.object(cx, name, bytes(mutated)):
                with self.assertRaises(ValueError):
                    cx.analyze(cx.TARGET.read_bytes())

    def test_mutation_control_cell_state(self):
        # Flip the shipped cell state byte in the raw image.
        data = bytearray(cx.TARGET.read_bytes())
        matches = [s for s in cx.Reader(bytes(data)).sections
                   if s['type'] != 8 and s['address'] <= cx.CELL_STATE_VA < s['address'] + s['size']]
        s = matches[0]
        off = s['offset'] + cx.CELL_STATE_VA - s['address']
        data[off:off + 4] = b'\x02\x00\x00\x00'
        with self.assertRaises(ValueError):
            cx.analyze(bytes(data))


if __name__ == '__main__':
    unittest.main()
