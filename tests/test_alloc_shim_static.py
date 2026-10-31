"""Target-grounded controls for the static allocator shim packet (no node execution)."""
import json
import sys
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import alloc_shim_static as ash


class AllocShimEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not ash.TARGET.is_file() or ash.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        cls.result = ash.inspect(ash.TARGET)

    def test_retained_record_matches_authenticated_target(self):
        record = ash.ROOT / 'research/work-items/RE-001-alloc-shim-94/evidence.json'
        self.assertEqual(self.result, json.loads(record.read_text()))

    def test_aligned_bytes_identity(self):
        # ceil-to-alignment times element size, matching the decoded mask math.
        for align in (1, 2, 4, 8, 16, 32):
            self.assertEqual(align & (align - 1), 0)
            for capacity in (0, 1, 2, 3, 5, 8, 15, 16, 17, 100, 4096):
                for size in (1, 8, 24):
                    got = ash.aligned_bytes(align, capacity, size)
                    expected = -(-capacity // align) * align * size if capacity else 0
                    self.assertEqual(got, expected)

    def test_dispatch_four_paths(self):
        dispatch = self.result['dispatch']
        self.assertEqual(len(dispatch), 4)
        targets = [int(d['target'], 16) for d in dispatch]
        self.assertIn(0x54c06b0, targets)   # shared alloc entry
        self.assertIn(0x54c5610, targets)   # aligned grow

    def test_census(self):
        census = self.result['call_census']
        self.assertEqual(census['direct_sites'], 253)
        self.assertEqual(census['got_indirect'], 0)
        self.assertEqual(census['lea_refs'], 0)
        self.assertEqual(census['growth_caller'], '0x454e5e5')
        self.assertEqual(len(ash.CALLERS), 253)

    def test_error_codes(self):
        self.assertEqual(self.result['error_codes'], {'overflow': 8, 'success': 16})

    def test_mutation_control_body(self):
        mutated = bytearray(ash.BODY)
        mutated[40] ^= 0xFF
        with unittest.mock.patch.object(ash, 'BODY', bytes(mutated)):
            with self.assertRaises(ValueError):
                ash.analyze(ash.TARGET.read_bytes())


if __name__ == '__main__':
    unittest.main()
