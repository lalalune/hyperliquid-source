"""Target-grounded controls for the static initializer entry-point packet (no node execution)."""
import json
import sys
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import init_entrypoints_static as ie


class InitEntrypointsEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not ie.TARGET.is_file() or ie.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        cls.result = ie.inspect(ie.TARGET)

    def test_retained_record_matches_authenticated_target(self):
        record = ie.ROOT / 'research/work-items/RE-001-init-entrypoints-94/evidence.json'
        self.assertEqual(self.result, json.loads(record.read_text()))

    def test_bound_identity(self):
        self.assertEqual(ie.BOUND * 3, (1 << 64) - 1)

    def test_stride_identity(self):
        self.assertEqual(ie.STRIDE, 3 * 8)

    def test_censuses(self):
        census = self.result['call_census']
        self.assertEqual(census['arg_sites'], 3)
        self.assertEqual(census['iterator_sites'], 3)
        self.assertEqual(census['initializer_sites'], ['0x143ef69', '0x143efba'])

    def test_shared_entry_points(self):
        shared = self.result['shared_entry_points']
        self.assertEqual(shared['alloc'], '0x54c06b0')
        self.assertEqual(shared['dealloc'], '0x54c8cb0')

    def test_imported_slots_have_no_relocations(self):
        self.assertEqual(ie.GOT_IMPORT, 0x576e038)
        self.assertEqual(ie.GOT_COPY, 0x576dfe0)

    def test_mutation_control_bodies(self):
        for name, const in [('ARG_BODY', ie.ARG_BODY), ('IT_BODY', ie.IT_BODY)]:
            mutated = bytearray(const)
            mutated[len(mutated) // 2] ^= 0xFF
            with unittest.mock.patch.object(ie, name, bytes(mutated)):
                with self.assertRaises(ValueError):
                    ie.analyze(ie.TARGET.read_bytes())


if __name__ == '__main__':
    unittest.main()
