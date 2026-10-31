"""Target-grounded controls for the static build-mode initializer packet (no node execution)."""
import json
import sys
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import build_mode_init_static as bm


class BuildModeInitEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not bm.TARGET.is_file() or bm.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        cls.result = bm.inspect(bm.TARGET)

    def test_retained_record_matches_authenticated_target(self):
        record = bm.ROOT / 'research/work-items/RE-001-build-mode-init-94/evidence.json'
        self.assertEqual(self.result, json.loads(record.read_text()))

    def test_project_source_anchor(self):
        anchors = self.result['project_anchors']
        self.assertEqual(anchors['source_file'], 'hl/code_Mainnet/base/src/build_mode.rs')
        self.assertEqual(anchors['assertion']['message'], "assertion failed: !arg.ends_with('/')")
        self.assertEqual(anchors['assertion']['location'], 'build_mode.rs:29:17')
        self.assertEqual(anchors['error_path']['location'], 'build_mode.rs:32:26')
        self.assertEqual(anchors['prefix'], '/cham/')

    def test_memchr_no_false_negative(self):
        # Every word containing 0x2f must be flagged by the decoded predicate.
        for shift in range(8):
            word = (0x6161616161616161 & ~(0xFF << (8 * shift))) | (0x2f << (8 * shift))
            self.assertFalse(bm.memchr_flag(word), f'needle at byte {shift} missed')
        # Clean ASCII words pass through.
        for word in (0x6161616161616161, 0x2f2f * 0x0001000100010001 ^ 0x2f2f2f2f2f2f2f2f):
            if not bm.contains_byte(word):
                self.assertTrue(bm.memchr_flag(word))

    def test_memchr_locations(self):
        locs = self.result['memchr']['locations']
        self.assertEqual(sorted(locs),
                         ['core/src/slice/memchr.rs:132:30', 'core/src/slice/memchr.rs:160:9'])
        self.assertEqual(bm.MEMCHR_LOCS, [(0x5674908, 160, 9), (0x5674920, 132, 30)])

    def test_reachability_cell_only(self):
        self.assertEqual(self.result['reachability'],
                         'cell initializer slot only; zero code references')
        self.assertEqual(self.result['initializer']['cell'], '0x577ab80')

    def test_mutation_control_body(self):
        mutated = bytearray(bm.BODY)
        mutated[700] ^= 0xFF
        with unittest.mock.patch.object(bm, 'BODY', bytes(mutated)):
            with self.assertRaises(ValueError):
                bm.analyze(bm.TARGET.read_bytes())


if __name__ == '__main__':
    unittest.main()
