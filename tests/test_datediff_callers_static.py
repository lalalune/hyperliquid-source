"""Target-grounded controls for the static datediff callers packet (no node execution)."""
import json
import struct
import sys
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import datediff_callers_static as dc
from elf_index import sections


class DateDiffCallersEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not dc.TARGET.is_file() or dc.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        cls.result = dc.inspect(dc.TARGET)
        cls.data = dc.TARGET.read_bytes()
        cls.sections = sections(cls.data)

    def test_retained_record_matches_authenticated_target(self):
        record = dc.ROOT / 'research/work-items/RE-001-datediff-callers-94/evidence.json'
        self.assertEqual(self.result, json.loads(record.read_text()))

    def test_wrapper_anchors(self):
        anchors = self.result['structure']['immediates']
        self.assertEqual(anchors['micros_per_second'], 1000000)
        self.assertEqual(anchors['nanos_per_second'], 1000000000)
        self.assertEqual(anchors['div1000_magic'], '0x10624dd3')
        self.assertEqual(anchors['div1000_shift'], 38)
        self.assertEqual(self.result['wrapper']['bytes'], 115)

    def test_shared_anchors(self):
        shared = self.result['shared_anchors']
        self.assertEqual(shared['one_e6_double'], '0x20ae60')
        self.assertEqual(shared['datediff_core'], '0x151d1b0')
        self.assertEqual(shared['datediff_got'], '0x576eaa0')

    def test_div1000_trunc_identity(self):
        # The decoded sequence is truncating division by 1000 for the signed
        # nanosecond remainder domain (-1e9, 1e9).
        for x in (-1000000000, -999999999, -1500, -1000, -999, -1,
                  0, 1, 999, 1000, 1500, 999999999, 1000000000):
            q = dc.div1000_quotient(x)
            expected = (-(-x // 1000)) if x < 0 else x // 1000
            self.assertEqual(q, expected, f'x={x}')

    def test_giant_scope(self):
        giant = self.result['giant']
        self.assertEqual(giant['bytes'], 0x13d0892 - 0x13cec80)
        self.assertEqual(giant['datediff_call_offset'], '0x1141')
        self.assertIn('stays unbound', giant['scope'])

    def test_census_single_callers(self):
        census = self.result['call_census']
        self.assertEqual(census['wrapper']['got_indirect'], ['0x44ab1b2'])
        self.assertEqual(census['wrapper']['direct_e8'], 0)
        self.assertEqual(census['giant']['got_indirect'], ['0x1400e4f'])
        self.assertEqual(census['giant']['direct_e8'], 0)
        # Both call sites stay inside their recorded caller FDEs.
        self.assertTrue(dc.CALLER_FN[0] <= dc.WRAP_CALLER < dc.CALLER_FN[1])
        self.assertTrue(dc.GIANT_CALLER_FN[0] <= dc.GIANT_CALLER < dc.GIANT_CALLER_FN[1])

    def test_mutation_control_wrapper_body(self):
        mutated = bytearray(dc.WRAP_BODY)
        mutated[40] ^= 0xFF
        with unittest.mock.patch.object(dc, 'WRAP_BODY', bytes(mutated)):
            with self.assertRaises(ValueError):
                dc.analyze(self.data)

    def test_mutation_control_giant_site(self):
        # Flip one byte of the giant's datediff call site in the raw image.
        matches = [s for s in self.sections if s['type'] != 8
                   and s['address'] <= dc.GIANT_START < s['address'] + s['size']]
        s = matches[0]
        off = s['offset'] + dc.GIANT_START + dc.GIANT_CALL_OFFSET - s['address']
        data = bytearray(self.data)
        data[off + 5] ^= 0x01
        with self.assertRaises(ValueError):
            dc.analyze(bytes(data))


if __name__ == '__main__':
    unittest.main()
