"""Target-grounded controls for the static foundation packet (no node execution)."""
import json
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_days_seconds as seconds
from elf_index import sections


class DaysToSecondsEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not seconds.TARGET.is_file() or seconds.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        # Authenticate once; structural mutation controls intentionally bypass
        # the identity gate so each downstream evidence check is exercised.
        cls.result = seconds.inspect(seconds.TARGET)
        cls.data = seconds.TARGET.read_bytes()
        cls.sections = sections(cls.data)

    def offset(self, va):
        s = next(s for s in self.sections if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        return s['offset'] + va - s['address']

    def mutated(self, va, raw):
        data = bytearray(self.data)
        off = self.offset(va)
        data[off:off + len(raw)] = raw
        return data

    def rela_entry_offset(self, address):
        rel = next(s for s in self.sections if s['name'] == '.rela.dyn')
        raw = self.data[rel['offset']:rel['offset'] + rel['size']]
        for off in range(0, len(raw), 24):
            entry, _info, _addend = struct.unpack_from('<QQq', raw, off)
            if entry == address:
                return rel['offset'] + off + 16
        raise AssertionError('Rela entry not found')

    def test_retained_record_matches_authenticated_target(self):
        record = seconds.ROOT / 'research/work-items/foundation-days-seconds-94/evidence.json'
        self.assertEqual(self.result, json.loads(record.read_text()))

    def test_checked_arithmetic_from_decoded_constants(self):
        arithmetic = self.result['arithmetic']
        self.assertEqual(arithmetic['seconds_per_day'], 86400)
        self.assertEqual(arithmetic['imul_overflow_arm'], '0x1518ccc')
        self.assertEqual(arithmetic['add_overflow_arm'], '0x1518cd9')
        self.assertEqual(arithmetic['imul_overflow_target'], '0x157b4a0')
        self.assertEqual(arithmetic['add_overflow_target'], '0x157b480')
        # The two overflow arms are distinct call targets reached by distinct
        # signed-overflow branches; both arms load the same argument value.
        self.assertNotEqual(arithmetic['imul_overflow_target'], arithmetic['add_overflow_target'])
        self.assertEqual(arithmetic['shared_arm_argument'], '0x5671988')
        self.assertEqual(arithmetic['first_callee'], '0x15183e0')
        self.assertEqual(arithmetic['second_callee'], '0x1518230')

    def test_fde_extent_is_not_the_index_stride(self):
        function = self.result['function']
        self.assertEqual(function['fde_bytes'], 70)
        self.assertEqual(function['index_stride_bytes'], 80)
        self.assertEqual(function['fde_end_va_exclusive'], '0x1518ce6')
        self.assertEqual(function['index_stride_end_va_exclusive'], '0x1518cf0')

    def test_identity_rejects_mutation(self):
        eh = next(s for s in self.sections if s['name'] == '.eh_frame')
        fde_range_va = eh['address'] + 0x148e8 + 12
        cases = {
            'multiplier byte': (0x1518cba, b'\x81'),
            'imul overflow branch byte': (0x1518cbf, b'\x0d'),
            'add overflow branch byte': (0x1518cc4, b'\x15'),
            'fde range byte': (fde_range_va, b'\x47'),
            'relocated slot bytes': (0x576e1b0, b'\x01'),
            'first callee call displacement': (0x1518ca9, b'\x34'),
            'imul-arm call slot displacement': (0x1518cd5, b'\xd8'),
            'fde padding byte': (0x1518ce6, b'\x90'),
            'incoming call byte': (0x1517e44, b'\x59'),
        }
        for name, (va, raw) in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(ValueError):
                    seconds.analyze(self.mutated(va, raw))

    def test_identity_rejects_relocation_addend_mutation(self):
        data = bytearray(self.data)
        off = self.rela_entry_offset(0x576e1b0)
        data[off:off + 8] = struct.pack('<q', 0x157b4a1)
        with self.assertRaises(ValueError):
            seconds.analyze(data)

    def test_incoming_call_pattern_is_exactly_two_sites(self):
        scan = self.result['incoming_pattern_scan']
        self.assertEqual(scan['e8_candidates'], ['0x1517e43', '0x1517eb5'])
        self.assertFalse(scan['complete_xref_census'])


if __name__ == '__main__':
    unittest.main()
