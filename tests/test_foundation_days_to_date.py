"""Target-grounded controls for the static foundation packet (no node execution)."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_days_to_date as days
from elf_index import sections


class DaysToDateEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not days.TARGET.is_file() or days.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        # Authenticate once; structural mutation controls intentionally bypass
        # the identity gate so each downstream evidence check is exercised.
        cls.result = days.inspect(days.TARGET)
        cls.data = days.TARGET.read_bytes()
        cls.sections = sections(cls.data)

    def offset(self, va):
        s = next(s for s in self.sections if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        return s['offset'] + va - s['address']

    def mutated(self, va, raw):
        data = bytearray(self.data)
        off = self.offset(va)
        data[off:off + len(raw)] = raw
        return data

    def test_retained_record_matches_authenticated_target(self):
        record = days.ROOT / 'research/work-items/foundation-days-to-date-94/evidence.json'
        self.assertEqual(self.result, json.loads(record.read_text()))

    def test_threshold_arithmetic_from_decoded_constants(self):
        arithmetic = self.result['arithmetic']
        self.assertEqual(arithmetic['seconds_per_day'], 86400)
        self.assertEqual(arithmetic['base'], '0xffff574000000000')
        self.assertEqual(arithmetic['bound'], '0xfffeae7ffffeae81')
        self.assertEqual(arithmetic['wrap_threshold_days'], 2 ** 31)
        base = int(arithmetic['base'], 16)
        bound = int(arithmetic['bound'], 16)
        threshold = arithmetic['wrap_threshold_days']
        # Exact wrap: the gap is an exact multiple of 86400.
        self.assertEqual(((1 << 64) - base) % 86400, 0)
        self.assertEqual(((1 << 64) - base) // 86400, threshold)
        # Branch sides at the threshold, from the unsigned comparison.
        self.assertGreaterEqual((base + (threshold - 1) * 86400) % (1 << 64), bound)
        self.assertLess((base + threshold * 86400) % (1 << 64), bound)
        # The gate is exact over the whole u32 input domain.
        self.assertGreater(base, bound)
        self.assertLess((2 ** 32 - 1 - threshold) * 86400, bound)

    def test_fde_extent_is_not_the_index_stride(self):
        function = self.result['function']
        self.assertEqual(function['fde_bytes'], 75)
        self.assertEqual(function['index_stride_bytes'], 80)
        self.assertEqual(function['fde_end_va_exclusive'], '0x145085b')
        self.assertEqual(function['index_stride_end_va_exclusive'], '0x1450860')

    def test_identity_rejects_mutation(self):
        eh = next(s for s in self.sections if s['name'] == '.eh_frame')
        fde_range_va = eh['address'] + 0xac74 + 12
        cases = {
            'multiplier byte': (0x1450816, b'\x81'),
            'bound byte': (0x1450829, b'\x82'),
            'fde range byte': (fde_range_va, b'\x4c'),
            'message byte': (0x219c91, b'X'),
            'relocated slot bytes': (0x576e8b0, b'\x01'),
            'converter call displacement': (0x1450838, b'\x75'),
            'fde padding byte': (0x145085b, b'\x90'),
        }
        for name, (va, raw) in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(ValueError):
                    days.analyze(self.mutated(va, raw))

    def test_identity_rejects_truncation(self):
        with self.assertRaises(Exception):
            days.analyze(self.data[:1000])

    def test_retained_disassembly_and_frames(self):
        packet = days.ROOT / 'research/work-items/foundation-days-to-date-94'
        disassembly = (packet / 'days.objdump.txt').read_text()
        self.assertIn('1450813:\t48 69 c0 80 51 01 00 \timul   $0x15180', disassembly)
        self.assertIn('1450855:\tff 15 0d dc 31 04', disassembly)
        caller = (packet / 'caller.objdump.txt').read_text()
        self.assertIn('374430c:\tff 15 a6 b3 02 02', caller)
        self.assertIn('3744324:\tff 15 8e b3 02 02', caller)
        frames = (packet / 'days.frames.txt').read_text()
        self.assertIn('pc=0000000001450810..000000000145085b', frames)
        self.assertIn('pc=000000000151f870..000000000151fa9c', frames)
        self.assertIn('pc=0000000003744020..0000000003744547', frames)

    def test_cli_check_passes(self):
        packet = days.ROOT / 'research/work-items/foundation-days-to-date-94'
        proc = subprocess.run(
            [sys.executable, str(days.ROOT / 'tools/foundation_days_to_date.py'),
             '--check', str(packet / 'evidence.json')],
            capture_output=True, text=True, check=False)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('Foundation days-to-date evidence reproduces exactly.', proc.stdout)


if __name__ == '__main__':
    unittest.main()
