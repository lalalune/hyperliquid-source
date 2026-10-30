"""Target-grounded controls for the static foundation packet (no node execution)."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_secs_f64 as secs
from elf_index import sections


class SecsF64EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not secs.TARGET.is_file() or secs.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        # Authenticate once; structural mutation controls intentionally bypass
        # the identity gate so each downstream evidence check is exercised.
        cls.result = secs.inspect(secs.TARGET)
        cls.data = secs.TARGET.read_bytes()
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
        record = secs.ROOT / 'research/work-items/foundation-secs-f64-94/evidence.json'
        self.assertEqual(self.result, json.loads(record.read_text()))

    def test_arithmetic_from_decoded_constants(self):
        arithmetic = self.result['arithmetic']
        self.assertEqual(arithmetic['seconds_scale'], 1000000)
        self.assertEqual(arithmetic['sub_divisor'], 1000)
        self.assertEqual(arithmetic['result_divisor'], 1000000.0)
        # The magic division is truncating division by 1000, not an assumption.
        for value in (0, 1, -1, 999, 1000, -1000, 1500, -1500, 2147483647, -2147483648):
            import math
            self.assertEqual(secs.trunc_div_1000(value), math.trunc(value / 1000))
        # Borrow normalization: a negative whole field with a positive
        # sub-second field is exactly the -0.5s pair (-1, 500000000).
        self.assertEqual(secs.window_result(-1, 500000000), -0.5)
        self.assertEqual(secs.window_result(2, 1500), 2.000001)
        # Both integer overflow paths return +0.0, not saturation or NaN.
        self.assertEqual(secs.window_result(9223372036855, 0), 0.0)
        self.assertEqual(secs.window_result(9223372036854, 2147483647), 0.0)

    def test_fde_extent_is_not_the_index_stride(self):
        function = self.result['function']
        self.assertEqual(function['fde_bytes'], 115)
        self.assertEqual(function['index_stride_bytes'], 128)
        self.assertEqual(function['fde_end_va_exclusive'], '0x1450ad3')
        self.assertEqual(function['index_stride_end_va_exclusive'], '0x1450ae0')

    def test_identity_rejects_mutation(self):
        eh = next(s for s in self.sections if s['name'] == '.eh_frame')
        fde_range_va = eh['address'] + 0xad24 + 12
        cases = {
            'scale byte': (0x1450a7f, b'\x41'),
            'borrow byte': (0x1450a8b, b'\x01'),
            'magic byte': (0x1450a9b, b'\xd4'),
            'fde range byte': (fde_range_va, b'\x74'),
            'divisor byte': (0x20ae60, b'\x01'),
            'mask byte': (0x202ed0, b'\x00'),
            'relocated slot bytes': (0x576eaa0, b'\x01'),
            'helper call displacement': (0x1450a63, b'\x3a'),
            'incoming call displacement': (0x44ab1b4, b'\x11'),
            'fde padding byte': (0x1450ad3, b'\x90'),
        }
        for name, (va, raw) in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(ValueError):
                    secs.analyze(self.mutated(va, raw))

    def test_identity_rejects_truncation(self):
        with self.assertRaises(Exception):
            secs.analyze(self.data[:1000])

    def test_retained_disassembly_and_frames(self):
        packet = secs.ROOT / 'research/work-items/foundation-secs-f64-94'
        disassembly = (packet / 'window.objdump.txt').read_text()
        self.assertIn('1450a7c:\t48 69 c6 40 42 0f 00 \timul   $0xf4240', disassembly)
        self.assertIn('1450ac1:\tf2 0f 5e 05', disassembly)
        caller = (packet / 'caller.objdump.txt').read_text()
        self.assertIn('44ab1b2:\tff 15 10 45 2c 01', caller)
        frames = (packet / 'window.frames.txt').read_text()
        self.assertIn('pc=0000000001450a60..0000000001450ad3', frames)
        self.assertIn('pc=000000000151d1b0..000000000151d33f', frames)
        self.assertIn('pc=00000000044aa5a0..00000000044ab55b', frames)

    def test_cli_check_passes(self):
        packet = secs.ROOT / 'research/work-items/foundation-secs-f64-94'
        proc = subprocess.run(
            [sys.executable, str(secs.ROOT / 'tools/foundation_secs_f64.py'),
             '--check', str(packet / 'evidence.json')],
            capture_output=True, text=True, check=False)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('Foundation seconds-as-f64 evidence reproduces exactly.', proc.stdout)


if __name__ == '__main__':
    unittest.main()
