"""Target-grounded bindings and complete reciprocal certificates, without execution."""
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import cumulative_minute_static as minute


@unittest.skipUnless(minute.TARGET.stat().st_size == 91774280, 'materialize node94')
class CumulativeMinuteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = minute.TARGET.read_bytes()
        cls.spec = json.loads((minute.PACKET / 'selected-windows.json').read_text())
        cls.report = minute.analyze(cls.data)

    def test_actual_ranges_conversions_and_source(self):
        self.assertEqual(len(self.report['ranges']), 8)
        self.assertEqual(sum(r['bytes'] for r in self.report['ranges']), 36214)
        self.assertEqual(len(self.report['conversions']), 14)
        self.assertEqual(self.report['source_location']['line'], 21)
        self.assertEqual(self.report['diagnostic']['literal'], 'assertion failed: cumin <= 1440')
        self.assertFalse(self.report['captured_binary_executed'])

    def test_complete_division_certificates_against_independent_integer_division(self):
        for proof in self.report['division_proofs']:
            c, k, d, maximum = int(proof['multiplier'], 16), proof['shift'], proof['divisor'], proof['maximum_input']
            for r in range(d):
                # Greatest quotient in each remainder class exercises the
                # certificate's extremum, rather than sampled pseudo-randoms.
                n = ((maximum - r) // d) * d + r
                self.assertEqual((n * c) >> k, n // d)
            for bad_c, bad_k in [(c - 1, k), (c, k + 1)]:
                with self.assertRaises(ValueError):
                    minute.prove_division(bad_c, bad_k, d, maximum)

    def test_local_guard_boundaries_and_valid_day_seconds(self):
        def observed_expression(n):
            h = (n * 0x91a2b3c5) >> 43
            m = (n * 0x88888889) >> 37
            return 60 * h + m - 60 * ((m * 0x08888889) >> 33)
        for n in range(86460):
            self.assertEqual(observed_expression(n), n // 60)
        self.assertEqual(observed_expression(86399), 1439)
        self.assertEqual(observed_expression(86400), 1440)
        self.assertEqual(observed_expression(86459), 1440)
        self.assertEqual(observed_expression(86460), 1441)
        self.assertEqual(observed_expression(3932159), 65535)
        self.assertEqual(observed_expression(3932160), 65536)
        self.assertEqual(observed_expression((1 << 32) - 1), ((1 << 32) - 1) // 60)
        self.assertEqual(self.report['local_raw_u32_domains']['both_guards_pass'], [0, 86459])

    def test_actual_byte_corruptions_below_admission_hash_are_rejected(self):
        controls = [0x21adef, 0x1e3851, 0x566cb60]
        for row in self.spec:
            controls.append(int(row['panic'], 16) + 3)
            for block in row['blocks']:
                va, raw = int(block['start'], 16), bytes.fromhex(block['body_hex'])
                controls += [va + raw.index(bytes.fromhex('c5b3a291')), va + len(raw) - 5]
        self.assertEqual(len(controls), 39)
        for va in controls:
            with self.subTest(va=hex(va)):
                changed = bytearray(self.data)
                off, _ = minute.read(changed, va, 1)
                changed[off] ^= 1
                with self.assertRaises(ValueError):
                    minute.analyze(changed)

    @unittest.skipUnless(shutil.which('readelf') and shutil.which('objdump'), 'GNU binutils required')
    def test_native_regeneration_preserves_packet(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            self.assertEqual(minute.generate(minute.TARGET, out), self.report)
            for name in ['frames.txt', 'records.json'] + [f'{a:x}.objdump.txt' for a, _ in minute.RANGES]:
                self.assertEqual((out / name).read_bytes(), (minute.PACKET / name).read_bytes(), name)


if __name__ == '__main__':
    unittest.main()
