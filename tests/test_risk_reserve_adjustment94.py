"""Byte admission and arithmetic controls for the RE-007 reserve path."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT/'research/work-items/RE-007-risk-reserve-adjustment-94'
spec = importlib.util.spec_from_file_location('reserve_packet94', PACKET/'verify.py')
packet = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packet)


class RiskReserveAdjustment94Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT/'artifacts/node/94/hl-node').read_bytes()
        cls.elf = packet.Elf(cls.data)

    def changed(self, va, offset=0):
        data = bytearray(self.data)
        data[self.elf.off(va)+offset] ^= 1
        return data

    def test_authenticated_regeneration(self):
        actual = packet.build(self.data)
        self.assertEqual(actual, json.loads((PACKET/'evidence.json').read_text()))
        self.assertEqual(packet.packet_samples(), json.loads((PACKET/'samples.json').read_text()))
        self.assertEqual(sum(f['length'] for f in actual['functions']), 999)
        self.assertEqual(len(actual['calls']), 8)
        self.assertEqual(len(actual['branches']), 24)

    def test_digest_and_all_branch_corruptions(self):
        data = self.changed(0x3708bf0)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            packet.build(data)
        # structural() deliberately omits only the whole-file SHA, so the
        # negative control cannot pass by rebinding a changed input digest.
        baseline = json.loads((PACKET/'evidence.json').read_text())
        for branch in baseline['branches']:
            with self.subTest(branch=branch['site']):
                with self.assertRaises(ValueError):
                    packet.structural(self.changed(int(branch['site'], 16)))

    def test_float_integer_and_predicate_byte_corruptions(self):
        sites = (0x3708d5e, 0x3708d61, 0x3708d66, 0x3708d6e, 0x3708d80,
                 0x3708d86, 0x3708d90, 0x3708d9c, 0x3708da6, 0x3708dab,
                 0x3708db3, 0x3708db9, 0x3708dbd, 0x3708dc4, 0x3708dd0,
                 0x21bc862, 0x21bc870, *packet.CONSTANTS)
        for site in sites:
            with self.subTest(site=hex(site)):
                with self.assertRaises(ValueError):
                    packet.structural(self.changed(site))
        # SIMD MOVD clears twelve high bytes. A nonzero rodata tail would make
        # a nominal matching 20-byte address fail; it must be authenticated.
        with self.assertRaisesRegex(ValueError, 'zero tail'):
            packet.structural(self.changed(0x203680, 4))

    def test_fde_cie_location_and_relocation_corruptions(self):
        frozen = packet.frozen_decode()
        for f in frozen:
            for key in ('fde', 'cie'):
                with self.subTest(kind=key, start=f['start']):
                    with self.assertRaises(ValueError):
                        packet.structural(self.changed(int(f[key], 16), 8))
        for va in packet.LOCATIONS:
            with self.subTest(location=hex(va)):
                with self.assertRaises(ValueError):
                    packet.structural(self.changed(va, 16))
        sec = next(s for s in packet.sections(self.data) if s['name'] == '.rela.dyn')
        for slot in packet.SLOTS:
            offsets = [off for off in range(sec['offset'], sec['offset']+sec['size'], 24)
                       if struct.unpack_from('<Q', self.data, off)[0] == slot]
            self.assertEqual(len(offsets), 1)
            data = bytearray(self.data)
            data[offsets[0]+16] ^= 1
            with self.subTest(slot=hex(slot)):
                with self.assertRaises(ValueError):
                    packet.structural(data)

    def test_decoder_transcript_has_separate_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            raw = bytearray((PACKET/'decode.json').read_bytes())
            raw[-2] ^= 1
            (target/'decode.json').write_bytes(raw)
            with patch.object(packet, 'HERE', target):
                with self.assertRaisesRegex(ValueError, 'decoder transcript'):
                    packet.frozen_decode()

    def test_independent_rational_rounding_and_wrong_integer_variant(self):
        rows = packet.samples()['binary64_scaling']
        self.assertEqual(len(rows), 1300)
        wrong = [r for r in rows if r['adjustment'] != min(packet.HIGH, r['exact_101_over_100'])]
        self.assertEqual(len(wrong), 66)
        self.assertEqual(packet.rational_reserve(2**52), 4548635623644201)
        self.assertEqual((2**52)*101//100, 4548635623644200)
        self.assertEqual(packet.rational_reserve(packet.HIGH), packet.HIGH)
        # Conversion is ties-to-even before multiplication. Adjacent integers
        # can collapse to the same binary64 value above 2**53.
        self.assertEqual(packet.rational_reserve(2**53), packet.rational_reserve(2**53+1))

    def test_error_precedence_skips_saturation_and_return_flag(self):
        m = packet.model
        self.assertEqual(m(1000, 100, 100)['amount'], 799)
        self.assertEqual(m(0, 0, 1)['amount'], -1)
        self.assertEqual(m(100, -1, -1)['status'], 'requirement_unwrap_error')
        self.assertEqual(m(100, 1, -1)['status'], 'reserve_unwrap_error')
        self.assertEqual(m(100, 1, -1, exempt=True)['amount'], 99)
        self.assertEqual(m(100, 1, -1, found=False)['amount'], 99)
        both = m(packet.LOW, packet.HIGH, packet.HIGH, row_word=7)
        self.assertEqual(both['amount'], packet.LOW)
        self.assertEqual(both['recorder_events'], ['first_subtraction', 'second_subtraction'])
        self.assertEqual(both['flag'], 1)
        self.assertEqual(m(0, 0, row_word=0)['flag'], 0)
        for bad in (packet.LOW-1, packet.HIGH+1):
            with self.assertRaises(ValueError):
                m(bad, 0)
        with self.assertRaises(ValueError):
            packet.rational_reserve(-1)


if __name__ == '__main__':
    unittest.main()
