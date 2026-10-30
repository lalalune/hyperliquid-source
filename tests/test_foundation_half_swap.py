"""Target-grounded controls for the static foundation packet (no node execution)."""
import json
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_half_swap as half_swap
from elf_index import sections


class HalfSwapEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not half_swap.TARGET.is_file() or half_swap.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        cls.result = half_swap.inspect(half_swap.TARGET)
        cls.data = half_swap.TARGET.read_bytes()
        cls.sections = sections(cls.data)

    def offset(self, va):
        s = next(s for s in self.sections if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        return s['offset'] + va - s['address']

    def mutated(self, va, raw):
        data = bytearray(self.data)
        off = self.offset(va)
        data[off:off + len(raw)] = raw
        return bytes(data)

    def test_identity_and_window(self):
        self.assertEqual(self.result['window'], (0x56544a0, 0x56544f0))
        self.assertEqual(self.result['body_sha256'],
                         '561dd28bd79c3d74c2f56d4ab1137f7cac3ce4ce045efe86e6368cfa6a08a1db')
        self.assertEqual(self.result['relocation_slots'], [])
        self.assertEqual(self.result['direct_callers'], [])

    def test_body_lock(self):
        bad = self.mutated(0x56544a0, b'\x90')
        with self.assertRaises(ValueError):
            half_swap.analyze(bad)

    def test_bswap_lock(self):
        bad = self.mutated(0x56544af, b'\x90')
        with self.assertRaises(ValueError):
            half_swap.analyze(bad)

    def test_shift_lock(self):
        bad = self.mutated(0x56544cb, b'\x90')
        with self.assertRaises(ValueError):
            half_swap.analyze(bad)

    def test_fde_lock(self):
        eh = next(s for s in self.sections if s['name'] == '.eh_frame')
        bad = bytearray(self.data)
        bad[eh['offset'] + 0x2daf80 + 8] ^= 0x01
        with self.assertRaises(ValueError):
            half_swap.analyze(bytes(bad))

    def test_next_fde_lock(self):
        eh = next(s for s in self.sections if s['name'] == '.eh_frame')
        bad = bytearray(self.data)
        bad[eh['offset'] + 0x2daf94 + 8] ^= 0x01
        with self.assertRaises(ValueError):
            half_swap.analyze(bytes(bad))

    def test_no_padding_lock(self):
        # The next FDE starts exactly at the FDE end; moving its PC must fail.
        eh = next(s for s in self.sections if s['name'] == '.eh_frame')
        bad = bytearray(self.data)
        bad[eh['offset'] + 0x2daf94 + 12] ^= 0x01
        with self.assertRaises(ValueError):
            half_swap.analyze(bytes(bad))

    def test_lane_rule_edges(self):
        self.assertEqual(half_swap.build(b'\x00' * 32), b'\x00' * 32)
        self.assertEqual(half_swap.build(bytes(range(1, 33))),
                         bytes.fromhex('04030201080706050c0b0a09100f0e0d'
                                       '14131211181716151c1b1a19201f1e1d'))
        self.assertEqual(half_swap.build(b'\xff' * 32), b'\xff' * 32)
        # A half-swap (the scout's wrong rule) must NOT match: lanes stay put.
        self.assertNotEqual(half_swap.build(bytes(range(1, 33))),
                            bytes(range(5, 9)) + bytes(range(1, 5)) +
                            bytes(range(13, 17)) + bytes(range(9, 13)) +
                            bytes(range(21, 25)) + bytes(range(17, 21)) +
                            bytes(range(29, 33)) + bytes(range(25, 29)))
        with self.assertRaises(ValueError):
            half_swap.build(b'\x00' * 31)

    def test_retained_evidence_matches(self):
        retained = json.loads(
            (Path(__file__).resolve().parents[1] / 'research/work-items'
             / 'foundation-half-swap-94' / 'evidence.json').read_text())
        self.assertEqual(retained['function']['sha256'], self.result['body_sha256'])
        self.assertEqual(retained['function']['bytes'], 80)
        self.assertEqual(retained['function']['padding_bytes'], 0)
