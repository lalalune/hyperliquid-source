"""Target-bound node115 fee-schedule ordering/range gate and window helper."""
import hashlib
import json
import math
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'tools'))
import fee_schedule_gate_static as subject
from elf_index import sections

NAN = math.nan


class FeeScheduleGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not subject.TARGET.is_file() or subject.TARGET.stat().st_size != subject.SIZE:
            raise unittest.SkipTest('materialized node115 required')
        cls.data = subject.TARGET.read_bytes()
        if hashlib.sha256(cls.data).hexdigest() != subject.SHA:
            raise ValueError('wrong node115 capture')
        cls.secs = sections(cls.data)
        cls.report = subject.analyze(cls.data)
        cls.cert = cls.report['certificate']

    def offset(self, va):
        s = next(s for s in self.secs if s['type'] != 8 and s['address'] <= va < s['address']+s['size'])
        return s['offset']+va-s['address']

    def mutate(self, va, raw):
        b = bytearray(self.data)
        o = self.offset(va)
        b[o:o+len(raw)] = raw
        return bytes(b)

    def test_retained_and_native_regeneration(self):
        self.assertEqual(self.report, json.loads((subject.PACKET/'records.json').read_text()))
        self.assertEqual(sum(x['bytes'] for x in self.report['owners']), 113+5599)
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            subject.generate(subject.TARGET, out)
            names = {p.name for p in out.iterdir()}
            self.assertEqual(names, {p.name for p in subject.PACKET.iterdir()} - {'README.md', 'MANIFEST.sha256'})
            for p in out.iterdir():
                self.assertEqual(p.read_bytes(), (subject.PACKET/p.name).read_bytes(), p.name)

    def test_decoded_sequence_predicates(self):
        loops = self.cert['loops']
        self.assertEqual(len(loops), 8)
        nonincreasing = loops[:6]
        for d in nonincreasing:
            self.assertEqual((d['element'], d['lhs'], d['rhs'], d['continue_if']), ('f64', 'next', 'prev', 'jbe'))
            self.assertTrue(subject.loop_passes(d, []))
            self.assertTrue(subject.loop_passes(d, [7.0]))
            self.assertTrue(subject.loop_passes(d, [3.0, 2.0, 2.0, -1.0]))
            self.assertFalse(subject.loop_passes(d, [1.0, 2.0]))
            self.assertFalse(subject.loop_passes(d, [3.0, 2.0, 2.5]))
            # Unordered comparisons set CF/ZF, so a NaN on either side continues.
            self.assertTrue(subject.loop_passes(d, [2.0, NAN, 5.0]))
            self.assertTrue(subject.loop_passes(d, [-0.0, 0.0]))
        u64 = loops[6]
        self.assertEqual((u64['element'], u64['lhs'], u64['rhs'], u64['continue_if']), ('u64', 'prev', 'next', 'jb'))
        self.assertTrue(subject.loop_passes(u64, [0, 5, 9]))
        self.assertFalse(subject.loop_passes(u64, [0, 5, 5]))
        self.assertFalse(subject.loop_passes(u64, [7, 3]))
        strict = loops[7]
        self.assertEqual(strict['source'], {'pointer': 'r14', 'length': 'rbx'})
        self.assertTrue(subject.loop_passes(strict, [1.0, 2.0, 3.5]))
        self.assertFalse(subject.loop_passes(strict, [1.0, 1.0]))
        self.assertFalse(subject.loop_passes(strict, [2.0, 1.0]))
        # `jb` continues on CF, which ucomisd also sets for unordered operands.
        self.assertTrue(subject.loop_passes(strict, [1.0, NAN, 0.5]))
        self.assertEqual({d['fail_to'] for d in loops}, {hex(subject.FAIL)})

    def test_window_helper_semantics(self):
        h = self.cert['helper']
        self.assertEqual(self.cert['helper_window_size'], 2)
        self.assertFalse(subject.helper_any(h, 2, [1.0, 0.5, 0.5]))
        self.assertTrue(subject.helper_any(h, 2, [1.0, 0.9, 1.1]))
        self.assertFalse(subject.helper_any(h, 2, [1.0, NAN, 2.0]))
        self.assertFalse(subject.helper_any(h, 2, []))
        self.assertFalse(subject.helper_any(h, 2, [1.0]))
        self.assertFalse(subject.helper_any(h, 1, []))
        with self.assertRaises(IndexError) as caught:
            subject.helper_any(h, 1, [1.0])
        self.assertEqual(caught.exception.args[0], (1, 1))
        loc = self.report['location']
        self.assertEqual((loc['path'], loc['line'], loc['column']), ('l1/src/fees/fees.rs', 259, 57))

    def test_pair_and_range_semantics(self):
        pairs = self.cert['pairs']
        self.assertEqual(pairs['source'], {'pointer': 'input+0x38', 'length': 'input+0x40'})
        self.assertEqual([c['value'] for c in pairs['caps_on_last_or_initial']], [5.0, 0.5])
        for good in [[], [(1.0, 0.1), (2.0, 0.2)], [(5.0, 0.5)]]:
            self.assertTrue(subject.pair_passes(pairs, good), good)
        for bad in [[(1.0, 0.2), (2.0, 0.1)], [(0.0, 0.1)], [(1.0, 0.0)], [(2.0, 0.1), (2.0, 0.2)],
                    [(6.0, 0.1)], [(1.0, 0.6)], [(1.0, NAN)], [(NAN, 0.1)]]:
            self.assertFalse(subject.pair_passes(pairs, bad), bad)
        for r in self.cert['ranges']:
            self.assertEqual((r['lower'], r['upper']), (0.0, 1.0))
            for good in [0.0, -0.0, 0.25, 1.0, NAN]:
                self.assertTrue(subject.range_passes(r, good), good)
            for bad in [-1e-300, 1.0000000000000002, math.inf, -math.inf]:
                self.assertFalse(subject.range_passes(r, bad), bad)

    def test_semantic_counterfactuals_change_the_certificate(self):
        # jbe -> jb on the first non-increasing back-edge: equal neighbours now fail.
        cert = subject.certificate(self.mutate(0x36a26a6, b'\x72'))
        self.assertEqual(cert['loops'][0]['continue_if'], 'jb')
        self.assertFalse(subject.loop_passes(cert['loops'][0], [1.0, 1.0]))
        # jb -> jbe on the u64 back-edge: duplicates now pass.
        cert = subject.certificate(self.mutate(0x36a27ef, b'\x76'))
        self.assertTrue(subject.loop_passes(cert['loops'][6], [0, 5, 5]))
        # Window size immediate 2 -> 1 passed to the helper.
        self.assertEqual(subject.certificate(self.mutate(0x36a282e, b'\x01'))['helper_window_size'], 1)
        # Helper back-edge jbe -> jb: an equal window now reports a match.
        cert = subject.certificate(self.mutate(0x36e1b4f, b'\x72'))
        self.assertTrue(subject.helper_any(cert['helper'], 2, [1.0, 1.0]))
        # The shared 5.0 literal read through the real RIP displacement.
        cert = subject.certificate(self.mutate(0x4593d0, struct.pack('<d', 6.0)))
        self.assertTrue(subject.pair_passes(cert['pairs'], [(6.0, 0.1)]))
        # ja -> jae on the first upper range test: 1.0 is now rejected.
        cert = subject.certificate(self.mutate(0x36a2a67, b'\x73'))
        self.assertFalse(subject.range_passes(cert['ranges'][0], 1.0))

    def test_corruption_controls_below_identity_gate(self):
        controls = [
            (0x36a26a8, b'\xe9\x00\x00\x00\x00'),      # loop failure jump retargeted
            (0x36a2694, b'\x72\x18'),                  # loop length exit retargeted
            (0x36a269d, b'\x66\x0f\x2e\x40\xf0'),      # compared element displacement
            (0x36a27e8, b'\x48\x3b\x11'),              # u64 comparison operand register
            (0x36a2841, b'\x0f\x84'),                  # helper result gate inverted
            (0x36a2847, b'\x48\x8b\x55\x30'),          # pair slice field
            (0x36a2a15, b'\x0f\x87\x00\x00\x00\x00'),  # cap failure retargeted
            (0x36a2a76, b'\x77\x6d'),                  # range failure retargeted
            (0x36e1b6d, b'\x00\x00\x00\x00'),          # helper Location displacement
            (0x36e1b62, b'\x02'),                      # helper panic index
            (0x6468ba8, struct.pack('<I', 260)),       # Location line
            (0x36a1c34, b'\xf2\x0f\x10\x47\x60'),      # vector seed field
            (0x36a1def, b'\x48\x89\x9c\x24\x30\x01'),  # input spill slot
            (0x36a2b5d, b'\xbb\x01\x00\x00\x00'),      # failure return value
            (0x36a2b00, b'\x90'),                      # unrelated caller byte: hash pin
        ]
        for va, raw in controls:
            with self.subTest(va=hex(va)), self.assertRaises(ValueError):
                subject._analyze(self.mutate(va, raw))
        with self.assertRaises(ValueError):
            subject.analyze(self.mutate(0x36a2b00, b'\x90'))
        with self.assertRaises(ValueError):
            subject.analyze(self.data[:-1])


if __name__ == '__main__':
    unittest.main()
