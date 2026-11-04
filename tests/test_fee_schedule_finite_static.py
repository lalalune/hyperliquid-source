"""Target-bound node115 fee-schedule finiteness gate 0x3d3b6c0."""
import hashlib
import json
import math
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'tools'))
import fee_schedule_finite_static as subject
import fee_schedule_sources_static as sources
import fee_schedule_gate_static as gate
from elf_index import sections
from test_fee_schedule_sources_static import valid_schedule

NAN, INF = math.nan, math.inf
MAX = sys.float_info.max


def finite_ok(schedule):
    """Decoded coverage applied to a synthetic schedule (normal path)."""
    s = schedule
    values = [s['in'][k] for k in (0x68, 0x70, 0x78, 0x80, 0x88, 0x90)]
    values += [r[k] for r in s['tiers'] for k in (0x00, 0x08, 0x10, 0x18, 0x28)]
    values += [r[k] for r in s['second'] for k in (0x00, 0x08)]
    values += list(s.get('map', []))
    return all(not subject.nonfinite(v, 0x7fffffffffffffff, 0x7fefffffffffffff, 'jg') for v in values)


class FeeScheduleFiniteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not gate.TARGET.is_file() or gate.TARGET.stat().st_size != gate.SIZE:
            raise unittest.SkipTest('materialized node115 required')
        cls.data = gate.TARGET.read_bytes()
        if hashlib.sha256(cls.data).hexdigest() != gate.SHA:
            raise ValueError('wrong node115 capture')
        cls.secs = sections(cls.data)
        cls.report = subject.analyze(cls.data)
        cls.gate_cert = gate._analyze(cls.data)['certificate']
        cls.slice_sources = sources._analyze(cls.data)['slice_sources']

    def offset(self, va):
        s = next(s for s in self.secs if s['type'] != 8 and s['address'] <= va < s['address']+s['size'])
        return s['offset']+va-s['address']

    def mutate(self, va, raw):
        b = bytearray(self.data)
        o = self.offset(va)
        b[o:o+len(raw)] = raw
        return bytes(b)

    def full_gate(self, s):
        return finite_ok(s) and sources.gate_passes(s, self.gate_cert, self.slice_sources)

    def test_retained_and_native_regeneration(self):
        self.assertEqual(self.report, json.loads((subject.PACKET/'records.json').read_text()))
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            subject.generate(gate.TARGET, out)
            self.assertEqual({p.name for p in out.iterdir()},
                             {p.name for p in subject.PACKET.iterdir()} - {'README.md', 'MANIFEST.sha256'})
            for p in out.iterdir():
                self.assertEqual(p.read_bytes(), (subject.PACKET/p.name).read_bytes(), p.name)

    def test_predicate_is_non_finite(self):
        for x, flagged in [(0.0, False), (-0.0, False), (5e-324, False), (MAX, False), (-MAX, False),
                           (INF, True), (-INF, True), (NAN, True), (-NAN, True)]:
            self.assertEqual(subject.nonfinite(x, 0x7fffffffffffffff, 0x7fefffffffffffff, 'jg'), flagged, x)
        self.assertEqual(self.report['slices_fully_checked_finite'], [1, 2, 3, 4, 5, 6, 8, 9])
        state = self.report['certificate']['caller_state_fields']
        self.assertEqual((state['0x48']['value'], state['0x50']['value'], state['0x58']['value']), (1, 0, 4))
        self.assertEqual((state['0xe0']['pointer'], state['0xe8']['pointer']), ('rsp+0x230', 'rsp+0x240'))

    def test_nan_cases_from_ordering_packets_are_rejected_earlier(self):
        s = valid_schedule()
        self.assertTrue(self.full_gate(s))
        for name, change in [('tier vip word NaN', lambda s: s['tiers'][0].__setitem__(0x28, NAN)),
                             ('maker cutoff NaN', lambda s: s['second'][1].__setitem__(0x00, NAN)),
                             ('range value NaN', lambda s: s['in'].__setitem__(0x88, NAN)),
                             ('tier rate +inf', lambda s: s['tiers'][1].__setitem__(0x08, INF)),
                             ('base rate -inf', lambda s: s['in'].__setitem__(0x78, -INF)),
                             ('map value NaN', lambda s: s.__setitem__('map', [0.1, NAN]))]:
            t = valid_schedule()
            change(t)
            with self.subTest(name):
                self.assertFalse(self.full_gate(t))
        # Ordering alone still accepts the NaN cases the gate packet documents.
        t = valid_schedule()
        t['tiers'][0][0x28] = NAN
        self.assertTrue(sources.gate_passes(t, self.gate_cert, self.slice_sources))

    def test_counterfactuals_change_the_certificate(self):
        # Limit 0x7fefffffffffffff -> 0x7ff0000000000000 in the array part: +/-inf now passes.
        cert = subject.certificate(self.mutate(0x3d3b7d0, struct.pack('<Q', 0x7ff0000000000000)))
        part = next(p for p in cert['callee_parts'] if p['part'] == 'array')
        self.assertEqual(part['limit'], '0x7ff0000000000000')
        self.assertFalse(subject.nonfinite(INF, 0x7fffffffffffffff, int(part['limit'], 16), 'jg'))
        # Array end 4 -> 3: the fourth tier vector is no longer covered.
        cert = subject.certificate(self.mutate(0x36a2572, b'\x03'))
        self.assertNotIn('0xd8', [c.get('pointer_slot') for c in cert['coverage']])
        # Array element 2 header 0xa0 -> 0xb8: coverage follows the bytes.
        cert = subject.certificate(self.mutate(0x36a258a, b'\xb8'))
        self.assertEqual([c['pointer_slot'] for c in cert['coverage'] if c['part'] == 'array'], ['0x90', '0xc0', '0xc0', '0xd8'])

    def test_corruption_controls_below_identity_gate(self):
        controls = [
            (0x3d3b72a, b'\xf0'),                      # front limit
            (0x3d3b7c6, b'\xfe'),                      # array mask
            (0x3d3b8fe, b'\x7c'),                      # s3 flag condition jle -> jl
            (0x3d3b8a5, b'\x48\xc7\x43\x48\x05'),      # state store 3 -> 5
            (0x3d3b6d3, b'\x08'),                      # dispatch immediate
            (0x3d3ba52, b'\xf0'),                      # map contiguous limit
            (0x36a2645, b'\x02'),                      # caller initial state
            (0x36a2658, b'\x0f\x84'),                  # caller failure condition inverted
            (0x36a2652, b'\x00'),                      # caller call target
            (0x36a246f, b'\x20'),                      # range copy destination
            (0x3d3baa0, b'\x90'),                      # unrelated callee byte: hash pin
        ]
        for va, raw in controls:
            with self.subTest(va=hex(va)), self.assertRaises(ValueError):
                subject._analyze(self.mutate(va, raw))
        with self.assertRaises(ValueError):
            subject.analyze(self.data[:-1])


if __name__ == '__main__':
    unittest.main()
