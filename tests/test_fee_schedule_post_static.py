"""Target-bound node115 fee-schedule validator post-gate path and true return."""
import hashlib
import json
import math
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'tools'))
import fee_schedule_post_static as subject
import fee_schedule_sources_static as sources
import fee_schedule_gate_static as gate
from elf_index import sections
from test_fee_schedule_finite_static import finite_ok

NAN = math.nan


def schedule():
    """Synthetic schedule meant to satisfy every decoded predicate (floors assumed)."""
    return {'in': {0x68: 0.00045, 0x70: 0.00015, 0x78: 0.0007, 0x80: 0.0004, 0x88: 0.2, 0x90: 0.5},
            'tiers': [{0x00: 0.0004, 0x08: 0.00012, 0x10: 0.0006, 0x18: 0.0003, 0x20: 5_000_000, 0x28: 0.9},
                      {0x00: 0.0003, 0x08: 0.0001, 0x10: 0.0005, 0x18: 0.0002, 0x20: 25_000_000, 0x28: 0.5}],
            'second': [{0x00: 0.005, 0x08: -0.00001}, {0x00: 0.015, 0x08: -0.00002}],
            'stake': [(0.0001, 0.05), (0.001, 0.1), (5.0, 0.4)],
            'map': [0.25, 0.5]}


class FeeSchedulePostTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not gate.TARGET.is_file() or gate.TARGET.stat().st_size != gate.SIZE:
            raise unittest.SkipTest('materialized node115 required')
        cls.data = gate.TARGET.read_bytes()
        if hashlib.sha256(cls.data).hexdigest() != gate.SHA:
            raise ValueError('wrong node115 capture')
        cls.secs = sections(cls.data)
        cls.report = subject.analyze(cls.data)
        cls.cert = cls.report['certificate']
        cls.gate_cert = gate._analyze(cls.data)['certificate']
        cls.src = sources._analyze(cls.data)['slice_sources']

    def offset(self, va):
        s = next(s for s in self.secs if s['type'] != 8 and s['address'] <= va < s['address']+s['size'])
        return s['offset']+va-s['address']

    def mutate(self, va, raw):
        b = bytearray(self.data)
        o = self.offset(va)
        b[o:o+len(raw)] = raw
        return bytes(b)

    def validator(self, s, cert=None, floors=(True, True)):
        """Decoded validator result: finiteness, ordering chain, then the post-gate path."""
        if not finite_ok(s) or not sources.gate_passes(s, self.gate_cert, self.src):
            return False
        seeds = {1: lambda s: s['in'][0x68], 2: lambda s: s['in'][0x70], 3: lambda s: s['in'][0x78],
                 4: lambda s: s['in'][0x80], 5: lambda s: s['in'][0x70], 6: lambda s: s['in'][0x80],
                 7: lambda s: 0, 8: lambda s: 0.0, 9: lambda s: 1.0}
        sl = sources.model_slices(s, self.src, seeds)
        last = s['stake'][-1][1] if s['stake'] else 0.0
        return subject.post_passes(cert or self.cert, sl, s['map'], last, floors)

    def test_retained_and_native_regeneration(self):
        self.assertEqual(self.report, json.loads((subject.PACKET/'records.json').read_text()))
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            subject.generate(gate.TARGET, out)
            self.assertEqual({p.name for p in out.iterdir()},
                             {p.name for p in subject.PACKET.iterdir()} - {'README.md', 'MANIFEST.sha256'})
            for p in out.iterdir():
                self.assertEqual(p.read_bytes(), (subject.PACKET/p.name).read_bytes(), p.name)

    def test_decoded_post_gate_predicates(self):
        for x, ok in [(0.0, True), (-0.0, True), (0.0001, True), (0.001, True), (0.00009, False), (0.0011, False), (-0.00001, False)]:
            self.assertEqual(subject.cross_ok(self.cert, x), ok, x)
        for x, ok in [(0.0, True), (-0.001, True), (-0.00001, True), (0.0001, True), (0.001, True), (0.00005, False), (-0.0011, False), (0.0011, False)]:
            self.assertEqual(subject.add_ok(self.cert, x), ok, x)
        perp, spot = self.cert['floor_calls']
        self.assertEqual((perp['fields']['0x0'], perp['fields']['0x8'], perp['fields']['0x18'], perp['fields']['0x20']),
                         ('&[rsp+0xa0]', '&[rsp+0x18]', '[rsp+0x80]', '[rsp+0x130]'))
        self.assertEqual((spot['fields']['0x0'], spot['fields']['0x10'], spot['fields']['0x18']), ('&[rsp+0xd0]', '&[rsp+0xb8]', '[rsp+0x78]'))

    def test_validator_over_synthetic_schedules(self):
        self.assertTrue(self.validator(schedule()))
        cases = [
            ('map sum above 1.0', lambda s: s.__setitem__('map', [0.6, 0.5]), False),
            ('map sum exactly 1.0', lambda s: s.__setitem__('map', [0.5, 0.5]), True),
            ('cross tier below positive minimum', lambda s: s['tiers'][1].__setitem__(0x00, 0.00005), False),
            ('cross tier zero allowed', lambda s: s['tiers'][1].__setitem__(0x00, 0.0), True),
            ('cross base above maximum', lambda s: s['in'].__setitem__(0x68, 0.0011), False),
            ('add tier small positive rejected', lambda s: s['tiers'][1].__setitem__(0x08, 0.00008), False),
            ('maker rebate beyond -0.001', lambda s: s['second'][1].__setitem__(0x08, -0.0012), False),
            ('spot add above maximum', lambda s: s['in'].__setitem__(0x80, 0.0012), False),
            ('floor helper false', None, False),
        ]
        for name, change, expected in cases:
            s = schedule()
            floors = (True, True)
            if change:
                change(s)
            else:
                floors = (True, False)
            with self.subTest(name):
                self.assertEqual(self.validator(s, floors=floors), expected)

    def test_counterfactuals_change_the_certificate(self):
        cert = subject.certificate(self.mutate(0x459b50, struct.pack('<d', 0.00005)))     # shared minimum literal
        self.assertTrue(subject.cross_ok(cert, 0.00008) and subject.add_ok(cert, 0.00008))
        cert = subject.certificate(self.mutate(0x36a3036, b'\x0f\x83'))                    # |x| ja -> jae
        self.assertEqual(cert['add_range']['fail_if'], ['|x| None 0.001'])
        cert = subject.certificate(self.mutate(0x36a2d8b, b'\x0f\x86'))                    # sum ja -> jbe
        self.assertEqual(cert['map_sum']['fail_if'], 'sum jbe 1.0')
        cert = subject.certificate(self.mutate(0x36a2da5, b'\x20'))                         # perp arg &[rsp+0x18] -> 0x20
        self.assertEqual(cert['floor_calls'][0]['fields']['0x8'], '&[rsp+0x20]')

    def test_corruption_controls_below_identity_gate(self):
        controls = [
            (0x459458, struct.pack('<d', 0.0)),         # sum start -0.0 -> +0.0 (bits)
            (0x36a2d67, b'\x0f\x86'),                    # discount upper condition
            (0x36a2e23, b'\x0f\x85'),                    # floor result gate inverted
            (0x36a2e1d, b'\x00'),                        # floor call target
            (0x36a2f25, b'\x0f\x86'),                    # cross lower condition
            (0x36a2f43, b'\x77'),                        # cross positive test
            (0x36a2f9e, b'\x02'),                        # chain iterator initial tag
            (0x36e1bb3, b'\x48\x0f\x44'),                # chain cmovne -> cmove
            (0x36a302a, b'\x00'),                        # abs mask address
            (0x36a30cd, b'\x00'),                        # success BPL value
            (0x36a2b00, b'\x90'),                        # unrelated caller byte: body hash
        ]
        for va, raw in controls:
            with self.subTest(va=hex(va)), self.assertRaises(ValueError):
                subject._analyze(self.mutate(va, raw))
        with self.assertRaises(ValueError):
            subject.analyze(self.data[:-1])


if __name__ == '__main__':
    unittest.main()
