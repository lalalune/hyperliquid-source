"""Target-bound sources of the node115 fee-schedule gate's ordered slices."""
import copy
import hashlib
import json
import math
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'tools'))
import fee_schedule_sources_static as subject
import fee_schedule_gate_static as gate
from elf_index import sections

NAN = math.nan


def valid_schedule():
    """A synthetic schedule satisfying every claimed predicate."""
    return {'in': {0x68: 0.0005, 0x70: 0.0002, 0x78: 0.0007, 0x80: 0.0004, 0x88: 0.1, 0x90: 0.9},
            'tiers': [{0x00: 0.0004, 0x08: 0.00012, 0x10: 0.0006, 0x18: 0.0003, 0x20: 5_000_000, 0x28: 0.9},
                      {0x00: 0.0003, 0x08: 0.00008, 0x10: 0.0005, 0x18: 0.0002, 0x20: 25_000_000, 0x28: 0.5}],
            'second': [{0x00: 0.005, 0x08: -0.00001}, {0x00: 0.015, 0x08: -0.00002}],
            'stake': [(0.0001, 0.05), (0.001, 0.1), (5.0, 0.4)]}


class FeeScheduleSourcesTests(unittest.TestCase):
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
        cls.sources = cls.report['slice_sources']

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
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            subject.generate(gate.TARGET, out)
            self.assertEqual({p.name for p in out.iterdir()},
                             {p.name for p in subject.PACKET.iterdir()} - {'README.md', 'MANIFEST.sha256'})
            for p in out.iterdir():
                self.assertEqual(p.read_bytes(), (subject.PACKET/p.name).read_bytes(), p.name)

    def test_decoded_sources(self):
        self.assertEqual([s['appended'] for s in self.sources],
                         ['tier[i]+0x0', 'tier[i]+0x8', 'tier[i]+0x10', 'tier[i]+0x18', 'second[i]+0x8',
                          'second[i]+0x8', 'tier[i]+0x20', 'second[i]+0x0', 'tier[i]+0x28'])
        tl = self.report['certificate']['tier_loop']
        self.assertEqual(tl['state_sequence_per_record'], [0, 1, 2, 3, 4])
        self.assertEqual((tl['list']['stride'], tl['fields']['0x20']['kind']), (48, 'u64'))
        self.assertEqual([s['element0'] for s in self.report['certificate']['mm_slice_seeds']], ['input+0x70', 'input+0x80'])

    def test_gate_over_synthetic_schedules(self):
        s = valid_schedule()
        self.assertTrue(subject.gate_passes(s, self.gate_cert, self.sources))
        cases = [
            ('tier cross rises above base', lambda s: s['tiers'][0].__setitem__(0x00, 0.0006), False),
            ('tier add equal to previous passes', lambda s: s['tiers'][1].__setitem__(0x08, 0.00012), True),
            ('spot add rises', lambda s: s['tiers'][1].__setitem__(0x18, 0.00035), False),
            ('cutoff not strictly increasing', lambda s: s['tiers'][1].__setitem__(0x20, 5_000_000), False),
            ('first u64 cutoff zero fails', lambda s: s['tiers'][0].__setitem__(0x20, 0), False),
            ('vip word above 1.0 fails', lambda s: s['tiers'][0].__setitem__(0x28, 1.5), False),
            ('vip word NaN is ignored', lambda s: s['tiers'][0].__setitem__(0x28, NAN), True),
            ('maker cutoff decreasing fails', lambda s: s['second'][1].__setitem__(0x00, 0.001), False),
            ('maker cutoff NaN passes', lambda s: s['second'][1].__setitem__(0x00, NAN), True),
            ('second-list add above base add fails', lambda s: s['second'][0].__setitem__(0x08, 0.0003), False),
            ('second-list add above perp base but below spot base', lambda s: s['second'][0].__setitem__(0x08, 0.00030),
             False),
            ('empty lists pass', lambda s: (s['tiers'].clear(), s['second'].clear()), True),
            ('range above 1 fails', lambda s: s['in'].__setitem__(0x90, 1.01), False),
            ('stake cap exceeded fails', lambda s: s['stake'].__setitem__(-1, (5.01, 0.4)), False),
        ]
        for name, change, expected in cases:
            s = valid_schedule()
            change(s)
            with self.subTest(name):
                self.assertEqual(subject.gate_passes(s, self.gate_cert, self.sources), expected)

    def test_counterfactuals_change_decoded_sources(self):
        # Swap two jump-table entries: states 1 and 2 now append each other's field.
        b = struct.unpack('<5i', self.data[self.offset(subject.JUMP_TABLE):self.offset(subject.JUMP_TABLE)+20])
        swapped = struct.pack('<5i', b[0], b[2], b[1], b[3], b[4])
        cert = subject.certificate(self.mutate(subject.JUMP_TABLE, swapped))
        appends = {a['pointer_slot']: a['record_field'] for a in cert['tier_loop']['appends_per_record_in_state_order']}
        self.assertEqual((appends['0xa8'], appends['0xc0']), ('0x8', '0x10'))  # value follows its block, not the index
        self.assertEqual([a['state'] for a in cert['tier_loop']['appends_per_record_in_state_order'][:3]], [0, 1, 2])
        self.assertEqual(cert['tier_loop']['state_targets'][1], '0x36a1fb0')
        # Record +0x10 load displacement changed to +0x30: slice 3 follows it.
        cert = subject.certificate(self.mutate(0x36a1e95, b'\x30'))
        appends = {a['pointer_slot']: a['record_field'] for a in cert['tier_loop']['appends_per_record_in_state_order']}
        self.assertEqual(appends['0xc0'], '0x30')
        # Second list remainder start 4 -> 0: remainder path now reads +0x0.
        cert = subject.certificate(self.mutate(0x36a219a, b'\x00'))
        self.assertEqual(cert['second_list']['extends'][0]['remainder_field'], 0)
        # Maker vector body base +0x30 -> +0x38: reads +0x8 instead of +0x0.
        cert = subject.certificate(self.mutate(0x36a2c80, b'\x38'))
        self.assertEqual(cert['second_list']['extends'][2]['body_fields_mod16'], [8])

    def test_corruption_controls_below_identity_gate(self):
        controls = [
            (0x36a1e4b, b'\x28'),                       # tier stride 0x30 -> 0x28
            (0x36a1e34, b'\x55'),                       # jump-table base displacement
            (0x36a1eb4, b'\x02'),                       # clamp constant
            (0x36a1f7e, b'\xa8'),                       # state-1 vector header
            (0x36a1f87, b'\x18'),                       # state-1 value slot
            (0x36a2010, b'\x50'),                       # u64 value slot
            (0x36a2029, b'\x40'),                       # f64 vector capacity slot
            (0x36a20b8, b'\x30'),                       # second list pointer field
            (0x36a2159, b'\xe8'),                       # vector body stride
            (0x36a2d0f, b'\xbe\x14\x00\x00\x00'),       # maker unrolled start
            (0x36a2402, b'\x48\xc7\x00\x01\x00\x00\x00'),  # slice-8 seed
            (0x36a260e, b'\x4c\x89\xeb'),               # slice-8 length register
            (0x36a1c46, b'\x78'),                       # seed input field for slice 5
            (0x36a2b00, b'\x90'),                       # unrelated caller byte: body hash
        ]
        for va, raw in controls:
            with self.subTest(va=hex(va)), self.assertRaises(ValueError):
                subject._analyze(self.mutate(va, raw))
        with self.assertRaises(ValueError):
            subject.analyze(self.data[:-1])


if __name__ == '__main__':
    unittest.main()
