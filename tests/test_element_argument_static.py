import tempfile
import unittest
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))

import element_argument_static as m
from artifacts import ROOT

PACKET_DIR = ROOT / 'research/work-items' / m.PACKET_ID
GENERATED = ('records.json', 'frames.txt') + tuple(
    m._export_name(name, *m.BODIES[name]['range'])
    for name in m.EXPORTED)


def _flip(data, va):
    for sec in m.sections(data):
        if sec['type'] != 8 and sec['address'] <= va < sec['address'] + sec['size']:
            off = sec['offset'] + (va - sec['address'])
            return data[:off] + bytes((data[off] ^ 1,)) + data[off + 1:]
    raise AssertionError(f'no file-backed section covers {va:#x}')


class ElementArgumentStaticTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT / 'artifacts/node/115/hl-node').read_bytes()
        cls.records = m.analyze(cls.data)

    def test_committed_artifacts_regenerate_byte_for_byte(self):
        with tempfile.TemporaryDirectory() as tmp:
            m.generate(self.data, tmp)
            for name in GENERATED:
                self.assertEqual((PACKET_DIR / name).read_bytes(),
                                 (Path(tmp) / name).read_bytes(), name)

    def test_generate_authenticates_before_writing(self):
        flipped = _flip(self.data, m.BODIES['cb2']['range'][0])
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(m.PacketError, 'artifact SHA-256 mismatch'):
                m.generate(flipped, tmp)

    def test_counters(self):
        counters = self.records['counters']
        self.assertEqual(counters, m.EXPECTED)
        self.assertEqual(counters['bodies'], 16)
        self.assertEqual(counters['rows'], 7822)
        self.assertEqual(counters['sites'], 13)
        self.assertEqual(counters['kind_a'], 1)
        self.assertEqual(counters['kind_b'], 6)
        self.assertEqual(counters['kind_c'], 6)
        self.assertEqual(counters['pointer_stores'], 0)
        self.assertEqual(counters['helper_rdx_stores'], 0)
        self.assertEqual(counters['ca_s_tail_stores'], 0)

    def test_full_body_mutation_fails_its_digest(self):
        with self.assertRaisesRegex(
                AssertionError, 'cb2 differs from its pinned digest'):
            m.analyze(_flip(self.data, m.BODIES['cb2']['range'][0]))

    def test_large_body_mutation_fails_its_digest(self):
        with self.assertRaisesRegex(
                AssertionError, 'big3 differs from its pinned digest'):
            m.analyze(_flip(self.data, m.BODIES['big3']['range'][0]))

    def test_driver_mutation_fails_its_digest(self):
        with self.assertRaisesRegex(
                AssertionError, 'caller_b2 differs from its pinned digest'):
            m.analyze(_flip(self.data, m.DRIVERS['caller_b2']['range'][0]))

    def test_pinned_row_check_catches_text_drift(self):
        secs = m.sections(self.data)
        rows = m._decode(self.data, secs, *m.BODIES['cb2']['range'])
        pins = dict(m.PINNED_ROWS['cb2'])
        addr = sorted(pins)[0]
        pins[addr] = (pins[addr][0], 'tampered text')
        with self.assertRaisesRegex(
                AssertionError, 'cb2 instruction at .* differs'):
            m._check_pins(rows, pins, 'cb2')

    def test_partial_pin_check_catches_text_drift(self):
        secs = m.sections(self.data)
        rows = m._decode(self.data, secs, *m.BODIES['big1']['range'])
        pins = dict(m.PINNED_ROWS_PARTIAL['big1'])
        addr = sorted(pins)[0]
        pins[addr] = (pins[addr][0], 'tampered text')
        with self.assertRaisesRegex(
                AssertionError, 'big1 instruction at .* differs'):
            m._check_pins_subset(rows, pins, 'big1')

    def test_verdict_shapes(self):
        sites = self.records['sites']
        self.assertEqual(len(sites), 13)
        kinds = {}
        for entry in sites:
            kinds[entry['kind']] = kinds.get(entry['kind'], 0) + 1
        self.assertEqual(kinds, {'a': 1, 'b': 6, 'c': 6})
        only_a = [e for e in sites if e['kind'] == 'a']
        self.assertEqual(only_a[0]['caller_fde'], 'cb2')
        self.assertEqual(only_a[0]['driver'], 'caller_b2')
        self.assertEqual(only_a[0]['site'], '0x36a1b67')
        self.assertEqual(set(self.records['field_attribution_cb2']),
                         {'0x40', '0x58', '0x60', '0x78',
                          '0x80', '0x88', '0x90', '0x98'})
        self.assertEqual(
            self.records['slots']['memcpy']['symbol'], 'memcpy')
        boundary = self.records['boundary']['driver_callers']
        self.assertEqual(len(boundary['caller_a']), 1)
        self.assertEqual(len(boundary['caller_b1']), 10)
        self.assertEqual(len(boundary['caller_b2']), 1)
        self.assertEqual(len(boundary['caller_c']), 1)
        ev = self.records['fde_evidence']
        self.assertEqual(
            ev['cb2']['eight_fields_covered_by_direct_stores'],
            ['0x40', '0x58', '0x60', '0x78',
             '0x80', '0x88', '0x90', '0x98'])
        for name in ('big1', 'big2', 'big3'):
            self.assertEqual(
                ev[name]['eight_fields_covered_by_direct_stores'], [])
        self.assertEqual(len(ev['ca']['query_record_stores']), 12)
        self.assertEqual(ev['ca']['memcpy_calls'][1]['size'], '0xa8')
        jc = [e for e in sites if e['caller_fde'] == 'jc1'][0]
        self.assertEqual(jc['kind'], 'c')


if __name__ == '__main__':
    unittest.main()
