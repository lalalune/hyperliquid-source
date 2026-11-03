import struct
import tempfile
import unittest
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))

import element_builder_static as m
from artifacts import ROOT

PACKET_DIR = ROOT / 'research/work-items' / m.PACKET_ID
GENERATED = ('records.json', 'frames.txt') + tuple(
    m._export_name(name, body['range'][0], body['range'][1])
    for name, body in m.BODIES.items())


def _flip(data, va):
    for sec in m.sections(data):
        if sec['type'] != 8 and sec['address'] <= va < sec['address'] + sec['size']:
            off = sec['offset'] + (va - sec['address'])
            return data[:off] + bytes((data[off] ^ 1,)) + data[off + 1:]
    raise AssertionError(f'no file-backed section covers {va:#x}')


def _rela_addend_va(data, slot):
    for sec in m.sections(data):
        if sec['type'] != 4:
            continue
        blob = data[sec['offset']:sec['offset'] + sec['size']]
        for i in range(0, len(blob) - 23, 24):
            r_offset, _r_info, _r_addend = struct.unpack_from('<QQq', blob, i)
            if r_offset == slot:
                return sec['address'] + i + 16
    raise AssertionError('slot relocation not found')


class ElementBuilderStaticTest(unittest.TestCase):
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
        flipped = _flip(self.data, m.BODIES['wrap_a']['range'][0])
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(m.PacketError, 'artifact SHA-256 mismatch'):
                m.generate(flipped, tmp)

    def test_counters(self):
        counters = self.records['counters']
        self.assertEqual(counters, m.EXPECTED)
        self.assertEqual(counters['bodies'], 21)
        self.assertEqual(counters['rows'], 5506)
        self.assertEqual(counters['field_stores'], 0)
        self.assertEqual(counters['element_other_stores'], 0)
        self.assertEqual(
            counters['stores_at_eight_displacements_nonstack'], 0)
        self.assertEqual(counters['head_stores'], 21)
        self.assertEqual(counters['memcpy_whole_element_0xb0'], 22)
        self.assertEqual(counters['memcpy_tail_0xa8'], 51)
        self.assertEqual(counters['memmove_element_shifts'], 15)
        self.assertEqual(counters['alloc_leaf_0x7f8'], 15)
        self.assertEqual(counters['alloc_internal_0x858'], 12)
        self.assertEqual(counters['sibling_e8_sites'], 99)
        self.assertEqual(counters['driver_caller_sites'], 13)

    def test_wrap_mutation_fails_its_digest(self):
        with self.assertRaisesRegex(
                AssertionError, 'wrap_a differs from its pinned digest'):
            m.analyze(_flip(self.data, m.BODIES['wrap_a']['range'][0]))

    def test_giant_mutation_fails_its_digest(self):
        with self.assertRaisesRegex(
                AssertionError, 'giant_b1 differs from its pinned digest'):
            m.analyze(_flip(self.data, m.BODIES['giant_b1']['range'][0]))

    def test_pinned_row_check_catches_text_drift(self):
        secs = m.sections(self.data)
        rows = m._decode(self.data, secs,
                         *m.BODIES['caller_b2']['range'])
        pins = dict(m.PINNED_ROWS['caller_b2'])
        addr = sorted(pins)[0]
        pins[addr] = (pins[addr][0], 'tampered text')
        with self.assertRaisesRegex(
                AssertionError, 'caller_b2 instruction at .* differs'):
            m._check_pins(rows, pins, 'caller_b2')

    def test_alloc_slot_relocation_mutation_fails(self):
        va = _rela_addend_va(self.data, m.ALLOC_SLOT)
        with self.assertRaises(AssertionError):
            m.analyze(_flip(self.data, va))

    def test_alloc_slot_content_mutation_fails(self):
        with self.assertRaisesRegex(
                AssertionError, 'slot 0x64df480 initialised content is not zero'):
            m.analyze(_flip(self.data, m.ALLOC_SLOT))

    def test_verdict_shapes(self):
        self.assertEqual(set(self.records['field_verdicts']),
                         {'0x40', '0x58', '0x60', '0x78',
                          '0x80', '0x88', '0x90', '0x98'})
        self.assertEqual(self.records['slots']['alloc']['rela_addend'],
                         '0x6355830')
        self.assertEqual(self.records['slots']['memcpy']['symbol'], 'memcpy')
        self.assertEqual(self.records['slots']['memmove']['symbol'],
                         'memmove')
        self.assertEqual(self.records['slots']['dealloc']['rela_addend'],
                         '0x635de30')
        self.assertEqual(len(self.records['call_graph']['wrap_b']), 2)
        self.assertEqual(len(self.records['call_graph']['giant_a1']), 1)
        self.assertEqual(len(self.records['call_graph']['giant_b3']), 2)
        boundary = self.records['boundary']['driver_callers']
        self.assertEqual(len(boundary['caller_a']), 1)
        self.assertEqual(len(boundary['caller_b1']), 10)
        self.assertEqual(len(boundary['caller_b2']), 1)
        self.assertEqual(len(boundary['caller_c']), 1)
        self.assertEqual(self.records['layouts']['node']['count'],
                         'node + 0x7f2 (u16)')
        self.assertEqual(self.records['layouts']['flat']['stride'], '0xb8')
        census = self.records['insertion_census']
        self.assertEqual(len(census), 19)
        for name, entry in census.items():
            self.assertEqual(entry['field_stores'], [], name)
            self.assertEqual(
                entry['stores_at_eight_displacements_nonstack'], 0, name)


if __name__ == '__main__':
    unittest.main()
