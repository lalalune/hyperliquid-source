import struct
import tempfile
import unittest
from collections import Counter
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))

import join_callee_static as m
from artifacts import ROOT

PACKET_DIR = ROOT / 'research/work-items' / m.PACKET_ID
GENERATED = ('records.json', 'frames.txt',
             'join_callee_full_body_36a0d80_36a0fd6_objdump.txt')


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


class JoinCalleeStaticTest(unittest.TestCase):
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
        flipped = _flip(self.data, m.CALLEE['range'][0])
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(m.PacketError, 'artifact SHA-256 mismatch'):
                m.generate(flipped, tmp)

    def test_counters(self):
        counters = self.records['counters']
        self.assertEqual(counters, m.EXPECTED)
        self.assertEqual(counters['call_sites'], 4)
        self.assertEqual(counters['join_call_sites'], 3)
        self.assertEqual(counters['element_loads'], 8)
        self.assertEqual(counters['element_stores'], 0)
        self.assertEqual(counters['helper_calls'], 7)
        self.assertEqual(counters['slot_rela_entries'], 1)

    def test_callee_mutation_fails_its_digest(self):
        with self.assertRaisesRegex(
                AssertionError, 'callee differs from its pinned digest'):
            m.analyze(_flip(self.data, m.CALLEE['range'][0]))

    def test_caller_mutation_fails_its_digest(self):
        with self.assertRaisesRegex(
                AssertionError, 'caller 0x2a89500 differs from its pinned digest'):
            m.analyze(_flip(self.data, 0x2A89500 + 0x10))

    def test_slot_relocation_mutation_fails(self):
        va = _rela_addend_va(self.data, m.SLOT)
        with self.assertRaisesRegex(
                AssertionError, 'slot 0x64e7198 relocation differs'):
            m.analyze(_flip(self.data, va))

    def test_slot_content_mutation_fails(self):
        with self.assertRaisesRegex(
                AssertionError, 'slot initialised content is not zero'):
            m.analyze(_flip(self.data, m.SLOT))

    def test_site_shapes(self):
        kinds = Counter(info['kind'] for info in m.CALL_SITES.values())
        self.assertEqual(kinds, {'join': 3, 'consumer_phase': 1})
        self.assertEqual(set(m.ELEMENT_LOADS),
                         {0x40, 0x58, 0x60, 0x78, 0x80, 0x88, 0x90, 0x98})
        self.assertEqual(self.records['slot']['rela_addend'], '0x36a0d80')
        self.assertEqual(self.records['callee']['sha256'], m.CALLEE['sha256'])


if __name__ == '__main__':
    unittest.main()
