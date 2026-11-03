import struct
import tempfile
import unittest
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))

import join_helper_element_static as m
from artifacts import ROOT

PACKET_DIR = ROOT / 'research/work-items' / m.PACKET_ID
GENERATED = ('records.json', 'frames.txt',
             'helper_full_body_63efec0_63eff7e_objdump.txt',
             'fallback_full_body_4556410_4556544_objdump.txt')


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


class JoinHelperElementStaticTest(unittest.TestCase):
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
        flipped = _flip(self.data, m.HELPER['range'][0])
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(m.PacketError, 'artifact SHA-256 mismatch'):
                m.generate(flipped, tmp)

    def test_counters(self):
        counters = self.records['counters']
        self.assertEqual(counters, m.EXPECTED)
        self.assertEqual(counters['helper_instructions'], 67)
        self.assertEqual(counters['helper_calls'], 0)
        self.assertEqual(counters['helper_memory_operands'], 0)
        self.assertEqual(counters['helper_div_sites'], 6)
        self.assertEqual(counters['element_derived_stores'], 0)
        self.assertEqual(counters['stores_at_eight_displacements'], 76)
        self.assertEqual(counters['window_callers'], 63)

    def test_helper_mutation_fails_its_digest(self):
        with self.assertRaisesRegex(
                AssertionError, 'helper differs from its pinned digest'):
            m.analyze(_flip(self.data, m.HELPER['range'][0]))

    def test_fallback_mutation_fails_its_digest(self):
        with self.assertRaisesRegex(
                AssertionError, 'fallback differs from its pinned digest'):
            m.analyze(_flip(self.data, m.FALLBACK['range'][0]))

    def test_window_caller_mutation_fails_its_digest(self):
        with self.assertRaisesRegex(
                AssertionError, 'window caller 0x296a390 differs from its '
                                'pinned digest'):
            m.analyze(_flip(self.data, 0x296A390 + 0x10))

    def test_helper_slot_relocation_mutation_fails(self):
        va = _rela_addend_va(self.data, m.HELPER_SLOT)
        with self.assertRaisesRegex(
                AssertionError, 'helper slot 0x64dfaf8 relocation differs'):
            m.analyze(_flip(self.data, va))

    def test_helper_slot_content_mutation_fails(self):
        with self.assertRaisesRegex(
                AssertionError, 'helper slot initialised content is not zero'):
            m.analyze(_flip(self.data, m.HELPER_SLOT))

    def test_contract_and_verdict_shapes(self):
        helper = self.records['helper']
        self.assertEqual(helper['sha256'], m.HELPER['sha256'])
        self.assertEqual(helper['size'], 190)
        self.assertEqual(helper['contract']['kind'],
                         'unsigned 128-by-128 division (__udivti3 shape)')
        self.assertEqual(self.records['slot']['rela_addend'], '0x63efec0')
        self.assertEqual(self.records['slot']['census']
                         ['rip_relative_references'], 305)
        self.assertEqual(self.records['slot']['census']['direct_e8_calls'], 0)
        self.assertEqual(set(self.records['field_verdicts']),
                         {'0x40', '0x58', '0x60', '0x78',
                          '0x80', '0x88', '0x90', '0x98'})
        self.assertEqual(self.records['layouts']['flat']['stride'], '0xb8')
        self.assertEqual(self.records['layouts']['node']['stride'], '0xb0')
        self.assertEqual(self.records['fallback']['stores'], 0)
        self.assertEqual(len(self.records['window']
                             ['stores_at_eight_displacements']), 76)


if __name__ == '__main__':
    unittest.main()
