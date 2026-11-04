import tempfile
import unittest
from collections import Counter
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))

import remaining_members_static as m
from artifacts import ROOT

PACKET_DIR = ROOT / 'research/work-items' / m.PACKET_ID
GENERATED = ('records.json', 'frames.txt') + tuple(
    f'{slug}_full_body_{info["range"][0]:x}_{info["range"][1]:x}_objdump.txt'
    for slug, info in sorted(m.BODIES.items()))


def _flip(data, va):
    for sec in m.sections(data):
        if sec['type'] != 8 and sec['address'] <= va < sec['address'] + sec['size']:
            off = sec['offset'] + (va - sec['address'])
            return data[:off] + bytes((data[off] ^ 1,)) + data[off + 1:]
    raise AssertionError(f'no file-backed section covers {va:#x}')


class RemainingMembersStaticTest(unittest.TestCase):
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
        flipped = _flip(self.data, m.BODIES['wide110_search']['range'][0])
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(m.PacketError, 'artifact SHA-256 mismatch'):
                m.generate(flipped, tmp)

    def test_counters(self):
        counters = self.records['counters']
        self.assertEqual(counters, m.EXPECTED)
        self.assertEqual(counters['bodies'], 6)
        self.assertEqual(counters['call_sites'], 11)
        self.assertEqual(counters['flag_only_sites'], 2)
        self.assertEqual(counters['node_position_sites'], 9)
        self.assertEqual(counters['height_consumed_reads'], 0)
        self.assertEqual(counters['clone_body_pairs'], 1)

    def test_body_mutation_fails_its_digest(self):
        start = m.BODIES['signed_u32_search']['range'][0]
        with self.assertRaisesRegex(
                AssertionError, 'signed_u32_search body differs from its pinned digest'):
            m.analyze(_flip(self.data, start))

    def test_caller_mutation_fails_its_digest(self):
        start = m.BOUNDARIES[0x2C81080][0][0]
        with self.assertRaisesRegex(
                AssertionError, 'caller 0x2c81080 differs from its pinned digest'):
            m.analyze(_flip(self.data, start + 0x10))

    def test_call_site_mutation_fails_the_caller_digest(self):
        with self.assertRaisesRegex(
                AssertionError, 'caller 0x4482950 differs from its pinned digest'):
            m.analyze(_flip(self.data, 0x44829AB))

    def test_height_read_mutation_fails_the_caller_digest(self):
        with self.assertRaisesRegex(
                AssertionError, 'caller 0x4473d10 differs from its pinned digest'):
            m.analyze(_flip(self.data, 0x44754B3))

    def test_site_shapes(self):
        classes = Counter(info['class'] for info in m.SITES.values())
        self.assertEqual(classes, {'flag_only': 2, 'node_position': 9})
        forms = Counter(info['flag_form'] for info in m.SITES.values())
        self.assertEqual(forms, {'dword': 9, 'register': 2})
        strides = {info['consumption']['stride'] for info in m.SITES.values()
                   if info['class'] == 'node_position'}
        self.assertEqual(strides, {0x10, 0x14, 0x30, 0x48})
        fallbacks = {info['fallback'] for info in m.SITES.values() if info['fallback']}
        self.assertEqual(fallbacks, {0x4551810, 0x4551C20, 0x45585E0,
                                     0x24C9200, 0x57F7210})
        clone = m.BODIES['wide110_search']['sha256']
        self.assertEqual(m.BODIES['wide110_clone_search']['sha256'], clone)
        self.assertEqual(
            sum(1 for info in m.SITES.values() if not info['fallback']), 2)


if __name__ == '__main__':
    unittest.main()
