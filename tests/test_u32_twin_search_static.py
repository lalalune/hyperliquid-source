import tempfile
import unittest
from collections import Counter
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))

import u32_twin_search_static as u
from artifacts import ROOT


def _flip(data, va):
    for sec in u.sections(data):
        if sec['type'] != 8 and sec['address'] <= va < sec['address'] + sec['size']:
            off = sec['offset'] + (va - sec['address'])
            return data[:off] + bytes((data[off] ^ 1,)) + data[off + 1:]
    raise AssertionError(f'no file-backed section covers {va:#x}')


class U32TwinSearchStaticTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT / 'artifacts/node/115/hl-node').read_bytes()
        cls.records = u.analyze(cls.data)

    def test_committed_artifacts_regenerate_byte_for_byte(self):
        with tempfile.TemporaryDirectory() as tmp:
            u.generate(self.data, tmp)
            for name in ('records.json', 'frames.txt',
                         'u32_twin_search_full_body_35bf500_35bf592_objdump.txt'):
                self.assertEqual((u.PACKET_DIR / name).read_bytes(),
                                 (Path(tmp) / name).read_bytes(), name)

    def test_generate_authenticates_before_writing(self):
        flipped = _flip(self.data, u.U32TWIN_START)
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(u.PacketError, 'artifact SHA-256 mismatch'):
                u.generate(flipped, tmp)

    def test_counters_and_site_classes(self):
        counters = self.records['counters']
        self.assertEqual(counters, u.EXPECTED)
        self.assertEqual(counters['call_sites'], 6)
        self.assertEqual(counters['flag_only_sites'], 6)
        self.assertEqual(counters['node_position_sites'], 0)
        self.assertEqual(counters['flag_byte_sites'], 6)
        self.assertEqual(counters['height_consumed_reads'], 0)
        self.assertEqual(counters['height_reads'], 219)
        self.assertEqual(counters['height_vector_copy_reads'], 96)
        self.assertEqual(counters['height_other_phase_reads'], 123)

    def test_body_mutation_fails_pinned_digest(self):
        flipped = _flip(self.data, 0x35bf520)
        with self.assertRaisesRegex(u.PacketError, 'u32 twin body differs from its pinned digest'):
            u.analyze(flipped)

    def test_caller_mutation_fails_its_digest(self):
        flipped = _flip(self.data, 0x2c44100)
        with self.assertRaisesRegex(u.PacketError, 'caller 0x2c440c0 differs from its pinned digest'):
            u.analyze(flipped)

    def test_call_site_byte_mutation_breaks_owning_caller(self):
        flipped = _flip(self.data, 0x2c4437a)
        with self.assertRaisesRegex(u.PacketError, 'caller 0x2c440c0 differs from its pinned digest'):
            u.analyze(flipped)

    def test_height_read_mutation_fails_owning_caller(self):
        flipped = _flip(self.data, 0x2c44220)
        with self.assertRaisesRegex(u.PacketError, 'caller 0x2c440c0 differs from its pinned digest'):
            u.analyze(flipped)

    def test_presentations_record_forms_and_flag_positions(self):
        sites = u.SITES
        self.assertEqual(len(sites), 6)
        self.assertEqual(Counter(s['presentation'] for s in sites.values()),
                         Counter({'embedded_frame': 3, 'embedded_register': 3}))
        self.assertEqual(Counter(s['record_form'] for s in sites.values()),
                         Counter({'lea': 3, 'register': 3}))
        for site, info in sites.items():
            self.assertEqual(info['class'], 'flag_only')
            self.assertEqual(info['flag'], site + 5)
            self.assertIsNone(info['triple'])


if __name__ == '__main__':
    unittest.main()
