"""Actual two-stage lookup, opaque output layout and borrow-comparison controls."""
import itertools
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import cid_lookup_static as cid


@unittest.skipUnless(cid.TARGET.stat().st_size == 91774280, 'materialize node94')
class CidLookupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = cid.TARGET.read_bytes()
        cls.report = cid.analyze(cls.data)

    def test_real_range_widths_branch_distinction_and_source(self):
        self.assertEqual(self.report['range']['bytes'], 712)
        self.assertEqual(self.report['inner_search']['key_step'], 16)
        self.assertEqual(self.report['inner_search']['per_key_value_step'], 20)
        self.assertEqual(self.report['output']['opaque_payload_bytes'], 20)
        self.assertEqual(self.report['sources'][0]['line'], 69)
        self.assertNotEqual(self.report['outer_search']['absent_path'], self.report['inner_search']['absent_path'])
        self.assertFalse(self.report['captured_binary_executed'])

    def test_limb_borrows_against_independent_unsigned_128_ordering(self):
        values = [0, 1, (1 << 63) - 1, 1 << 63, (1 << 64) - 1]
        for elo, ehi, qlo, qhi in itertools.product(values, repeat=4):
            entry, query = (ehi << 64) | elo, (qhi << 64) | qlo
            expected = 1 if entry < query else 255 if entry > query else 0
            self.assertEqual(cid.limb_comparison(elo, ehi, qlo, qhi), expected)
        # Explicit representatives of all nine high/low order relations.
        relations = [(0, 1), (1, 1), (1, 0)]
        for (ehi, qhi), (elo, qlo) in itertools.product(relations, repeat=2):
            entry, query = (ehi << 64) | elo, (qhi << 64) | qlo
            self.assertEqual(cid.limb_comparison(elo, ehi, qlo, qhi),
                             1 if entry < query else 255 if entry > query else 0)

    def test_real_instruction_layout_and_source_corruptions_rejected(self):
        controls = [0x1405258, 0x140526d, 0x1405280, 0x1405299, 0x14052be,
                    0x14052d3, 0x14052de, 0x14052f8, 0x140530a, 0x140530f,
                    0x1405325, 0x1405336, 0x1405352, 0x1405358, 0x1405366,
                    0x140536b, 0x1405381, 0x1405398, 0x14053b0, 0x14053b8,
                    0x14053bb, 0x1405461, 0x14054d2, 0x1edfe6, 0x1e4c4a, 0x5668dc8]
        for va in controls:
            with self.subTest(va=hex(va)):
                changed = bytearray(self.data)
                off, _ = cid.read(changed, va, 1)
                changed[off] ^= 1
                with self.assertRaises(ValueError):
                    cid.analyze(changed)

    def test_real_relocation_retargets_rejected(self):
        sec = next(s for s in cid.sections(self.data) if s['name'] == '.rela.dyn')
        offsets = {struct.unpack_from('<Q', self.data, off)[0]: off
                   for off in range(sec['offset'], sec['offset'] + sec['size'], 24)}
        for slot in cid.RELATIVE:
            with self.subTest(slot=hex(slot)):
                changed = bytearray(self.data)
                changed[offsets[slot] + 16] ^= 1
                with self.assertRaises(ValueError):
                    cid.analyze(changed)

    @unittest.skipUnless(shutil.which('readelf') and shutil.which('objdump'), 'GNU binutils required')
    def test_native_packet_regeneration(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            self.assertEqual(cid.generate(cid.TARGET, out), self.report)
            for name in ['records.json', 'frames.txt', '1405240.objdump.txt']:
                self.assertEqual((out / name).read_bytes(), (cid.PACKET / name).read_bytes(), name)


if __name__ == '__main__':
    unittest.main()
