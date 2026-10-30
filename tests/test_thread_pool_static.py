"""Real pool clamp, num_cpus source/import bindings and affinity bit coverage."""
import itertools
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import thread_pool_static as pool


@unittest.skipUnless(pool.TARGET.stat().st_size == 91774280, 'materialize node94')
class ThreadPoolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = pool.TARGET.read_bytes()
        cls.report = pool.analyze(cls.data)

    def test_real_ranges_sources_and_imports(self):
        self.assertEqual([r['bytes'] for r in self.report['ranges']], [318, 312])
        self.assertEqual(self.report['provider']['affinity_bits'], 1024)
        self.assertEqual([r['name'] for r in self.report['imports']], ['sched_getaffinity', 'sysconf'])
        self.assertIn('num_cpus-1.17.0', self.report['sources'][2]['path'])
        self.assertEqual([s['line'] for s in self.report['sources'][2:]], [114, 45])
        self.assertEqual(self.report['builder']['success_raw_tag'], 3)
        self.assertFalse(self.report['captured_binary_executed'])

    def test_clamp_against_independent_formula_and_signed_fallback(self):
        counts = list(range(17)) + [63, 64, 65, 1 << 63, (1 << 64) - 1]
        bounds = [0, 1, 2, 3, 4, 63, 64, (1 << 64) - 1]
        cases = 0
        for count, a, b in itertools.product(counts, bounds, bounds):
            low, high = sorted([a, b])
            expected = max(1, min(max(count // 4, low), high))
            self.assertEqual(pool.requested_threads(count, a, b), expected)
            self.assertEqual(pool.requested_threads(count, a, b), pool.requested_threads(count, b, a))
            cases += 1
        self.assertEqual(cases, 1408)
        self.assertEqual(pool.requested_threads(0, 0, 0), 1)  # floor can exceed a zero upper bound
        for raw in [0, 1, 2, 3, 1024, (1 << 63) - 1, 1 << 63, (1 << 64) - 1]:
            signed = int.from_bytes(raw.to_bytes(8, 'little'), 'little', signed=True)
            self.assertEqual(pool.sysconf_fallback(raw), max(1, signed))

    def test_affinity_pair_indexing_covers_every_bit_once(self):
        visits = []
        for i in range(0, 1024, 2):
            word_index, bit = i >> 6, i & 0x3e
            visits += [word_index * 64 + bit, word_index * 64 + bit + 1]
        self.assertEqual(visits, list(range(1024)))
        # A disjoint visit to every bit proves linear reduction over arbitrary
        # masks. Single-bit basis controls catch word/bit shifts, not randoms.
        for position in range(1024):
            mask = 1 << position
            words = [(mask >> (64 * i)) & ((1 << 64) - 1) for i in range(16)]
            self.assertEqual(pool.affinity_count(words), 1)
        for mask in [0, (1 << 1024) - 1, int('aa' * 128, 16), int('55' * 128, 16),
                     (1 << 63) | (1 << 64) | (1 << 1023)]:
            words = [(mask >> (64 * i)) & ((1 << 64) - 1) for i in range(16)]
            self.assertEqual(pool.affinity_count(words), mask.bit_count())

    def test_actual_semantic_bytes_relocations_and_imports_reject_changes(self):
        controls = [0x13cba58, 0x13cba62, 0x13cba66, 0x13cba6d, 0x13cba74,
                    0x13cba86, 0x13cba94, 0x13cbac9, 0x13cbad4, 0x13cbadb,
                    0x4e06880, 0x4e0688d, 0x4e068d3, 0x4e0690a, 0x4e0690e,
                    0x4e06911, 0x4e06919, 0x4e0691b, 0x4e0692b, 0x4e06934,
                    0x4e06953, 0x4e06957, 0x4e06962, 0x4e0696c, 0x4e06981,
                    0x216f9d, 0x1f1396, 0x5747fe8]
        for va in controls:
            with self.subTest(va=hex(va)):
                changed = bytearray(self.data)
                off, _ = pool.read(changed, va, 1)
                changed[off] ^= 1
                with self.assertRaises(ValueError):
                    pool.analyze(changed)
        sec = next(s for s in pool.sections(self.data) if s['name'] == '.rela.dyn')
        offsets = {struct.unpack_from('<Q', self.data, off)[0]: off
                   for off in range(sec['offset'], sec['offset'] + sec['size'], 24)}
        for slot in pool.RELATIVE:
            changed = bytearray(self.data)
            changed[offsets[slot] + 16] ^= 1
            with self.assertRaises(ValueError):
                pool.analyze(changed)
        for slot in [0x5776b70, 0x57708a8]:
            changed = bytearray(self.data)
            changed[offsets[slot] + 12] ^= 1
            with self.assertRaises(ValueError):
                pool.analyze(changed)

    @unittest.skipUnless(shutil.which('readelf') and shutil.which('objdump'), 'GNU binutils required')
    def test_native_regeneration_and_wrong_input(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            self.assertEqual(pool.generate(pool.TARGET, out), self.report)
            for name in ['records.json', 'frames.txt', '13cba40.objdump.txt', '4e06870.objdump.txt']:
                self.assertEqual((out / name).read_bytes(), (pool.PACKET / name).read_bytes(), name)
            with self.assertRaises(ValueError):
                pool.generate(Path(__file__), out)


if __name__ == '__main__':
    unittest.main()
