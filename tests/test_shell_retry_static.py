"""Real retry defaults, explicit call-site budget and imported sleep bindings."""
import itertools
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import shell_retry_static as retry


@unittest.skipUnless(retry.TARGET.stat().st_size == 91774280, 'materialize node94')
class ShellRetryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = retry.TARGET.read_bytes()
        cls.report = retry.analyze(cls.data)

    def test_real_default_schedule_and_normal_finite_conversion_vectors(self):
        self.assertEqual([r['bytes'] for r in self.report['ranges']], [739, 110])
        values = self.report['schedule']['binary64_values']
        self.assertEqual(values, [0.001, 0.05, 1.0])
        self.assertNotEqual(values, [0.001, 0.05, 0.1])
        # Only these three finite defaults, not all f64 or actual sleeping.
        microseconds = [int(value * 1000000.0) for value in values]
        self.assertEqual(microseconds, [1000, 50000, 1000000])
        for micro, expected in zip(microseconds, [(0, 1000000), (0, 50000000), (1, 0)]):
            seconds = ((micro * 0x431bde82d7b634db) >> 64) >> 18
            nanos = (micro - seconds * 1000000) * 1000
            self.assertEqual((seconds, nanos), expected)
            self.assertEqual(seconds, micro // 1000000)
        self.assertFalse(self.report['captured_binary_executed'])

    def test_explicit_attempt_paths_for_all_short_outcome_sequences(self):
        for length in range(6):
            for outcomes in itertools.product([False, True], repeat=length + 1):
                trace, status = retry.explicit_attempt_trace(length, outcomes)
                first_success = next((i for i, succeeded in enumerate(outcomes) if succeeded), None)
                calls = [event for event in trace if event in {'initial_call', 'sleep_then_loop_call'}]
                self.assertEqual(len(calls), first_success + 1 if first_success is not None else length + 1)
                self.assertEqual(status, 'zero_return' if first_success is not None else 'exhausted')
                self.assertEqual(trace[-1] == 'format_then_distinct_helper', first_success is None)
        self.assertEqual(retry.explicit_attempt_trace(0, [False])[0], ['initial_call', 'format_then_distinct_helper'])
        self.assertEqual(len(retry.explicit_attempt_trace(3, [False] * 4)[0]), 5)  # four calls plus formatting event
        self.assertFalse(self.report['exhaustion']['extra_explicit_wait_slot_call'])

    def test_actual_instruction_data_and_reference_value_controls(self):
        controls = [0x13c9093, 0x13c90b7, 0x13c90c0, 0x13c90d2, 0x13c90f6,
                    0x13c9129, 0x13c91ba, 0x13c91e7, 0x13c920c, 0x13c920f,
                    0x13c922d, 0x13c9238, 0x13c9256, 0x13c9262, 0x13c9272,
                    0x13c927e, 0x13c9285, 0x13c92e7, 0x13c9301, 0x14b5572,
                    0x216dd8, 0x216de0, 0x216de8, 0x20ae60, 0x1fceaf,
                    0x1ef309, 0x5666e48]
        for va in controls:
            with self.subTest(va=hex(va)):
                changed = bytearray(self.data)
                off, _ = retry.read(changed, va, 1)
                changed[off] ^= 1
                with self.assertRaises(ValueError):
                    retry.analyze(changed)
        changed = bytearray(self.data)
        off, _ = retry.read(changed, 0x216de8, 8)
        changed[off:off + 8] = struct.pack('<d', 0.1)
        with self.assertRaisesRegex(ValueError, 'default retry schedule'):
            retry.analyze(changed)

    def test_actual_relocation_and_dynamic_symbol_controls(self):
        secs = retry.sections(self.data)
        rela = next(s for s in secs if s['name'] == '.rela.dyn')
        offsets = {struct.unpack_from('<Q', self.data, off)[0]: off
                   for off in range(rela['offset'], rela['offset'] + rela['size'], 24)}
        for slot in retry.RELATIVE:
            changed = bytearray(self.data)
            changed[offsets[slot] + 16] ^= 1
            with self.assertRaises(ValueError):
                retry.analyze(changed)
        for slot in [0x576e8d0, 0x576e8d8]:
            changed = bytearray(self.data)
            changed[offsets[slot] + 12] ^= 1  # dynsym index, not the zero GOT bytes
            with self.assertRaises(ValueError):
                retry.analyze(changed)
        self.assertEqual([r['name'] for r in self.report['sleep_imports']], ['nanosleep', '__errno_location'])

    @unittest.skipUnless(shutil.which('readelf') and shutil.which('objdump'), 'GNU binutils required')
    def test_native_packet_regeneration(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            self.assertEqual(retry.generate(retry.TARGET, out), self.report)
            for name in ['records.json', 'frames.txt', '13c9080.objdump.txt', '14b5530.objdump.txt']:
                self.assertEqual((out / name).read_bytes(), (retry.PACKET / name).read_bytes(), name)


if __name__ == '__main__':
    unittest.main()
