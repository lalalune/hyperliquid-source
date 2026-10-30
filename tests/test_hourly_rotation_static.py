"""Actual captured aggregate-output and caller controls; no target execution."""
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import hourly_rotation_static as hourly


@unittest.skipUnless(hourly.TARGET.stat().st_size == 91774280, 'materialize node94')
class HourlyRotationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = hourly.TARGET.read_bytes()
        cls.report = hourly.analyze(cls.data)

    def test_actual_output_member_and_symbol_bindings(self):
        self.assertEqual([r['bytes'] for r in self.report['ranges']], [902, 387])
        self.assertEqual(self.report['aggregate_copy_bytes'], 176)
        self.assertEqual(self.report['member_copy_bytes'], 80)
        self.assertEqual(self.report['memcpy']['symbol'], 'memcpy')
        self.assertEqual(self.report['relative_bindings']['0x576ef78'], '0x14019b0')
        self.assertEqual(self.report['object_field_offsets']['mode_byte_store'], '0xa8')
        self.assertFalse(self.report['captured_binary_executed'])

    def test_pointer_width_return_and_cleanup_corruptions_rejected(self):
        for va in [0x14019c3, 0x1401a0f, 0x1401a1a, 0x1401b38,
                   0x1401b42, 0x1401b5a, 0x1401bcf, 0x1401bf9,
                   0x1401ca4, 0x1401784, 0x14017b7, 0x1e9396]:
            with self.subTest(va=hex(va)):
                changed = bytearray(self.data)
                offset, _ = hourly.locate(changed, va, 1)
                changed[offset] ^= 1
                with self.assertRaises(ValueError):
                    hourly.analyze(changed)

    def test_memcpy_and_entry_relocations_are_real_requirements(self):
        position = int(self.report['memcpy']['relocation_file_offset'], 16)
        changed = bytearray(self.data)
        changed[position + 8] ^= 1
        with self.assertRaisesRegex(ValueError, 'dynamic symbol'):
            hourly.analyze(changed)
        changed = bytearray(self.data)
        # Change the caller's GOT displacement, retaining the call opcode.
        offset, _ = hourly.locate(changed, 0x1401790, 1)
        changed[offset] ^= 1
        with self.assertRaisesRegex(ValueError, 'target'):
            hourly.analyze(changed)

    @unittest.skipUnless(shutil.which('readelf') and shutil.which('objdump'), 'GNU binutils required')
    def test_native_packet_regenerates_identically(self):
        packet = ROOT / 'research/work-items/RE-001-hourly-rotation-abi-94'
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            self.assertEqual(hourly.generate(hourly.TARGET, output), self.report)
            for name in ['records.json', 'frames.txt', '14019b0.objdump.txt', '14016d0.objdump.txt']:
                self.assertEqual((output / name).read_bytes(), (packet / name).read_bytes(), name)

    def test_wrong_capture_rejected_before_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'wrong.elf'
            path.write_bytes(b'not the capture')
            output = Path(directory) / 'out'
            with self.assertRaises(ValueError):
                hourly.generate(path, output)
            self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
