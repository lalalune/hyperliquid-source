"""Node94 entry gates, initialized/uninitialized routes and a real caller."""
import itertools
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import critical_message_static as critical


@unittest.skipUnless(critical.TARGET.stat().st_size == 91774280, 'materialize node94')
class CriticalMessageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = critical.TARGET.read_bytes()
        cls.report = critical.analyze(cls.data)

    def test_actual_gate_caller_and_source_bindings(self):
        self.assertEqual([r['bytes'] for r in self.report['ranges']], [6264, 124])
        self.assertEqual(self.report['first_gate']['accepted_raw_tags'], [13, 14, 30])
        self.assertEqual(self.report['sources'][0]['line'], 291)
        self.assertEqual(self.report['sources'][1]['line'], 219)
        self.assertEqual(self.report['selected_caller']['cleared_fields'], ['qword+0', 'bytes+0x10..+0x14'])
        self.assertFalse(self.report['captured_binary_executed'])

    def test_conditional_predicate_for_every_raw_tag_and_boolean_gate_state(self):
        count = 0
        for tag in range(256):
            for f12, f13, f14, global_byte, helper_al in itertools.product([0, 1], repeat=5):
                if f12 and tag not in {13, 14, 30}:
                    expected = 'tag_gate'
                elif f13 and global_byte:
                    expected = 'global_byte_gate'
                elif f14 and helper_al:
                    expected = 'helper_gate'
                else:
                    expected = 'continue_past_entry_gates'
                self.assertEqual(critical.abstract_gate_reason(f12, tag, f13, global_byte, f14, helper_al), expected)
                count += 1
        self.assertEqual(count, 8192)
        # Byte TEST instructions consume nonzero, not just canonical 1.
        for nonzero in [2, 128, 255]:
            self.assertEqual(critical.abstract_gate_reason(nonzero, 45, 0, 0, 0, 0), 'tag_gate')
            self.assertEqual(critical.abstract_gate_reason(0, 45, nonzero, nonzero, 0, 0), 'global_byte_gate')
            self.assertEqual(critical.abstract_gate_reason(0, 45, 0, 0, nonzero, nonzero), 'helper_gate')

    def test_real_instruction_data_and_source_corruptions_rejected(self):
        controls = [0x143d047, 0x143d059, 0x143d070, 0x143d080, 0x143d08b,
                    0x143d094, 0x143d09b, 0x143d09d, 0x143d0a0, 0x143d0b0,
                    0x143d0cc, 0x143d3d7, 0x143d3ed, 0x143d3f3, 0x143e366,
                    0x4779e60, 0x4779e68, 0x4779e6d, 0x4779e9f,
                    0x1fcf88, 0x566a288, 0x567b248, 0x572e8b8]
        for va in controls:
            with self.subTest(va=hex(va)):
                changed = bytearray(self.data)
                off, _ = critical.read(changed, va, 1)
                changed[off] ^= 1
                with self.assertRaises(ValueError):
                    critical.analyze(changed)

    def test_real_relocation_addend_changes_rejected(self):
        sec = next(s for s in critical.sections(self.data) if s['name'] == '.rela.dyn')
        offsets = {struct.unpack_from('<Q', self.data, off)[0]: off
                   for off in range(sec['offset'], sec['offset'] + sec['size'], 24)}
        for slot in critical.RELATIVE:
            with self.subTest(slot=hex(slot)):
                changed = bytearray(self.data)
                changed[offsets[slot] + 16] ^= 1
                with self.assertRaises(ValueError):
                    critical.analyze(changed)

    @unittest.skipUnless(shutil.which('readelf') and shutil.which('objdump'), 'GNU binutils required')
    def test_native_packet_regeneration_and_wrong_input(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            self.assertEqual(critical.generate(critical.TARGET, out), self.report)
            for name in ['frames.txt', 'records.json', '143d010.objdump.txt', '4779e30.objdump.txt']:
                self.assertEqual((out / name).read_bytes(), (critical.PACKET / name).read_bytes(), name)
            with self.assertRaises(ValueError):
                critical.generate(Path(__file__), out)


if __name__ == '__main__':
    unittest.main()
