"""Real node94 wrapper controls and a conditional end-of-input predicate."""
import itertools
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import json_trailing_static as trailing


@unittest.skipUnless(trailing.TARGET.stat().st_size == 91774280, 'materialize node94')
class JsonTrailingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = trailing.TARGET.read_bytes()
        cls.report = trailing.analyze(cls.data)

    def test_real_function_state_and_call_bindings(self):
        self.assertEqual([r['bytes'] for r in self.report['ranges']], [440, 14705])
        self.assertEqual(self.report['tail_check']['accepted_bytes'], [9, 10, 13, 32])
        self.assertEqual(self.report['tail_check']['local_error_code'], '0x16')
        self.assertEqual(self.report['initial_delegate']['target'], '0x15c0d90')
        self.assertFalse(self.report['captured_binary_executed'])

    def test_every_byte_and_pair_against_independent_json_whitespace_class(self):
        # Four JSON whitespace bytes, not Python bytes.isspace() or Rust's
        # different ASCII class. This models only the post-delegate suffix.
        allowed = {9, 10, 13, 32}
        for byte in range(256):
            result = trailing.conditional_tail(bytes([byte]))
            self.assertEqual(result['local_error_code'] is None, byte in allowed)
        for a, b in itertools.product(range(256), repeat=2):
            suffix = bytes([a, b])
            expected_count = next((i for i, value in enumerate(suffix) if value not in allowed), 2)
            result = trailing.conditional_tail(suffix)
            self.assertEqual(result['consumed'], expected_count)
            self.assertEqual(result['local_error_code'], None if expected_count == 2 else 0x16)
        self.assertEqual(trailing.conditional_tail(b''), {'consumed': 0, 'local_error_code': None})

    def test_form_feed_distinguishes_ascii_pretrim_and_tail_check(self):
        rust_ascii = {9, 10, 12, 13, 32}  # stamped core::num u8 contract
        sample = b'{}\x0c'
        end = len(sample)
        while end and sample[end - 1] in rust_ascii:
            end -= 1
        self.assertEqual(sample[:end], b'{}')
        # Conditional witness: initial delegate consumed {}, cursor=2.
        self.assertEqual(trailing.conditional_tail(sample[2:])['local_error_code'], 0x16)
        self.assertEqual(trailing.conditional_tail(b'\x0b')['local_error_code'], 0x16)
        self.assertEqual(trailing.conditional_tail(b' \t\r\n')['local_error_code'], None)
        self.assertEqual(trailing.conditional_tail(b' \x0c')['consumed'], 1)
        # Negative control on the classifier model itself, separate from the
        # actual-byte corruption controls below.
        self.assertEqual(trailing.conditional_tail(b'\x0c', mask=0x100002600 | (1 << 12))['local_error_code'], None)

    def test_real_instruction_corruptions_below_admission_hash_rejected(self):
        controls = [0x15ba025, 0x15ba02b, 0x15ba05c, 0x15ba061, 0x15ba06e,
                    0x15ba0c0, 0x15ba0c5, 0x15ba0cb, 0x15ba0da, 0x15ba0f4,
                    0x15ba0f8, 0x15ba0fa, 0x15ba0fd, 0x15ba100, 0x15ba105,
                    0x15ba10e, 0x15ba115, 0x15ba142, 0x15ba152, 0x15ba159,
                    0x15ba15b, 0x1613e00, 0x1613e09]
        for va in controls:
            with self.subTest(va=hex(va)):
                changed = bytearray(self.data)
                off, _ = trailing.read(changed, va, 1)
                changed[off] ^= 1
                with self.assertRaises(ValueError):
                    trailing.analyze(changed)

    @unittest.skipUnless(shutil.which('readelf') and shutil.which('objdump'), 'GNU binutils required')
    def test_native_regeneration_and_wrong_input(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            self.assertEqual(trailing.generate(trailing.TARGET, out), self.report)
            for name in ['frames.txt', 'records.json', '15ba010.objdump.txt', '1611910.objdump.txt']:
                self.assertEqual((out / name).read_bytes(), (trailing.PACKET / name).read_bytes(), name)
            with self.assertRaises(ValueError):
                trailing.generate(Path(__file__), out)


if __name__ == '__main__':
    unittest.main()
