import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import bridge_inventory as bi


def magic_prefixed(length):
    return b'\x7fELF\x02\x01' + b'\x00' * (length - 6)


class ShortHeaderTests(unittest.TestCase):
    def test_short_magic_prefixed_inputs_fail_closed(self):
        # Each length below 56 leaves at least one header field unreadable,
        # so the phoff/phentsize unpacks escaped as struct.error on base.
        for length in (6, 20, 39, 40, 55):
            with self.subTest(length=length), self.assertRaises(ValueError):
                bi.load_segments(magic_prefixed(length))

    def test_valid_header_still_parses(self):
        header = bytearray(64 + 56)
        header[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<Q', header, 32, 64)  # phoff
        struct.pack_into('<HH', header, 54, 56, 1)  # phentsize, phnum
        struct.pack_into('<IIQQQQ', header, 64, 1, 5, 0, 0x1000, 0, 16)
        rows = bi.load_segments(bytes(header))
        self.assertEqual(rows, [(0, 0x1000, 16, 5)])


if __name__ == '__main__':
    unittest.main()
