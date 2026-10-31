import struct
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from constants_scan import ScanError, entries_size


def _truncated(size):
    return b'\x7fELF\x02\x01' + b'\x00' * (size - 6)


def _valid():
    """Minimal header whose only section row names itself '.rela.dyn'."""
    table = b'\x00.rela.dyn\x00'
    data = bytearray(128 + len(table))
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 40, 64)
    struct.pack_into('<HHH', data, 58, 64, 1, 0)
    struct.pack_into('<IIQQQQIIQQ', data, 64,
                     1, 3, 0, 0, 128, len(table), 0, 0, 1, 24)
    data[128:128 + len(table)] = table
    return bytes(data)


class TruncatedHeaderTests(unittest.TestCase):
    def test_short_magic_input_fails_closed(self):
        # On base the bare unpack_from at offset 40 escapes as struct.error;
        # with the fix it raises ScanError like every other malformed
        # section-table case in this function.
        with self.assertRaises(ScanError):
            entries_size(_truncated(6), '.rela.dyn')

    def test_63_byte_input_fails_closed(self):
        with self.assertRaises(ScanError):
            entries_size(_truncated(63), '.rela.dyn')

    def test_valid_header_still_parses(self):
        self.assertEqual(entries_size(_valid(), '.rela.dyn'), 24)


if __name__ == '__main__':
    unittest.main()
