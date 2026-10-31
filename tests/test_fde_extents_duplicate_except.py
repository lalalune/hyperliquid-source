from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from test_fde_extents import build, SHOFF
from fde_extents import fde_extents


def with_duplicate_except_table():
    """The base fixture plus a second .gcc_except_table row at another address."""
    data, _ = build()
    duplicate = bytearray(SHOFF + 7 * 64)
    duplicate[:len(data)] = data
    struct.pack_into('<HHH', duplicate, 58, 64, 7, 1)
    row = struct.unpack_from('<IIQQQQIIQQ', data, SHOFF + 5 * 64)
    duplicate_row = (row[0], row[1], row[2], 0x5000, row[4], row[5], row[6], row[7], row[8], row[9])
    struct.pack_into('<IIQQQQIIQQ', duplicate, SHOFF + 6 * 64, *duplicate_row)
    return bytes(duplicate)


class DuplicateExceptTableTests(unittest.TestCase):
    def test_rejects_duplicate_gcc_except_table(self):
        with self.assertRaises(ValueError):
            fde_extents(with_duplicate_except_table())

    def test_single_except_table_still_passes(self):
        data, _ = build()
        summary, _, _ = fde_extents(data)
        self.assertEqual(summary['with_lsda'], 1)


if __name__ == '__main__':
    unittest.main()
