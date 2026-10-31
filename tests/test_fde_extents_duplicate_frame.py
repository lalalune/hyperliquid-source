from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from test_fde_extents import build, SHOFF, OFFSET
from fde_extents import eh_frame_records


def with_duplicate_frame():
    """The base fixture plus a second .eh_frame row pointing at .text bytes.

    The duplicate would fail to parse as .eh_frame if it were the frame, so
    success on base proves eh_frame_records silently reads the first copy.
    """
    data, _ = build()
    duplicate = bytearray(SHOFF + 7 * 64)
    duplicate[:len(data)] = data
    struct.pack_into('<HHH', duplicate, 58, 64, 7, 1)
    names = bytes(data[64:64 + 60])
    row = (names.index(b'.eh_frame\x00'), 1, 2, 0x3000, OFFSET[0x1000], 0x40)
    struct.pack_into('<IIQQQQIIQQ', duplicate, SHOFF + 6 * 64, *row, 0, 0, 1, 0)
    return bytes(duplicate)


class DuplicateFrameTests(unittest.TestCase):
    def test_rejects_duplicate_eh_frame_section(self):
        with self.assertRaises(ValueError):
            eh_frame_records(with_duplicate_frame())

    def test_single_eh_frame_still_passes(self):
        data, _ = build()
        _, fdes = eh_frame_records(data)
        self.assertEqual(len(fdes), 3)


if __name__ == '__main__':
    unittest.main()
