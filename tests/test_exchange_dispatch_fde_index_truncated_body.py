"""exchange_dispatch fde_index: a file-backed FDE whose 16-byte body runs
past EOF must fail closed with EvidenceError, not escape as struct.error
from the bare unpack_from calls for pc_begin / pc_range."""
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import exchange_dispatch as ed  # noqa: E402

VA_HDR = 0x400000
FDE_VA = VA_HDR + 0x1000
FO = 0x1000


def make_elf(file_len):
    # Full-length buffer first, then truncated to file_len, so the
    # truncated cases keep the FDE bytes that do fit.
    data = bytearray(FO + 16)
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 0x20, 64)    # phoff
    struct.pack_into('<Q', data, 0x28, 128)   # shoff
    struct.pack_into('<HHHHH', data, 0x36, 56, 1, 64, 3, 1)
    struct.pack_into('<IIQQQQ', data, 64, 1, 0, 0, VA_HDR, 0, 0x2000)
    struct.pack_into('<IIQQQQIIQQ', data, 192, 0, 3, 0, 0, 320, 24, 0, 0, 0, 0)
    struct.pack_into('<IIQQQQIIQQ', data, 256, 10, 0, 0, VA_HDR, 344, 20, 0, 0, 0, 0)
    data[320:344] = b'.shstrtab\x00.eh_frame_hdr\x00'
    data[344] = 1
    data[345:348] = bytes([0x1B, 0x03, 0x3B])
    struct.pack_into('<I', data, 352, 1)          # count
    struct.pack_into('<ii', data, 356, 0, 0x1000)  # pc_rel, fde_rel
    # Delta pinned so pc_begin == start; otherwise a mismatch EvidenceError
    # would mask the truncation on base.
    struct.pack_into('<i', data, FO + 8, VA_HDR - FDE_VA - 8)
    struct.pack_into('<I', data, FO + 12, 0x100)   # pc_range
    return bytes(data[:file_len])


class FdeIndexTruncatedBody(unittest.TestCase):
    def test_pc_begin_truncated(self):
        # fo+8 read needs 4 bytes; only 2 remain.
        with self.assertRaises(ed.EvidenceError):
            ed.fde_index(ed.Elf(make_elf(FO + 10)))

    def test_pc_range_truncated(self):
        # pc_begin read fits and matches, but fo+12 needs 4 bytes and
        # only 2 remain.
        with self.assertRaises(ed.EvidenceError):
            ed.fde_index(ed.Elf(make_elf(FO + 14)))

    def test_valid_fde(self):
        starts, ends = ed.fde_index(ed.Elf(make_elf(FO + 16)))
        self.assertEqual((starts, ends), ([VA_HDR], [VA_HDR + 0x100]))


if __name__ == '__main__':
    unittest.main()
