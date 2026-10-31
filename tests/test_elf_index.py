from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from elf_index import generate, unwind_index

NAMES = b'\0.text\0.eh_frame\0.eh_frame_hdr\0.shstrtab\0'
# Name offsets inside NAMES: .text=1, .eh_frame=7, .eh_frame_hdr=17, .shstrtab=31.
HDR_VA = 0x402000
HDR_OFF = 0x3000


def build(entries):
    """Minimal ELF64-LE image whose .eh_frame_hdr lists the given (start, fde) pairs."""
    data = bytearray(0x4000)
    data[0:16] = b'\x7fELF\x02\x01\x01' + b'\0' * 9
    struct.pack_into('<HHIQQQIHHHHHH', data, 16,
                     2, 0x3E, 1, 0, 0, 64, 0, 64, 0, 0, 64, 5, 4)

    def section(index, name, typ, flags, addr, off, size):
        struct.pack_into('<IIQQQQIIQQ', data, 64 + index * 64,
                         name, typ, flags, addr, off, size, 0, 0, 1, 0)

    section(1, 1, 1, 0x6, 0x400000, 0x1000, 0x2000)      # .text
    section(2, 7, 1, 0x2, 0x401000, 0x2000, 0x100)       # .eh_frame
    section(3, 17, 1, 0x2, HDR_VA, HDR_OFF, 28)          # .eh_frame_hdr
    section(4, 31, 3, 0, 0, 64 + 5 * 64, len(NAMES))     # .shstrtab
    data[64 + 5 * 64:64 + 5 * 64 + len(NAMES)] = NAMES
    data[HDR_OFF:HDR_OFF + 4] = bytes([1, 0x1b, 0x03, 0x3b])
    struct.pack_into('<i', data, HDR_OFF + 4, 0)         # eh_frame_ptr (unused here)
    struct.pack_into('<I', data, HDR_OFF + 8, len(entries))
    for i, (start, fde) in enumerate(entries):
        struct.pack_into('<ii', data, HDR_OFF + 12 + i * 8, start - HDR_VA, fde - HDR_VA)
    return bytes(data)


class UnwindIndexOrderingTests(unittest.TestCase):
    def test_duplicate_starts_rejected(self):
        data = build([(0x400100, 0x401010), (0x400100, 0x401020)])
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            unwind_index(data)

    def test_duplicate_starts_rejected_by_generate(self):
        data = build([(0x400100, 0x401010), (0x400100, 0x401020)])
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / 'bin'
            binary.write_bytes(data)
            with self.assertRaisesRegex(ValueError, 'duplicate'):
                generate(binary, Path(tmp) / 'out')

    def test_strictly_increasing_starts_accepted(self):
        data = build([(0x400100, 0x401010), (0x400200, 0x401020)])
        _, entries = unwind_index(data)
        self.assertEqual([e['start'] for e in entries], [0x400100, 0x400200])
        self.assertEqual(entries[0]['next_index_upper_bound'], 0x400200)
        self.assertEqual(entries[1]['next_index_upper_bound'], 0x402000)

    def test_unsorted_starts_still_rejected(self):
        data = build([(0x400200, 0x401010), (0x400100, 0x401020)])
        with self.assertRaisesRegex(ValueError, 'not ordered'):
            unwind_index(data)


if __name__ == '__main__':
    unittest.main()
