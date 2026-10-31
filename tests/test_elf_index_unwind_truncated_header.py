"""elf_index.unwind_index must fail closed on a truncated .eh_frame_hdr.

Sibling of the header-bounds fixes in the render tools and
exchange_dispatch: unwind_index reads the entry-count field and the
start/FDE table with bare unpack_from, trusting the section header's
size. sections() exempts SHT_NOBITS sections from its file-bounds
check, so a NOBITS .eh_frame_hdr whose 12-byte header (or table) runs
past EOF escapes every other malformed-input guard as struct.error
instead of the ValueError the module raises for all other bad input.
"""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from elf_index import unwind_index


def build_elf(hdr_off, hdr_size, hdr_type, tail):
    """Minimal ELF64-LE: null section, .eh_frame_hdr, .shstrtab."""
    h = bytearray(64)
    h[0:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', h, 40, 64)
    struct.pack_into('<HHH', h, 58, 64, 3, 2)
    sh = bytearray(3 * 64)
    struct.pack_into('<IIQQQQIIQQ', sh, 64, 1, hdr_type, 0, 0x400000,
                     hdr_off, hdr_size, 0, 0, 1, 0)
    struct.pack_into('<IIQQQQIIQQ', sh, 128, 0, 3, 0, 0, 256, 15, 0, 0, 1, 0)
    return bytes(h) + bytes(sh) + b'\0.eh_frame_hdr\0' + tail


MAGIC = bytes([1, 0x1b, 0x03, 0x3b])


class UnwindTruncatedHeaderTests(unittest.TestCase):
    def test_count_field_past_eof_rejected(self):
        # NOBITS header at 271 with only the 4 magic bytes in file:
        # the count unpack at off + 8 is past EOF.
        data = build_elf(271, 20, 8, MAGIC)
        self.assertEqual(len(data), 275)
        with self.assertRaisesRegex(ValueError, 'Unwind table is truncated'):
            unwind_index(data)

    def test_table_entries_past_eof_rejected(self):
        # Count field present (count 2) but the 16-byte table runs past EOF.
        tail = MAGIC + b'\0\0\0\0' + struct.pack('<I', 2)
        data = build_elf(271, 28, 8, tail)
        with self.assertRaisesRegex(ValueError, 'Unwind table is truncated'):
            unwind_index(data)

    def test_valid_header_still_parses(self):
        # PROGBITS header fully in file, one entry inside .text-like
        # executable section is out of scope here: use count 0, which
        # parses to an empty index without needing executable sections.
        tail = MAGIC + b'\0\0\0\0' + struct.pack('<I', 0)
        data = build_elf(271, 12, 1, tail)
        _secs, entries = unwind_index(data)
        self.assertEqual(entries, [])


if __name__ == '__main__':
    unittest.main()
