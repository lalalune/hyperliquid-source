"""constants_scan.relocations must fail closed on a truncated .rela.dyn.

Sibling of the truncated-relocation-section fixes in the *_static tools
and the sign-guard tools: there the reader raised struct.error or silently
truncated through iter_unpack; here `size // 24` silently drops a trailing
partial entry, so a malformed section still yields a relocation map.
"""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from constants_scan import ScanError, relocations


def fixture(size, entries):
    """Minimal ELF64-LE with .shstrtab and a .rela.dyn of `size` bytes."""
    data = bytearray(0x1000)
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 40, 0x100)
    struct.pack_into('<HHH', data, 58, 64, 3, 1)
    names = b'\0.shstrtab\0.rela.dyn\0'
    data[0x200:0x200 + len(names)] = names
    rows = [
        (0, 0, 0, 0, 0, 0, 0),
        (1, 3, 0, 0, 0x200, len(names), 0),
        (names.index(b'.rela.dyn'), 4, 0, 0, 0x300, size, 24),
    ]
    for index, row in enumerate(rows):
        struct.pack_into('<IIQQQQIIQQ', data, 0x100 + index * 64,
                         *row[:6], 0, 0, 1, row[6])
    for i, (slot, addend) in enumerate(entries):
        struct.pack_into('<QQq', data, 0x300 + i * 24, slot, 8, addend)
    return bytes(data)


class RelocationsTruncation(unittest.TestCase):
    def test_ragged_tail_is_rejected(self):
        # One complete entry plus a trailing byte: base returns the entry
        # and silently drops the partial one.
        with self.assertRaisesRegex(ScanError, 'truncated'):
            relocations(fixture(25, [(0x3000, 0x2002)]))

    def test_partial_entry_only_is_rejected(self):
        # Fewer than 24 bytes: base returns an empty map.
        with self.assertRaisesRegex(ScanError, 'truncated'):
            relocations(fixture(23, []))

    def test_valid_section_still_parses(self):
        self.assertEqual(relocations(fixture(48, [(0x3000, 0x2002), (0x3010, 0x2020)])),
                         {0x3000: 0x2002, 0x3010: 0x2020})

    def test_empty_section_still_parses(self):
        self.assertEqual(relocations(fixture(0, [])), {})


if __name__ == '__main__':
    unittest.main()
