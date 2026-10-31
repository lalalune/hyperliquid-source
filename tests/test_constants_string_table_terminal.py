"""constants_scan.string_table must include a complete terminal slot.

Sibling of the terminal-operand fixes in open #444 (xref scans): the
scan loop stops at `relro['size'] - 16`, so a complete 16-byte
(pointer, length) slot starting exactly at size - 16 is never examined.
Open #409 only adds the pointer+length .rodata bounds check; it does not
touch this loop bound.
"""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from constants_scan import ScanError, section, string_table


def fixture(relro_size, slots):
    """Minimal ELF64-LE with .rodata, .data.rel.ro and .rela.dyn.

    `slots` is a list of (pointer_va, length) pairs laid out from the
    start of .data.rel.ro; .rela.dyn maps each slot VA to its pointer.
    """
    data = bytearray(0x1000)
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 40, 0x800)
    struct.pack_into('<HHH', data, 58, 64, 5, 1)
    names = b'\0.shstrtab\0.rodata\0.data.rel.ro\0.rela.dyn\0'
    data[0x200:0x200 + len(names)] = names
    rows = [
        (0, 0, 0, 0, 0, 0, 0),
        (1, 3, 0, 0, 0x200, len(names), 0),
        (names.index(b'.rodata'), 1, 2, 0x2000, 0x340, 0x100, 0),
        (names.index(b'.data.rel.ro'), 1, 3, 0x3000, 0x440, relro_size, 0),
        (names.index(b'.rela.dyn'), 4, 0, 0, 0x480, len(slots) * 24, 24),
    ]
    for index, row in enumerate(rows):
        struct.pack_into('<IIQQQQIIQQ', data, 0x800 + index * 64,
                         *row[:6], 0, 0, 1, row[6])
    data[0x340:0x345] = b'alpha'
    data[0x348:0x34C] = b'beta'
    pointers = [0x2000, 0x2008, 0x2010, 0x2018]
    for i, (pointer, length) in enumerate(slots):
        struct.pack_into('<Q', data, 0x448 + i * 16, length)
        struct.pack_into('<QQq', data, 0x480 + i * 24, 0x3000 + i * 16, 8, pointer)
    return bytes(data)


def table(data, names, count):
    return string_table(data, section(data, '.rodata'),
                        section(data, '.data.rel.ro'), names, count)


class StringTableTerminal(unittest.TestCase):
    def test_terminal_slot_is_included(self):
        # Two slots exactly fill the 32-byte section; base finds only the
        # first and reports a longest run of 1.
        va, rows = table(fixture(32, [(0x2000, 5), (0x2008, 4)]),
                         ['alpha', 'beta'], 2)
        self.assertEqual(va, 0x3000)
        self.assertEqual(rows, [(0x3000, 0x2000, 5, 'alpha'),
                                (0x3010, 0x2008, 4, 'beta')])

    def test_single_slot_filling_section_is_included(self):
        va, rows = table(fixture(16, [(0x2000, 5)]), ['alpha'], 1)
        self.assertEqual(va, 0x3000)
        self.assertEqual(rows, [(0x3000, 0x2000, 5, 'alpha')])

    def test_mid_section_table_still_parses(self):
        # Control: the same two slots with trailing space parse on base too.
        va, rows = table(fixture(48, [(0x2000, 5), (0x2008, 4)]),
                         ['alpha', 'beta'], 2)
        self.assertEqual(va, 0x3000)
        self.assertEqual(len(rows), 2)


if __name__ == '__main__':
    unittest.main()
