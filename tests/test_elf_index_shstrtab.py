import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from elf_index import sections

NAMES = b'\0.text\0.shstrtab\0'


def build(shstrtab_type):
    """Minimal ELF64-LE image whose string table section has the given type.

    The bytes at the table offset are .text content, not a string table:
    a NOBITS section occupies no file bytes, so reading names from that
    offset must fail instead of silently reporting phantom names.
    """
    data = bytearray(0x2000)
    data[0:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 40, 64)          # shoff
    struct.pack_into('<HHH', data, 58, 64, 3, 2)  # entsize, count, names_index

    def section(index, name, typ, flags, addr, off, size):
        struct.pack_into('<IIQQQQIIQQ', data, 64 + index * 64,
                         name, typ, flags, addr, off, size, 0, 0, 1, 0)

    section(0, 0, 0, 0, 0, 0, 0)
    section(1, 1, 1, 0x6, 0x400000, 0x1000, 0x10)  # .text
    section(2, 7, shstrtab_type, 0, 0, 0x1000, len(NAMES))  # .shstrtab
    data[0x1000:0x1000 + len(NAMES)] = NAMES
    return bytes(data)


class ShstrtabTypeTests(unittest.TestCase):
    def test_nobits_shstrtab_rejected(self):
        with self.assertRaises(ValueError):
            sections(build(8))

    def test_strtab_shstrtab_accepted(self):
        names = [row['name'] for row in sections(build(3))]
        self.assertEqual(names, ['', '.text', '.shstrtab'])


if __name__ == '__main__':
    unittest.main()
