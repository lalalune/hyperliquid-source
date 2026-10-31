import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from elf_index import sections


def build(names):
    """Minimal ELF64-LE image with the given section-name string table.

    Layout mirrors the shstrtab builder in the NOBITS test: three
    sections (null, .text, .shstrtab), with the .text entry's name
    offset pointing at the second byte of the table so a table of
    b'\\x00\\xff\\x00...' makes the .text name non-UTF-8.
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
    section(2, names.index(b'.shstrtab'), 3, 0, 0, 0x1000, len(names))
    data[0x1000:0x1000 + len(names)] = names
    return bytes(data)


VALID_NAMES = b'\x00.text\x00.shstrtab\x00'
BAD_NAMES = b'\x00\xff\x00.shstrtab\x00'


class SectionNameEncodingTests(unittest.TestCase):
    def test_non_utf8_section_name_rejected(self):
        # sections() raises ValueError diagnostics for every other
        # malformed section table; a non-UTF-8 name must fail the same
        # way, not escape as a raw codec error. UnicodeDecodeError is
        # a ValueError subclass, so the type check is what separates
        # the defect from the fix.
        with self.assertRaises(ValueError) as ctx:
            sections(build(BAD_NAMES))
        self.assertIs(type(ctx.exception), ValueError)
        self.assertEqual(str(ctx.exception), 'Invalid section name encoding')

    def test_valid_names_accepted(self):
        names = [row['name'] for row in sections(build(VALID_NAMES))]
        self.assertEqual(names, ['', '.text', '.shstrtab'])


if __name__ == '__main__':
    unittest.main()
