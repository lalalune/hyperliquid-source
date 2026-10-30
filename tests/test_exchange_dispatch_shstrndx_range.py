"""exchange_dispatch Elf: a section name string table index outside the
section header table must fail closed with EvidenceError, not escape as
IndexError from the bare raw[shstrndx] lookup."""
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import exchange_dispatch as ed  # noqa: E402


def elf_bytes(shoff=0, shnum=0, shstrndx=0, size=64):
    data = bytearray(size)
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 0x20, 0)
    struct.pack_into('<Q', data, 0x28, shoff)
    struct.pack_into('<HHHHH', data, 0x36, 56, 0, 64, shnum, shstrndx)
    return bytes(data)


def valid_elf():
    data = bytearray(256)
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 0x20, 0)
    struct.pack_into('<Q', data, 0x28, 64)
    struct.pack_into('<HHHHH', data, 0x36, 56, 0, 64, 1, 0)
    struct.pack_into('<IIQQQQIIQQ', data, 64, 0, 3, 0, 0, 128, 8, 0, 0, 1, 0)
    data[128:136] = b'\x00.text\x00'
    return bytes(data)


class ShstrndxRange(unittest.TestCase):
    def test_no_sections_index_zero(self):
        # shnum=0 makes shstrndx=0 out of range (the #167 shape).
        with self.assertRaises(ed.EvidenceError):
            ed.Elf(elf_bytes(shnum=0, shstrndx=0))

    def test_index_beyond_table(self):
        with self.assertRaises(ed.EvidenceError):
            ed.Elf(elf_bytes(shoff=64, shnum=1, shstrndx=5, size=256))

    def test_valid_minimal_elf_parses(self):
        elf = ed.Elf(valid_elf())
        self.assertEqual(elf.sections, {'': (0, 128, 8)})


if __name__ == '__main__':
    unittest.main()
