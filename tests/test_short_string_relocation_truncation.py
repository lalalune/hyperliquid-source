"""Synthetic-ELF controls for short_string_static.relevant_relocations truncation.

The real node #94 binary is an LFS pointer on this machine, so these tests
build a minimal ELF64-LE document in memory: a .rela.dyn section plus the
.shstrtab it names, with the section headers placed before the relocation
bytes so a trailing partial entry sits at end of file.
"""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from short_string_static import SLOTS, relevant_relocations

WANTED = {**SLOTS, 0x566A990: 0x1EA56A, 0x566A9A8: 0x1EA56A, 0x566A9C0: 0x1EA56A}


def build(rela):
    shstr = b'\x00.rela.dyn\x00.shstrtab\x00'
    shstr_off = 64
    shoff = shstr_off + len(shstr)
    rela_off = shoff + 3 * 64
    header = bytearray(64)
    header[0:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', header, 40, shoff)
    struct.pack_into('<HHH', header, 58, 64, 3, 2)
    rows = b''
    rows += struct.pack('<IIQQQQIIQQ', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    rows += struct.pack('<IIQQQQIIQQ', 1, 4, 0, 0, rela_off, len(rela), 0, 0, 0, 0)
    rows += struct.pack('<IIQQQQIIQQ', 11, 3, 0, 0, shstr_off, len(shstr), 0, 0, 0, 0)
    return bytes(header) + shstr + rows + rela


def pack():
    return b''.join(struct.pack('<QQq', slot, 8, addend)
                    for slot, addend in sorted(WANTED.items()))


class ShortStringRelocationTruncationTests(unittest.TestCase):
    def test_valid_relocation_section_returns_all_slots(self):
        self.assertEqual(len(relevant_relocations(build(pack()))), len(WANTED))

    def test_trailing_byte_rejected_with_value_error(self):
        with self.assertRaisesRegex(ValueError, 'Truncated relocation section'):
            relevant_relocations(build(pack() + b'\x00'))

    def test_partial_trailing_entry_rejected_with_value_error(self):
        with self.assertRaisesRegex(ValueError, 'Truncated relocation section'):
            relevant_relocations(build(pack() + b'\x00' * 5))


if __name__ == '__main__':
    unittest.main()
