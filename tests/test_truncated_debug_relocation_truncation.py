"""Synthetic-ELF controls for truncated_debug_static.source_bindings truncation.

The real node #94 binary is an LFS pointer on this machine, so these tests
build a minimal ELF64-LE document in memory: a .rela.dyn section, the
.shstrtab it names, and a .rodata section carrying the expected source-path
bytes at PATH_VA (source_bindings checks the path first), with the section
headers placed before the relocation bytes so a trailing partial entry sits
at end of file.
"""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from truncated_debug_static import PATH_VA, SLOTS, SOURCE, source_bindings


def build(rela):
    shstr = b'\x00.rela.dyn\x00.shstrtab\x00.rodata\x00'
    shstr_off = 64
    shoff = shstr_off + len(shstr)
    rodata_off = shoff + 4 * 64
    rela_off = rodata_off + len(SOURCE)
    header = bytearray(64)
    header[0:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', header, 40, shoff)
    struct.pack_into('<HHH', header, 58, 64, 4, 2)
    rows = b''
    rows += struct.pack('<IIQQQQIIQQ', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    rows += struct.pack('<IIQQQQIIQQ', 1, 4, 0, 0, rela_off, len(rela), 0, 0, 0, 0)
    rows += struct.pack('<IIQQQQIIQQ', 11, 3, 0, 0, shstr_off, len(shstr), 0, 0, 0, 0)
    rows += struct.pack('<IIQQQQIIQQ', 21, 1, 0, PATH_VA, rodata_off, len(SOURCE), 0, 0, 0, 0)
    return bytes(header) + shstr + rows + SOURCE + rela


def pack():
    return b''.join(struct.pack('<QQq', slot, 8, PATH_VA) for slot in SLOTS)


class TruncatedDebugRelocationTruncationTests(unittest.TestCase):
    def test_valid_relocation_section_returns_all_slots(self):
        self.assertEqual(len(source_bindings(build(pack()))), len(SLOTS))

    def test_trailing_byte_rejected_with_value_error(self):
        with self.assertRaisesRegex(ValueError, 'Truncated relocation section'):
            source_bindings(build(pack() + b'\x00'))

    def test_partial_trailing_entry_rejected_with_value_error(self):
        with self.assertRaisesRegex(ValueError, 'Truncated relocation section'):
            source_bindings(build(pack() + b'\x00' * 5))


if __name__ == '__main__':
    unittest.main()
