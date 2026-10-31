"""Synthetic-ELF controls for receiver_poll_static.relocations truncation.

The real node #94 binary is an LFS pointer on this machine, so these tests
build a minimal ELF64-LE document in memory: a .rela.dyn section plus the
.shstrtab it names, a .dynsym section (linked from .rela.dyn) and a .dynstr
section carrying the 'exit' name that relocations() resolves for the exit
import slot, with the section headers placed before the relocation bytes so
a trailing partial entry sits at end of file.
"""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from receiver_poll_static import RELATIVE, relocations

EXIT = 0x5777378


def build(rela):
    shstr = b'\x00.rela.dyn\x00.shstrtab\x00.dynsym\x00.dynstr\x00'
    shstr_off = 64
    shoff = shstr_off + len(shstr)
    dynsym_off = shoff + 5 * 64
    dynstr = b'exit\x00'
    dynstr_off = dynsym_off + 24
    rela_off = dynstr_off + len(dynstr)
    header = bytearray(64)
    header[0:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', header, 40, shoff)
    struct.pack_into('<HHH', header, 58, 64, 5, 2)
    rows = b''
    rows += struct.pack('<IIQQQQIIQQ', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    rows += struct.pack('<IIQQQQIIQQ', 1, 4, 0, 0, rela_off, len(rela), 3, 0, 0, 0)
    rows += struct.pack('<IIQQQQIIQQ', 11, 3, 0, 0, shstr_off, len(shstr), 0, 0, 0, 0)
    rows += struct.pack('<IIQQQQIIQQ', 21, 11, 0, 0, dynsym_off, 24, 4, 0, 0, 24)
    rows += struct.pack('<IIQQQQIIQQ', 29, 3, 0, 0, dynstr_off, len(dynstr), 0, 0, 0, 0)
    dynsym = struct.pack('<IBBHQQ', 0, 0, 0, 0, 0, 0)
    return bytes(header) + shstr + rows + dynsym + dynstr + rela


def pack():
    out = b''.join(struct.pack('<QQq', slot, 8, addend)
                   for slot, addend in sorted(RELATIVE.items()))
    out += struct.pack('<QQq', EXIT, (0 << 32) | 6, 0)
    return out


class ReceiverPollRelocationTruncationTests(unittest.TestCase):
    def test_valid_relocation_section_returns_all_slots(self):
        self.assertEqual(len(relocations(build(pack()))), len(RELATIVE) + 1)

    def test_trailing_byte_rejected_with_value_error(self):
        with self.assertRaisesRegex(ValueError, 'Truncated relocation section'):
            relocations(build(pack() + b'\x00'))

    def test_partial_trailing_entry_rejected_with_value_error(self):
        with self.assertRaisesRegex(ValueError, 'Truncated relocation section'):
            relocations(build(pack() + b'\x00' * 5))


if __name__ == '__main__':
    unittest.main()
