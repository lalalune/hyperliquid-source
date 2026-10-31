"""Synthetic-ELF controls for receiver_poll_static.relocations truncation.

A partial trailing relocation entry must not be unpacked. At end of file that
read raises struct.error; when the file continues, the same read treats the
next section's bytes as a receiver relocation.
"""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from receiver_poll_static import RELATIVE, relocations


def build(rela, extra=b''):
    shstr = b'\x00.rela.dyn\x00.dynsym\x00.dynstr\x00.shstrtab\x00'
    dynstr = b'\x00exit\x00'
    dynsym = b'\x00' * 24 + struct.pack('<IBBHQQ', 1, 0, 0, 0, 0, 0)
    names = {name: shstr.index(name.encode()) for name in
             ('.rela.dyn', '.dynsym', '.dynstr', '.shstrtab')}
    shstr_off = 64
    shoff = shstr_off + len(shstr)
    dynstr_off = shoff + 5 * 64
    dynsym_off = dynstr_off + len(dynstr)
    rela_off = dynsym_off + len(dynsym)

    def shdr(name, typ, off, size, link, entsize):
        return struct.pack('<IIQQQQIIQQ', names.get(name, 0), typ, 0, 0, off, size, link, 0, 1, entsize)

    rows = b''.join([
        shdr('', 0, 0, 0, 0, 0),
        shdr('.rela.dyn', 4, rela_off, len(rela), 2, 24),
        shdr('.dynsym', 11, dynsym_off, len(dynsym), 3, 24),
        shdr('.dynstr', 3, dynstr_off, len(dynstr), 0, 0),
        shdr('.shstrtab', 3, shstr_off, len(shstr), 0, 0),
    ])
    header = bytearray(64)
    header[0:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', header, 40, shoff)
    struct.pack_into('<HHH', header, 58, 64, 5, 4)
    return bytes(header) + shstr + rows + dynstr + dynsym + rela + extra


def pack():
    entries = b''.join(struct.pack('<QQq', slot, 8, addend)
                       for slot, addend in sorted(RELATIVE.items()))
    return entries + struct.pack('<QQq', 0x5777378, (1 << 32) | 6, 0)


class ReceiverPollRelocationTruncationTests(unittest.TestCase):
    def test_aligned_section_returns_relative_slots_and_exit(self):
        rows = relocations(build(pack()))
        self.assertEqual(len(rows), len(RELATIVE) + 1)
        self.assertEqual(rows[-1]['symbol'], 'exit')

    def test_trailing_byte_at_eof_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Truncated relocation section'):
            relocations(build(pack() + b'\x00'))

    def test_tail_that_continues_into_the_next_bytes_is_rejected(self):
        forged = struct.pack('<QQq', 0x566B328, 8, 1)
        body = pack() + forged
        data = build(body[:len(pack()) + 1], extra=body[len(pack()) + 1:])
        with self.assertRaisesRegex(ValueError, 'Truncated relocation section'):
            relocations(data)


if __name__ == '__main__':
    unittest.main()
