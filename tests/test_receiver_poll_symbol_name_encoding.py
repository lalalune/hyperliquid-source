"""Synthetic-ELF tests for the receiver exit symbol name decode.

Builds a minimal ELF64-LE image with a SHT_RELA section whose exit entry
(slot 0x5777378) links to a dynamic symbol table entry whose name lives in
a string table, mirroring tools/receiver_poll_static.py::relocations.
"""
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from receiver_poll_static import RELATIVE, relocations


def build(name):
    names = b'\x00.shstrtab\x00.rela.dyn\x00.dynsym\x00.dynstr\x00'
    shstr_off, rela_off, dynsym_off, dynstr_off = 0x100, 0x200, 0x300, 0x400
    entries = [(slot, 8, add) for slot, add in RELATIVE.items()]
    entries.append((0x5777378, (1 << 32) | 6, 0))
    rela = b''.join(struct.pack('<QQq', *e) for e in entries)
    dynsym = b'\x00' * 24 + struct.pack('<I', 1) + b'\x00' * 20
    dynstr = b'\x00' + name + b'\x00'
    shoff = 0x500
    data = bytearray(shoff + 5 * 64)
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 40, shoff)
    struct.pack_into('<HHH', data, 58, 64, 5, 1)
    data[shstr_off:shstr_off + len(names)] = names
    data[rela_off:rela_off + len(rela)] = rela
    data[dynsym_off:dynsym_off + len(dynsym)] = dynsym
    data[dynstr_off:dynstr_off + len(dynstr)] = dynstr

    def sh(name_off, typ, off, size, link=0, entsize=0):
        return struct.pack('<IIQQQQIIQQ', name_off, typ, 0, 0, off, size, link, 0, 1, entsize)

    rows = [
        sh(0, 0, 0, 0),
        sh(names.index(b'.shstrtab'), 3, shstr_off, len(names)),
        sh(names.index(b'.rela.dyn'), 4, rela_off, len(rela), link=3),
        sh(names.index(b'.dynsym'), 11, dynsym_off, len(dynsym), link=4, entsize=24),
        sh(names.index(b'.dynstr'), 3, dynstr_off, len(dynstr)),
    ]
    for i, row in enumerate(rows):
        data[shoff + i * 64:shoff + (i + 1) * 64] = row
    return bytes(data)


class ReceiverPollSymbolNameEncodingTests(unittest.TestCase):
    def test_non_ascii_symbol_name_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'not ASCII'):
            relocations(build(b'\xfeexit'))

    def test_valid_exit_symbol_unchanged(self):
        rows = relocations(build(b'exit'))
        self.assertEqual(len(rows), len(RELATIVE) + 1)
        self.assertEqual(rows[-1]['symbol'], 'exit')


if __name__ == '__main__':
    unittest.main()
