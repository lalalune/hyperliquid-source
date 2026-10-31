"""Symbol-name bounds for receiver_poll_static.relocations().

The exit-import resolution reads the dynamic symbol name with an unbounded
``data.index(b'\\0', start)`` over the whole file, so a name unterminated
inside the string table was silently completed with bytes from the section
that follows it, and a name offset past the end of the string table was
read from those following bytes as well. Both forgeries were accepted as
the 'exit' binding when the borrowed bytes happened to spell it.

The real node #94 binary is an LFS pointer on this machine, so these tests
build a minimal ELF64-LE document in memory: a .rela.dyn section carrying
every RELATIVE slot plus the exit-import slot, the .dynsym/.dynstr pair the
exit resolution follows, and a .pad section placed directly after .dynstr
so borrowed bytes have a definite source.
"""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from receiver_poll_static import RELATIVE, relocations

EXIT = 0x5777378


def build(dynstr, pad, name_off):
    shstr = b'\x00.rela.dyn\x00.shstrtab\x00.dynsym\x00.dynstr\x00.pad\x00'
    names = {n: shstr.index(n) for n in (b'.rela.dyn', b'.shstrtab', b'.dynsym', b'.dynstr', b'.pad')}
    shoff = 64 + len(shstr)
    nsec = 6
    dynsym_off = shoff + nsec * 64
    dynstr_off = dynsym_off + 24
    pad_off = dynstr_off + len(dynstr)
    rela_off = pad_off + len(pad)
    rela = b''.join(struct.pack('<QQq', slot, 8, addend) for slot, addend in sorted(RELATIVE.items()))
    rela += struct.pack('<QQq', EXIT, (0 << 32) | 6, 0)
    data = bytearray(rela_off + len(rela))
    data[0:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 40, shoff)
    struct.pack_into('<HHH', data, 58, 64, nsec, 2)

    def shdr(index, name, typ, off, size, link, entsize):
        struct.pack_into('<IIQQQQIIQQ', data, shoff + index * 64,
                         names.get(name, 0), typ, 0, 0, off, size, link, 0, 0, entsize)

    shdr(0, b'', 0, 0, 0, 0, 0)
    shdr(1, b'.rela.dyn', 4, rela_off, len(rela), 3, 0)
    shdr(2, b'.shstrtab', 3, 64, len(shstr), 0, 0)
    shdr(3, b'.dynsym', 11, dynsym_off, 24, 4, 24)
    shdr(4, b'.dynstr', 3, dynstr_off, len(dynstr), 0, 0)
    shdr(5, b'.pad', 3, pad_off, len(pad), 0, 0)
    data[64:64 + len(shstr)] = shstr
    struct.pack_into('<I', data, dynsym_off, name_off)
    data[dynstr_off:dynstr_off + len(dynstr)] = dynstr
    data[pad_off:pad_off + len(pad)] = pad
    data[rela_off:rela_off + len(rela)] = rela
    return bytes(data)


class ReceiverPollSymbolNameBoundsTests(unittest.TestCase):
    def test_valid_exit_name_inside_string_table_passes(self):
        rows = relocations(build(b'exit\x00', b'', 0))
        self.assertEqual(len(rows), len(RELATIVE) + 1)
        self.assertEqual(rows[-1]['symbol'], 'exit')

    def test_name_borrowing_terminator_past_string_table_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'not terminated inside string table'):
            relocations(build(b'exi', b't\x00', 0))

    def test_name_offset_past_string_table_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'offset outside string table'):
            relocations(build(b'zzzz\x00', b'exit\x00', 5))


if __name__ == '__main__':
    unittest.main()
