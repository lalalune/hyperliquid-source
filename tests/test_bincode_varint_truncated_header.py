import struct
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import bincode_varint as bv


def _truncated(size):
    return b'\x7fELF\x02\x01' + b'\x00' * (size - 6)


def _valid():
    """Minimal header with the six sections sections() requires."""
    names = (b'\x00.text\x00.eh_frame\x00.eh_frame_hdr\x00.rela.dyn\x00'
             b'.data.rel.ro\x00.rodata\x00.shstrtab\x00')
    offsets = {'': 0, '.text': 1, '.eh_frame': 7, '.eh_frame_hdr': 17,
               '.rela.dyn': 31, '.data.rel.ro': 41, '.rodata': 54,
               '.shstrtab': 62}
    shoff, nsec = 64, 8
    table_off = shoff + nsec * 64
    data = bytearray(table_off + len(names))
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 40, shoff)
    struct.pack_into('<HHH', data, 58, 64, nsec, 7)
    rows = ['.text', '.eh_frame', '.eh_frame_hdr', '.rela.dyn',
            '.data.rel.ro', '.rodata']
    struct.pack_into('<IIQQQQIIQQ', data, shoff,
                     0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    for i, name in enumerate(rows, 1):
        struct.pack_into('<IIQQQQIIQQ', data, shoff + i * 64,
                         offsets[name], 1, 0, 0, 0, 0, 0, 0, 0, 0)
    # Row 7 is the string table itself.
    struct.pack_into('<IIQQQQIIQQ', data, shoff + 7 * 64,
                     offsets['.shstrtab'], 3, 0, 0, table_off, len(names),
                     0, 0, 0, 0)
    data[table_off:table_off + len(names)] = names
    return bytes(data)


class TruncatedHeaderTests(unittest.TestCase):
    def test_short_magic_input_fails_closed(self):
        # On base the bare unpack_from at offset 40 escapes as struct.error;
        # with the fix it raises EvidenceError like every other malformed
        # section-table case in this function.
        with self.assertRaises(bv.EvidenceError):
            bv.sections(_truncated(6))

    def test_63_byte_input_fails_closed(self):
        with self.assertRaises(bv.EvidenceError):
            bv.sections(_truncated(63))

    def test_valid_header_still_parses(self):
        secs = bv.sections(_valid())
        for name in ('.text', '.eh_frame', '.eh_frame_hdr', '.rela.dyn',
                     '.data.rel.ro', '.rodata'):
            self.assertIn(name, secs)


if __name__ == '__main__':
    unittest.main()
