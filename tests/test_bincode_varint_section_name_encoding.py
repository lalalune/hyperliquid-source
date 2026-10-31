"""RE-005: a non-UTF-8 section name must fail closed as EvidenceError.

Synthetic minimal ELF64: header + section headers + shstrtab carrying the
sections bv.sections() requires (.text .eh_frame .eh_frame_hdr .rela.dyn
.data.rel.ro .rodata). Same construction style as the sibling section-name
encoding tests (e.g. test_exchange_dispatch_section_name_encoding.py).
"""
import struct
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import bincode_varint as bv  # noqa: E402

NAMES = [b'', b'.text', b'.eh_frame', b'.eh_frame_hdr', b'.rela.dyn',
         b'.data.rel.ro', b'.rodata', b'.shstrtab']


def build(name_blobs):
    blob = b''
    offs = []
    for n in name_blobs:
        offs.append(len(blob))
        blob += n + b'\0'
    nsec = len(name_blobs)
    shoff = 64
    data_start = shoff + nsec * 64
    shstr_off = data_start + 0x100
    data = bytearray(shstr_off + len(blob))
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 40, shoff)
    struct.pack_into('<HHH', data, 58, 64, nsec, nsec - 1)
    for i, off in enumerate(offs):
        addr = 0x1000 * (i + 1)
        struct.pack_into('<IIQQQQIIQQ', data, shoff + i * 64,
                         off, 1, 0, addr, data_start, 0x10, 0, 0, 1, 0)
    struct.pack_into('<Q', data, shoff + (nsec - 1) * 64 + 24, shstr_off)
    data[shstr_off:shstr_off + len(blob)] = blob
    return bytes(data)


class SectionNameEncodingTests(unittest.TestCase):
    def test_nonutf8_section_name_fails_closed(self):
        # On base the bare .decode() in sections() escapes as
        # UnicodeDecodeError; with the fix it raises EvidenceError.
        bad = list(NAMES)
        bad[1] = b'.\xffext'
        with self.assertRaisesRegex(bv.EvidenceError,
                                    'section name is not valid UTF-8'):
            bv.sections(build(bad))

    def test_ascii_section_names_still_parse(self):
        secs = bv.sections(build(NAMES))
        for name in ('.text', '.eh_frame', '.eh_frame_hdr', '.rela.dyn',
                     '.data.rel.ro', '.rodata'):
            self.assertIn(name, secs)


if __name__ == '__main__':
    unittest.main()
