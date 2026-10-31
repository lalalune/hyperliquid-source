"""RE-005: an unterminated section name must fail closed as EvidenceError.

Synthetic minimal ELF64: header + section headers + shstrtab carrying
the sections bincode_varint.sections() reads. The defect input points the
shstrtab at a region with no NUL terminator, so the bare data.index()
in sections() escapes as ValueError on base.
"""
import struct
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import bincode_varint as bv  # noqa: E402


def build_unterminated():
    # One section header (the shstrtab itself); its string table region
    # contains only 'A' bytes, so no NUL terminator exists after stro.
    shoff = 64
    shstr_off = shoff + 64
    data = bytearray(shstr_off + 16)
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 40, shoff)
    struct.pack_into('<HHH', data, 58, 64, 1, 0)
    struct.pack_into('<IIQQQQIIQQ', data, shoff,
                     0, 3, 0, 0, shstr_off, 16, 0, 0, 1, 0)
    data[shstr_off:shstr_off + 16] = b'A' * 16
    return bytes(data)


def build_valid():
    names = [b'', b'.text', b'.eh_frame', b'.eh_frame_hdr', b'.rela.dyn',
             b'.data.rel.ro', b'.rodata', b'.shstrtab']
    blob = b''
    offs = []
    for n in names:
        offs.append(len(blob))
        blob += n + b'\0'
    nsec = len(names)
    shoff = 64
    data_start = shoff + nsec * 64
    shstr_off = data_start + 0x100
    data = bytearray(shstr_off + len(blob))
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 40, shoff)
    struct.pack_into('<HHH', data, 58, 64, nsec, nsec - 1)
    for i, off in enumerate(offs):
        struct.pack_into('<IIQQQQIIQQ', data, shoff + i * 64,
                         off, 1, 0, 0, data_start, 0x10, 0, 0, 1, 0)
    struct.pack_into('<Q', data, shoff + (nsec - 1) * 64 + 24, shstr_off)
    data[shstr_off:shstr_off + len(blob)] = blob
    return bytes(data)


class SectionNameTerminatedTests(unittest.TestCase):
    def test_unterminated_section_name_fails_closed(self):
        # On base the bare data.index() in sections() escapes as
        # ValueError; with the fix it raises EvidenceError.
        with self.assertRaisesRegex(bv.EvidenceError,
                                    'section name is not NUL-terminated'):
            bv.sections(build_unterminated())

    def test_terminated_section_names_still_parse(self):
        secs = bv.sections(build_valid())
        for name in ('.text', '.eh_frame', '.eh_frame_hdr', '.rela.dyn',
                     '.data.rel.ro', '.rodata'):
            self.assertIn(name, secs)


if __name__ == '__main__':
    unittest.main()
