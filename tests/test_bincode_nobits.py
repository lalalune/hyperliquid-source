"""NOBITS sections must not map VAs to file bytes in bincode_varint.

A SHT_NOBITS section (e.g. .bss) occupies no file bytes, so resolving one
of its VAs must fail closed with EvidenceError. On base, sections()
discarded the section type, so VA resolution matched the NOBITS range and
returned whatever file bytes its sh_offset happened to point at.
"""
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import bincode_varint as m

TEXT = b'\x90' * 16
EXTRA = ('.eh_frame', '.eh_frame_hdr', '.rela.dyn', '.data.rel.ro', '.rodata')


def synthetic_elf(bss_first=False, bss_addr=0x500000, bss_off=None, extra=()):
    """Minimal ELF64-LE: .text (PROGBITS) + .bss (NOBITS) [+ extra PROGBITS].

    The .bss sh_offset deliberately points at real file bytes, so a
    NOBITS-mapping bug is observable instead of reading past the end.
    """
    names = ['.text', '.bss'] + list(extra) + ['.shstrtab']
    shstr = b'\x00' + b''.join(n.encode() + b'\x00' for n in names)
    idx = {}
    pos = 1
    for n in names:
        idx[n] = pos
        pos += len(n) + 1
    shoff = 64 + len(TEXT) + len(shstr)

    def sh(name, typ, flags, addr, off, size):
        return struct.pack('<IIQQQQIIQQ', idx[name] if name else 0, typ, flags, addr, off, size, 0, 0, 1, 0)

    text = sh('.text', 1, 6, 0x400000, 64, len(TEXT))
    bss = sh('.bss', 8, 3, bss_addr, 64 if bss_off is None else bss_off, 16)
    rows = [sh(None, 0, 0, 0, 0, 0)] + ([bss, text] if bss_first else [text, bss])
    rows += [sh(n, 1, 2, 0x700000 + 0x10 * i, 64, 4) for i, n in enumerate(extra)]
    rows.append(sh('.shstrtab', 3, 0, 0, 64 + len(TEXT), len(shstr)))
    ehdr = bytearray(64)
    ehdr[0:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', ehdr, 0x28, shoff)
    struct.pack_into('<HHH', ehdr, 0x3a, 64, len(rows), len(rows) - 1)
    return bytes(ehdr) + TEXT + shstr + b''.join(rows)


def resolve(va, **kw):
    return m.va_to_off(m.sections(synthetic_elf(extra=EXTRA, **kw)), va)


class NobitsTests(unittest.TestCase):
    def test_nobits_va_rejected(self):
        with self.assertRaises(m.EvidenceError):
            resolve(0x500000)

    def test_nobits_absent_from_sections(self):
        self.assertNotIn('.bss', m.sections(synthetic_elf(extra=EXTRA)))

    def test_progbits_resolution_unaffected(self):
        self.assertEqual(resolve(0x400004), 68)

    def test_outside_all_sections_still_rejected(self):
        with self.assertRaises(m.EvidenceError):
            resolve(0x600000)

    def test_nobits_does_not_shadow_progbits(self):
        # .bss header first, same VA range as .text, sh_offset pointing at
        # the shstrtab bytes: base returns that offset, fixed code resolves
        # to the .text bytes.
        self.assertEqual(resolve(0x400000, bss_first=True, bss_addr=0x400000, bss_off=80), 64)


if __name__ == '__main__':
    unittest.main()
