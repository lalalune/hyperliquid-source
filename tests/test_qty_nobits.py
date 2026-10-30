"""NOBITS sections must not map VAs to file bytes in qty_newtype_sign_guards.

A SHT_NOBITS section (e.g. .bss) occupies no file bytes, so Image.read()
on one of its VAs must fail closed with EvidenceError. On base, sections()
discarded the section type, so Image.off() matched the NOBITS range and
returned whatever file bytes its sh_offset happened to point at.
"""
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import qty_newtype_sign_guards as qsg


def synthetic_elf(bss_first=False, bss_addr=0x500000, bss_off=None):
    """Minimal ELF64-LE: .text (PROGBITS, 0x90 bytes) + .bss (NOBITS).

    The .bss sh_offset deliberately points at real file bytes, so a
    NOBITS-mapping bug is observable instead of reading past the end.
    """
    shstr = b'\x00.text\x00.bss\x00.shstrtab\x00'
    text_bytes = b'\x90' * 16
    ehsize, shentsize = 64, 64
    shoff = ehsize + len(text_bytes) + len(shstr)

    def sh(name, typ, flags, addr, off, size):
        return struct.pack('<IIQQQQIIQQ', name, typ, flags, addr, off, size, 0, 0, 1, 0)

    null = sh(0, 0, 0, 0, 0, 0)
    text = sh(1, 1, 6, 0x400000, ehsize, len(text_bytes))
    bss = sh(7, 8, 3, bss_addr, ehsize if bss_off is None else bss_off, 16)
    shstrtab = sh(12, 3, 0, 0, ehsize + len(text_bytes), len(shstr))
    headers = null + (bss + text if bss_first else text + bss) + shstrtab
    ehdr = bytearray(64)
    ehdr[0:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', ehdr, 0x28, shoff)
    struct.pack_into('<HHH', ehdr, 0x3a, shentsize, 4, 3)
    return bytes(ehdr) + text_bytes + shstr + headers


class NobitsTests(unittest.TestCase):
    def test_nobits_va_rejected(self):
        img = qsg.Image(synthetic_elf())
        with self.assertRaises(qsg.EvidenceError):
            img.read(0x500000, 4)

    def test_nobits_absent_from_sections(self):
        self.assertNotIn('.bss', qsg.sections(synthetic_elf()))

    def test_progbits_read_unaffected(self):
        img = qsg.Image(synthetic_elf())
        self.assertEqual(img.read(0x400000, 4), b'\x90' * 4)
        self.assertEqual(img.text()[1][:4], b'\x90' * 4)

    def test_outside_all_sections_still_rejected(self):
        img = qsg.Image(synthetic_elf())
        with self.assertRaises(qsg.EvidenceError):
            img.read(0x600000, 4)

    def test_nobits_does_not_shadow_progbits(self):
        # .bss header first, same VA range as .text, sh_offset pointing at
        # the shstrtab bytes: base returns those bytes, fixed code resolves
        # to the .text bytes.
        img = qsg.Image(synthetic_elf(bss_first=True, bss_addr=0x400000, bss_off=80))
        self.assertEqual(img.read(0x400000, 4), b'\x90' * 4)


if __name__ == '__main__':
    unittest.main()
