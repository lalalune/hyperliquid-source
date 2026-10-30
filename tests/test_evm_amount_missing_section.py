"""Missing required sections must fail closed in evm_amount_scale.

Fdes.__init__, call_sites(), relative_relocs(), slots() and
Machine.load() (via in_rodata()) are all on the analyse() path, so
each genuinely requires its section (.eh_frame_hdr, .text,
.rela.dyn, .dynsym, .dynstr, .got and .rodata respectively). On base
they are bare dict lookups, so an ELF without one of them fails with
a KeyError traceback instead of the tool's EvidenceError, which every
other input-shape failure on this path raises via checked().
"""
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import evm_amount_scale as eas


def synthetic_elf(contents):
    """Minimal ELF64-LE with the given PROGBITS sections (name -> bytes)."""
    names = list(contents)
    shstr = b'\x00' + b''.join(n.encode() + b'\x00' for n in names) + b'.shstrtab\x00'
    offsets = {}
    pos = 1
    for name in names:
        offsets[name] = pos
        pos += len(name) + 1
    shstrtab_name = pos
    ehsize, shentsize = 64, 64
    body = b''
    file_offsets = {}
    for name in names:
        file_offsets[name] = ehsize + len(body)
        body += contents[name]
    shoff = ehsize + len(body) + len(shstr)

    def sh(name, typ, flags, addr, off, size):
        return struct.pack('<IIQQQQIIQQ', name, typ, flags, addr, off, size, 0, 0, 1, 0)

    headers = [sh(0, 0, 0, 0, 0, 0)]
    addr = 0x400000
    for name in names:
        headers.append(sh(offsets[name], 1, 6, addr, file_offsets[name], len(contents[name])))
        addr += 0x1000
    headers.append(sh(shstrtab_name, 3, 0, 0, ehsize + len(body), len(shstr)))
    ehdr = bytearray(64)
    ehdr[0:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', ehdr, 0x28, shoff)
    struct.pack_into('<HHH', ehdr, 0x3a, shentsize, len(headers), len(headers) - 1)
    return bytes(ehdr) + body + shstr + b''.join(headers)


BASE = {'.text': b'\x90' * 16, '.rela.dyn': b'\x00' * 24,
        '.eh_frame_hdr': b'\x00' * 16, '.rodata': b'\x00' * 32,
        '.dynsym': b'\x00' * 24, '.dynstr': b'\x00' * 16,
        '.got': b'\x00' * 16}


def without(name):
    return {k: v for k, v in BASE.items() if k != name}


class MissingSectionTests(unittest.TestCase):
    def test_missing_text_is_evidence_error(self):
        img = eas.Image(synthetic_elf(without('.text')))
        with self.assertRaises(eas.EvidenceError):
            eas.call_sites(img, 0)

    def test_missing_rela_dyn_is_evidence_error(self):
        img = eas.Image(synthetic_elf(without('.rela.dyn')))
        with self.assertRaises(eas.EvidenceError):
            img.relative_relocs()

    def test_missing_dynsym_is_evidence_error(self):
        img = eas.Image(synthetic_elf(without('.dynsym')))
        with self.assertRaises(eas.EvidenceError):
            img.slots()

    def test_missing_dynstr_is_evidence_error(self):
        img = eas.Image(synthetic_elf(without('.dynstr')))
        with self.assertRaises(eas.EvidenceError):
            img.slots()

    def test_missing_got_is_evidence_error(self):
        img = eas.Image(synthetic_elf(without('.got')))
        with self.assertRaises(eas.EvidenceError):
            img.slots()

    def test_missing_eh_frame_hdr_is_evidence_error(self):
        img = eas.Image(synthetic_elf(without('.eh_frame_hdr')))
        with self.assertRaises(eas.EvidenceError):
            eas.Fdes(img)

    def test_missing_rodata_is_evidence_error(self):
        img = eas.Image(synthetic_elf(without('.rodata')))
        with self.assertRaises(eas.EvidenceError):
            img.in_rodata(0x400000, 1)

    def test_present_sections_unchanged(self):
        img = eas.Image(synthetic_elf(BASE))
        self.assertEqual(img.section('.text'), (0x400000, 64, 16))
        self.assertEqual(img.text()[1][:4], b'\x90' * 4)

    def test_section_accessor_names_the_missing_section(self):
        img = eas.Image(synthetic_elf(without('.rodata')))
        with self.assertRaises(eas.EvidenceError) as ctx:
            img.section('.rodata')
        self.assertIn('.rodata', str(ctx.exception))


if __name__ == '__main__':
    unittest.main()
