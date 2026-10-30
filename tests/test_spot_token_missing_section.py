"""Missing required sections must fail closed in spot_token_decimals.

Image.text(), Fdes.__init__ and find_unique() are all on the analyse()
path, so each genuinely requires its section (.text, .eh_frame_hdr and
.rodata respectively). On base they are bare dict lookups, so an ELF
without one of them escapes main()'s EvidenceError-only handler as a
KeyError traceback instead of a clean rejection.
"""
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import spot_token_decimals as std


def synthetic_elf(section_names):
    """Minimal ELF64-LE with exactly the named PROGBITS sections."""
    shstr = b'\x00' + b''.join(n.encode() + b'\x00' for n in section_names) + b'.shstrtab\x00'
    offsets = {}
    pos = 1
    for name in section_names:
        offsets[name] = pos
        pos += len(name) + 1
    shstrtab_name = pos
    text_bytes = b'\x90' * 16
    ehsize, shentsize = 64, 64
    shoff = ehsize + len(text_bytes) + len(shstr)

    def sh(name, typ, flags, addr, off, size):
        return struct.pack('<IIQQQQIIQQ', name, typ, flags, addr, off, size, 0, 0, 1, 0)

    headers = [sh(0, 0, 0, 0, 0, 0)]
    addr = 0x400000
    for name in section_names:
        headers.append(sh(offsets[name], 1, 6, addr, ehsize, 16))
        addr += 0x1000
    headers.append(sh(shstrtab_name, 3, 0, 0, ehsize + len(text_bytes), len(shstr)))
    ehdr = bytearray(64)
    ehdr[0:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', ehdr, 0x28, shoff)
    struct.pack_into('<HHH', ehdr, 0x3a, shentsize, len(headers), len(headers) - 1)
    return bytes(ehdr) + text_bytes + shstr + b''.join(headers)


FULL = ('.text', '.eh_frame_hdr', '.rodata')


class MissingSectionTests(unittest.TestCase):
    def test_missing_text_is_evidence_error(self):
        img = std.Image(synthetic_elf(('.eh_frame_hdr', '.rodata')))
        with self.assertRaises(std.EvidenceError):
            img.text()

    def test_missing_eh_frame_hdr_is_evidence_error(self):
        img = std.Image(synthetic_elf(('.text', '.rodata')))
        with self.assertRaises(std.EvidenceError):
            std.Fdes(img)

    def test_missing_rodata_is_evidence_error(self):
        img = std.Image(synthetic_elf(('.text', '.eh_frame_hdr')))
        with self.assertRaises(std.EvidenceError):
            std.find_unique(img, b'szDecimals too large')

    def test_present_sections_unchanged(self):
        img = std.Image(synthetic_elf(FULL))
        self.assertEqual(img.section('.text'), (0x400000, 64, 16))
        self.assertEqual(img.text()[1][:4], b'\x90' * 4)

    def test_section_accessor_names_the_missing_section(self):
        img = std.Image(synthetic_elf(('.text',)))
        with self.assertRaises(std.EvidenceError) as ctx:
            img.section('.rodata')
        self.assertIn('.rodata', str(ctx.exception))


if __name__ == '__main__':
    unittest.main()
