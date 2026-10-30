"""Malformed ELF section tables must fail closed in spot_token_decimals.

sections() is on every analyse() path (via Image), and main() catches only
EvidenceError, so a malformed table must raise EvidenceError — not the raw
struct.error / IndexError / ValueError / UnicodeDecodeError it raises on
base. The sibling tools tools/elf_index.py and tools/bincode_varint.py
already validate the table bounds this way; the seven RE-004 tools do not.
"""
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import spot_token_decimals as wsg


def sh(name, typ, flags, addr, off, size):
    return struct.pack('<IIQQQQIIQQ', name, typ, flags, addr, off, size, 0, 0, 1, 0)


def elf(shoff, shentsize, shnum, shstrndx, body=b''):
    """ELF64-LE header + body; callers place section headers at shoff."""
    ehdr = bytearray(64)
    ehdr[0:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', ehdr, 0x28, shoff)
    struct.pack_into('<HHH', ehdr, 0x3a, shentsize, shnum, shstrndx)
    data = bytes(ehdr) + body
    if len(data) < shoff:
        data += b'\x00' * (shoff - len(data))
    return data


def valid_elf():
    """Two sections (null + .shstrtab) plus one named section, all valid."""
    shstr = b'\x00.text\x00.shstrtab\x00'
    shoff = 64 + len(shstr)
    headers = sh(0, 0, 0, 0, 0, 0) + sh(1, 1, 6, 0x400000, 64, 16) + sh(7, 3, 0, 0, 64, len(shstr))
    data = elf(shoff, 64, 3, 2, shstr)
    return data + headers


class SectionsTableTests(unittest.TestCase):
    def test_valid_table_still_parses(self):
        secs = wsg.sections(valid_elf())
        self.assertEqual(secs['.text'], (0x400000, 64, 16))
        self.assertIn('.shstrtab', secs)

    def test_short_header_is_evidence_error(self):
        with self.assertRaises(wsg.EvidenceError):
            wsg.sections(b'\x7fELF\x02\x01' + b'\x00' * 10)

    def test_section_table_beyond_file_is_evidence_error(self):
        with self.assertRaises(wsg.EvidenceError):
            wsg.sections(elf(0x9999, 64, 2, 1))

    def test_small_entry_size_is_evidence_error(self):
        # shentsize 32 with a 64-byte file body: the second 64-byte entry
        # read would run past the end of the file on base (struct.error).
        data = elf(64, 32, 2, 1, b'\x00' * 64)
        with self.assertRaises(wsg.EvidenceError):
            wsg.sections(data)

    def test_shstrndx_out_of_range_is_evidence_error(self):
        data = elf(64, 64, 2, 5, b'\x00' * 128)
        with self.assertRaises(wsg.EvidenceError):
            wsg.sections(data)

    def test_name_offset_beyond_file_is_evidence_error(self):
        shstr = b'\x00.text\x00.shstrtab\x00'
        shoff = 64 + len(shstr)
        headers = sh(0, 0, 0, 0, 0, 0) + sh(0xffff, 1, 6, 0x400000, 64, 16) + sh(7, 3, 0, 0, 64, len(shstr))
        data = elf(shoff, 64, 3, 2, shstr) + headers
        with self.assertRaises(wsg.EvidenceError):
            wsg.sections(data)

    def test_non_utf8_name_is_evidence_error(self):
        shstr = b'\x00\xff\xfe\x00.shstrtab\x00'
        shoff = 64 + len(shstr)
        headers = sh(0, 0, 0, 0, 0, 0) + sh(1, 1, 6, 0x400000, 64, 16) + sh(5, 3, 0, 0, 64, len(shstr))
        data = elf(shoff, 64, 3, 2, shstr) + headers
        with self.assertRaises(wsg.EvidenceError):
            wsg.sections(data)


if __name__ == '__main__':
    unittest.main()
