"""Truncated .rela.dyn handling in tools/wei_buffered_cap.py Image.relative_relocs.

A section ending in a partial entry, or claiming bytes past EOF, must fail
closed with EvidenceError like every other malformed input in the module,
instead of escaping as struct.error or silently truncating the entry list.
"""

import importlib.util
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools' / 'wei_buffered_cap.py'

spec = importlib.util.spec_from_file_location('wei_buffered_cap', TOOL)
wbc = importlib.util.module_from_spec(spec)
sys.modules['wei_buffered_cap'] = wbc
spec.loader.exec_module(wbc)


def build_elf(rela_bytes, claim_size=None):
    shstr = b'\x00.rela.dyn\x00.shstrtab\x00'
    hdr = bytearray(64)
    hdr[0:6] = b'\x7fELF\x02\x01'
    shoff = 64 + len(shstr)
    struct.pack_into('<Q', hdr, 0x28, shoff)
    struct.pack_into('<HHH', hdr, 0x3a, 64, 3, 2)

    def sh(name, off, size):
        return struct.pack('<IIQQQQIIQQ', name, 1, 0, 0, off, size, 0, 0, 1, 0)

    secs = (sh(0, 0, 0)
            + sh(1, shoff + 3 * 64, len(rela_bytes) if claim_size is None else claim_size)
            + sh(11, 64, len(shstr)))
    return bytes(hdr) + shstr + secs + rela_bytes


def reloc(where, addend):
    return struct.pack('<QQq', where, 8, addend)


class RelativeRelocsTruncated(unittest.TestCase):
    def test_ragged_tail_rejected(self):
        data = build_elf(reloc(0x1000, 7) + reloc(0x2000, 9) + b'\x00' * 5)
        with self.assertRaises(wbc.EvidenceError):
            wbc.Image(data).relative_relocs()

    def test_past_eof_claim_rejected(self):
        data = build_elf(reloc(0x1000, 7), claim_size=48)
        with self.assertRaises(wbc.EvidenceError):
            wbc.Image(data).relative_relocs()

    def test_valid_section_still_parses(self):
        data = build_elf(reloc(0x1000, 7) + reloc(0x2000, 9))
        self.assertEqual(wbc.Image(data).relative_relocs(), {0x1000: 7, 0x2000: 9})


if __name__ == '__main__':
    unittest.main()
