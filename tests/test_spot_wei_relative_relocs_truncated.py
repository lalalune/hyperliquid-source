"""relative_relocs() in tools/spot_wei_scale.py must fail closed on a truncated .rela.dyn.

Sibling of the evm_amount_scale relative_relocs() truncation fix (open #435)
and its slots() sibling (open #441): this copy feeds the `.rela.dyn` slice
straight to struct.iter_unpack, so a section ending in a partial entry escapes
as struct.error and a section claiming bytes past EOF is silently truncated
to a shorter multiple-of-24 slice, while every other malformed input in the
module raises EvidenceError.
"""

import importlib.util
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools' / 'spot_wei_scale.py'

spec = importlib.util.spec_from_file_location('spot_wei_scale_relocs', TOOL)
sws = importlib.util.module_from_spec(spec)
sys.modules['spot_wei_scale_relocs'] = sws
spec.loader.exec_module(sws)


def build(rela_bytes, claimed_size=None):
    """Minimal ELF64-LE with .rela.dyn at EOF, plus .shstrtab."""
    names = b'\x00.rela.dyn\x00.shstrtab\x00'
    o_rela = 1
    o_shstr = 1 + len(b'.rela.dyn\x00')
    hdr = bytearray(64)
    hdr[:6] = b'\x7fELF\x02\x01'
    shstr_off = 64
    # Section headers sit before the relocation bytes so .rela.dyn ends at EOF.
    shoff = shstr_off + len(names)
    rela_off = shoff + 3 * 64
    struct.pack_into('<Q', hdr, 0x28, shoff)
    struct.pack_into('<HHH', hdr, 0x3a, 64, 3, 2)

    def sh(name, typ, addr, off, size):
        return struct.pack('<IIQQQQIIQQ', name, typ, 0, addr, off, size, 0, 0, 0, 0)

    size = len(rela_bytes) if claimed_size is None else claimed_size
    headers = b''.join([
        sh(0, 0, 0, 0, 0),
        sh(o_rela, 4, 0, rela_off, size),
        sh(o_shstr, 3, 0, shstr_off, len(names)),
    ])
    return bytes(hdr) + names + headers + rela_bytes


def reloc(where, addend):
    return struct.pack('<QQq', where, 8, addend)


class RelativeRelocsTruncatedTests(unittest.TestCase):
    def test_ragged_tail_rejected(self):
        data = build(reloc(0x5000, 111) + b'\x00')
        with self.assertRaises(sws.EvidenceError):
            sws.Image(data).relative_relocs()

    def test_past_eof_rejected(self):
        data = build(reloc(0x5000, 111), claimed_size=48)
        with self.assertRaises(sws.EvidenceError):
            sws.Image(data).relative_relocs()

    def test_valid_section_still_parses(self):
        data = build(reloc(0x5000, 111) + reloc(0x5008, 222))
        self.assertEqual(sws.Image(data).relative_relocs(), {0x5000: 111, 0x5008: 222})


if __name__ == '__main__':
    unittest.main()
