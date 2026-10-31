"""slots() in tools/evm_amount_scale.py must fail closed on a truncated .rela.dyn.

Sibling of the relative_relocs() truncation fix (open #435): slots() reads the
same section through the same unguarded struct.iter_unpack, so a section
ending in a partial entry escapes as struct.error and a section claiming
bytes past EOF is silently truncated to a shorter multiple-of-24 slice.
"""

import importlib.util
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools' / 'evm_amount_scale.py'

spec = importlib.util.spec_from_file_location('evm_amount_scale_slots', TOOL)
eas = importlib.util.module_from_spec(spec)
sys.modules['evm_amount_scale_slots'] = eas
spec.loader.exec_module(eas)

GOT_ADDR = 0x5000


def build(rela_bytes, claimed_size=None):
    """Minimal ELF64-LE with .rela.dyn at EOF, plus .dynsym/.dynstr/.got."""
    names = b'\x00.rela.dyn\x00.dynsym\x00.dynstr\x00.got\x00.shstrtab\x00'
    o_rela = 1
    o_dynsym = 1 + len(b'.rela.dyn\x00')
    o_dynstr = o_dynsym + len(b'.dynsym\x00')
    o_got = o_dynstr + len(b'.dynstr\x00')
    o_shstr = o_got + len(b'.got\x00')
    hdr = bytearray(64)
    hdr[:6] = b'\x7fELF\x02\x01'
    dynsym_off = 64
    dynsym = b'\x00' * 24
    dynstr_off = dynsym_off + len(dynsym)
    dynstr = b'\x00'
    got_off = dynstr_off + len(dynstr)
    got = b'\x00' * 16
    shstr_off = got_off + len(got)
    # Section headers sit before the relocation bytes so that .rela.dyn ends
    # at EOF: a claimed size past the file end then truly truncates the slice.
    shoff = shstr_off + len(names)
    rela_off = shoff + 6 * 64
    struct.pack_into('<Q', hdr, 0x28, shoff)
    struct.pack_into('<HHH', hdr, 0x3a, 64, 6, 5)

    def sh(name, typ, addr, off, size):
        return struct.pack('<IIQQQQIIQQ', name, typ, 0, addr, off, size, 0, 0, 0, 0)

    size = len(rela_bytes) if claimed_size is None else claimed_size
    headers = b''.join([
        sh(0, 0, 0, 0, 0),
        sh(o_rela, 4, 0, rela_off, size),
        sh(o_dynsym, 11, 0, dynsym_off, len(dynsym)),
        sh(o_dynstr, 3, 0, dynstr_off, len(dynstr)),
        sh(o_got, 1, GOT_ADDR, got_off, len(got)),
        sh(o_shstr, 3, 0, shstr_off, len(names)),
    ])
    return bytes(hdr) + dynsym + dynstr + got + names + headers + rela_bytes


def reloc(where, addend):
    return struct.pack('<QQq', where, 8, addend)


class SlotsTruncatedTests(unittest.TestCase):
    def test_ragged_tail_rejected(self):
        data = build(reloc(GOT_ADDR, 111) + b'\x00')
        with self.assertRaises(eas.EvidenceError):
            eas.Image(data).slots()

    def test_past_eof_rejected(self):
        data = build(reloc(GOT_ADDR, 111), claimed_size=48)
        with self.assertRaises(eas.EvidenceError):
            eas.Image(data).slots()

    def test_valid_section_still_parses(self):
        data = build(reloc(GOT_ADDR, 111) + reloc(GOT_ADDR + 8, 222))
        self.assertEqual(eas.Image(data).slots(), {GOT_ADDR: 111, GOT_ADDR + 8: 222})


if __name__ == '__main__':
    unittest.main()
