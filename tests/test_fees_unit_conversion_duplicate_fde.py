"""Fdes must refuse a non-increasing .eh_frame_hdr table in
fees_unit_conversion.

The sibling Fdes family (evm_amount_scale, evm_extra_wei_decimals,
qty_newtype_sign_guards, spot_token_decimals, spot_wei_scale,
wei_buffered_cap, weipriv_sign_guard) rejects such a table with
'.eh_frame_hdr table not strictly increasing'; this tool's private copy
(byte-identical to the ones in fees_schedule_cancel_gate and
fees_spot_volume) collected the starts with no ordering or duplicate
check at all, so one of two same-start FDEs was silently shadowed and
range_of() attributed the VA to the wider range.
"""

import importlib.util
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools' / 'fees_unit_conversion.py'

spec = importlib.util.spec_from_file_location('fees_unit_conversion', TOOL)
tool = importlib.util.module_from_spec(spec)
sys.modules['fees_unit_conversion'] = tool
spec.loader.exec_module(tool)

BASE = 0x400000
HDR = BASE + 0x1000                 # .eh_frame_hdr VA
CIE = BASE + 0x2100                 # shared CIE VA (inside .text)
S = BASE + 0x2000                   # shared (duplicated) start VA
S2 = BASE + 0x3000                  # normal start VA
F1, F2, F3 = BASE + 0x2400, BASE + 0x2500, BASE + 0x2600   # FDE VAs


def build(entries):
    """Synthetic ELF64 in the tool's own input format (section headers).

    Each entry is (start, fde, size); every FDE body honestly claims
    pc_begin == start and points at one shared CIE whose R encoding is
    udata4, so the tool's own cross-checks pass.
    """
    total = 0x4000
    blob = bytearray(total)
    blob[0:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<H', blob, 18, 62)
    shoff = 0x3800
    struct.pack_into('<QQ', blob, 32, 0, shoff)
    struct.pack_into('<HHHHHH', blob, 52, 64, 56, 0, 64, 4, 3)
    names = b'\x00.text\x00.eh_frame_hdr\x00.shstrtab\x00'
    blob[0x3900:0x3900 + len(names)] = names

    def shdr(i, name, typ, flags, addr, off, size):
        struct.pack_into('<IIQQQQIIQQ', blob, shoff + 64 * i,
                         name, typ, flags, addr, off, size, 0, 0, 1, 0)

    shdr(0, 0, 0, 0, 0, 0, 0)
    shdr(1, 1, 1, 0x6, BASE + 0x2000, 0x2000, 0x2000)
    shdr(2, 7, 1, 0x2, HDR, HDR - BASE, 12 + 8 * len(entries))
    shdr(3, 21, 3, 0, 0, 0x3900, len(names))
    blob[HDR - BASE:HDR - BASE + 4] = bytes([1, 0x1B, 0x03, 0x3B])
    struct.pack_into('<i', blob, HDR - BASE + 4, 0)
    struct.pack_into('<I', blob, HDR - BASE + 8, len(entries))
    struct.pack_into('<I', blob, CIE - BASE, 20)
    struct.pack_into('<I', blob, CIE - BASE + 4, 0)
    blob[CIE - BASE + 8] = 1
    blob[CIE - BASE + 9:CIE - BASE + 12] = b'zR\x00'
    blob[CIE - BASE + 12] = 1     # code alignment
    blob[CIE - BASE + 13] = 1     # data alignment
    blob[CIE - BASE + 14] = 0     # return register
    blob[CIE - BASE + 15] = 1     # augmentation length
    blob[CIE - BASE + 16] = 0x03  # R encoding: udata4 absolute
    for i, (start, fde, size) in enumerate(entries):
        struct.pack_into('<ii', blob, HDR - BASE + 12 + 8 * i,
                         start - HDR, fde - HDR)
        struct.pack_into('<II', blob, fde - BASE, 16, (fde + 4) - CIE)
        struct.pack_into('<I', blob, fde - BASE + 8, start)
        struct.pack_into('<I', blob, fde - BASE + 12, size)
    return bytes(blob)


def fdes(entries):
    return tool.Fdes(tool.Image(build(entries)))


class DuplicateStarts(unittest.TestCase):
    def test_duplicate_starts_rejected(self):
        with self.assertRaises(tool.EvidenceError) as cm:
            fdes([(S, F1, 0x40), (S, F2, 0x80), (S2, F3, 0x30)])
        self.assertIn('not strictly increasing', str(cm.exception))

    def test_unsorted_starts_rejected(self):
        with self.assertRaises(tool.EvidenceError) as cm:
            fdes([(S2, F3, 0x30), (S, F1, 0x40)])
        self.assertIn('not strictly increasing', str(cm.exception))

    def test_normal_table_accepted(self):
        f = fdes([(S, F1, 0x40), (S2, F3, 0x30)])
        r = f.range_of(S + 0x10)
        self.assertEqual((r['start'], r['end'], r['hdr_index']),
                         (S, S + 0x40, 0))

    def test_normal_table_out_of_range_raises(self):
        f = fdes([(S, F1, 0x40), (S2, F3, 0x30)])
        with self.assertRaises(tool.EvidenceError):
            f.range_of(S + 0x50)


if __name__ == '__main__':
    unittest.main()
