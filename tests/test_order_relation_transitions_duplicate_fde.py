"""Image.fde_table must refuse duplicate FDE starts in order_relation_transitions.

elf_index.unwind_index, fde_extents and bincode_varint already reject a
.eh_frame_hdr table that names one start VA twice; this tool's private
Image copy only checked the table was sorted (non-strictly), so a
duplicate start passed and bisect_right in fde() attributed the VA to
the later, wider FDE while the narrower one was silently shadowed.
"""

import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import order_relation_transitions as tool  # noqa: E402

BASE = 0x400000
HDR = BASE + 0x1000
S = BASE + 0x2000
S2 = BASE + 0x3000
F1, F2, F3 = BASE + 0x400, BASE + 0x500, BASE + 0x600


def build(entries):
    """Minimal synthetic ELF64 in the layout Image parses.

    One PT_LOAD with VA == BASE + file offset; .text, .eh_frame_hdr and
    .shstrtab sections. Each entry is (start, fde, size); the FDE body
    honestly claims pc_begin == start, so the tool's own cross-check
    passes.
    """
    total = 0x4000
    blob = bytearray(total)
    blob[0:5] = b"\x7fELF\x02"
    struct.pack_into("<H", blob, 18, 62)
    shoff = 0x3800
    struct.pack_into("<QQ", blob, 32, 64, shoff)
    struct.pack_into("<HHHH", blob, 56, 1, 64, 4, 3)
    struct.pack_into("<IIQQQQQQ", blob, 64, 1, 5, 0, BASE, BASE,
                     total, total, 0x1000)
    names = b"\x00.text\x00.eh_frame_hdr\x00.shstrtab\x00"
    blob[0x3900:0x3900 + len(names)] = names

    def shdr(i, name, typ, flags, addr, off, size):
        struct.pack_into("<IIQQQQIIQQ", blob, shoff + 64 * i,
                         name, typ, flags, addr, off, size, 0, 0, 1, 0)

    shdr(0, 0, 0, 0, 0, 0, 0)
    shdr(1, 1, 1, 0x6, BASE + 0x2000, 0x2000, 0x2000)
    shdr(2, 7, 1, 0x2, HDR, HDR - BASE, 12 + 8 * len(entries))
    shdr(3, 21, 3, 0, 0, 0x3900, len(names))
    blob[HDR - BASE:HDR - BASE + 4] = bytes([1, 0x1B, 0x03, 0x3B])
    struct.pack_into("<I", blob, HDR - BASE + 8, len(entries))
    for i, (start, fde, size) in enumerate(entries):
        struct.pack_into("<ii", blob, HDR - BASE + 12 + 8 * i,
                         start - HDR, fde - HDR)
        struct.pack_into("<IIiI", blob, fde - BASE, 16, 0,
                         start - (fde + 8), size)
    return bytes(blob)


class FdeTableDuplicateTests(unittest.TestCase):
    def test_duplicate_starts_with_different_ranges_rejected(self):
        blob = build([(S, F1, 0x40), (S, F2, 0x80), (S2, F3, 0x30)])
        with self.assertRaisesRegex(tool.EvidenceError, 'duplicate FDE start'):
            tool.Image(blob)

    def test_duplicate_starts_with_identical_ranges_rejected(self):
        blob = build([(S, F1, 0x40), (S, F2, 0x40)])
        with self.assertRaisesRegex(tool.EvidenceError, 'duplicate FDE start'):
            tool.Image(blob)

    def test_distinct_starts_accepted_and_fde_resolves(self):
        img = tool.Image(build([(S, F1, 0x40), (S2, F3, 0x30)]))
        self.assertEqual(img.starts, [S, S2])
        self.assertEqual(img.fde(S + 0x10), (S, S + 0x40))
        with self.assertRaises(tool.EvidenceError):
            img.fde(S + 0x50)

    def test_unsorted_distinct_starts_still_rejected(self):
        blob = build([(S2, F3, 0x30), (S, F1, 0x40)])
        with self.assertRaisesRegex(tool.EvidenceError, 'unsorted'):
            tool.Image(blob)


if __name__ == '__main__':
    unittest.main()
