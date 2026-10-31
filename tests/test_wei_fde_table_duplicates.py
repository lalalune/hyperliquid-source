"""fde_table must refuse duplicate FDE starts in wei_saturating_ops.

elf_index.unwind_index, fde_extents and bincode_varint already reject a
.eh_frame_hdr table that names one start VA twice; this tool's private
copy (byte-identical to the one in ntl_ten_thousand_add) sorted the rows
and bisected them, so one of two same-start FDEs was silently shadowed
and enclosing() attributed the VA to the wider range.
"""

import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import wei_saturating_ops as tool  # noqa: E402

HDR_VA = tool.HDR_VA
S = HDR_VA + 0x1000
S2 = HDR_VA + 0x2000
F1, F2, F3 = HDR_VA + 0x400, HDR_VA + 0x500, HDR_VA + 0x600


def build(entries):
    """Synthetic blob in the tool's layout: header at HDR_VA, VA == offset.

    Each entry is (start, fde, size); the FDE body honestly claims
    pc_begin == start, so the tool's own cross-check passes.
    """
    blob = bytearray(HDR_VA + 0x4000)
    blob[HDR_VA:HDR_VA + 4] = bytes([1, 0x1B, 0x03, 0x3B])
    struct.pack_into('<I', blob, HDR_VA + 8, len(entries))
    for i, (start, fde, size) in enumerate(entries):
        struct.pack_into('<ii', blob, HDR_VA + 12 + 8 * i,
                         start - HDR_VA, fde - HDR_VA)
        struct.pack_into('<iI', blob, fde + 8, start - (fde + 8), size)
    return bytes(blob)


class FdeTableDuplicateTests(unittest.TestCase):
    def test_duplicate_starts_with_different_ranges_rejected(self):
        blob = build([(S, F1, 0x40), (S, F2, 0x80), (S2, F3, 0x30)])
        with self.assertRaisesRegex(tool.EvidenceError, 'duplicate FDE start'):
            tool.fde_table(blob)

    def test_duplicate_starts_with_identical_ranges_rejected(self):
        blob = build([(S, F1, 0x40), (S, F2, 0x40)])
        with self.assertRaisesRegex(tool.EvidenceError, 'duplicate FDE start'):
            tool.fde_table(blob)

    def test_distinct_starts_accepted_and_enclosing_resolves(self):
        blob = build([(S, F1, 0x40), (S2, F3, 0x30)])
        table = tool.fde_table(blob)
        self.assertEqual(table, [(S, S + 0x40), (S2, S2 + 0x30)])
        starts = [row[0] for row in table]
        self.assertEqual(tool.enclosing(table, starts, S + 0x10), (S, S + 0x40))

    def test_unordered_distinct_starts_still_sorted(self):
        blob = build([(S2, F3, 0x30), (S, F1, 0x40)])
        self.assertEqual(tool.fde_table(blob), [(S, S + 0x40), (S2, S2 + 0x30)])


if __name__ == '__main__':
    unittest.main()
