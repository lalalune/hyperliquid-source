"""Synthetic controls for duplicate FDE starts in bincode_varint.fde_extents()."""
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import bincode_varint as bv  # noqa: E402

HDR_ADDR = 0x1000
FRAME_ADDR = 0x2000


def build(entries):
    """entries: list of (start_va, fde_va, pc_range) sharing one hdr/frame pair."""
    hdr = bytearray(64)
    hdr[0:4] = bytes([1, 0x1b, 0x03, 0x3b])
    struct.pack_into('<I', hdr, 8, len(entries))
    for i, (start, fde_va, _pc_range) in enumerate(entries):
        struct.pack_into('<ii', hdr, 12 + i * 8, start - HDR_ADDR, fde_va - HDR_ADDR)
    frame = bytearray(256)
    for start, fde_va, pc_range in entries:
        fo = fde_va - FRAME_ADDR
        struct.pack_into('<II', frame, fo, 16, 1)
        struct.pack_into('<iI', frame, fo + 8, start - fde_va - 8, pc_range)
    data = bytes(hdr) + bytes(frame)
    secs = {'.eh_frame_hdr': {'addr': HDR_ADDR, 'offset': 0, 'size': len(hdr)},
            '.eh_frame': {'addr': FRAME_ADDR, 'offset': len(hdr), 'size': len(frame)}}
    return data, secs


class DuplicateFdeTests(unittest.TestCase):
    def test_duplicate_fde_start_raises(self):
        data, secs = build([(0x1100, 0x2000, 0x40), (0x1100, 0x2020, 0x80)])
        with self.assertRaisesRegex(bv.EvidenceError, 'duplicate FDE start'):
            bv.fde_extents(data, secs)

    def test_unique_fde_starts_parse(self):
        data, secs = build([(0x1100, 0x2000, 0x40), (0x1200, 0x2020, 0x80)])
        self.assertEqual(bv.fde_extents(data, secs), {0x1100: 0x1140, 0x1200: 0x1280})


if __name__ == '__main__':
    unittest.main()
