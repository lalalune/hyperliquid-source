"""Anchor reads in tools/bincode_varint.py must stay inside one section.

Sibling of the bincode_varint_decode anchor fix (open #437): `va_to_off`
only checks the first byte is mapped, so an anchor straddling the end of
its section silently borrowed the next section's bytes on base.
"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import bincode_varint as bv  # noqa: E402

WANT = bytes.fromhex('4881f9fb000000')


class SectionSlice(unittest.TestCase):
    def test_anchor_inside_section_is_returned(self):
        data = b'\xaa\xaa' + WANT + b'\xff' * 8
        secs = {'.text': {'addr': 0x1000, 'offset': 2, 'size': 16}}
        self.assertEqual(bv.section_slice(data, secs, 0x1000, len(WANT)), (2, WANT))

    def test_anchor_straddling_section_end_is_rejected(self):
        # Only the first 4 anchor bytes lie in .text; the remaining 3 are
        # the next file bytes. On base the slice matched and scan accepted.
        data = WANT[:4] + WANT[4:] + b'\xff' * 8
        secs = {'.text': {'addr': 0x1000, 'offset': 0, 'size': 4},
                '.rodata': {'addr': 0x2000, 'offset': 7, 'size': 8}}
        with self.assertRaisesRegex(bv.EvidenceError, r'leaves its section'):
            bv.section_slice(data, secs, 0x1000, len(WANT))

    def test_anchor_ending_on_last_section_byte_is_returned(self):
        data = WANT + b'\xff' * 8
        secs = {'.text': {'addr': 0x1000, 'offset': 0, 'size': len(WANT)}}
        self.assertEqual(bv.section_slice(data, secs, 0x1000, len(WANT)), (0, WANT))

    def test_anchor_outside_every_section_is_rejected(self):
        data = WANT + b'\xff' * 8
        secs = {'.text': {'addr': 0x1000, 'offset': 0, 'size': len(WANT)}}
        with self.assertRaisesRegex(bv.EvidenceError, r'outside every section'):
            bv.section_slice(data, secs, 0x3000, len(WANT))

    def test_anchor_past_eof_is_rejected(self):
        data = WANT[:5]
        secs = {'.text': {'addr': 0x1000, 'offset': 0, 'size': 16}}
        with self.assertRaisesRegex(bv.EvidenceError, r'leaves the file'):
            bv.section_slice(data, secs, 0x1000, len(WANT))


if __name__ == '__main__':
    unittest.main()
