"""Synthetic RELA controls for the varint scanners' single-value evidence map."""
from pathlib import Path
import struct
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import bincode_varint as bv  # noqa: E402


def rela(where, kind, addend, symbol=0):
    return struct.pack('<QQq', where, (symbol << 32) | kind, addend)


def parse(*records):
    prefix = b'ELF?'
    payload = b''.join(records)
    return bv.relative_relocs(
        prefix + payload,
        {'.rela.dyn': {'offset': len(prefix), 'size': len(payload)}},
    )


class RelativeRelocationTests(unittest.TestCase):
    def test_equal_duplicate_relative_offsets_are_unrepresentable(self):
        with self.assertRaisesRegex(bv.EvidenceError, 'duplicate RELATIVE relocation at 0x1000'):
            parse(rela(0x1000, 8, 9), rela(0x1000, 8, 9))

    def test_conflicting_duplicate_relative_offsets_are_unrepresentable(self):
        with self.assertRaisesRegex(bv.EvidenceError, 'duplicate RELATIVE relocation at 0x1000'):
            parse(rela(0x1000, 8, -9), rela(0x1000, 8, 12))

    def test_separated_duplicate_relative_offsets_are_unrepresentable(self):
        with self.assertRaisesRegex(bv.EvidenceError, 'duplicate RELATIVE relocation at 0x1000'):
            parse(rela(0x1000, 8, 1), rela(0x2000, 8, 2),
                  rela(0x1000, 1, 100), rela(0x1000, 8, 3))

    def test_unique_offsets_keep_signed_addends(self):
        self.assertEqual(parse(rela(0x1000, 8, -1),
                               rela(0x2000, 8, -(1 << 63)),
                               rela(0x3000, 8, (1 << 63) - 1)),
                         {0x1000: -1, 0x2000: -(1 << 63), 0x3000: (1 << 63) - 1})

    def test_empty_relocation_section_has_empty_map(self):
        self.assertEqual(parse(), {})

    def test_non_relative_records_at_same_offset_are_ignored(self):
        self.assertEqual(parse(rela(0x1000, 1, 11), rela(0x1000, 8, -5),
                               rela(0x1000, 6, 12), rela(0x2000, 8, 4, symbol=7)),
                         {0x1000: -5, 0x2000: 4})
        self.assertEqual(parse(rela(0x1000, 1, 11), rela(0x1000, 6, 12)), {})


if __name__ == '__main__':
    unittest.main()
