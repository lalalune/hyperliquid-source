"""constants_scan.relocations must refuse duplicate RELATIVE slots.

relocations() folds .rela.dyn into a {slot: addend} dict with no duplicate
check, so two R_X86_64_RELATIVE records for the same slot collapse
last-wins and the surviving addend depends purely on record order.
string_table() resolves the AWS name table's pointers through this map,
so the flip silently changes which string a slot is attributed. The
sibling copies of this fold (state_roots, exchange_dispatch,
info_request_path, consensus_wire) already refuse with the same message;
this raw-bytes copy (ScanError) was the unguarded one.
"""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from constants_scan import ScanError, relocations

RELATIVE = 8


def fixture(entries):
    """Minimal ELF64-LE with .shstrtab and a .rela.dyn holding `entries`
    as (r_offset, r_info, r_addend) triples."""
    data = bytearray(0x1000)
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 40, 0x100)
    struct.pack_into('<HHH', data, 58, 64, 3, 1)
    names = b'\0.shstrtab\0.rela.dyn\0'
    data[0x200:0x200 + len(names)] = names
    rows = [
        (0, 0, 0, 0, 0, 0, 0),
        (1, 3, 0, 0, 0x200, len(names), 0),
        (names.index(b'.rela.dyn'), 4, 0, 0, 0x300, 24 * len(entries), 24),
    ]
    for index, row in enumerate(rows):
        struct.pack_into('<IIQQQQIIQQ', data, 0x100 + index * 64,
                         *row[:6], 0, 0, 1, row[6])
    for i, (slot, info, addend) in enumerate(entries):
        struct.pack_into('<QQq', data, 0x300 + i * 24, slot, info, addend)
    return bytes(data)


class RelocationsDuplicateSlot(unittest.TestCase):
    def test_duplicate_slot_rejected_with_differing_addends(self):
        for entries in ([(0x5000, RELATIVE, 0x1111), (0x5000, RELATIVE, 0x2222)],
                        [(0x5000, RELATIVE, 0x2222), (0x5000, RELATIVE, 0x1111)]):
            with self.subTest(entries=entries):
                with self.assertRaisesRegex(ScanError,
                                            'duplicate RELATIVE relocation slot'):
                    relocations(fixture(entries))

    def test_duplicate_slot_rejected_with_identical_addend(self):
        entries = [(0x5000, RELATIVE, 0x1111), (0x5000, RELATIVE, 0x1111)]
        with self.assertRaisesRegex(ScanError,
                                    'duplicate RELATIVE relocation slot'):
            relocations(fixture(entries))

    def test_distinct_slots_still_parse(self):
        entries = [(0x5000, RELATIVE, 0x1111), (0x5008, RELATIVE, 0x2222)]
        self.assertEqual(relocations(fixture(entries)),
                         {0x5000: 0x1111, 0x5008: 0x2222})

    def test_non_relative_duplicate_offset_is_not_a_relocation(self):
        # The map only admits RELATIVE records; a repeated slot under a
        # different relocation type never enters it and must not raise.
        entries = [(0x5000, 6, 0x1111), (0x5000, 6, 0x2222),
                   (0x5008, RELATIVE, 0x3333)]
        self.assertEqual(relocations(fixture(entries)),
                         {0x5008: 0x3333})


if __name__ == '__main__':
    unittest.main()
