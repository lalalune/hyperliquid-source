"""Duplicate RELATIVE slots must be refused by rocksdb_open_options.

Image.relative_relocs() folds .rela.dyn into a slot -> addend map that
check_slots() and the bundle/row readers trust. Two RELATIVE records for
the same slot must be refused, not folded last-wins: the surviving
addend would otherwise depend on record order, so a forged wrong addend
placed before the genuine record is masked (check_slots accepts) while
the same forgery after it is rejected. The genuine node94 table holds
80,022 records with no duplicate offset at all, and the sibling tools
(constants_scan, state_roots) already refuse a duplicate RELATIVE slot.
"""
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import rocksdb_open_options as tool

TOTAL = 640
RELA_OFF = 408
RELATIVE = 8
SLOT, TARGET = 0x5775cf8, 0x4f944f0  # FFI block_options_create


def make_elf(entries):
    """ELF64-LE with .rela.dyn holding `entries` as (r_offset, r_info,
    r_addend) triples, an empty .text, and a .shstrtab section."""
    table = b'\x00.rela.dyn\x00.text\x00.shstrtab\x00'
    data = bytearray(TOTAL)
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 40, 128)          # shoff
    struct.pack_into('<HHH', data, 58, 64, 4, 3)   # shentsize, shnum, shstrndx
    # Section headers: null, .rela.dyn, .text, .shstrtab.
    struct.pack_into('<IIQQQQIIQQ', data, 128,
                     0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    struct.pack_into('<IIQQQQIIQQ', data, 192,
                     1, 4, 0, 0x402000, RELA_OFF, 24 * len(entries),
                     0, 0, 8, 24)
    struct.pack_into('<IIQQQQIIQQ', data, 256,
                     11, 1, 6, 0x400000, 384, 0, 0, 0, 16, 0)
    struct.pack_into('<IIQQQQIIQQ', data, 320,
                     17, 3, 0, 0, 388, len(table), 0, 0, 1, 0)
    data[388:388 + len(table)] = table
    for i, (r_off, info, add) in enumerate(entries):
        struct.pack_into('<QQq', data, RELA_OFF + 24 * i, r_off, info, add)
    return bytes(data)


class RelativeRelocsDuplicateTests(unittest.TestCase):
    def test_duplicate_relative_slot_rejected_with_differing_addends(self):
        for entries in ([(0x5000, RELATIVE, 0x1111), (0x5000, RELATIVE, 0x2222)],
                        [(0x5000, RELATIVE, 0x2222), (0x5000, RELATIVE, 0x1111)]):
            with self.subTest(entries=entries):
                with self.assertRaisesRegex(ValueError, 'duplicate RELATIVE relocation slot'):
                    tool.Image(make_elf(entries))

    def test_duplicate_relative_slot_rejected_with_identical_addend(self):
        entries = [(0x5000, RELATIVE, 0x1111), (0x5000, RELATIVE, 0x1111)]
        with self.assertRaisesRegex(ValueError, 'duplicate RELATIVE relocation slot'):
            tool.Image(make_elf(entries))

    def test_distinct_slots_and_other_types_still_parse(self):
        entries = [(0x5000, RELATIVE, 0x1111), (0x5008, 6, 0x2222),
                   (0x5008, 6, 0x3333), (0x5010, RELATIVE, 0x4444)]
        img = tool.Image(make_elf(entries))
        self.assertEqual(img.rel, {0x5000: 0x1111, 0x5010: 0x4444})


@unittest.skipUnless(tool.BINARY.stat().st_size == 91774280,
                     'materialize the pinned node94 capture')
class RealTableDuplicateTests(unittest.TestCase):
    """The forged duplicate must be refused on the real table, in either
    record order; on the unfixed tool the before-genuine order leaves
    check_slots() accepting a table that carries a duplicated watched
    slot with a wrong addend."""

    @classmethod
    def setUpClass(cls):
        cls.data = tool.load()
        from elf_index import sections
        cls.sec = next(s for s in sections(cls.data) if s['name'] == '.rela.dyn')

    def forge(self, place_after):
        entries = list(struct.iter_unpack(
            '<QQq', self.data[self.sec['offset']:self.sec['offset'] + self.sec['size']]))
        genuine = next(i for i, (a, inf, v) in enumerate(entries)
                       if a == SLOT and (inf & 0xffffffff) == RELATIVE and v == TARGET)
        watched = {slot for slot, _ in tool.FFI.values()}
        rng = range(genuine + 1, len(entries)) if place_after else range(genuine)
        victim = next(i for i in rng if entries[i][0] not in watched)
        mutated = bytearray(self.data)
        struct.pack_into('<QQq', mutated,
                         self.sec['offset'] + 24 * victim, SLOT, RELATIVE, 0xdeadbeef)
        return bytes(mutated)

    def test_genuine_table_accepted(self):
        img = tool.Image(self.data)
        self.assertEqual(img.rel[SLOT], TARGET)
        tool.check_slots(img)

    def test_forged_duplicate_before_genuine_rejected(self):
        with self.assertRaisesRegex(ValueError, 'duplicate RELATIVE relocation slot'):
            tool.Image(self.forge(place_after=False))

    def test_forged_duplicate_after_genuine_rejected(self):
        with self.assertRaisesRegex(ValueError, 'duplicate RELATIVE relocation slot'):
            tool.Image(self.forge(place_after=True))


if __name__ == '__main__':
    unittest.main()
