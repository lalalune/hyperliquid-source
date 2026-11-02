"""Duplicate .rela.dyn slots must be refused by cumulative_minute_static.

relocations() folds .rela.dyn into a slot -> (info, addend) index that the
Location/helper binding check in analyze() reads. Two records for the
same slot must be refused, not folded last-wins: the surviving pair would
otherwise depend on record order, so a forged wrong binding placed
before the genuine record would be masked. The genuine node94 table
holds 80,022 records with no duplicate offset at all, and the sibling
cid_lookup_static / ren_format_static relocations() already refuse any
duplicate slot.
"""
import importlib.util
import json
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
spec = importlib.util.spec_from_file_location(
    "cumulative_minute_static", ROOT / "tools/cumulative_minute_static.py")
cm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cm)
from artifacts import check
from elf_index import sections

TOTAL = 512
RELA_OFF = 344
RELATIVE = 8
SLOT, WANT = 0x566cb50, (8, 0x1e3851)
WATCHED = {0x566cb50, 0x576e108}


def make_elf(entries):
    """ELF64-LE with .rela.dyn holding `entries` as (r_offset, r_info,
    r_addend) triples, plus a .shstrtab section."""
    table = b'\x00.rela.dyn\x00.shstrtab\x00'
    data = bytearray(TOTAL)
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 40, 128)          # shoff
    struct.pack_into('<HHH', data, 58, 64, 3, 2)   # shentsize, shnum, shstrndx
    # Section headers: null, .rela.dyn, .shstrtab.
    struct.pack_into('<IIQQQQIIQQ', data, 128,
                     0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    struct.pack_into('<IIQQQQIIQQ', data, 192,
                     1, 4, 0, 0x402000, RELA_OFF, 24 * len(entries),
                     0, 0, 8, 24)
    struct.pack_into('<IIQQQQIIQQ', data, 256,
                     11, 3, 0, 0, 320, len(table), 0, 0, 1, 0)
    data[320:320 + len(table)] = table
    for i, (r_off, info, add) in enumerate(entries):
        struct.pack_into('<QQq', data, RELA_OFF + 24 * i, r_off, info, add)
    return bytes(data)


class RelocationsDuplicateTests(unittest.TestCase):
    def test_duplicate_slot_rejected_with_differing_addends(self):
        for entries in ([(0x5000, RELATIVE, 0x1111), (0x5000, RELATIVE, 0x2222)],
                        [(0x5000, RELATIVE, 0x2222), (0x5000, RELATIVE, 0x1111)]):
            with self.subTest(entries=entries):
                with self.assertRaisesRegex(ValueError, 'duplicate relocation slot'):
                    cm.relocations(make_elf(entries))

    def test_duplicate_slot_rejected_with_identical_addend(self):
        entries = [(0x5000, RELATIVE, 0x1111), (0x5000, RELATIVE, 0x1111)]
        with self.assertRaisesRegex(ValueError, 'duplicate relocation slot'):
            cm.relocations(make_elf(entries))

    def test_distinct_slots_still_parse(self):
        entries = [(0x5000, RELATIVE, 0x1111), (0x5008, 6, 0x2222)]
        self.assertEqual(cm.relocations(make_elf(entries)),
                         {0x5000: (RELATIVE, 0x1111), 0x5008: (6, 0x2222)})


@unittest.skipUnless(
    (ROOT / 'artifacts/node/94/hl-node').stat().st_size == 91774280,
    'materialize the pinned node94 capture')
class RealTableDuplicateTests(unittest.TestCase):
    """The forged duplicate must be refused on the real table, in either
    record order; on the unfixed tool the before-genuine order is accepted."""

    @classmethod
    def setUpClass(cls):
        target = ROOT / 'artifacts/node/94/hl-node'
        identity = next(i for i in json.loads(
            (ROOT / 'provenance/artifacts.json').read_text())['files']
            if i['path'] == 'artifacts/node/94/hl-node')
        check(target, identity)
        cls.data = target.read_bytes()
        cls.sec = next(s for s in sections(cls.data) if s['name'] == '.rela.dyn')

    def forge(self, place_after):
        entries = list(struct.iter_unpack(
            '<QQq', self.data[self.sec['offset']:self.sec['offset'] + self.sec['size']]))
        genuine = next(i for i, (a, inf, v) in enumerate(entries)
                       if a == SLOT and (inf, v) == WANT)
        rng = range(genuine + 1, len(entries)) if place_after else range(genuine)
        victim = next(i for i in rng if entries[i][0] not in WATCHED)
        mutated = bytearray(self.data)
        struct.pack_into('<QQq', mutated,
                         self.sec['offset'] + 24 * victim, SLOT, 8, 0xdeadbeef)
        return bytes(mutated)

    def test_genuine_table_accepted(self):
        cm.analyze(self.data)

    def test_forged_duplicate_before_genuine_rejected(self):
        with self.assertRaisesRegex(ValueError, 'duplicate relocation slot'):
            cm.analyze(self.forge(place_after=False))

    def test_forged_duplicate_after_genuine_rejected(self):
        with self.assertRaisesRegex(ValueError, 'duplicate relocation slot'):
            cm.analyze(self.forge(place_after=True))


if __name__ == '__main__':
    unittest.main()
