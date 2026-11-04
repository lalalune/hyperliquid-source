"""Fail-closed controls: flag_group_write_static on a missing/
truncated .rela.dyn table and a missing .text section.

relocations() looked .rela.dyn up with bare next() and unpacked it
with an unguarded struct.iter_unpack; address_as_data_count() looked
.rela.dyn up with bare next(); slot_call_census() looked .text up
with bare next(). The mutants rename a section in .shstrtab or shrink
.rela.dyn by one byte; no instruction bytes change. The module's
refusal idiom is ValueError.
"""
import hashlib
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import flag_group_write_static as subject
from elf_index import sections
from fde_extents import eh_frame_records


def renamed(data, name):
    shoff = struct.unpack_from("<Q", data, 40)[0]
    entsize, count, strndx = struct.unpack_from("<HHH", data, 58)
    rows = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * entsize)
            for i in range(count)]
    strtab = rows[strndx]
    table = data[strtab[4]:strtab[4] + strtab[5]]
    target = None
    for row in rows:
        end = table.find(b"\0", row[0])
        if table[row[0]:end].decode() == name:
            target = row
            break
    assert target is not None, name
    shstr = next(s for s in sections(data) if s["name"] == ".shstrtab")
    mutant = bytearray(data)
    mutant[shstr["offset"] + target[0]] = ord("X")
    return bytes(mutant)


def resized(data, name, new_size):
    shoff = struct.unpack_from("<Q", data, 40)[0]
    entsize, count, strndx = struct.unpack_from("<HHH", data, 58)
    rows = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * entsize)
            for i in range(count)]
    strtab = rows[strndx]
    table = data[strtab[4]:strtab[4] + strtab[5]]
    target = None
    for row in rows:
        end = table.find(b"\0", row[0])
        if table[row[0]:end].decode() == name:
            target = row
            break
    assert target is not None, name
    mutant = bytearray(data)
    struct.pack_into("<Q", mutant, shoff + rows.index(target) * entsize + 32,
                     new_size)
    return bytes(mutant)


class FlagGroupWriteRequiredSections(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.TARGET.read_bytes()
        if hashlib.sha256(cls.data).hexdigest() != subject.SHA:
            raise unittest.SkipTest("node 115 artifact is not materialised")
        _cies, cls.fdes = eh_frame_records(cls.data, sections(cls.data))

    def test_relocations_missing_rela_dyn_refuses(self):
        with self.assertRaisesRegex(ValueError, "missing.rela.dyn section"):
            subject.relocations(renamed(self.data, ".rela.dyn"))

    def test_relocations_truncated_rela_dyn_refuses(self):
        secs = sections(self.data)
        rela = next(s for s in secs if s["name"] == ".rela.dyn")
        mutant = resized(self.data, ".rela.dyn", rela["size"] - 1)
        with self.assertRaisesRegex(ValueError, "truncated.rela.dyn section"):
            subject.relocations(mutant)

    def test_address_as_data_count_missing_rela_dyn_refuses(self):
        with self.assertRaisesRegex(ValueError, "missing.rela.dyn section"):
            subject.address_as_data_count(renamed(self.data, ".rela.dyn"))

    def test_slot_call_census_missing_text_refuses(self):
        with self.assertRaisesRegex(ValueError, "missing.text section"):
            subject.slot_call_census(renamed(self.data, ".text"), self.fdes)

    def test_unmutated_controls(self):
        by_offset, _hits = subject.relocations(self.data)
        self.assertTrue(by_offset)
        self.assertIsInstance(subject.address_as_data_count(self.data), int)
        census = subject.slot_call_census(self.data, self.fdes)
        self.assertEqual(len(census), 5)
        self.assertIsInstance(subject.analyze(self.data), dict)


if __name__ == "__main__":
    unittest.main()
