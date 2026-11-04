"""Fail-closed controls: element_argument_static on a truncated
relocation table, a missing .text section, a missing dynamic symbol
table, an out-of-range symbol-table link, and a non-UTF-8 symbol name.

Same helper shapes as argument_producers_static: _rela_entries()
range-stepped over SHT_RELA blobs with no size check, _e8_callers()
looked .text up with bare next(), _dynsym_name() searched for the
SHT_DYNSYM section with bare next(), indexed secs[link] unchecked,
and decoded with a bare .decode('utf-8'). The mutants shrink a
section header, rename a section in .shstrtab, change a
section-header type/link field, or flip one byte inside the memcpy
name; no instruction bytes change. The module's refusal idiom is
AssertionError throughout. The analyze() SITES lookups are not
claimed: SITES is a module constant, not input data.
"""
import hashlib
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import element_argument_static as m
from elf_index import sections
from fde_extents import fde_extents

ARTIFACT = ROOT / "artifacts" / "node" / "115" / "hl-node"


def artifact_bytes():
    data = ARTIFACT.read_bytes()
    if hashlib.sha256(data).hexdigest() != m.ARTIFACT_SHA256:
        raise unittest.SkipTest("node 115 artifact is not materialised")
    return data


def section_rows(data):
    shoff = struct.unpack_from("<Q", data, 40)[0]
    entsize, count, strndx = struct.unpack_from("<HHH", data, 58)
    rows = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * entsize)
            for i in range(count)]
    strtab = rows[strndx]
    table = data[strtab[4]:strtab[4] + strtab[5]]
    named = {}
    for i, row in enumerate(rows):
        end = table.find(b"\0", row[0])
        named[table[row[0]:end].decode()] = (shoff + i * entsize, row)
    return named, rows, table


def renamed(data, name):
    named, _, _ = section_rows(data)
    shoff, row = named[name]
    shstr = next(s for s in sections(data) if s["name"] == ".shstrtab")
    mutant = bytearray(data)
    mutant[shstr["offset"] + row[0]] = ord("X")
    return bytes(mutant)


def resized(data, name, new_size):
    named, _, _ = section_rows(data)
    shoff, _row = named[name]
    mutant = bytearray(data)
    struct.pack_into("<Q", mutant, shoff + 32, new_size)
    return bytes(mutant)


def retyped_dynsym(data):
    named, _, _ = section_rows(data)
    shoff, _row = named[".dynsym"]
    mutant = bytearray(data)
    struct.pack_into("<I", mutant, shoff + 4, 1)
    return bytes(mutant)


def corrupt_link(data):
    named, _, _ = section_rows(data)
    shoff, _row = named[".dynsym"]
    mutant = bytearray(data)
    struct.pack_into("<I", mutant, shoff + 40, 999)
    return bytes(mutant)


class ElementArgumentRequiredSections(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = artifact_bytes()
        cls.secs = sections(cls.data)
        cls.relas = m._rela_entries(cls.data, cls.secs)
        cls.memcpy_index = next(e[2] for e in cls.relas
                                if e[0] == m.MEMCPY_SLOT)

    def test_truncated_rela_dyn_refuses(self):
        named, _, _ = section_rows(self.data)
        size = named[".rela.dyn"][1][5]
        mutant = resized(self.data, ".rela.dyn", size - 1)
        with self.assertRaisesRegex(AssertionError, "truncated.rela.dyn section"):
            m._rela_entries(mutant, sections(mutant))
        with self.assertRaisesRegex(AssertionError, "truncated.rela.dyn section"):
            m.analyze(mutant)

    def test_missing_text_refuses_in_e8_callers(self):
        mutant = renamed(self.data, ".text")
        _, ordered, _ = fde_extents(mutant)
        with self.assertRaisesRegex(AssertionError, "missing.text section"):
            m._e8_callers(mutant, sections(mutant), ordered, {})

    def test_missing_text_refuses_in_analyze(self):
        with self.assertRaisesRegex(AssertionError, "missing.text section"):
            m.analyze(renamed(self.data, ".text"))

    def test_missing_dynsym_refuses(self):
        mutant = retyped_dynsym(self.data)
        with self.assertRaisesRegex(AssertionError, "missing.dynsym section"):
            m._dynsym_name(mutant, sections(mutant), self.memcpy_index)

    def test_dynsym_link_out_of_range_refuses(self):
        mutant = corrupt_link(self.data)
        with self.assertRaisesRegex(AssertionError, "link out of range"):
            m._dynsym_name(mutant, sections(mutant), self.memcpy_index)

    def test_non_utf8_symbol_name_refuses(self):
        sym = next(s for s in self.secs if s["name"] == ".dynsym")
        strs = next(s for s in self.secs if s["name"] == ".dynstr")
        name_off = struct.unpack_from(
            "<I", self.data, sym["offset"] + self.memcpy_index * 24)[0]
        mutant = bytearray(self.data)
        mutant[strs["offset"] + name_off] = 0xFF
        mutant = bytes(mutant)
        with self.assertRaisesRegex(AssertionError, "not valid UTF-8"):
            m._dynsym_name(mutant, sections(mutant), self.memcpy_index)
        with self.assertRaisesRegex(AssertionError, "not valid UTF-8"):
            m.analyze(mutant)

    def test_unmutated_controls(self):
        self.assertEqual(len(self.relas), 61001)
        self.assertEqual(
            m._dynsym_name(self.data, self.secs, self.memcpy_index), "memcpy")
        self.assertIsInstance(m.analyze(self.data), dict)


if __name__ == "__main__":
    unittest.main()
