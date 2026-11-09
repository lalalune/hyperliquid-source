"""Fail-closed controls: entry_tag_consumers_static on a missing/
truncated .rela.dyn table.

_relocations() looked .rela.dyn up with bare next() and walked it
with a range-step loop, so a truncated table was silently accepted.
The mutants rename the section in .shstrtab or shrink .rela.dyn by
one byte; no instruction bytes change. The module's refusal idiom
is ValueError raised directly. analyze() reaches _relocations()
through slot_bindings(), so the missing-table escape is visible
there too. NOTE: _dynsym_name() is not covered here -- no wanted
slot is type 6 on the pinned binary, so it is never called there.
"""
import hashlib
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import entry_tag_consumers_static as subject
from elf_index import sections


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


class EntryTagConsumersRequiredSections(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.TARGET.read_bytes()
        if hashlib.sha256(cls.data).hexdigest() != subject.SHA:
            raise unittest.SkipTest("node 115 artifact is not materialised")

    def test_relocations_missing_rela_dyn_refuses(self):
        with self.assertRaisesRegex(ValueError, "missing.rela.dyn section"):
            subject._relocations(renamed(self.data, ".rela.dyn"))

    def test_relocations_truncated_rela_dyn_refuses(self):
        secs = sections(self.data)
        rela = next(s for s in secs if s["name"] == ".rela.dyn")
        mutant = resized(self.data, ".rela.dyn", rela["size"] - 1)
        with self.assertRaisesRegex(ValueError, "truncated.rela.dyn section"):
            subject._relocations(mutant)

    def test_analyze_missing_rela_dyn_refuses(self):
        with self.assertRaisesRegex(ValueError, "missing.rela.dyn section"):
            subject.analyze(renamed(self.data, ".rela.dyn"))

    def test_unmutated_controls(self):
        bindings = subject.slot_bindings(self.data)
        self.assertIn("merge_delegate", bindings)
        self.assertIsInstance(subject.analyze(self.data), dict)


if __name__ == "__main__":
    unittest.main()
