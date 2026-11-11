"""Fail-closed controls: block_fill_writers_static on a missing .text
section and a missing/truncated .rela.dyn table.

caller_census() and rip_references() looked .text up with bare
next(); slot_census() looked .rela.dyn up with bare next() and
walked it with a size // 24 floor division, so a truncated table
was silently accepted. The mutants rename a section in .shstrtab
or shrink .rela.dyn by one byte; no instruction bytes change. The
module's refusal idiom is check() -> ValueError.
"""
import hashlib
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import block_fill_writers_static as subject
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


class BlockFillWritersRequiredSections(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.TARGET.read_bytes()
        if hashlib.sha256(cls.data).hexdigest() != subject.TARGET_SHA256:
            raise unittest.SkipTest("node 115 artifact is not materialised")

    def test_caller_census_missing_text_refuses(self):
        with self.assertRaisesRegex(ValueError, "missing.text section"):
            subject.caller_census(renamed(self.data, ".text"))

    def test_rip_references_missing_text_refuses(self):
        with self.assertRaisesRegex(ValueError, "missing.text section"):
            subject.rip_references(renamed(self.data, ".text"),
                                   subject.B_SIDE_SLOT)

    def test_slot_census_missing_rela_dyn_refuses(self):
        with self.assertRaisesRegex(ValueError, "missing.rela.dyn section"):
            subject.slot_census(renamed(self.data, ".rela.dyn"))

    def test_slot_census_truncated_rela_dyn_refuses(self):
        secs = sections(self.data)
        rela = next(s for s in secs if s["name"] == ".rela.dyn")
        mutant = resized(self.data, ".rela.dyn", rela["size"] - 1)
        with self.assertRaisesRegex(ValueError, "truncated.rela.dyn section"):
            subject.slot_census(mutant)

    def test_unmutated_controls(self):
        census = subject.caller_census(self.data)
        self.assertIn("direct_call_sites", census)
        self.assertIsInstance(
            subject.rip_references(self.data, subject.B_SIDE_SLOT), list)
        slot = subject.slot_census(self.data)
        self.assertIn("relocation", slot)
        self.assertIsInstance(subject.analyze(self.data), dict)


if __name__ == "__main__":
    unittest.main()
