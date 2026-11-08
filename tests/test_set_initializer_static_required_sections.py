"""Fail-closed controls: set_initializer_static on a missing/
truncated .rela.dyn table, missing .dynsym/.dynstr tables, and a
non-UTF-8 dynamic symbol name.

_relocations() looked .rela.dyn up with bare next() and walked it
with a range-step loop, so a truncated table was silently accepted;
_dynsym_name() looked .dynsym/.dynstr up with bare next() and
decoded the name with a bare .decode(). The mutants rename a
section in .shstrtab, shrink .rela.dyn by one byte, or flip one
byte of the memcpy name (symbol index 7) to 0xFF; no instruction
bytes change. The module's refusal idiom is ValueError raised
directly.
"""
import hashlib
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import set_initializer_static as subject
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


def corrupt_name(data, sym_idx):
    secs = sections(data)
    sym = next(s for s in secs if s["name"] == ".dynsym")
    strs = next(s for s in secs if s["name"] == ".dynstr")
    name_off = struct.unpack_from("<I", data, sym["offset"] + sym_idx * 24)[0]
    mutant = bytearray(data)
    mutant[strs["offset"] + name_off] = 0xFF
    return bytes(mutant)


class SetInitializerRequiredSections(unittest.TestCase):
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

    def test_dynsym_name_missing_dynsym_refuses(self):
        with self.assertRaisesRegex(ValueError, "missing.dynsym section"):
            subject._dynsym_name(renamed(self.data, ".dynsym"), 7)

    def test_dynsym_name_missing_dynstr_refuses(self):
        with self.assertRaisesRegex(ValueError, "missing.dynstr section"):
            subject._dynsym_name(renamed(self.data, ".dynstr"), 7)

    def test_dynsym_name_corrupt_memcpy_refuses(self):
        with self.assertRaisesRegex(ValueError, "dynamic symbol name is not valid UTF-8"):
            subject._dynsym_name(corrupt_name(self.data, 7), 7)

    def test_slot_bindings_corrupt_memcpy_refuses(self):
        with self.assertRaisesRegex(ValueError, "dynamic symbol name is not valid UTF-8"):
            subject.slot_bindings(corrupt_name(self.data, 7))

    def test_unmutated_controls(self):
        bindings = subject.slot_bindings(self.data)
        self.assertEqual(bindings["memcpy"]["symbol"], "memcpy")
        self.assertIsInstance(subject.analyze(self.data), dict)


if __name__ == "__main__":
    unittest.main()
