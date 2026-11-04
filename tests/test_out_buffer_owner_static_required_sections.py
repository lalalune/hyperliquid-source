"""Fail-closed controls: out_buffer_owner_static on a missing/
truncated .rela.dyn table, missing .dynsym/.dynstr sections, and a
non-ASCII dynamic symbol name.

relocations() looked .rela.dyn up with bare next() and unpacked it
with an unguarded struct.iter_unpack; dynsym_name() looked .dynsym/
.dynstr up with bare next() and decoded with a bare .decode('ascii').
The mutants rename a section in .shstrtab, shrink .rela.dyn by one
byte, or flip one byte inside the memcpy name; no instruction bytes
change. The module's refusal idiom is ValueError.
"""
import hashlib
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import out_buffer_owner_static as subject
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


class OutBufferOwnerRequiredSections(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.TARGET.read_bytes()
        if hashlib.sha256(cls.data).hexdigest() != subject.SHA:
            raise unittest.SkipTest("node 115 artifact is not materialised")
        cls.memcpy_index = subject.MEMCPY_RELOCATION[1]

    def test_relocations_missing_rela_dyn_refuses(self):
        with self.assertRaisesRegex(ValueError, "missing.rela.dyn section"):
            subject.relocations(renamed(self.data, ".rela.dyn"))

    def test_relocations_truncated_rela_dyn_refuses(self):
        secs = sections(self.data)
        rela = next(s for s in secs if s["name"] == ".rela.dyn")
        mutant = resized(self.data, ".rela.dyn", rela["size"] - 1)
        with self.assertRaisesRegex(ValueError, "truncated.rela.dyn section"):
            subject.relocations(mutant)

    def test_dynsym_name_missing_dynsym_refuses(self):
        with self.assertRaisesRegex(ValueError, "missing.dynsym section"):
            subject.dynsym_name(renamed(self.data, ".dynsym"), self.memcpy_index)

    def test_dynsym_name_missing_dynstr_refuses(self):
        with self.assertRaisesRegex(ValueError, "missing.dynstr section"):
            subject.dynsym_name(renamed(self.data, ".dynstr"), self.memcpy_index)

    def test_dynsym_name_non_ascii_refuses(self):
        secs = sections(self.data)
        sym = next(s for s in secs if s["name"] == ".dynsym")
        strs = next(s for s in secs if s["name"] == ".dynstr")
        name_off = struct.unpack_from(
            "<I", self.data, sym["offset"] + self.memcpy_index * 24)[0]
        mutant = bytearray(self.data)
        mutant[strs["offset"] + name_off] = 0xFF
        mutant = bytes(mutant)
        with self.assertRaisesRegex(ValueError, "not valid ASCII"):
            subject.dynsym_name(mutant, self.memcpy_index)
        with self.assertRaisesRegex(ValueError, "not valid ASCII"):
            subject.slot_bindings(mutant)

    def test_unmutated_controls(self):
        self.assertTrue(subject.relocations(self.data))
        self.assertEqual(subject.dynsym_name(self.data, self.memcpy_index),
                         subject.MEMCPY_NAME)
        self.assertIsInstance(subject.analyze(self.data), dict)


if __name__ == "__main__":
    unittest.main()
