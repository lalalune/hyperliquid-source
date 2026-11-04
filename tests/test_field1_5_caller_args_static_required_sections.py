"""Fail-closed controls: field1_5_caller_args_static on missing/truncated
sections and a non-UTF-8 dynamic symbol name.

relocations() looked .rela.dyn up with bare next() and range-stepped
over it with unpack_from, so a missing table escaped as StopIteration
and a truncated table was silently accepted (the range-step reads
past the section into the next section's bytes and the entries map
comes out identical); dynsym_name() looked .dynsym/.dynstr up with
bare next() and decoded with a bare .decode(); census() looked .text
up with bare next(). The mutants rename or shrink section headers,
or flip one byte inside the memcpy name, only; no instruction bytes
change. analyze() reaches all three sites (relocations first, then
the memcpy slot name, then the .text census), and a short but aligned
table already refuses via the require(len(entries) == 1) check, so no
slot-presence guard is needed. generate()'s digest gate is untouched
and irrelevant to analyze().
"""
import hashlib
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import field1_5_caller_args_static as subject
from elf_index import sections


def section_headers(data):
    shoff = struct.unpack_from("<Q", data, 40)[0]
    entsize, count, strndx = struct.unpack_from("<HHH", data, 58)
    rows = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * entsize) for i in range(count)]
    strtab = rows[strndx]
    table = data[strtab[4]:strtab[4] + strtab[5]]
    named = {}
    for i, row in enumerate(rows):
        end = table.find(b"\0", row[0])
        named[table[row[0]:end].decode()] = (shoff + i * entsize, row)
    return named


class Field15CallerArgsSectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        target = subject.TARGET
        if not target.is_file() or target.stat().st_size != subject.SIZE:
            raise unittest.SkipTest("materialized node115 required")
        cls.data = target.read_bytes()
        if hashlib.sha256(cls.data).hexdigest() != subject.SHA:
            raise ValueError("wrong node115 fixture")

    def rename_section(self, name):
        mutant = bytearray(self.data)
        named = section_headers(bytes(mutant))
        shoff, row = named[name]
        secs = sections(bytes(mutant))
        shstr = next(s for s in secs if s["name"] == ".shstrtab")
        mutant[shstr["offset"] + row[0]] = ord("X")
        return bytes(mutant)

    def truncate_section(self, name):
        mutant = bytearray(self.data)
        shoff, row = section_headers(bytes(mutant))[name]
        struct.pack_into("<Q", mutant, shoff + 32, row[5] - 1)
        return bytes(mutant)

    def corrupt_dynstr_name(self, name):
        secs = {s["name"]: s for s in sections(self.data)}
        dynsym, dynstr = secs[".dynsym"], secs[".dynstr"]
        for i in range(dynsym["size"] // 24):
            name_off = struct.unpack_from("<I", self.data, dynsym["offset"] + i * 24)[0]
            start = dynstr["offset"] + name_off
            end = self.data.index(b"\0", start)
            if self.data[start:end] == name.encode():
                mutant = bytearray(self.data)
                mutant[start + 1] = 0xFF
                return bytes(mutant)
        raise ValueError("name not found")

    def test_missing_rela_dyn_refuses(self):
        with self.assertRaisesRegex(ValueError, "missing.rela.dyn section"):
            subject.analyze(self.rename_section(".rela.dyn"))

    def test_truncated_rela_dyn_refuses(self):
        with self.assertRaisesRegex(ValueError, "truncated.rela.dyn section"):
            subject.analyze(self.truncate_section(".rela.dyn"))

    def test_missing_dynsym_refuses(self):
        with self.assertRaisesRegex(ValueError, "missing.dynsym section"):
            subject.analyze(self.rename_section(".dynsym"))

    def test_missing_dynstr_refuses(self):
        with self.assertRaisesRegex(ValueError, "missing.dynstr section"):
            subject.analyze(self.rename_section(".dynstr"))

    def test_missing_text_refuses(self):
        with self.assertRaisesRegex(ValueError, "missing.text section"):
            subject.analyze(self.rename_section(".text"))

    def test_non_utf8_symbol_name_refuses(self):
        with self.assertRaisesRegex(ValueError, "not valid UTF-8"):
            subject.analyze(self.corrupt_dynstr_name("memcpy"))

    def test_unrelated_section_rename_is_not_a_refusal(self):
        self.assertEqual(subject.analyze(self.rename_section(".shstrtab"))["target_sha256"], subject.SHA)


if __name__ == "__main__":
    unittest.main()
