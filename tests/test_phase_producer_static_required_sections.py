"""Fail-closed controls: phase_producer_static helpers on corrupt input.

analyze() itself refuses any byte-level corruption first, through
the artifact digest check in owners(), so these guards live in the
helpers the analysis is built from: rela_entries() range-stepped
over .rela.dyn with no size-multiple check, so a truncated table was
read past the section and silently accepted with an identical
entries map; caller_census() and rip_references() looked .text up
with bare next(); dynsym_name() looked .dynsym/.dynstr up with bare
next() and decoded with a bare .decode('ascii'). A raw
UnicodeDecodeError is a ValueError subclass but is not this module's
refusal: the module refuses with check() messages, so the decode
test asserts the module message. The mutants rename or shrink
section headers, or flip one byte inside a decoded name, only; no
instruction bytes change. A missing .rela.dyn already refuses
downstream (rela_entries() returns an empty map and got_census()'s
check() fails), so no missing guard is added there. The module's
other read_string() helper has no callers and is left untouched.
"""
import hashlib
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import phase_producer_static as subject
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


class PhaseProducerHelperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not subject.TARGET.is_file() or subject.TARGET.stat().st_size != subject.TARGET_SIZE:
            raise unittest.SkipTest("materialized node115 required")
        cls.data = subject.TARGET.read_bytes()
        if hashlib.sha256(cls.data).hexdigest() != subject.TARGET_SHA256:
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

    def corrupt_memcpy_name(self):
        idx = subject.rela_entries(self.data)[subject.COPY_SLOT][1]
        secs = sections(self.data)
        dynsym = next(s for s in secs if s["name"] == ".dynsym")
        dynstr = next(s for s in secs if s["name"] == ".dynstr")
        name_off = struct.unpack_from(
            "<I", self.data, dynsym["offset"] + idx * 24)[0]
        mutant = bytearray(self.data)
        mutant[dynstr["offset"] + name_off] = 0xFF
        return bytes(mutant), idx

    def test_truncated_rela_dyn_refuses(self):
        with self.assertRaisesRegex(ValueError, "truncated.rela.dyn section"):
            subject.rela_entries(self.truncate_section(".rela.dyn"))

    def test_missing_rela_dyn_refuses_via_got_census(self):
        with self.assertRaisesRegex(ValueError, "relocation mismatch"):
            subject.got_census(self.rename_section(".rela.dyn"))

    def test_caller_census_missing_text_refuses(self):
        with self.assertRaisesRegex(ValueError, "missing.text section"):
            subject.caller_census(self.rename_section(".text"))

    def test_rip_references_missing_text_refuses(self):
        with self.assertRaisesRegex(ValueError, "missing.text section"):
            subject.rip_references(self.rename_section(".text"), subject.COPY_SLOT)

    def test_dynsym_name_missing_dynsym_refuses(self):
        with self.assertRaisesRegex(ValueError, "missing.dynsym section"):
            subject.dynsym_name(self.rename_section(".dynsym"), 1)

    def test_dynsym_name_missing_dynstr_refuses(self):
        with self.assertRaisesRegex(ValueError, "missing.dynstr section"):
            subject.dynsym_name(self.rename_section(".dynstr"), 1)

    def test_dynsym_name_non_ascii_refuses(self):
        mutant, idx = self.corrupt_memcpy_name()
        with self.assertRaisesRegex(
                ValueError, "dynamic symbol name is not valid ASCII"):
            subject.dynsym_name(mutant, idx)

    def test_helpers_unchanged_on_unmutated_input(self):
        idx = subject.rela_entries(self.data)[subject.COPY_SLOT][1]
        self.assertEqual(subject.dynsym_name(self.data, idx), "memcpy")
        self.assertTrue(len(subject.rela_entries(self.data)) > 60000)


if __name__ == "__main__":
    unittest.main()
