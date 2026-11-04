"""Fail-closed controls: key_consumers_static helpers on corrupt input.

analyze() itself refuses any byte-level corruption first, through the
artifact digest check in owners(), so these guards live in the helpers
the analysis is built from: rela_entries() range-stepped over
.rela.dyn with no size-multiple check, so a truncated table was read
past the section and silently accepted; rip_references() and
gate_call_census() looked .text up with bare next(); dynsym_name()
looked .dynsym/.dynstr up with bare next() and decoded with a bare
.decode('ascii'); read_string() and the crit-message prefix decode in
strings_census() decoded with bare .decode('ascii'). A raw
UnicodeDecodeError is a ValueError subclass but is not this module's
refusal: the module refuses with check() messages, so the tests assert
the module messages. The mutants rename or shrink section headers, or
flip one byte inside a decoded name, only; no instruction bytes change.
A missing .rela.dyn already refuses downstream (rela_entries() returns
an empty map and slot_census() check() fails), so no missing guard is
added there.
"""
import hashlib
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import key_consumers_static as subject
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


def va_offset(data, va):
    for s in sections(data):
        if s["type"] != 8 and s["address"] <= va < s["address"] + s["size"]:
            return s["offset"] + va - s["address"]
    raise ValueError("unmapped")


class KeyConsumersHelperTests(unittest.TestCase):
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
                return bytes(mutant), i
        raise ValueError("name not found")

    def corrupt_byte_at_va(self, va):
        mutant = bytearray(self.data)
        mutant[va_offset(self.data, va) + 1] = 0xFF
        return bytes(mutant)

    def test_truncated_rela_dyn_refuses(self):
        with self.assertRaisesRegex(ValueError, "truncated.rela.dyn section"):
            subject.rela_entries(self.truncate_section(".rela.dyn"))

    def test_missing_rela_dyn_refuses_via_slot_census(self):
        with self.assertRaisesRegex(ValueError, "relocation mismatch"):
            subject.slot_census(self.rename_section(".rela.dyn"))

    def test_rip_references_missing_text_refuses(self):
        with self.assertRaisesRegex(ValueError, "missing.text section"):
            subject.rip_references(self.rename_section(".text"), subject.KEY_SLOT)

    def test_gate_call_census_missing_text_refuses(self):
        with self.assertRaisesRegex(ValueError, "missing.text section"):
            subject.gate_call_census(self.rename_section(".text"))

    def test_dynsym_name_missing_dynsym_refuses(self):
        with self.assertRaisesRegex(ValueError, "missing.dynsym section"):
            subject.dynsym_name(self.rename_section(".dynsym"), 0)

    def test_dynsym_name_missing_dynstr_refuses(self):
        with self.assertRaisesRegex(ValueError, "missing.dynstr section"):
            subject.dynsym_name(self.rename_section(".dynstr"), 0)

    def test_dynsym_name_non_ascii_refuses(self):
        mutant, index = self.corrupt_dynstr_name("memcpy")
        with self.assertRaisesRegex(ValueError, "not valid ASCII"):
            subject.dynsym_name(mutant, index)

    def test_read_string_non_ascii_refuses(self):
        with self.assertRaisesRegex(ValueError, "not valid ASCII"):
            subject.read_string(0x60F0B2, self.corrupt_byte_at_va(0x60F0B2), 7)

    def test_strings_census_prefix_non_ascii_refuses(self):
        with self.assertRaisesRegex(ValueError, "not valid ASCII"):
            subject.strings_census(self.corrupt_byte_at_va(0x465B90))

    def test_helpers_unchanged_on_unmutated_input(self):
        entries = subject.rela_entries(self.data)
        self.assertIn(subject.COPY_SLOT, entries)
        mutant, index = self.corrupt_dynstr_name("memcpy")
        self.assertEqual(subject.dynsym_name(self.data, index), "memcpy")
        self.assertEqual(subject.read_string(0x60F0B2, self.data, 7), "hl-node")


if __name__ == "__main__":
    unittest.main()
