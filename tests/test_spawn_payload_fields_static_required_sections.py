"""Fail-closed controls: spawn_payload_fields_static helpers on
corrupt input.

analyze() itself refuses any byte-level corruption first, through
the artifact digest check in owners(), so these guards live in the
helpers the analysis is built from: rela_entries() range-stepped
over .rela.dyn with no size-multiple check, so a truncated table was
read past the section and silently accepted; caller_census(),
rip_references(), and _window_raw_scan() looked .text up with bare
next(); read_string() decoded with a bare .decode('ascii'). A raw
UnicodeDecodeError is a ValueError subclass but is not this module's
refusal: the module refuses with check() messages, so the decode
test asserts the module message. The mutants rename or shrink
section headers, or flip one byte inside a decoded string, only; no
instruction bytes change. A missing .rela.dyn already refuses
downstream (rela_entries() returns an empty map and got_census()'s
check() fails), so no missing guard is added there.
"""
import hashlib
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import spawn_payload_fields_static as subject
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


class SpawnPayloadHelperTests(unittest.TestCase):
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
            subject.rip_references(self.rename_section(".text"), 0x64E0B38)

    def test_window_raw_scan_missing_text_refuses(self):
        with self.assertRaisesRegex(ValueError, "missing.text section"):
            subject._window_raw_scan(self.rename_section(".text"))

    def test_read_string_non_ascii_refuses(self):
        va = next(iter(subject.STATIC_STRINGS))
        mutant = bytearray(self.data)
        mutant[va_offset(self.data, va) + 1] = 0xFF
        with self.assertRaisesRegex(ValueError, "not valid ASCII"):
            subject.read_string(va, bytes(mutant))

    def test_helpers_unchanged_on_unmutated_input(self):
        va, want = next(iter(subject.STATIC_STRINGS.items()))
        self.assertEqual(subject.read_string(va, self.data), want)
        self.assertTrue(len(subject.rela_entries(self.data)) > 60000)


if __name__ == "__main__":
    unittest.main()
