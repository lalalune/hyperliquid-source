"""Fail-closed controls: record_producer_static helpers on corrupt
input.

analyze() itself refuses any byte-level corruption first, through
the artifact digest check in owners(), so these guards live in the
helpers the analysis is built from: slot_census() looked .rela.dyn
up with bare next() and counted entries with size // 24, so a
missing table escaped as StopIteration and a truncated table was
silently accepted (the floor division drops the partial last entry
and the wanted slots still check out); caller_census() and
rip_references() looked .text up with bare next(). The mutants
rename or shrink section headers only; no instruction bytes change.
A short but aligned table already refuses via the slot check in
slot_census(), so no slot-presence guard is needed, and this module
has no dynsym_name, so no decode guard applies.
"""
import hashlib
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import record_producer_static as subject
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


class RecordProducerHelperTests(unittest.TestCase):
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

    def test_slot_census_missing_rela_dyn_refuses(self):
        with self.assertRaisesRegex(ValueError, "missing.rela.dyn section"):
            subject.slot_census(self.rename_section(".rela.dyn"))

    def test_slot_census_truncated_rela_dyn_refuses(self):
        with self.assertRaisesRegex(ValueError, "truncated.rela.dyn section"):
            subject.slot_census(self.truncate_section(".rela.dyn"))

    def test_caller_census_missing_text_refuses(self):
        with self.assertRaisesRegex(ValueError, "missing.text section"):
            subject.caller_census(self.rename_section(".text"))

    def test_rip_references_missing_text_refuses(self):
        with self.assertRaisesRegex(ValueError, "missing.text section"):
            subject.rip_references(self.rename_section(".text"), 0x64DF508)

    def test_helpers_unchanged_on_unmutated_input(self):
        slots = subject.slot_census(self.data)
        self.assertEqual(set(slots), set(subject.SLOT_SUBJECTS))
        census = subject.caller_census(self.data)
        self.assertIn("direct_call_sites", census)


if __name__ == "__main__":
    unittest.main()
