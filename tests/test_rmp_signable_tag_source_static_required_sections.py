"""Fail-closed controls: rmp_signable_tag_source_static on missing/truncated
sections.

relocations() looked .rela.dyn up with bare next() and unpacked it with
an unguarded iter_unpack; call_census(), rip_relative_refs(), and
analyze() itself looked .text up with bare next(). On a well-formed ELF
without one of those sections the lookups escaped as StopIteration, and
a .rela.dyn whose size is not a multiple of 24 bytes escaped as
struct.error, instead of the module's ValueError refusal. The mutants
rename or shrink section headers only; no instruction bytes change.
A short but aligned table already refuses with the module's ValueError
via the exact-match relocation check, so no slot-presence guard is
needed, and this module has no dynsym_name, so no decode guard
applies. generate()'s .eh_frame lookup is provably safe and
untouched: analyze() runs first and fde_extents refuses a missing
.eh_frame.
"""
import hashlib
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import rmp_signable_tag_source_static as subject
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


class TagSourceSectionTests(unittest.TestCase):
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

    def test_missing_rela_dyn_refuses(self):
        with self.assertRaisesRegex(ValueError, "missing.rela.dyn section"):
            subject.analyze(self.rename_section(".rela.dyn"))

    def test_truncated_rela_dyn_refuses(self):
        with self.assertRaisesRegex(ValueError, "truncated.rela.dyn section"):
            subject.analyze(self.truncate_section(".rela.dyn"))

    def test_missing_text_refuses(self):
        with self.assertRaisesRegex(ValueError, "missing.text section"):
            subject.analyze(self.rename_section(".text"))

    def test_call_census_missing_text_refuses(self):
        with self.assertRaisesRegex(ValueError, "missing.text section"):
            subject.call_census(self.rename_section(".text"), {"x": 0x3EBDD10})

    def test_rip_relative_refs_missing_text_refuses(self):
        with self.assertRaisesRegex(ValueError, "missing.text section"):
            subject.rip_relative_refs(self.rename_section(".text"), 0x64E6C60)

    def test_unrelated_section_rename_is_not_a_refusal(self):
        self.assertEqual(subject.analyze(self.rename_section(".shstrtab"))["target_sha256"], subject.TARGET_SHA256)


if __name__ == "__main__":
    unittest.main()
