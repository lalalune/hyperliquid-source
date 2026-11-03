"""Fail-closed controls: numeric_selector_static on missing/truncated sections.

extract() looked up .rela.dyn, .dynsym and .dynstr with bare next(), so a
well-formed ELF without one of them escaped as StopIteration, and a
.rela.dyn whose size is not a multiple of 24 bytes escaped as struct.error
from iter_unpack, instead of the module's ValueError refusal. The mutants
rename or shrink section headers only; no instruction bytes change.
"""
import hashlib
import struct
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import numeric_selector_static as subject
from elf_index import sections


def section_headers(data):
    shoff = struct.unpack_from('<Q', data, 40)[0]
    entsize, count, strndx = struct.unpack_from('<HHH', data, 58)
    rows = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * entsize) for i in range(count)]
    strtab = rows[strndx]
    table = data[strtab[4]:strtab[4] + strtab[5]]
    named = {}
    for i, row in enumerate(rows):
        end = table.find(b'\0', row[0])
        named[table[row[0]:end].decode()] = (shoff + i * entsize, row)
    return named


class NumericSelectorSectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not subject.TARGET.is_file() or subject.TARGET.stat().st_size != 105896032:
            raise unittest.SkipTest('materialized node115 required')
        cls.data = subject.TARGET.read_bytes()
        if hashlib.sha256(cls.data).hexdigest() != subject.SHA:
            raise ValueError('wrong node115 fixture')

    def rename_section(self, name):
        mutant = bytearray(self.data)
        named = section_headers(bytes(mutant))
        shoff, row = named[name]
        secs = sections(bytes(mutant))
        shstr = next(s for s in secs if s['name'] == '.shstrtab')
        mutant[shstr['offset'] + row[0]] = ord('X')
        return bytes(mutant)

    def truncate_rela_dyn(self):
        mutant = bytearray(self.data)
        shoff, row = section_headers(bytes(mutant))['.rela.dyn']
        struct.pack_into('<Q', mutant, shoff + 32, row[5] - 1)
        return bytes(mutant)

    def test_missing_rela_dyn_refuses(self):
        with self.assertRaisesRegex(ValueError, 'missing .rela.dyn section'):
            subject.analyze(self.rename_section('.rela.dyn'))

    def test_truncated_rela_dyn_refuses(self):
        with self.assertRaisesRegex(ValueError, 'truncated .rela.dyn section'):
            subject.analyze(self.truncate_rela_dyn())

    def test_missing_dynsym_refuses(self):
        with self.assertRaisesRegex(ValueError, 'missing .dynsym section'):
            subject.analyze(self.rename_section('.dynsym'))

    def test_missing_dynstr_refuses(self):
        with self.assertRaisesRegex(ValueError, 'missing .dynstr section'):
            subject.analyze(self.rename_section('.dynstr'))

    def test_unrelated_section_rename_is_not_a_refusal(self):
        # Renaming a section no check looks up must not change the verdict;
        # this proves the rename helper targets one name string only.
        self.assertEqual(subject.analyze(self.rename_section('.shstrtab'))[0]['target_sha256'], subject.SHA)


if __name__ == '__main__':
    unittest.main()
