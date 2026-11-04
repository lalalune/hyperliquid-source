"""Fail-closed controls: merge_delegate_static on missing/truncated
sections, a short relocation table, and a non-UTF-8 dynamic symbol name.

_relocations() looked .rela.dyn up with bare next() and walked it with a
range step of 24, so a truncated table silently read one byte past the
section into the next section's bytes and analyze() still succeeded;
_dynsym_name() looked .dynsym/.dynstr up with bare next() and decoded
with an unwrapped .decode(); direct_call_census() and rip_ref_census()
looked .text up with bare next(); and slot_bindings() indexed rel[slot]
directly, so a short but aligned .rela.dyn escaped as KeyError. On a
well-formed ELF without one of those sections the lookups escaped as
StopIteration, and a 0xFF byte inside a decoded name escaped as a raw
UnicodeDecodeError, instead of the module's ValueError refusal via
require(). The mutants rename/shrink section headers or flip one name
byte only; no instruction bytes change. descriptors() uses .get() and
is untouched.
"""
import hashlib
import struct
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import merge_delegate_static as subject
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


class MergeDelegateSectionTests(unittest.TestCase):
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

    def resize_rela_dyn(self, size):
        mutant = bytearray(self.data)
        shoff, row = section_headers(bytes(mutant))['.rela.dyn']
        struct.pack_into('<Q', mutant, shoff + 32, size)
        return bytes(mutant)

    def corrupt_dynstr_name(self, name):
        mutant = bytearray(self.data)
        secs = sections(bytes(mutant))
        strings_sec = next(s for s in secs if s['name'] == '.dynstr')
        off = bytes(mutant).find(name + b'\0', strings_sec['offset'])
        self.assertNotEqual(off, -1, f'{name} not found in .dynstr')
        mutant[off + 1] = 0xFF
        return bytes(mutant)

    def test_missing_rela_dyn_refuses(self):
        with self.assertRaisesRegex(ValueError, 'missing.rela.dyn section'):
            subject.analyze(self.rename_section('.rela.dyn'))

    def test_truncated_rela_dyn_refuses(self):
        with self.assertRaisesRegex(ValueError, 'truncated.rela.dyn section'):
            subject.analyze(self.resize_rela_dyn(1457351))

    def test_short_rela_dyn_refuses_missing_slot(self):
        with self.assertRaisesRegex(ValueError, 'missing relocation for slot 0x64eafd8'):
            subject.analyze(self.resize_rela_dyn(24))

    def test_missing_dynsym_refuses(self):
        with self.assertRaisesRegex(ValueError, 'missing.dynsym section'):
            subject.analyze(self.rename_section('.dynsym'))

    def test_missing_dynstr_refuses(self):
        with self.assertRaisesRegex(ValueError, 'missing.dynstr section'):
            subject.analyze(self.rename_section('.dynstr'))

    def test_missing_text_refuses(self):
        with self.assertRaisesRegex(ValueError, 'missing.text section'):
            subject.analyze(self.rename_section('.text'))

    def test_non_utf8_memcpy_name_refuses(self):
        # Only the type-6 slots (memcpy, bcmp) are decoded on the
        # analyze() path.
        with self.assertRaisesRegex(ValueError, 'dynamic symbol name is not valid UTF-8'):
            subject.analyze(self.corrupt_dynstr_name(b'memcpy'))

    def test_unrelated_section_rename_is_not_a_refusal(self):
        self.assertEqual(subject.analyze(self.rename_section('.shstrtab'))['target_sha256'], subject.SHA)


if __name__ == '__main__':
    unittest.main()
