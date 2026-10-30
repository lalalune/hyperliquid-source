"""state_roots Elf: a non-UTF-8 section name must fail as EvidenceError.

Elf.__init__ decodes each section name with bare ``.decode()``. Every other
malformed-input rejection in the class raises EvidenceError, which main()
catches and reports as a diagnostic (``state_roots: ...``, exit 2).
A section name containing a non-UTF-8 byte instead escaped as a bare
UnicodeDecodeError, bypassing that diagnostic path. Open PR #167 fixes
only the out-of-range string-table index in this file, not the decode,
and open PR #169 widens the main() handler to OSError only.
"""
import importlib.util
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "state_roots", ROOT / "tools/state_roots.py")
sr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sr)


def elf_bytes(corrupt=False):
    data = bytearray(1024)
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 0x20, 0)      # phoff, no program headers
    struct.pack_into('<Q', data, 0x28, 512)    # shoff
    struct.pack_into('<HHHHH', data, 0x36, 56, 0, 64, 3, 1)
    names = b'\0.shstrtab\0.text\0'
    data[64:64 + len(names)] = names
    if corrupt:
        data[64 + names.index(b'.text')] = 0xFF
    entries = [(0, 0, 0, 0, 0, 0),
               (1, 3, 0, 0, 64, len(names)),
               (names.index(b'.text'), 1, 6, 0x100, 256, 32)]
    for i, e in enumerate(entries):
        struct.pack_into('<IIQQQQIIQQ', data, 512 + i * 64, *e, 0, 0, 1, 0)
    return bytes(data)


class SectionNameEncodingTests(unittest.TestCase):
    def test_valid_names_parse(self):
        elf = sr.Elf(elf_bytes())
        self.assertEqual(sorted(elf.sections),
                         ['', '.shstrtab', '.text'])

    def test_non_utf8_section_name_is_evidence_error(self):
        with self.assertRaises(sr.EvidenceError):
            sr.Elf(elf_bytes(corrupt=True))

    def test_non_utf8_section_name_is_not_a_bare_decode_error(self):
        try:
            sr.Elf(elf_bytes(corrupt=True))
        except sr.EvidenceError:
            return
        except UnicodeDecodeError:
            self.fail('non-UTF-8 section name escaped as UnicodeDecodeError')
        self.fail('non-UTF-8 section name was accepted')


if __name__ == '__main__':
    unittest.main()
