import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from build_provenance import derive


def symtab_elf(symtab_type):
    """Minimal ELF64 with a section named .symtab of the given sh_type.

    symtab_type 1 (PROGBITS) names a section .symtab without making it a
    symbol table; 2 (SHT_SYMTAB) is a real symbol table. None omits it.
    """
    names = b'\0.shstrtab\0.symtab\0'
    body = bytearray(64)
    body[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<HH', body, 16, 3, 0x3E)
    blobs = [names, b'\0' * 24]
    offsets = []
    for blob in blobs:
        offsets.append(len(body))
        body += blob
    shoff = len(body)
    struct.pack_into('<Q', body, 40, shoff)
    rows = [(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            (names.index(b'.shstrtab\0'), 3, 0, 0, offsets[0], len(names), 0, 0, 1, 0)]
    if symtab_type is not None:
        rows.append((names.index(b'.symtab\0'), symtab_type, 0, 0, offsets[1], 24, 0, 0, 8, 0))
    struct.pack_into('<HHH', body, 58, 64, len(rows), 1)
    for row in rows:
        body += struct.pack('<IIQQQQIIQQ', *row)
    return bytes(body)


def has_symtab(data):
    return [i['value'] for i in derive(data) if i['key'] == 'elf.has_symtab']


class SymtabTypeTests(unittest.TestCase):
    def test_progbits_named_symtab_is_not_a_symbol_table(self):
        self.assertEqual(has_symtab(symtab_elf(1)), [False])

    def test_real_symtab_is_reported(self):
        self.assertEqual(has_symtab(symtab_elf(2)), [True])

    def test_absent_symtab_is_reported_absent(self):
        self.assertEqual(has_symtab(symtab_elf(None)), [False])


if __name__ == '__main__':
    unittest.main()
