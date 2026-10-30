"""Out-of-range table indexes in receiver_poll_static.relocations().

The exit-symbol resolution follows two section-header links (the RELA
section's sh_link to the dynamic symbol table, then that table's sh_link
to the string table) and then reads one symbol entry. Before this fix all
three resolutions were bare list indexing / unpacking, so a malformed
binary escaped relocations() -- whose contract is ValueError, as the
existing tests assert for every other malformed binding -- as IndexError
or struct.error instead of a diagnostic ValueError.
"""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from receiver_poll_static import relocations

EXIT_SLOT = 0x5777378


def build(symbol_index=3, string_index=4, sym_entry=0, name=b'exit'):
    names = b'\x00.rela\x00.shstrtab\x00.dynsym\x00.dynstr\x00'
    off = {'rela': 1, 'shstrtab': 7, 'dynsym': 17, 'dynstr': 25}
    shoff = 64
    nsec = 5
    rela_off = shoff + nsec * 64
    dynsym_off = rela_off + 24
    dynstr_off = dynsym_off + 24
    names_off = dynstr_off + len(name) + 1
    total = names_off + len(names)
    data = bytearray(total)
    data[0:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 40, shoff)
    struct.pack_into('<HHH', data, 58, 64, nsec, 2)

    def shdr(i, name_off, typ, addr, off, size, link, entsize):
        struct.pack_into('<IIQQQQIIQQ', data, shoff + i * 64,
                         name_off, typ, 0, addr, off, size, link, 0, 0, entsize)

    shdr(0, 0, 0, 0, 0, 0, 0, 0)
    shdr(1, off['rela'], 4, 0, rela_off, 24, symbol_index, 0)
    shdr(2, off['shstrtab'], 3, 0, names_off, len(names), 0, 0)
    shdr(3, off['dynsym'], 11, 0, dynsym_off, 24, string_index, 24)
    shdr(4, off['dynstr'], 3, 0, dynstr_off, len(name) + 1, 0, 0)
    info = 6 | (sym_entry << 32)
    struct.pack_into('<QQq', data, rela_off, EXIT_SLOT, info, 0)
    struct.pack_into('<I', data, dynsym_off, 0)
    data[dynstr_off:dynstr_off + len(name)] = name
    data[names_off:names_off + len(names)] = names
    return bytes(data)


class RelocationIndexTests(unittest.TestCase):
    def test_symbol_table_index_out_of_range(self):
        with self.assertRaisesRegex(ValueError, 'symbol table index out of range'):
            relocations(build(symbol_index=99))

    def test_string_table_index_out_of_range(self):
        with self.assertRaisesRegex(ValueError, 'string table index out of range'):
            relocations(build(string_index=99))

    def test_symbol_entry_outside_file(self):
        with self.assertRaisesRegex(ValueError, 'symbol entry outside file'):
            relocations(build(sym_entry=100))

    def test_valid_indexes_reach_binding_check(self):
        # Wrong name: guards pass, the binding check itself rejects it.
        with self.assertRaisesRegex(ValueError, 'Exit import binding changed'):
            relocations(build(name=b'notexit'))

    def test_valid_exit_binding_passes_resolution(self):
        # Correct exit binding: resolution succeeds and only the final
        # census check (RELATIVE slots absent from this synthetic file)
        # rejects the input -- proving the index guards let valid
        # indexes through.
        with self.assertRaisesRegex(ValueError, 'Missing receiver/exit binding'):
            relocations(build())


if __name__ == '__main__':
    unittest.main()
