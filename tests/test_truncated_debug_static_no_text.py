"""census() must fail closed with ValueError when .text is absent.

elf_index.unwind_index() already raises ValueError('No .eh_frame_hdr') for a
missing section; truncated_debug_static.census() leaked a bare StopIteration
from its next() lookup instead, escaping every ValueError-only diagnostic
path that calls it. Synthetic ELFs only — no captured binary is needed.
"""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from truncated_debug_static import census


def make_elf(section_names):
    """Minimal ELF64-LE: a null entry, then section_names, then .shstrtab."""
    names = b'\x00' + b''.join(n.encode() + b'\x00'
                              for n in section_names + ['.shstrtab'])
    shoff = 64
    count = len(section_names) + 2
    strtab_off = shoff + 64 * count
    data = bytearray(strtab_off + len(names))
    data[0:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 40, shoff)
    struct.pack_into('<HHH', data, 58, 64, count, count - 1)
    off = 1
    for i, name in enumerate(section_names + ['.shstrtab']):
        is_strtab = name == '.shstrtab'
        struct.pack_into('<IIQQQQIIQQ', data, shoff + 64 * (i + 1), off,
                         3 if is_strtab else 1, 0, 0,
                         strtab_off if is_strtab else 0,
                         len(names) if is_strtab else 0, 0, 0, 0, 0)
        off += len(name) + 1
    data[strtab_off:strtab_off + len(names)] = names
    return bytes(data)


class CensusNoTextTests(unittest.TestCase):
    def test_missing_text_raises_value_error(self):
        with self.assertRaisesRegex(ValueError, 'No .text section'):
            census(make_elf(['.shstrtab']), [])

    def test_text_present_but_empty_still_fails_closed(self):
        # A present .text with no bytes yields no rows, so the census-count
        # gate — not a leaked iterator error — rejects it.
        with self.assertRaisesRegex(ValueError, 'census changed'):
            census(make_elf(['.text', '.shstrtab']), [])

    def test_missing_text_with_other_sections_raises_value_error(self):
        with self.assertRaisesRegex(ValueError, 'No .text section'):
            census(make_elf(['.rodata', '.shstrtab']), [])


if __name__ == '__main__':
    unittest.main()
