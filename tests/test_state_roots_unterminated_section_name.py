import importlib.util
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "state_roots", ROOT / "tools/state_roots.py")
sr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sr)


def make_elf_raw(table, entries):
    """Elf from a raw string table and (name_offset, offset, size) entries.

    The last entry is the string table itself (shstrndx = len(entries) - 1).
    """
    shoff = 64
    str_off = 1024
    data = bytearray(str_off + len(table))
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 0x20, 0)
    struct.pack_into('<Q', data, 0x28, shoff)
    struct.pack_into('<HHHHH', data, 0x36, 56, 0, 64,
                     len(entries), len(entries) - 1)
    for i, (name_off, off, size) in enumerate(entries):
        struct.pack_into('<IIQQQQIIQQ', data, shoff + i * 64,
                         name_off, 3, 0, 0, off, size, 0, 0, 1, 0)
    data[str_off:str_off + len(table)] = table
    return bytes(data)


class UnterminatedSectionNameTests(unittest.TestCase):
    def test_unterminated_name_fails_closed(self):
        # No NUL anywhere after the .text name start.
        data = make_elf_raw(b'\x00.text.shstrtab',
                            [(1, 0, 0), (6, 1024, 16)])
        with self.assertRaises(sr.EvidenceError):
            sr.Elf(data)

    def test_name_offset_past_end_fails_closed(self):
        table = b'\x00.text\x00.shstrtab\x00'
        data = make_elf_raw(table, [(9999, 0, 0), (7, 1024, len(table))])
        with self.assertRaises(sr.EvidenceError):
            sr.Elf(data)

    def test_terminated_names_still_parse(self):
        table = b'\x00.text\x00.shstrtab\x00'
        elf = sr.Elf(make_elf_raw(table, [(1, 0, 0), (7, 1024, len(table))]))
        self.assertEqual(sorted(elf.sections), ['.shstrtab', '.text'])


if __name__ == "__main__":
    unittest.main()
