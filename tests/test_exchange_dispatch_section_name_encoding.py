import importlib.util
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "exchange_dispatch", ROOT / "tools/exchange_dispatch.py")
ed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ed)

TOTAL = 440
TABLE = b"\x00.text\x00\xff\x00.shstrtab\x00"


def make_elf(bad=True):
    """Elf with .text, a bad/valid section, and .shstrtab sections.

    A PT_LOAD maps VA 0x400000 to file offset 0. Section headers at
    128/192/256/320; the string table at offset 400 holds ".text", then
    either a 0xff byte (bad) or ".data" (valid), then ".shstrtab".
    """
    table = TABLE if bad else b"\x00.text\x00.data\x00.shstrtab\x00"
    data = bytearray(TOTAL)
    data[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<Q", data, 0x20, 64)    # phoff
    struct.pack_into("<Q", data, 0x28, 128)   # shoff
    struct.pack_into("<HHHHH", data, 0x36, 56, 1, 64, 4, 3)
    # Program header: PT_LOAD, offset 0, VA 0x400000, filesz = TOTAL.
    struct.pack_into("<IIQQQQ", data, 64,
                     1, 0, 0, 0x400000, 0, TOTAL)
    # Section headers: null, .text, bad/.data, .shstrtab.
    struct.pack_into("<IIQQQQIIQQ", data, 128,
                     0, 0, 0, 0, 0, 0, 0, 0, 1, 0)
    struct.pack_into("<IIQQQQIIQQ", data, 192,
                     1, 3, 0, 0x400000, 0, TOTAL, 0, 0, 1, 0)
    struct.pack_into("<IIQQQQIIQQ", data, 256,
                     7, 3, 0, 0, 0, 0, 0, 0, 1, 0)
    struct.pack_into("<IIQQQQIIQQ", data, 320,
                     9 if bad else 13, 3, 0, 0, 400, len(table), 0, 0, 1, 0)
    data[400:400 + len(table)] = table
    return data


class SectionNameEncodingTests(unittest.TestCase):
    def test_nonutf8_section_name_fails_closed(self):
        # On base the bare .decode() in Elf.__init__ escapes as
        # UnicodeDecodeError; with the fix it raises EvidenceError.
        with self.assertRaises(ed.EvidenceError):
            ed.Elf(bytes(make_elf(bad=True)))

    def test_ascii_section_names_still_parse(self):
        elf = ed.Elf(bytes(make_elf(bad=False)))
        self.assertIn(".text", elf.sections)
        self.assertIn(".data", elf.sections)


if __name__ == "__main__":
    unittest.main()
