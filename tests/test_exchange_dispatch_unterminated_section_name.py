import importlib.util
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "exchange_dispatch", ROOT / "tools/exchange_dispatch.py")
ed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ed)


def make_elf(table, entries, shstrndx, size=1024):
    """Minimal ELF64-LE whose string table lives at offset 512.

    entries: (name_offset, addr, offset, size) per section header.
    Bytes after the table are 0xff so an unterminated name cannot
    accidentally find a NUL later in the file.
    """
    data = bytearray(size)
    data[:4] = b"\x7fELF"
    data[4] = 2
    data[5] = 1
    shoff = 128
    struct.pack_into("<QQ", data, 0x20, 0, shoff)
    struct.pack_into("<HHHHH", data, 0x36, 0, 0, 64, len(entries), shstrndx)
    for i, (name, addr, off, sz) in enumerate(entries):
        struct.pack_into("<IIQQQQIIQQ", data, shoff + i * 64,
                         name, 1, 0, addr, off, sz, 0, 0, 1, 0)
    data[512:512 + len(table)] = table
    for i in range(512 + len(table), size):
        data[i] = 0xFF
    return bytes(data)


class UnterminatedSectionNameTests(unittest.TestCase):
    def test_unterminated_name_fails_closed(self):
        # Section 1's name starts at table offset 1 and never terminates.
        data = make_elf(b"\x00.text",
                        [(0, 0, 0, 0), (1, 0, 512, 6)], shstrndx=1)
        with self.assertRaises(ed.EvidenceError):
            ed.Elf(data)

    def test_name_offset_past_end_fails_closed(self):
        data = make_elf(b"\x00.text\x00",
                        [(0, 0, 0, 0), (2000, 0, 512, 7)], shstrndx=1)
        with self.assertRaises(ed.EvidenceError):
            ed.Elf(data)

    def test_terminated_names_still_parse(self):
        data = make_elf(b"\x00.text\x00.data\x00",
                        [(0, 0, 0, 0),
                         (1, 0x400000, 0, 16),
                         (7, 0x401000, 16, 8),
                         (0, 0, 512, 14)], shstrndx=3)
        elf = ed.Elf(data)
        self.assertIn(".text", elf.sections)
        self.assertIn(".data", elf.sections)


if __name__ == "__main__":
    unittest.main()
