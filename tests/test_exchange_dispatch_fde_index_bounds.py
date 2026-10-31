"""exchange_dispatch fde_index: a .eh_frame_hdr section shorter than its
12-byte header must fail with EvidenceError, not a raw struct.error."""
import importlib.util
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "exchange_dispatch", ROOT / "tools/exchange_dispatch.py")
ed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ed)


def make_elf(count, size, file_size=620):
    """Minimal ELF64-LE with a .eh_frame_hdr section at file offset 600.

    One PT_LOAD maps VA 0x500000 to file offset 0, so the single table
    entry's FDE is file-backed. `count` is the declared entry count and
    `size` the section's declared size; `file_size` may cut the file short
    inside the header to simulate a truncated section.
    """
    data = bytearray(file_size)
    data[:4] = b"\x7fELF"
    data[4] = 2
    data[5] = 1
    struct.pack_into("<QQ", data, 0x20, 64, 128)
    struct.pack_into("<HHHHH", data, 0x36, 56, 1, 64, 3, 2)
    struct.pack_into("<IIQQQQ", data, 64, 1, 0, 0, 0x500000, 0, file_size)
    for i, (name, addr, off, sz) in enumerate(
            [(0, 0, 0, 0), (1, 0x500000, 600, size), (15, 0, 512, 25)]):
        struct.pack_into("<IIQQQQIIQQ", data, 128 + i * 64,
                         name, 1, 0, addr, off, sz, 0, 0, 1, 0)
    table = b"\x00.eh_frame_hdr\x00.shstrtab\x00"
    data[512:512 + len(table)] = table
    data[600:604] = bytes([1, 0x1B, 0x03, 0x3B])
    if file_size > 608:
        struct.pack_into("<I", data, 608, count)
    if file_size > 612:
        struct.pack_into("<ii", data, 612, 0x100, 0x100)
    if file_size > 268:
        struct.pack_into("<i", data, 264, -8)
        struct.pack_into("<I", data, 268, 0x40)
    return bytes(data)


class FdeIndexHeaderBoundsTests(unittest.TestCase):
    def test_truncated_header_fails_closed(self):
        # Section declares 8 bytes and the file ends at offset 608, so the
        # count field at offset 608 is incomplete: on base this raises a
        # raw struct.error from unpack_from, escaping the tool's
        # EvidenceError contract (and the open #512 main handler, which
        # catches EvidenceError/OSError only).
        with self.assertRaises(ed.EvidenceError):
            ed.fde_index(ed.Elf(make_elf(1, 8, file_size=608)))

    def test_valid_single_entry_still_parses(self):
        starts, ends = ed.fde_index(ed.Elf(make_elf(1, 20)))
        self.assertEqual(starts, [0x500100])
        self.assertEqual(ends, [0x500140])


if __name__ == "__main__":
    unittest.main()
