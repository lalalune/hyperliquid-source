import importlib.util
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "exchange_dispatch", ROOT / "tools/exchange_dispatch.py")
ed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ed)


def make_elf(table, entries, shstrndx, extra=None, size=1024):
    """Minimal ELF64-LE whose string table lives at offset 512.

    entries: (name_offset, addr, offset, size) per section header.
    extra: {file_offset: bytes} for section contents.
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
    for off, blob in (extra or {}).items():
        data[off:off + len(blob)] = blob
    return bytes(data)


def text_only_elf():
    # Sections: .text + shstrtab; no .eh_frame_hdr, no .rela.dyn.
    return make_elf(b"\x00.text\x00.shstrtab\x00",
                    [(0, 0, 0, 0),
                     (1, 0x400000, 0, 16),
                     (7, 0, 512, 17)], shstrndx=2)


class MissingSectionTests(unittest.TestCase):
    def test_missing_eh_frame_hdr_fails_closed(self):
        elf = ed.Elf(text_only_elf())
        with self.assertRaises(ed.EvidenceError):
            ed.fde_index(elf)

    def test_missing_rela_dyn_fails_closed(self):
        elf = ed.Elf(text_only_elf())
        with self.assertRaises(ed.EvidenceError):
            ed.relative_relocs(elf)

    def test_present_sections_still_resolve(self):
        hdr = bytes([1, 0x1B, 0x03, 0x3B]) + b"\x00" * 4 + struct.pack("<I", 0)
        data = make_elf(b"\x00.text\x00.eh_frame_hdr\x00.rela.dyn\x00.shstrtab\x00",
                        [(0, 0, 0, 0),
                         (1, 0x400000, 0, 16),
                         (7, 0x500000, 600, 12),
                         (21, 0x600000, 700, 0),
                         (31, 0, 512, 41)], shstrndx=4,
                        extra={600: hdr})
        elf = ed.Elf(data)
        self.assertEqual(ed.fde_index(elf), ([], []))
        self.assertEqual(ed.relative_relocs(elf), {})
        self.assertEqual(elf.section(".text"), (0x400000, 0, 16))


if __name__ == "__main__":
    unittest.main()
