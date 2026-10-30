import importlib.util
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "info_request_path", ROOT / "tools/info_request_path.py")
irp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(irp)

HDR_ADDR = 0x401000
TOTAL = 420
RELA_OFF = 380


def make_elf(rela_size):
    """Elf with .eh_frame_hdr, .shstrtab and .rela.dyn sections.

    The relocation section sits at file offset 380, so a declared
    size of 48 needs entries up to offset 428 — past the 420-byte
    file — and a size of 40 leaves a ragged 16-byte tail entry.
    """
    table = b'\x00.eh_frame_hdr\x00.shstrtab\x00.rela.dyn\x00'
    data = bytearray(TOTAL)
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 0x20, 64)    # phoff
    struct.pack_into('<Q', data, 0x28, 128)   # shoff
    struct.pack_into('<HHHHH', data, 0x36, 56, 1, 64, 3, 1)
    # Program header: PT_LOAD, offset 0, VA 0x400000, filesz = TOTAL.
    struct.pack_into('<IIQQQQQQ', data, 64,
                     1, 0, 0, 0x400000, 0, TOTAL, 0, 0)
    # Section headers: .eh_frame_hdr, .shstrtab, .rela.dyn.
    struct.pack_into('<IIQQQQIIQQ', data, 128,
                     1, 3, 0, HDR_ADDR, 320, 20, 0, 0, 1, 0)
    struct.pack_into('<IIQQQQIIQQ', data, 192,
                     15, 3, 0, 0, 340, len(table), 0, 0, 1, 0)
    struct.pack_into('<IIQQQQIIQQ', data, 256,
                     25, 3, 0, 0x402000, RELA_OFF, rela_size, 0, 0, 1, 0)
    data[320:324] = bytes([1, 0x1B, 0x03, 0x3B])
    data[340:340 + len(table)] = table
    return bytes(data)


class RelativeRelocsTruncatedTests(unittest.TestCase):
    def test_truncated_section_fails_closed(self):
        # Declared size 48 needs a second entry past EOF.
        # On base this escaped as struct.error.
        with self.assertRaises(irp.EvidenceError):
            irp.relative_relocs(irp.Elf(make_elf(48)))

    def test_ragged_tail_entry_fails_closed(self):
        # Declared size 40: the first entry fits, the 16-byte tail
        # entry does not. On base the tail read escaped as
        # struct.error.
        with self.assertRaises(irp.EvidenceError):
            irp.relative_relocs(irp.Elf(make_elf(40)))

    def test_exact_section_still_parses(self):
        data = bytearray(make_elf(24))
        # One RELATIVE entry: r_offset, type 8, addend.
        struct.pack_into('<QQq', data, RELA_OFF, 0x5000, 8, 0x1234)
        self.assertEqual(irp.relative_relocs(irp.Elf(bytes(data))),
                         {0x5000: 0x1234})


if __name__ == "__main__":
    unittest.main()
