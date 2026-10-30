import importlib.util
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "consensus_wire", ROOT / "tools/consensus_wire.py")
cw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cw)

HDR_ADDR = 0x401000
FDE_OFF = 300


def make_elf(count, size):
    """Elf with one .eh_frame_hdr section (header + one valid entry).

    A PT_LOAD maps VA 0x400000 to file offset 0, so the FDE at FDE_OFF
    is file-backed. `size` is the section's declared size; `count` is
    the declared entry count, so count=2 with size=20 overruns the table.
    """
    table = b'\x00.eh_frame_hdr\x00.shstrtab\x00'
    data = bytearray(FDE_OFF + 16)
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 0x20, 64)    # phoff
    struct.pack_into('<Q', data, 0x28, 128)   # shoff
    struct.pack_into('<HHHHH', data, 0x36, 56, 1, 64, 2, 1)
    # Program header: PT_LOAD, offset 0, VA 0x400000, filesz = len(data).
    struct.pack_into('<IIQQQQQQ', data, 64,
                     1, 0, 0, 0x400000, 0, len(data), 0, 0)
    # Section headers: .eh_frame_hdr, then .shstrtab.
    struct.pack_into('<IIQQQQIIQQ', data, 128,
                     1, 3, 0, HDR_ADDR, 256, size, 0, 0, 1, 0)
    struct.pack_into('<IIQQQQIIQQ', data, 192,
                     14, 3, 0, 0, 276, len(table), 0, 0, 1, 0)
    # .eh_frame_hdr body: version/encodings, pcrel slot, count.
    data[256:260] = bytes([1, 0x1B, 0x03, 0x3B])
    struct.pack_into('<i', data, 260, 0)
    struct.pack_into('<I', data, 264, count)
    # One valid table entry: pc == HDR_ADDR, FDE at FDE_OFF.
    fde_va = 0x400000 + FDE_OFF
    struct.pack_into('<i', data, 268, 0)
    struct.pack_into('<i', data, 272, fde_va - HDR_ADDR)
    data[276:276 + len(table)] = table
    # FDE: length, CIE pointer, pc_begin (pcrel sdata4), pc_range.
    struct.pack_into('<I', data, FDE_OFF, 16)
    struct.pack_into('<I', data, FDE_OFF + 4, 0)
    struct.pack_into('<i', data, FDE_OFF + 8, HDR_ADDR - (fde_va + 8))
    struct.pack_into('<I', data, FDE_OFF + 12, 0x40)
    return bytes(data)


class FdeIndexTableBoundsTests(unittest.TestCase):
    def test_table_overrun_fails_closed(self):
        # Declared count 2 needs 28 bytes but the section is only 20.
        with self.assertRaises(cw.EvidenceError):
            cw.fde_index(cw.Elf(make_elf(2, 20)))

    def test_exact_table_still_parses(self):
        starts, ends = cw.fde_index(cw.Elf(make_elf(1, 20)))
        self.assertEqual(starts, [HDR_ADDR])
        self.assertEqual(ends, [HDR_ADDR + 0x40])


if __name__ == "__main__":
    unittest.main()
