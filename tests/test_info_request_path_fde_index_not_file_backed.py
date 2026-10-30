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
FDE_OFF = 300


def make_elf(fde_va):
    """Elf with one .eh_frame_hdr section and one table entry.

    A PT_LOAD maps VA 0x400000 to file offset 0, so only VAs in
    [0x400000, 0x400000 + len(data)) are file-backed. The entry's
    FDE VA is caller-chosen, so 0x500000 is not file-backed.
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
                     1, 3, 0, HDR_ADDR, 256, 20, 0, 0, 1, 0)
    struct.pack_into('<IIQQQQIIQQ', data, 192,
                     14, 3, 0, 0, 276, len(table), 0, 0, 1, 0)
    # .eh_frame_hdr body: version/encodings, pcrel slot, count.
    data[256:260] = bytes([1, 0x1B, 0x03, 0x3B])
    struct.pack_into('<i', data, 260, 0)
    struct.pack_into('<I', data, 264, 1)
    # One table entry: pc == HDR_ADDR, FDE at the chosen VA.
    struct.pack_into('<i', data, 268, 0)
    struct.pack_into('<i', data, 272, fde_va - HDR_ADDR)
    data[276:276 + len(table)] = table
    # FDE body (only reached when the FDE VA is file-backed):
    # length, CIE pointer, pc_begin (pcrel sdata4), pc_range.
    fde_va_ok = 0x400000 + FDE_OFF
    struct.pack_into('<I', data, FDE_OFF, 16)
    struct.pack_into('<I', data, FDE_OFF + 4, 0)
    struct.pack_into('<i', data, FDE_OFF + 8, HDR_ADDR - (fde_va_ok + 8))
    struct.pack_into('<I', data, FDE_OFF + 12, 0x40)
    return bytes(data)


class FdeIndexNotFileBackedTests(unittest.TestCase):
    def test_unmapped_fde_fails_closed(self):
        # On base this escaped main()'s EvidenceError-only handler as
        # TypeError (None + 8); it must raise EvidenceError instead.
        with self.assertRaises(irp.EvidenceError):
            irp.fde_index(irp.Elf(make_elf(0x500000)))

    def test_file_backed_fde_still_parses(self):
        starts, ends = irp.fde_index(irp.Elf(make_elf(0x400000 + FDE_OFF)))
        self.assertEqual(starts, [HDR_ADDR])
        self.assertEqual(ends, [HDR_ADDR + 0x40])


if __name__ == "__main__":
    unittest.main()
