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
TOTAL = 316


def make_elf(fde_off, write_body=False):
    """Elf with one .eh_frame_hdr section and one table entry.

    A PT_LOAD maps VA 0x400000 to file offset 0 with filesz = TOTAL,
    so an FDE at offset 304 or 312 is file-backed but its 16-byte body
    (length, CIE pointer, pc_begin, pc_range) runs past EOF.
    """
    table = b'\x00.eh_frame_hdr\x00.shstrtab\x00'
    data = bytearray(TOTAL)
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 0x20, 64)    # phoff
    struct.pack_into('<Q', data, 0x28, 128)   # shoff
    struct.pack_into('<HHHHH', data, 0x36, 56, 1, 64, 2, 1)
    # Program header: PT_LOAD, offset 0, VA 0x400000, filesz = TOTAL.
    struct.pack_into('<IIQQQQQQ', data, 64,
                     1, 0, 0, 0x400000, 0, TOTAL, 0, 0)
    # Section headers: .eh_frame_hdr, then .shstrtab.
    struct.pack_into('<IIQQQQIIQQ', data, 128,
                     1, 3, 0, HDR_ADDR, 256, 20, 0, 0, 1, 0)
    struct.pack_into('<IIQQQQIIQQ', data, 192,
                     14, 3, 0, 0, 276, len(table), 0, 0, 1, 0)
    # .eh_frame_hdr body: version/encodings, pcrel slot, count.
    data[256:260] = bytes([1, 0x1B, 0x03, 0x3B])
    struct.pack_into('<i', data, 260, 0)
    struct.pack_into('<I', data, 264, 1)
    # One table entry: pc == HDR_ADDR, FDE at the chosen offset.
    fde_va = 0x400000 + fde_off
    struct.pack_into('<i', data, 268, 0)
    struct.pack_into('<i', data, 272, fde_va - HDR_ADDR)
    data[276:276 + len(table)] = table
    if write_body:
        # FDE body: length, CIE pointer, pc_begin (pcrel sdata4),
        # pc_range. Only used by the valid control (offset 300).
        struct.pack_into('<I', data, fde_off, 16)
        struct.pack_into('<I', data, fde_off + 4, 0)
        struct.pack_into('<i', data, fde_off + 8, HDR_ADDR - (fde_va + 8))
        struct.pack_into('<I', data, fde_off + 12, 0x40)
    return bytes(data)


class FdeIndexTruncatedBodyTests(unittest.TestCase):
    def test_body_truncated_at_pc_begin_fails_closed(self):
        # FDE at 312: even the pc_begin read (fo + 8) runs past EOF.
        # On base this escaped as struct.error.
        with self.assertRaises(irp.EvidenceError):
            irp.fde_index(irp.Elf(make_elf(312)))

    def test_body_truncated_at_pc_range_fails_closed(self):
        # FDE at 304: pc_begin reads fine and is made to match pc,
        # but pc_range (fo + 12) runs past EOF. On base this escaped
        # as struct.error (a mismatching pc_begin would mask it with
        # an EvidenceError, so the fixture pins pc_begin to pc).
        data = bytearray(make_elf(304))
        struct.pack_into('<i', data, 312, HDR_ADDR - (0x400000 + 304) - 8)
        with self.assertRaises(irp.EvidenceError):
            irp.fde_index(irp.Elf(bytes(data)))

    def test_complete_body_still_parses(self):
        starts, ends = irp.fde_index(irp.Elf(make_elf(300, write_body=True)))
        self.assertEqual(starts, [HDR_ADDR])
        self.assertEqual(ends, [HDR_ADDR + 0x40])


if __name__ == "__main__":
    unittest.main()
