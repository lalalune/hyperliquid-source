"""first_party_locations must not read past its sections.

elf.read() only checks that the first byte is file-backed, so a Location
record straddling the end of .data.rel.ro, or a path straddling the end of
.rodata, silently borrows the next section's bytes on base. Both reads must
fail closed with EvidenceError instead.
"""
import importlib.util
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "consensus_wire", ROOT / "tools/consensus_wire.py")
cw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cw)

TOTAL = 600
NAMES = b"\x00.rodata\x00.data.rel.ro\x00.shstrtab\x00"  # 32 bytes
FP = cw.FIRST_PARTY + b"foo.rs"  # 34 bytes


def make_elf():
    data = bytearray(TOTAL)
    data[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<Q", data, 0x20, 64)    # phoff
    struct.pack_into("<Q", data, 0x28, 128)   # shoff (headers 128..384)
    struct.pack_into("<HHHHH", data, 0x36, 56, 1, 64, 4, 3)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 0, 0, 0x400000, 0, TOTAL, 0, 0)
    struct.pack_into("<IIQQQQIIQQ", data, 128, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0)
    # .rodata: VA 0x4001B8, offset 440, size 64 (440..504)
    struct.pack_into("<IIQQQQIIQQ", data, 192, 1, 3, 0, 0x4001B8, 440, 64, 0, 0, 1, 0)
    # .data.rel.ro: VA 0x400190, offset 400, size 40 (400..440)
    struct.pack_into("<IIQQQQIIQQ", data, 256, 9, 3, 0, 0x400190, 400, 40, 0, 0, 1, 0)
    # .shstrtab: offset 540, size 32
    struct.pack_into("<IIQQQQIIQQ", data, 320, 22, 3, 0, 0, 540, len(NAMES), 0, 0, 1, 0)
    data[540:540 + len(NAMES)] = NAMES
    return data


def locations(data, slot, path_va):
    return cw.first_party_locations(cw.Elf(bytes(data)), {slot: path_va})


class SectionBoundsTests(unittest.TestCase):
    def test_record_past_data_rel_ro_is_rejected(self):
        # Slot 420 -> record 428..444; the column bytes at 440..444 live in
        # .rodata, not .data.rel.ro. On base this returns ('foo.rs', 10, 5).
        data = make_elf()
        struct.pack_into("<QI", data, 428, len(FP), 10)
        struct.pack_into("<I", data, 440, 5)
        data[444:444 + len(FP)] = FP
        with self.assertRaises(cw.EvidenceError):
            locations(data, 0x400000 + 420, 0x400000 + 444)

    def test_path_past_rodata_is_rejected(self):
        # Path at 500, only 4 bytes inside .rodata; the tail sits past the
        # section. On base this returns ('foo.rs', 10, 5).
        data = make_elf()
        struct.pack_into("<QII", data, 408, len(FP), 10, 5)
        data[500:504] = FP[:4]
        data[504:504 + len(FP) - 4] = FP[4:]
        with self.assertRaises(cw.EvidenceError):
            locations(data, 0x400000 + 400, 0x400000 + 500)

    def test_record_ending_at_section_end_still_parses(self):
        # Slot 416 -> record 424..440, ending exactly at the .data.rel.ro end.
        data = make_elf()
        struct.pack_into("<QII", data, 424, len(FP), 10, 5)
        data[444:444 + len(FP)] = FP
        self.assertEqual(locations(data, 0x400000 + 416, 0x400000 + 444),
                         {0x400000 + 416: ("foo.rs", 10, 5)})

    def test_valid_record_still_parses(self):
        data = make_elf()
        struct.pack_into("<QII", data, 408, len(FP), 10, 5)
        data[444:444 + len(FP)] = FP
        self.assertEqual(locations(data, 0x400000 + 400, 0x400000 + 444),
                         {0x400000 + 400: ("foo.rs", 10, 5)})


if __name__ == "__main__":
    unittest.main()
