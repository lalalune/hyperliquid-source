"""exchange_dispatch relative_relocs: a .rela.dyn section running past EOF or
leaving a ragged tail entry must fail closed with EvidenceError, not escape
as struct.error from the bare unpack_from."""
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import exchange_dispatch as ed  # noqa: E402


def make_elf(rela_size, rela_bytes):
    # Header (64 bytes), section headers at 64 (3 x 64), shstrtab at 256,
    # .rela.dyn right after it. No PT_LOAD entries: relative_relocs reads
    # elf.data directly, so no loads are needed.
    shstr = b".shstrtab\0.rela.dyn\0"
    shoff, shstr_off, rela_off = 64, 256, 256 + len(shstr)
    buf = bytearray(rela_off + len(rela_bytes))
    buf[0:4] = b"\x7fELF"
    buf[4] = 2
    buf[5] = 1
    struct.pack_into("<QQ", buf, 0x20, 64, shoff)
    struct.pack_into("<HHHHH", buf, 0x36, 0, 0, 64, 3, 1)
    struct.pack_into("<IIQQQQIIQQ", buf, shoff + 64,
                     0, 0, 0, 0, shstr_off, len(shstr), 0, 0, 0, 0)
    struct.pack_into("<IIQQQQIIQQ", buf, shoff + 128,
                     10, 0, 0, 0, rela_off, rela_size, 0, 0, 0, 0)
    buf[shstr_off:shstr_off + len(shstr)] = shstr
    buf[rela_off:rela_off + len(rela_bytes)] = rela_bytes
    return bytes(buf)


def entry(off, info=8, add=0x1000):
    return struct.pack("<QQq", off, info, add)


class RelativeRelocsTruncated(unittest.TestCase):
    def test_section_past_eof(self):
        # Size claims two entries but the file ends 16 bytes into the second.
        data = make_elf(48, entry(0x1000) + entry(0x2000)[:16])
        with self.assertRaises(ed.EvidenceError):
            ed.relative_relocs(ed.Elf(data))

    def test_ragged_tail_entry(self):
        # Size 40 is not a multiple of 24: the tail entry is only 16 bytes.
        data = make_elf(40, entry(0x1000) + entry(0x2000)[:16])
        with self.assertRaises(ed.EvidenceError):
            ed.relative_relocs(ed.Elf(data))

    def test_valid_section(self):
        data = make_elf(48, entry(0x1000) + entry(0x2000, 8, 0x2000))
        self.assertEqual(ed.relative_relocs(ed.Elf(data)),
                         {0x1000: 0x1000, 0x2000: 0x2000})


if __name__ == '__main__':
    unittest.main()
