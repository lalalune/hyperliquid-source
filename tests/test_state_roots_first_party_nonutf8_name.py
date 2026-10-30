import importlib.util
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "state_roots", ROOT / "tools/state_roots.py")
sr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sr)

TOTAL = 440


def make_elf():
    """Elf with .rodata, .data.rel.ro and .shstrtab sections.

    A PT_LOAD maps VA 0x400000 to file offset 0. The .data.rel.ro
    VA range covers file offsets 360..455, so a slot at VA
    0x400000 + 430 has its location record at offset 438 — only
    2 bytes of file remain, and elf.read() returns a short slice.
    Layout (no overlaps): string at 340, record at 384, shstrtab
    at 400.
    """
    table = b'\x00.rodata\x00.data.rel.ro\x00.shstrtab\x00'
    data = bytearray(TOTAL)
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 0x20, 64)    # phoff
    struct.pack_into('<Q', data, 0x28, 128)   # shoff
    struct.pack_into('<HHHHH', data, 0x36, 56, 1, 64, 3, 2)
    # Program header: PT_LOAD, offset 0, VA 0x400000, filesz = TOTAL.
    struct.pack_into('<IIQQQQQQ', data, 64,
                     1, 0, 0, 0x400000, 0, TOTAL, 0, 0)
    # Section headers: .rodata, .data.rel.ro, .shstrtab.
    struct.pack_into('<IIQQQQIIQQ', data, 128,
                     1, 3, 0, 0x400154, 340, 64, 0, 0, 1, 0)
    struct.pack_into('<IIQQQQIIQQ', data, 192,
                     9, 3, 0, 0x400168, 360, 96, 0, 0, 1, 0)
    struct.pack_into('<IIQQQQIIQQ', data, 256,
                     22, 3, 0, 0, 400, len(table), 0, 0, 1, 0)
    data[400:400 + len(table)] = table
    return data


class FirstPartyNonUtf8NameTests(unittest.TestCase):
    def test_nonutf8_name_fails_closed(self):
        # String starts with FIRST_PARTY, ends with .rs, carries a
        # 0xff byte. On base the bare .decode() escapes as
        # UnicodeDecodeError; with the fix it raises EvidenceError.
        data = make_elf()
        s = sr.FIRST_PARTY + b"\xff.rs"
        struct.pack_into('<QII', data, 384, len(s), 10, 5)
        data[340:340 + len(s)] = s
        with self.assertRaises(sr.EvidenceError):
            sr.first_party_locations(
                sr.Elf(bytes(data)), {0x400000 + 376: 0x400000 + 340})

    def test_complete_record_still_parses(self):
        data = make_elf()
        s = sr.FIRST_PARTY + b"foo.rs"
        struct.pack_into('<QII', data, 384, len(s), 10, 5)
        data[340:340 + len(s)] = s
        out = sr.first_party_locations(
            sr.Elf(bytes(data)), {0x400000 + 376: 0x400000 + 340})
        self.assertEqual(out, {0x400000 + 376: ("foo.rs", 10, 5)})


if __name__ == "__main__":
    unittest.main()
