"""Synthetic-input tests for the consensus_wire.fde_index header bound.

A .eh_frame_hdr section shorter than its 12-byte header (version/encodings
plus count field) must fail with the tool's EvidenceError contract, not a
raw struct.error from unpack_from. The valid single-entry table still
parses. No pinned binary is needed: the ELF is built synthetically.

Note: the table-overrun bound (12 + count * 8 > size) is already covered
by open PR #259, so this file deliberately does not re-test it.
"""
import importlib.util
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("consensus_wire", ROOT / "tools/consensus_wire.py")
cw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cw)

HDR_VA = 0x1000


def build_elf(hdr_bytes, hdr_size, load=None):
    """Minimal ELF64 with .eh_frame_hdr and .shstrtab sections.

    load: optional (p_va, p_filesz) PT_LOAD entry covering the header file
    offset, for the valid case where fde_index dereferences an FDE body.
    """
    phnum = 1 if load else 0
    phoff = 64
    shoff = phoff + 56 * phnum
    shstr = b"\x00.eh_frame_hdr\x00.shstrtab\x00"
    shstr_off = shoff + 3 * 64
    hdr_off = shstr_off + len(shstr)
    e = bytearray(64)
    e[0:4] = b"\x7fELF"
    e[4] = 2
    e[5] = 1
    struct.pack_into("<Q", e, 0x20, phoff)
    struct.pack_into("<Q", e, 0x28, shoff)
    struct.pack_into("<HHHHH", e, 0x36, 56, phnum, 64, 3, 2)
    out = bytearray(e)
    if load:
        p_va, p_filesz = load
        out += struct.pack("<IIQQQQQQ", 1, 0, hdr_off, p_va, 0, p_filesz, 0, 0)
    out += struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    out += struct.pack("<IIQQQQIIQQ", 1, 1, 0, HDR_VA, hdr_off, hdr_size, 0, 0, 1, 0)
    out += struct.pack("<IIQQQQIIQQ", 15, 3, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0)
    out += shstr
    out += hdr_bytes
    return bytes(out), hdr_off


def header(count, table=b""):
    return bytes([1, 0x1B, 0x03, 0x3B]) + b"\x00" * 4 + struct.pack("<I", count) + table


class FdeIndexBoundsTests(unittest.TestCase):
    def test_header_shorter_than_count_field(self):
        data, _ = build_elf(header(0)[:8], 8)
        with self.assertRaises(cw.EvidenceError):
            cw.fde_index(cw.Elf(data))

    def test_valid_single_entry_table(self):
        # Table entry: start at HDR_VA, FDE at HDR_VA + 0x100. The FDE body
        # carries pc_begin == start (rel -0x108 from fde_va + 8) and a
        # 0x40-byte range.
        table = struct.pack("<ii", 0, 0x100)
        data, hdr_off = build_elf(header(1, table), 12 + len(table),
                                  load=(HDR_VA, 0x200))
        fde_file_off = hdr_off + 0x100
        data = data + b"\x00" * (fde_file_off + 16 - len(data))
        data = (bytearray(data[:fde_file_off + 8])
                + struct.pack("<i", -0x108) + struct.pack("<I", 0x40)
                + data[fde_file_off + 16:])
        starts, ends = cw.fde_index(cw.Elf(bytes(data)))
        self.assertEqual(starts, [HDR_VA])
        self.assertEqual(ends, [HDR_VA + 0x40])


if __name__ == "__main__":
    unittest.main()
