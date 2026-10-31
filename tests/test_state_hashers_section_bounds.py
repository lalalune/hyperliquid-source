"""Synthetic-ELF tests for the section-bounds flaw in state_hashers.build.

state_hashers.build walks every .data.rel.ro relocation slot whose target
lies in .rodata and decodes the 24-byte panic Location record at slot+8
plus the path at the target, mirroring tools/state_roots.py's
first_party_locations() — but without that function's section-bounds
discipline (cf. the sibling fixes for consensus_wire, info_request_path
and state_roots). Elf.read() only checks the first byte is file-backed,
so a record straddling the end of .data.rel.ro silently borrowed the
next section's bytes and a path straddling the end of .rodata silently
borrowed bytes past the section.

sr.build is stubbed: the real one walks the references/can1357-hl
claims tree, which is absent on this VM (LFS pointers). The stub keeps
the real Elf/FDE/relocation/LEA parsing under test; only the preamble
that produces base["functions"] is replaced.
"""
import importlib.util
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("state_hashers", ROOT / "tools/state_hashers.py")
sh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sh)
sr = sh.sr

BASE = 0x400000
TEXT_VA = 0x400100
DR_VA = 0x400200
PATH = b"/x/blake3-1.0/src/lib.rs"  # 24 bytes, matches HASH_CRATE_RE


def build_elf(*, dr_size, ro_size, slot_off, record_off, path_off, tail_len=16):
    text_off, dr_off = 0x100, 0x200
    ro_off = dr_off + dr_size
    tail_off = ro_off + ro_size
    rela_off = (tail_off + tail_len + 7) & ~7
    hdr_off = rela_off + 24
    pcs = sorted([TEXT_VA] + list(sh.RE005_ENCODERS))
    count = len(pcs)
    table_len = 12 + 8 * count
    fde_off = hdr_off + table_len
    hdr_size = table_len + 16 * count
    shstr_off = hdr_off + hdr_size
    names = b"\0.text\0.data.rel.ro\0.rodata\0.rela.dyn\0.eh_frame_hdr\0.shstrtab\0"
    offs = {}
    for name in (b".text", b".data.rel.ro", b".rodata", b".rela.dyn", b".eh_frame_hdr", b".shstrtab"):
        offs[name] = names.index(name)
    shoff = shstr_off + len(names)
    total = shoff + 7 * 64
    data = bytearray(total)
    hdr_va = BASE + hdr_off

    # ELF header + one PT_LOAD covering the whole file.
    struct.pack_into("<16sHHIQQQIHHHHHH", data, 0,
                     b"\x7fELF\x02\x01\x01" + b"\0" * 9, 2, 62, 1, 0, 0x40, shoff, 0,
                     64, 56, 1, 64, 7, 6)
    struct.pack_into("<IIQQQQQQ", data, 0x40, 1, 5, 0, BASE, 0, total, total, 0x1000)

    # .text: a single RIP-relative LEA at +0x10 targeting the slot.
    slot_va = DR_VA + slot_off
    site_va = TEXT_VA + 0x10
    struct.pack_into("<3s", data, text_off + 0x10, b"\x48\x8d\x3d")
    struct.pack_into("<i", data, text_off + 0x13, slot_va - (site_va + 7))

    # Location record + path (written last so crossings overwrite fillers).
    struct.pack_into("<QII", data, record_off, len(PATH), 1, 1)
    data[path_off:path_off + len(PATH)] = PATH

    # .rela.dyn: one RELATIVE entry, slot -> path.
    struct.pack_into("<QQq", data, rela_off, slot_va, 8, BASE + path_off)

    # .eh_frame_hdr: encodings (1, 0x1B, 0x03, 0x3B), count, table, FDE blobs.
    data[hdr_off:hdr_off + 4] = bytes([1, 0x1B, 0x03, 0x3B])
    struct.pack_into("<I", data, hdr_off + 8, count)
    for i, pc in enumerate(pcs):
        blob_va = BASE + fde_off + 16 * i
        struct.pack_into("<ii", data, hdr_off + 12 + 8 * i, pc - hdr_va, blob_va - hdr_va)
        struct.pack_into("<IIiI", data, fde_off + 16 * i, 16, 0,
                         pc - (blob_va + 8), 0x100 if pc == TEXT_VA else 0x10)

    # Section headers: (name, type, flags, addr, off, size, link, info, align, entsize).
    secs = [
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (offs[b".text"], 1, 6, TEXT_VA, text_off, 0x100, 0, 0, 16, 0),
        (offs[b".data.rel.ro"], 1, 2, DR_VA, dr_off, dr_size, 0, 0, 8, 0),
        (offs[b".rodata"], 1, 2, BASE + ro_off, ro_off, ro_size, 0, 0, 8, 0),
        (offs[b".rela.dyn"], 4, 2, BASE + rela_off, rela_off, 24, 0, 0, 8, 24),
        (offs[b".eh_frame_hdr"], 1, 2, hdr_va, hdr_off, hdr_size, 0, 0, 8, 0),
        (offs[b".shstrtab"], 3, 0, 0, shstr_off, len(names), 0, 0, 1, 0),
    ]
    for i, s in enumerate(secs):
        struct.pack_into("<IIQQQQIIQQ", data, shoff + 64 * i, *s)
    data[shstr_off:shstr_off + len(names)] = names
    return bytes(data)


def hasher_reasons(result):
    rows = [h for h in result["hashers"] if h["function"] == TEXT_VA]
    return rows[0]["reasons"] if rows else None


class StateHashersSectionBoundsTests(unittest.TestCase):
    def setUp(self):
        self._real = sr.build
        sr.build = lambda data, expected_sha256=None: {
            "binary_sha256": "0" * 64,
            "functions": [{"start": TEXT_VA, "scoped": True}]}
        self.addCleanup(setattr, sr, "build", self._real)

    def test_record_crossing_data_rel_ro_rejected(self):
        # Slot is the last 8 bytes of .data.rel.ro, so slot+8..slot+24
        # borrows the first 16 bytes of .rodata as the record fields.
        data = build_elf(dr_size=0x40, ro_size=0x40, slot_off=0x38,
                         record_off=0x240, path_off=0x250)
        with self.assertRaises(sh.EvidenceError):
            sh.build(data)

    def test_path_crossing_rodata_rejected(self):
        # Path starts 14 bytes before the end of .rodata and runs 10
        # bytes past it into the following file bytes.
        data = build_elf(dr_size=0x40, ro_size=0x40, slot_off=0x10,
                         record_off=0x218, path_off=0x26e)
        with self.assertRaises(sh.EvidenceError):
            sh.build(data)

    def test_record_ending_at_section_end_parses(self):
        data = build_elf(dr_size=0x40, ro_size=0x40, slot_off=0x28,
                         record_off=0x230, path_off=0x250)
        self.assertEqual(hasher_reasons(sh.build(data)), ["crate_location:blake3-1.0"])

    def test_path_ending_at_section_end_parses(self):
        data = build_elf(dr_size=0x40, ro_size=0x40, slot_off=0x10,
                         record_off=0x218, path_off=0x268)
        self.assertEqual(hasher_reasons(sh.build(data)), ["crate_location:blake3-1.0"])


if __name__ == "__main__":
    unittest.main()
