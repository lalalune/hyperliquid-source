"""Synthetic-ELF tests for the non-UTF-8 path flaw in state_hashers.build.

state_hashers.build decodes every Location path it accepts with a bare
``p.decode()``. Its ``main()`` catches only EvidenceError, so a path
that ends in ``.rs`` and passes the record-validity filter but contains
non-UTF-8 bytes escapes as a bare UnicodeDecodeError traceback instead
of the tool's fail-closed rejection (sibling of the non-UTF-8-name
fixes for first_party_locations, which do not reach this inline loop
because it decodes every path, not just first-party ones).

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
VALID_PATH = b"/x/blake3-1.0/src/lib.rs"  # 24 bytes, matches HASH_CRATE_RE
BAD_PATH = b"/x/blake3-1.0/src/l\xffib.rs"  # 24 bytes, non-UTF-8, ends .rs
OTHER_BAD_PATH = b"/x/other-1.0/src/l\xffib.rs"  # no crate match, still decoded


def build_elf(path):
    text_off, dr_off = 0x100, 0x200
    dr_size, ro_size = 0x40, 0x40
    ro_off = dr_off + dr_size
    tail_off = ro_off + ro_size
    rela_off = (tail_off + 16 + 7) & ~7
    hdr_off = rela_off + 24
    pcs = sorted([TEXT_VA] + list(sh.RE005_ENCODERS))
    count = len(pcs)
    table_len = 12 + 8 * count
    fde_off = hdr_off + table_len
    hdr_size = table_len + 16 * count
    shstr_off = hdr_off + hdr_size
    names = b"\0.text\0.data.rel.ro\0.rodata\0.rela.dyn\0.eh_frame_hdr\0.shstrtab\0"
    offs = {n: names.index(n) for n in
            (b".text", b".data.rel.ro", b".rodata", b".rela.dyn", b".eh_frame_hdr", b".shstrtab")}
    shoff = shstr_off + len(names)
    total = shoff + 7 * 64
    data = bytearray(total)
    hdr_va = BASE + hdr_off

    struct.pack_into("<16sHHIQQQIHHHHHH", data, 0,
                     b"\x7fELF\x02\x01\x01" + b"\0" * 9, 2, 62, 1, 0, 0x40, shoff, 0,
                     64, 56, 1, 64, 7, 6)
    struct.pack_into("<IIQQQQQQ", data, 0x40, 1, 5, 0, BASE, 0, total, total, 0x1000)

    # .text: a single RIP-relative LEA at +0x10 targeting the slot.
    slot_va = DR_VA + 0x10
    site_va = TEXT_VA + 0x10
    struct.pack_into("<3s", data, text_off + 0x10, b"\x48\x8d\x3d")
    struct.pack_into("<i", data, text_off + 0x13, slot_va - (site_va + 7))

    # Mid-section Location record + path.
    struct.pack_into("<QII", data, dr_off + 0x18, len(path), 1, 1)
    path_off = ro_off + 0x10
    data[path_off:path_off + len(path)] = path

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


class StateHashersNonUtf8PathTests(unittest.TestCase):
    def setUp(self):
        self._real = sr.build
        sr.build = lambda data, expected_sha256=None: {
            "binary_sha256": "0" * 64,
            "functions": [{"start": TEXT_VA, "scoped": True}]}
        self.addCleanup(setattr, sr, "build", self._real)

    def test_non_utf8_path_rejected(self):
        with self.assertRaises(sh.EvidenceError):
            sh.build(build_elf(BAD_PATH))

    def test_non_utf8_path_without_crate_match_rejected(self):
        # Decoding happens for every accepted path, before any reason match.
        with self.assertRaises(sh.EvidenceError):
            sh.build(build_elf(OTHER_BAD_PATH))

    def test_valid_utf8_path_still_parses(self):
        self.assertEqual(hasher_reasons(sh.build(build_elf(VALID_PATH))),
                         ["crate_location:blake3-1.0"])


if __name__ == "__main__":
    unittest.main()
