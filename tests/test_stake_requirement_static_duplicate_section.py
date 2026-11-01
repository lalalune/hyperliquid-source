"""stake_requirement_static parse_elf_sections(): a duplicate section name must fail.

parse_elf_sections() stored sections in a dict keyed by name, so an ELF
carrying two sections with the same name silently kept only the last one.
analyse()'s va_to_offset() walks that dict, so a VA inside the dropped
duplicate either resolved to None or was resolved against the wrong
section, with no error. The sibling parsers refuse this ambiguity
(decimal_scaled_u64, state_roots, exchange_dispatch, action_signable,
vault_guard_static and others); this applies the same rule here, raising
the tool's own EvidenceError.
"""
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import stake_requirement_static as srs  # noqa: E402


def elf_bytes(duplicate=None):
    data = bytearray(1024)
    data[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<Q", data, 40, 512)  # e_shoff
    names = b"\0.shstrtab\0.text\0.rodata\0"
    data[64:64 + len(names)] = names
    text_off = names.index(b".text")
    rodata_off = names.index(b".rodata")
    entries = [
        (0, 0, 0, 0, 0, 0),
        (1, 3, 0, 0, 64, len(names)),
        (text_off, 1, 6, 0x1000, 256, 32),
        (rodata_off, 1, 2, 0x2000, 320, 16),
    ]
    if duplicate == ".text":
        entries.append((text_off, 1, 6, 0x9000, 768, 64))
    if duplicate == ".rodata":
        entries.append((rodata_off, 1, 2, 0xA000, 896, 8))
    # e_shentsize, e_shnum, e_shstrndx
    struct.pack_into("<HHH", data, 58, 64, len(entries), 1)
    for i, e in enumerate(entries):
        struct.pack_into("<IIQQQQIIQQ", data, 512 + i * 64, *e, 0, 0, 1, 0)
    return bytes(data)


class DuplicateSectionNameTests(unittest.TestCase):
    def test_unique_names_parse_exactly(self):
        sec = srs.parse_elf_sections(elf_bytes())
        self.assertEqual(sorted(sec), ["", ".rodata", ".shstrtab", ".text"])
        self.assertEqual(sec[".text"], {"addr": 0x1000, "offset": 256, "size": 32})
        self.assertEqual(sec[".rodata"], {"addr": 0x2000, "offset": 320, "size": 16})

    def test_duplicate_text_is_evidence_error(self):
        with self.assertRaises(srs.EvidenceError) as cm:
            srs.parse_elf_sections(elf_bytes(duplicate=".text"))
        self.assertIn("duplicate section name .text", str(cm.exception))

    def test_duplicate_rodata_is_evidence_error(self):
        with self.assertRaises(srs.EvidenceError) as cm:
            srs.parse_elf_sections(elf_bytes(duplicate=".rodata"))
        self.assertIn("duplicate section name .rodata", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
