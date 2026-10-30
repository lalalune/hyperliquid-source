import importlib.util
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "state_roots", ROOT / "tools/state_roots.py")
sr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sr)


def make_elf(names):
    """Elf whose sections are exactly `names` (plus the string table itself)."""
    entries = list(names) + ['.shstrtab']
    table = b'\x00'
    offsets = {}
    for name in entries:
        offsets[name] = len(table)
        table += name.encode() + b'\x00'
    shoff = 64
    str_off = 1024
    data = bytearray(str_off + len(table))
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 0x20, 0)
    struct.pack_into('<Q', data, 0x28, shoff)
    struct.pack_into('<HHHHH', data, 0x36, 56, 0, 64, len(entries), len(entries) - 1)
    for i, name in enumerate(entries):
        off = str_off if name == '.shstrtab' else 0
        size = len(table) if name == '.shstrtab' else 0
        struct.pack_into('<IIQQQQIIQQ', data, shoff + i * 64,
                         offsets[name], 3, 0, 0, off, size, 0, 0, 1, 0)
    data[str_off:str_off + len(table)] = table
    return sr.Elf(bytes(data))


class MissingSectionTests(unittest.TestCase):
    def test_fde_index_missing_eh_frame_hdr(self):
        with self.assertRaises(sr.EvidenceError):
            sr.fde_index(make_elf([]))

    def test_relative_relocs_missing_rela_dyn(self):
        with self.assertRaises(sr.EvidenceError):
            sr.relative_relocs(make_elf([]))

    def test_first_party_locations_missing_rodata(self):
        with self.assertRaises(sr.EvidenceError):
            sr.first_party_locations(make_elf([]), {})

    def test_first_party_locations_missing_data_rel_ro(self):
        with self.assertRaises(sr.EvidenceError):
            sr.first_party_locations(make_elf(['.rodata']), {})

    def test_lea_targets_missing_text(self):
        with self.assertRaises(sr.EvidenceError):
            sr.lea_targets(make_elf([]))

    def test_literal_anchors_missing_rodata(self):
        with self.assertRaises(sr.EvidenceError):
            sr.literal_anchors(make_elf([]), "exact", "x", {}, {})

    def test_present_sections_pass_through(self):
        elf = make_elf(['.text', '.rela.dyn'])
        self.assertEqual(sr.lea_targets(elf), {})
        self.assertEqual(sr.relative_relocs(elf), {})


if __name__ == "__main__":
    unittest.main()
