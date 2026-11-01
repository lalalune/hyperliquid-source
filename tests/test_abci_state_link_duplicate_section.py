"""abci_state_link sections(): a duplicate section name must fail as ValueError.

sections() stores sections in a dict keyed by name, so an ELF carrying
two sections with the same name silently kept only the last one, and
every later lookup (.rela.dyn in rela_dyn, .eh_frame_hdr in fde_index,
.text/.init/.fini/.plt in caller_scan) read whichever duplicate
happened to come last. The sibling parsers refuse the ambiguity
instead: decimal_scaled_u64 raises "duplicate section name <name>",
abci_state_inventory requires unique section names, and the
consensus_wire / bincode_varint / state_roots duplicate-name fixes
were merged on the same rule. No open PR covers the duplicate-name
case in this file.
"""
import importlib.util
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "abci_state_link", ROOT / "tools/abci_state_link.py")
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


def elf_bytes(duplicate=None):
    data = bytearray(1024)
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 0x20, 0)      # phoff, no program headers
    struct.pack_into('<Q', data, 0x28, 512)    # shoff
    names = b'\0.shstrtab\0.text\0.rela.dyn\0'
    data[64:64 + len(names)] = names
    text_off = names.index(b'.text')
    rela_off = names.index(b'.rela.dyn')
    entries = [(0, 0, 0, 0, 0, 0),
               (1, 3, 0, 0, 64, len(names)),
               (text_off, 1, 6, 0x1000, 256, 32),
               (rela_off, 4, 0, 0, 512, 24)]
    if duplicate == '.text':
        entries.append((text_off, 1, 6, 0x9000, 768, 99))
    if duplicate == '.rela.dyn':
        entries.append((rela_off, 4, 0, 0, 1024, 48))
    struct.pack_into('<HHHHH', data, 0x36, 56, 0, 64, len(entries), 1)
    for i, e in enumerate(entries):
        struct.pack_into('<IIQQQQIIQQ', data, 512 + i * 64, *e, 0, 0, 1, 0)
    return bytes(data)


class DuplicateSectionNameTests(unittest.TestCase):
    def test_valid_names_parse(self):
        sec = tool.sections(elf_bytes())
        self.assertEqual(sorted(sec), ['', '.rela.dyn', '.shstrtab', '.text'])
        self.assertEqual(sec['.text'], {'addr': 0x1000, 'offset': 256, 'size': 32})
        self.assertEqual(sec['.rela.dyn'], {'addr': 0, 'offset': 512, 'size': 24})

    def test_duplicate_scanned_section_name_is_value_error(self):
        with self.assertRaises(ValueError) as cm:
            tool.sections(elf_bytes(duplicate='.text'))
        self.assertIn('duplicate section name .text', str(cm.exception))

    def test_duplicate_unscanned_section_name_is_value_error(self):
        with self.assertRaises(ValueError) as cm:
            tool.sections(elf_bytes(duplicate='.rela.dyn'))
        self.assertIn('duplicate section name .rela.dyn', str(cm.exception))

    def test_duplicate_section_name_is_not_silently_collapsed(self):
        try:
            sec = tool.sections(elf_bytes(duplicate='.text'))
        except ValueError:
            return
        self.fail('duplicate section name silently collapsed to %r'
                  % (sec['.text'],))


if __name__ == '__main__':
    unittest.main()
