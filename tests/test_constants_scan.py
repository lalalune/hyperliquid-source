import re
import struct
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from constants_scan import (ScanError, entries_size, pool_entry, relocations,
                            section, string_table, window, xrefs)


def fixture():
    """Minimal ELF64-LE with .text/.rodata/.data.rel.ro/.rela.dyn/.eh_frame*."""
    data = bytearray(0x1000)
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 40, 0x800)
    struct.pack_into('<HHH', data, 58, 64, 7, 1)
    names = b'\0.shstrtab\0.text\0.rodata\0.data.rel.ro\0.rela.dyn\0.eh_frame_hdr\0.eh_frame\0'
    data[0x200:0x200 + len(names)] = names
    rows = [
        (0, 0, 0, 0, 0, 0, 0),
        (1, 3, 0, 0, 0x200, len(names), 0),
        (names.index(b'.text'), 1, 6, 0x1000, 0x300, 0x20, 0),
        (names.index(b'.rodata'), 1, 2, 0x2000, 0x340, 0x100, 0),
        (names.index(b'.data.rel.ro'), 1, 3, 0x3000, 0x440, 0x40, 0),
        (names.index(b'.rela.dyn'), 4, 0, 0, 0x480, 0x30, 24),
        (names.index(b'.eh_frame_hdr'), 1, 2, 0x4000, 0x4C0, 0x14, 0),
        (names.index(b'.eh_frame'), 1, 2, 0x5000, 0x4E0, 0x10, 0),
    ]
    for index, row in enumerate(rows):
        struct.pack_into('<IIQQQQIIQQ', data, 0x800 + index * 64, *row[:6], 0, 0, 1, row[6])

    # lea rsi, [rip + 0xffe]  -> 0x2002
    data[0x300:0x307] = bytes.fromhex('488d35fb0f0000')

    data[0x340:0x348] = b'\xc0\x05/cham\x00'
    data[0x34F:0x355] = b'\x05/cham'
    data[0x360:0x364] = b'abc\x00'

    for slot, addend in ((0x3000, 0x2002), (0x3010, 0x2020)):
        struct.pack_into('<Q', data, 0x440 + slot - 0x3000, 0)
        struct.pack_into('<Q', data, 0x440 + slot - 0x3000 + 8, 5 if addend == 0x2002 else 3)
    for index, (slot, addend) in enumerate(((0x3000, 0x2002), (0x3010, 0x2020))):
        struct.pack_into('<QQq', data, 0x480 + index * 24, slot, 8, addend)

    data[0x4C0:0x4C4] = bytes([1, 0x1B, 3, 0x3B])
    struct.pack_into('<Iii', data, 0x4C8, 1, -0x3000, 0x1000)
    return data


class PoolTests(unittest.TestCase):
    def setUp(self):
        self.data = fixture()
        self.rodata = section(self.data, '.rodata')

    def test_finds_marker_and_text(self):
        entry, text, prefixed = pool_entry(self.data, self.rodata, '/cham', require_marker=True)
        self.assertEqual((entry, text, prefixed), (0x2000, 0x2002, True))

    def test_unprefixed_copy_is_not_a_marker_candidate(self):
        # 0x350 is a bare length-prefixed copy, so only the 0xc0 entry qualifies.
        entry, text, prefixed = pool_entry(self.data, self.rodata, '/cham', require_marker=True)
        self.assertEqual(entry, 0x2000)
        with self.assertRaises(ScanError):
            pool_entry(self.data, self.rodata, '/cham')

    def test_duplicate_marker_entries_are_rejected(self):
        self.data[0x370:0x378] = b'\xc0\x05/cham\x00'
        with self.assertRaises(ScanError):
            pool_entry(self.data, self.rodata, '/cham', require_marker=True)


class TableTests(unittest.TestCase):
    def setUp(self):
        self.data = fixture()

    def test_reads_pointer_length_pairs_in_order(self):
        relro = section(self.data, '.data.rel.ro')
        va, rows = string_table(self.data, section(self.data, '.rodata'), relro,
                                {'/cham', 'abc'}, count=2)
        self.assertEqual(va, 0x3000)
        self.assertEqual([row[3] for row in rows], ['/cham', 'abc'])

    def test_wrong_expected_count_fails(self):
        with self.assertRaises(ScanError):
            string_table(self.data, section(self.data, '.rodata'),
                         section(self.data, '.data.rel.ro'), {'/cham', 'abc'}, count=3)

    def test_relative_relocations_only(self):
        self.assertEqual(relocations(self.data), {0x3000: 0x2002, 0x3010: 0x2020})

    def test_entsize_is_read(self):
        self.assertEqual(entries_size(self.data, '.rela.dyn'), 24)


class XrefTests(unittest.TestCase):
    def setUp(self):
        self.data = fixture()

    def test_resolves_rip_relative_operand(self):
        found = xrefs(self.data, section(self.data, '.text'), [0x2002])
        self.assertEqual(found[0x2002], [(0x1001, '488d35fb0f0000')])

    def test_window_is_nearest_start(self):
        self.assertEqual(window([0x1000, 0x2000], 0x1001), (0x1000, 0x2000))

    def test_window_before_first_start_fails(self):
        with self.assertRaises(ScanError):
            window([0x1000], 0x0FFF)


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / 'artifacts/node/94/hl-node'


@unittest.skipUnless(ARTIFACT.exists(), 'captured node #94 not present')
class ReadmeAnchorTests(unittest.TestCase):
    def test_serde_bound_strings_start_at_cited_relocated_targets(self):
        data = ARTIFACT.read_bytes()
        readme = (ROOT / 'research/work-items/constants/README.md').read_text()
        rodata, rel_ro = section(data, '.rodata'), section(data, '.data.rel.ro')
        relocs = relocations(data)
        for text in ('variant index 0 <= i < 76', 'variant index 0 <= i < 4'):
            with self.subTest(text=text):
                cited = re.search(rf'`{re.escape(text)}` at `(0x[0-9a-f]+)`'
                                  rf'(?: \(`&str` pair `(0x[0-9a-f]+)`)?', readme)
                self.assertIsNotNone(cited)
                va = int(cited.group(1), 16)
                start = rodata['offset'] + va - rodata['address']
                self.assertEqual(data[start:start + len(text)], text.encode())
                self.assertIsNotNone(cited.group(2), 'cite the relocated &str pair')
                pair = int(cited.group(2), 16)
                self.assertEqual(relocs[pair], va)
                length = struct.unpack_from('<Q', data, rel_ro['offset'] + pair + 8 - rel_ro['address'])[0]
                self.assertEqual(length, len(text))
        bound = re.search(r'\| agree 76/76 \| table `0x5668288`; bound `(0x[0-9a-f]+)` \|', readme)
        self.assertIsNotNone(bound)
        start = rodata['offset'] + int(bound.group(1), 16) - rodata['address']
        self.assertEqual(data[start:start + 25], b'variant index 0 <= i < 76')

    def test_default_select_instructions_are_at_cited_addresses(self):
        data = ARTIFACT.read_bytes()
        readme = (ROOT / 'research/work-items/constants/README.md').read_text()
        text = section(data, '.text')

        def insn(va, size):
            start = text['offset'] + va - text['address']
            return data[start:start + size].hex()

        sites = re.search(r'`cmovel %eax,%ebp` \(`(0x[0-9a-f]+)`, `(0x[0-9a-f]+)`, `(0x[0-9a-f]+)`\)', readme)
        self.assertIsNotNone(sites)
        test, mov, cmove = (int(g, 16) for g in sites.groups())
        self.assertEqual((insn(test, 3), insn(mov, 5), insn(cmove, 3)),
                         ('4084ed', 'bd20000000', '0f44e8'))  # testb %bpl / movl $0x20 / cmovel
        row = re.search(r'\| `DEFAULT_AWS_NAME = NvTestnet` \(32\) \| agree \| '
                        r'`(0x[0-9a-f]+)`, `(0x[0-9a-f]+)` \|', readme)
        self.assertIsNotNone(row)
        fallback, select = (int(g, 16) for g in row.groups())
        self.assertEqual((insn(fallback, 3), insn(select, 5)), ('40b520', 'bd20000000'))


if __name__ == '__main__':
    unittest.main()
