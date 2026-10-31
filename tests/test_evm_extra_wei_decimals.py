import contextlib
import filecmp
import io
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import evm_extra_wei_decimals as tool  # noqa: E402

PACKET = ROOT / 'research' / 'work-items' / 'RE-004-evm-extra-wei-decimals-94'
GENERATED = ['evidence.json', 'guards.tsv', 'guard-bytes.txt']
EXPECTED = list(range(-2, 19))


class EvmExtraWeiDecimalsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT / tool.BINARY).read_bytes()
        cls.result, cls.funcs, cls.table = tool.analyse(cls.data)

    def test_rejects_wrong_digest(self):
        bad = bytearray(self.data[:4096])
        with self.assertRaises(tool.EvidenceError):
            tool.check_digest(bytes(bad))
        corrupted = bytearray(self.data)
        corrupted[0x599967] ^= 0x01
        with self.assertRaises(tool.EvidenceError):
            tool.analyse(bytes(corrupted))

    def test_summary(self):
        s = self.result['summary']
        self.assertEqual(s['lea_refs'], 6)
        self.assertEqual(s['functions'], 6)
        self.assertEqual(s['sites_with_exactly_one_guard'], 6)
        self.assertEqual(s['sites_fully_verified'], 6)
        self.assertEqual(s['sites_gated_by_already_set'], 6)
        self.assertEqual(s['sites_ok_path_stores_input_byte'], 3)
        self.assertEqual(s['guard_forms'], 2)
        self.assertEqual((s['admitted_i8_min'], s['admitted_i8_max'], s['admitted_count']), (-2, 18, 21))
        self.assertEqual(s['error_tags'], [0xdf])

    def test_every_guard_admits_exactly_message_range(self):
        for site in self.result['sites']:
            g = site['guards'][0]
            self.assertEqual(tool.admitted_signed(g['k'], g['c'], g['jcc']), EXPECTED, site['lea_va'])
            self.assertEqual(site['payload']['length'], len(tool.MESSAGE))

    def test_model_negative_controls(self):
        # Off-by-one compare constants or a shifted bias change the admitted set.
        self.assertNotEqual(tool.admitted_signed(0xed, 0xeb, 'ja'), EXPECTED)
        self.assertNotEqual(tool.admitted_signed(0xed, 0xea, 'jae'), EXPECTED)
        self.assertNotEqual(tool.admitted_signed(0xec, 0xea, 'ja'), EXPECTED)
        self.assertEqual(len(tool.admitted_signed(0xed, 0xea, 'ja')), 21)
        self.assertFalse(tool.admitted(0x13, 0xed, 0xea, 'ja'))   # 19
        self.assertFalse(tool.admitted(0xfd, 0xed, 0xeb, 'jae'))  # -3
        self.assertTrue(tool.admitted(0xfe, 0xed, 0xeb, 'jae'))   # -2
        self.assertTrue(tool.admitted(0x12, 0xed, 0xea, 'ja'))    # 18

    def test_decoder_both_forms_and_prefix_dedup(self):
        a = bytes.fromhex('418d40ed3cea7723')
        got = tool.decode_guard(a, 0x1000, len(a))
        self.assertEqual(len(got), 1)
        self.assertEqual((got[0]['input_reg'], got[0]['k'], got[0]['c'], got[0]['jcc']), ('r8', 0xed, 0xea, 'ja'))
        b = bytes.fromhex('4180c1ed4180f9eb732e')
        got = tool.decode_guard(b, 0x1000, len(b))
        self.assertEqual(len(got), 1)
        self.assertEqual((got[0]['input_reg'], got[0]['c'], got[0]['jcc']), ('r9', 0xeb, 'jae'))

    def test_decoder_rejects_corrupted_guard(self):
        # jbe instead of ja, and a compare on a different register.
        self.assertEqual(tool.decode_guard(bytes.fromhex('418d40ed3cea7623'), 0, 8), [])
        self.assertEqual(tool.decode_guard(bytes.fromhex('4180c1ed4180faeb732e'), 0, 10), [])

    def test_out_of_range_addresses(self):
        img = tool.Image(self.data)
        with self.assertRaises(tool.EvidenceError):
            img.read(0x10, 4)
        fdes = tool.Fdes(img)
        with self.assertRaises(tool.EvidenceError):
            fdes.range_of(0x1000)
        with self.assertRaises(tool.EvidenceError):
            tool.message_bounds(b'EVM extra wei decimals must be small')

    def test_generated_files_match_packet(self):
        with tempfile.TemporaryDirectory() as tmp:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(tool.main(['--out', tmp]), 0)
            for name in GENERATED:
                self.assertTrue(filecmp.cmp(Path(tmp) / name, PACKET / name, shallow=False), name)


def elf_with_names(inside, outside=b'', extra_name_off=None):
    """ELF64 whose .shstrtab is `inside` and whose next file bytes are `outside`."""
    shstr_off = 64
    labels = [b'', b'.text', b'.shstrtab', b'.extra']
    shoff = shstr_off + len(inside) + len(outside)

    def name_off(label):
        if label == b'':
            return 0
        return inside.index(label)

    headers = b''
    for label in labels:
        off, size = (shstr_off, len(inside)) if label == b'.shstrtab' else (0, 0)
        off_name = extra_name_off if (label == b'.extra' and extra_name_off is not None) else name_off(label)
        headers += struct.pack('<IIQQQQIIQQ', off_name, 3 if label == b'.shstrtab' else 1,
                               0, 0, off, size, 0, 0, 1, 0)
    header = bytearray(64)
    header[0:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', header, 40, shoff)
    struct.pack_into('<HHH', header, 58, 64, len(labels), labels.index(b'.shstrtab'))
    return bytes(header) + inside + outside + headers


NAMES = b'\0.text\0.shstrtab\0'


class SectionNameBoundsTests(unittest.TestCase):
    def test_name_terminated_inside_shstrtab_is_kept(self):
        self.assertIn('.extra', tool.sections(elf_with_names(NAMES + b'.extra\0')))

    def test_name_finished_outside_shstrtab_is_rejected(self):
        # '.extra' has no NUL inside .shstrtab; its terminator lives in the
        # following bytes, which the old unbounded search accepted as
        # '.extra_name'.
        with self.assertRaisesRegex(tool.EvidenceError, 'unterminated section name'):
            tool.sections(elf_with_names(NAMES + b'.extra', b'_name\0'))

    def test_unterminated_name_is_rejected(self):
        with self.assertRaisesRegex(tool.EvidenceError, 'unterminated section name'):
            tool.sections(elf_with_names(NAMES + b'.extra'))

    def test_name_offset_outside_shstrtab_is_rejected(self):
        # The offset points at 'bogus' in the bytes after .shstrtab; on base
        # it was read as a section name instead of being rejected.
        inside = NAMES + b'.extra\0'
        with self.assertRaisesRegex(tool.EvidenceError, 'section name offset outside .shstrtab'):
            tool.sections(elf_with_names(inside, b'bogus\0', extra_name_off=len(inside)))


if __name__ == '__main__':
    unittest.main()
