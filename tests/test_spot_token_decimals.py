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

import spot_token_decimals as tool  # noqa: E402

PACKET = ROOT / 'research' / 'work-items' / 'RE-004-spot-token-decimals-94'
GENERATED = ['evidence.json', 'admission.tsv', 'guard-bytes.txt']
RANGE_GUARD_A = bytes.fromhex('4538ec0f97c04180fd0b0f93c108c10f84fe000000' '66bddf00')
RANGE_GUARD_B = bytes.fromhex('4138ef0f97c04080fd0b0f93c108c10f84ca000000' '66b8df00')


def count(pred):
    return sum(1 for a in range(256) for b in range(256) if pred(a, b))


class SpotTokenDecimalsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT / tool.BINARY).read_bytes()
        cls.result, cls.funcs, cls.grid = tool.analyse(cls.data)

    def test_rejects_wrong_digest(self):
        with self.assertRaises(tool.EvidenceError):
            tool.check_digest(self.data[:4096])
        corrupted = bytearray(self.data)
        corrupted[0x5997f9] ^= 0x01          # one byte of "szDecimals too large"
        with self.assertRaises(tool.EvidenceError):
            tool.analyse(bytes(corrupted))

    def test_summary(self):
        s = self.result['summary']
        self.assertEqual((s['deploy_lea_refs'], s['wei_min_lea_refs']), (1, 1))
        self.assertEqual((s['deploy_sites_decoded'], s['deploy_sites_fully_verified']), (1, 1))
        self.assertEqual((s['deploy_sz_max'], s['deploy_wei_offset']), (5, 5))
        self.assertEqual(s['deploy_admitted_pairs'], 1491)
        self.assertFalse(s['deploy_add_can_wrap'])
        self.assertEqual(s['deploy_gated'], 1)
        self.assertEqual((s['range_lea_refs'], s['range_functions']), (5, 5))
        self.assertEqual(s['range_sites_with_exactly_one_guard'], 5)
        self.assertEqual(s['range_sites_fully_verified'], 5)
        self.assertEqual(s['range_byte_forms'], 2)
        self.assertEqual(s['range_admitted_pairs'], [66])
        self.assertEqual(s['range_load_disps'], [[0x18, 0x19]])
        self.assertEqual(s['joint_admitted_pairs'], 21)
        self.assertEqual(s['error_tags'], [0xdf])

    def test_every_guard_matches_message_predicate(self):
        for g in self.result['deploy_sites']:
            self.assertEqual(g['mismatch_vs_message_predicate'], 0)
            self.assertEqual(g['wei_min_for_sz'], {str(a): a + 5 for a in range(6)})
        for s in self.result['range_sites']:
            g = s['guards'][0]
            self.assertEqual(g['mismatch_vs_message_predicate'], 0, s['lea_va'])
            self.assertEqual((g['n'], g['tag'], s['length']['value']), (11, 0xdf, len(tool.RANGE)))

    def test_model_negative_controls(self):
        # Range: an off-by-one bound, or swapped operands, changes the admitted set.
        spec = lambda a, b: a <= b <= 10  # noqa: E731
        self.assertEqual(count(lambda a, b: tool.range_admitted(a, b, 11) != spec(a, b)), 0)
        self.assertNotEqual(count(lambda a, b: tool.range_admitted(a, b, 10) != spec(a, b)), 0)
        self.assertNotEqual(count(lambda a, b: tool.range_admitted(b, a, 11) != spec(a, b)), 0)
        self.assertTrue(tool.range_admitted(10, 10, 11))
        self.assertFalse(tool.range_admitted(0, 11, 11))
        self.assertFalse(tool.range_admitted(3, 2, 11))
        # Deploy: sz 5 / wei 10 admitted; sz 6, or wei one below sz+5, rejected.
        self.assertTrue(tool.deploy_admitted(5, 10, 5, 5))
        self.assertTrue(tool.deploy_admitted(0, 255, 5, 5))
        self.assertFalse(tool.deploy_admitted(6, 255, 5, 5))
        self.assertFalse(tool.deploy_admitted(2, 6, 5, 5))
        self.assertNotEqual(count(lambda a, b: tool.deploy_admitted(a, b, 5, 4)), 1491)
        # With a wider sz bound the u8 add would wrap: sz 251 + 5 = 0 admits wei 0.
        self.assertTrue(tool.deploy_admitted(251, 0, 255, 5))

    def test_range_decoder_and_corruptions(self):
        for raw, regs in ((RANGE_GUARD_A, ('r12b', 'r13b')), (RANGE_GUARD_B, ('r15b', 'bpl'))):
            got = tool.decode_range(raw + b'\x48\x8d\x05\0\0\0\0', 0x1000, len(raw))
            self.assertEqual(len(got), 1)
            self.assertEqual(((got[0]['a_reg'], got[0]['b_reg']), got[0]['n'], got[0]['tag']), (regs, 11, 0xdf))
        pad = b'\x48\x8d\x05\0\0\0\0'
        # setb instead of seta, compare of a different register with 0xb, je -> jne.
        for i, v in ((4, 0x92), (8, 0xfc), (16, 0x85)):
            bad = bytearray(RANGE_GUARD_A)
            bad[i] = v
            self.assertEqual(tool.decode_range(bytes(bad) + pad, 0, len(bad)), [], (i, v))

    def test_deploy_decoder_rejects_corruption(self):
        fn_start = int(self.result['deploy_sites'][0]['fn_start'], 16)
        lea = int(self.result['deploy_sites'][0]['lea_va'], 16)
        r, fn = self.funcs[fn_start]
        self.assertEqual(len(tool.decode_deploy(fn, fn_start, lea - fn_start)), 1)
        bad = bytearray(fn)
        bad[lea - fn_start - 7] = 0x77      # jbe -> ja
        self.assertEqual(tool.decode_deploy(bytes(bad), fn_start, lea - fn_start), [])
        self.assertEqual(tool.decode_deploy(fn, fn_start, lea - fn_start + 1), [])

    def test_out_of_range_and_message_parsing(self):
        img = tool.Image(self.data)
        with self.assertRaises(tool.EvidenceError):
            img.read(0x10, 4)
        fdes = tool.Fdes(img)
        with self.assertRaises(tool.EvidenceError):
            fdes.range_of(0x1000)
        with self.assertRaises(tool.EvidenceError):
            tool.parse_range_message(b'must have szDecimals <= weiDecimals')
        with self.assertRaises(tool.EvidenceError):
            tool.parse_deploy_messages(tool.SZ_TOO_LARGE, b'weiDecimals must be large')
        self.assertEqual(tool.parse_range_message(tool.RANGE), 10)
        self.assertEqual(tool.parse_deploy_messages(tool.SZ_TOO_LARGE, tool.WEI_MIN), 5)

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
