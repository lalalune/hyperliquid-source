import contextlib
import filecmp
import io
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


class MainErrorHandlingTests(unittest.TestCase):
    def test_missing_binary_is_one_line_error(self):
        err = io.StringIO()
        with tempfile.TemporaryDirectory() as d:
            with contextlib.redirect_stderr(err):
                rc = tool.main(['--binary', '/nonexistent.bin', '--out', str(Path(d) / 'out.json')])
        self.assertEqual(rc, 1)
        self.assertTrue(err.getvalue().startswith('error: '))
        self.assertEqual(len(err.getvalue().strip().splitlines()), 1)
        self.assertNotIn('Traceback', err.getvalue())


if __name__ == '__main__':
    unittest.main()
