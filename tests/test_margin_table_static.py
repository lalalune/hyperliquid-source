import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import margin_table_static as mts

PACKET = ROOT / 'research' / 'work-items' / 'RE-007-margin-table-94'
GENERATED = ['evidence.json', 'functions.tsv', 'vectors.tsv', 'MANIFEST.sha256']


class MarginTableDecoderTests(unittest.TestCase):
    def test_digest_verification_against_artifacts_json(self):
        item = mts.load_expected_artifact(ROOT, mts.BINARY_REL)
        self.assertEqual(item['sha256'], mts.EXPECTED_SHA256)
        self.assertEqual(item['size'], mts.EXPECTED_SIZE)

        # Mismatch in sha256 or size must fail-closed
        with self.assertRaises(mts.EvidenceError):
            mts.check_digest(b'tampered payload', root=ROOT)

        with self.assertRaises(mts.EvidenceError):
            mts.load_expected_artifact(ROOT, 'artifacts/nonexistent/hl-node')

    def test_max_leverage_fallback(self):
        self.assertEqual(mts.max_leverage_fallback(), 50)

    def test_mode2_margin_formula(self):
        # Normal positive cases
        # ntl = 1000000, lev = 50 -> divisor = 100, div = 10000. prior = 0 -> 10000
        self.assertEqual(mts.mode2_margin(1_000_000, 50, 0), 10_000)
        # prior = 5000 -> 10000 - 5000 = 5000
        self.assertEqual(mts.mode2_margin(1_000_000, 50, 5000), 5_000)
        # Exact zero: prior == div
        self.assertEqual(mts.mode2_margin(1_000_000, 50, 10_000), 0)
        # Saturating subtraction underflow at zero: prior > div
        self.assertEqual(mts.mode2_margin(1_000_000, 50, 10_001), 0)
        self.assertEqual(mts.mode2_margin(100, 50, 500), 0)
        self.assertEqual(mts.mode2_margin(0, 50, 10), 0)
        self.assertEqual(mts.mode2_margin(0, 50, 0), 0)

        # Integer truncation towards zero (x86 div behavior)
        # ntl = 199, lev = 50 -> div = 100 -> 199 // 100 = 1
        self.assertEqual(mts.mode2_margin(199, 50, 0), 1)

        # Invalid arguments
        with self.assertRaises(ValueError):
            mts.mode2_margin(1000, 0, 0)
        with self.assertRaises(ValueError):
            mts.mode2_margin(1000, -5, 0)
        with self.assertRaises(ValueError):
            mts.mode2_margin(-10, 50, 0)
        with self.assertRaises(ValueError):
            mts.mode2_margin(1000, 50, -1)

    def test_mode3_margin_formula(self):
        # Normal positive cases
        # ntl = 1000000, lev = 50, prior = 0 -> lhs = 2000000, rhs = 0, div = 300 -> 2000000 // 300 = 6666
        self.assertEqual(mts.mode3_margin(1_000_000, 50, 0), 6666)
        # prior = 5000 -> rhs = 4 * 50 * 5000 = 1000000. num = 2000000 - 1000000 = 1000000 // 300 = 3333
        self.assertEqual(mts.mode3_margin(1_000_000, 50, 5000), 3333)
        # Exact zero: 2 * ntl == 4 * lev * prior -> ntl == 2 * lev * prior
        self.assertEqual(mts.mode3_margin(10_000, 50, 100), 0)
        # Saturating subtraction underflow at zero before division
        self.assertEqual(mts.mode3_margin(10_000, 50, 200), 0)
        self.assertEqual(mts.mode3_margin(100, 50, 500), 0)
        self.assertEqual(mts.mode3_margin(0, 50, 10), 0)
        self.assertEqual(mts.mode3_margin(0, 50, 0), 0)

        # Integer truncation towards zero
        # 2 * ntl = 599, lev = 50 -> div = 300 -> 599 // 300 = 1
        self.assertEqual(mts.mode3_margin(299, 50, 0), 1)

        # Invalid arguments
        with self.assertRaises(ValueError):
            mts.mode3_margin(1000, 0, 0)
        with self.assertRaises(ValueError):
            mts.mode3_margin(1000, -5, 0)
        with self.assertRaises(ValueError):
            mts.mode3_margin(-10, 50, 0)
        with self.assertRaises(ValueError):
            mts.mode3_margin(1000, 50, -1)


class MarginTableBinaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT / mts.BINARY_REL).read_bytes()
        cls.result, cls.vectors = mts.analyse(cls.data, root=ROOT)

    def test_summary_metrics(self):
        summary = self.result['summary']
        expected = {
            'all_fde_bounds_verified': True,
            'all_instruction_controls_verified': True,
            'all_panic_records_verified': True,
            'all_relocations_verified': True,
            'controls_verified': 14,
            'fallback_leverage': 50,
            'functions_verified': 3,
            'panic_records_verified': 2,
            'relocations_verified': 5,
            'sample_vectors_verified': len(self.vectors),
        }
        self.assertEqual(summary, expected)

    def test_function_bounds_and_sha256(self):
        funcs = self.result['functions']
        self.assertEqual(set(funcs.keys()), {
            'max_leverage_for_position',
            'margin_after_tier_offset_div_6x_leverage',
            'ntl_div_2x_leverage_minus_prior_contribution',
        })

        self.assertEqual(funcs['max_leverage_for_position']['start'], '0x3333580')
        self.assertEqual(funcs['max_leverage_for_position']['end'], '0x333366e')
        self.assertEqual(funcs['max_leverage_for_position']['size'], 238)
        self.assertEqual(funcs['max_leverage_for_position']['sha256'],
                         '70a264b0719c28fec54a5c7aab0d8d50c133795abf14ef1ec43a17938616bb1e')
        self.assertEqual(funcs['max_leverage_for_position']['reloc_slot'], '0x5775998')

        self.assertEqual(funcs['margin_after_tier_offset_div_6x_leverage']['start'], '0x3333670')
        self.assertEqual(funcs['margin_after_tier_offset_div_6x_leverage']['end'], '0x33337f9')
        self.assertEqual(funcs['margin_after_tier_offset_div_6x_leverage']['size'], 393)
        self.assertEqual(funcs['margin_after_tier_offset_div_6x_leverage']['sha256'],
                         '3c931bafcdd34ed228728e61b2c7fc1e1a21b66ffe554d8a4c87bde083ba82f9')
        self.assertEqual(funcs['margin_after_tier_offset_div_6x_leverage']['reloc_slot'], '0x57759a0')

        self.assertEqual(funcs['ntl_div_2x_leverage_minus_prior_contribution']['start'], '0x3333800')
        self.assertEqual(funcs['ntl_div_2x_leverage_minus_prior_contribution']['end'], '0x3333915')
        self.assertEqual(funcs['ntl_div_2x_leverage_minus_prior_contribution']['size'], 277)
        self.assertEqual(funcs['ntl_div_2x_leverage_minus_prior_contribution']['sha256'],
                         '2774ef152d00b90e6d846604c65ada3efc7d58de4865338d84c49235e33e79f8')
        self.assertEqual(funcs['ntl_div_2x_leverage_minus_prior_contribution']['reloc_slot'], '0x57746e8')

    def test_panic_records_and_file_path(self):
        panic = self.result['panic_records']
        self.assertEqual(set(panic.keys()), {'0x56e9b40', '0x56e9b58'})
        self.assertEqual(panic['0x56e9b40']['line'], 107)
        self.assertEqual(panic['0x56e9b40']['col'], 105)
        self.assertEqual(panic['0x56e9b40']['file'],
                         '/home/ubuntu/hl/code_Mainnet/l1/src/clearinghouse/margin_table.rs')

        self.assertEqual(panic['0x56e9b58']['line'], 101)
        self.assertEqual(panic['0x56e9b58']['col'], 57)
        self.assertEqual(panic['0x56e9b58']['file'],
                         '/home/ubuntu/hl/code_Mainnet/l1/src/clearinghouse/margin_table.rs')

    def test_negative_controls_digest(self):
        bad_digest_data = bytearray(self.data)
        bad_digest_data[0x200] ^= 0x01
        with self.assertRaises(mts.EvidenceError):
            mts.analyse(bytes(bad_digest_data), root=ROOT)

    def test_negative_controls_controls_corruption(self):
        img = mts.Image(self.data)
        # Test tampering 50x fallback constant
        bad_data = bytearray(self.data)
        offset = img.off(0x3333665)
        bad_data[offset + 1] = 0x64  # change 50x (0x32) to 100x (0x64)
        bad_img = mts.Image(bytes(bad_data))
        with self.assertRaises(mts.EvidenceError) as ctx:
            mts.verify_controls(bad_img)
        self.assertIn('0x3333665', str(ctx.exception))

        # Test tampering mode 3 div instruction
        bad_data2 = bytearray(self.data)
        offset2 = img.off(0x3333780)
        bad_data2[offset2 + 1] ^= 0x01
        bad_img2 = mts.Image(bytes(bad_data2))
        with self.assertRaises(mts.EvidenceError) as ctx:
            mts.verify_controls(bad_img2)
        self.assertIn('0x3333780', str(ctx.exception))

        # Test tampering mode 2 div instruction
        bad_data3 = bytearray(self.data)
        offset3 = img.off(0x33338c8)
        bad_data3[offset3 + 1] ^= 0x01
        bad_img3 = mts.Image(bytes(bad_data3))
        with self.assertRaises(mts.EvidenceError) as ctx:
            mts.verify_controls(bad_img3)
        self.assertIn('0x33338c8', str(ctx.exception))

    def test_negative_controls_relocations_corruption(self):
        img = mts.Image(self.data)
        addr, off, size = img.sec['.rela.dyn']
        # Find entry for 0x5775998 and corrupt its addend
        bad_data = bytearray(self.data)
        for i in range(off, off + size, 24):
            r_offset, r_info, r_addend = struct.unpack_from('<QQq', self.data, i)
            if r_offset == 0x5775998:
                struct.pack_into('<QQq', bad_data, i, r_offset, r_info, r_addend ^ 0x10)
                break
        bad_img = mts.Image(bytes(bad_data))
        with self.assertRaises(mts.EvidenceError) as ctx:
            mts.verify_relocations(bytes(bad_data), bad_img)
        self.assertIn('0x5775998', str(ctx.exception))

    def test_negative_controls_panic_record_corruption(self):
        img = mts.Image(self.data)
        bad_data = bytearray(self.data)
        offset = img.off(0x56e9b40)
        # Corrupt line number
        struct.pack_into('<II', bad_data, offset + 16, 999, 105)
        bad_img = mts.Image(bytes(bad_data))
        with self.assertRaises(mts.EvidenceError) as ctx:
            mts.verify_panic_records(bad_img)
        self.assertIn('0x56e9b40', str(ctx.exception))

    def test_packet_files_and_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            self.assertEqual(mts.main(['--out', str(tmp_path)]), 0)
            for fname in GENERATED:
                self.assertTrue((tmp_path / fname).is_file(), f'missing {fname}')
                if PACKET.exists() and (PACKET / fname).exists():
                    self.assertEqual(
                        (tmp_path / fname).read_bytes(),
                        (PACKET / fname).read_bytes(),
                        f'content mismatch for {fname}'
                    )

            # Check that MANIFEST.sha256 matches all generated files
            manifest_lines = (tmp_path / 'MANIFEST.sha256').read_text().splitlines()
            for line in manifest_lines:
                if not line.strip():
                    continue
                expected_sha, fname = line.split('  ', 1)
                actual_sha = hashlib.sha256((tmp_path / fname).read_bytes()).hexdigest()
                self.assertEqual(actual_sha, expected_sha, f'manifest hash mismatch for {fname}')


if __name__ == '__main__':
    unittest.main()
