import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import position_margin_static as pms

GENERATED = ['evidence.json', 'jump_table.tsv', 'vectors.tsv', 'MANIFEST.sha256']


class PositionMarginDecoderTests(unittest.TestCase):
    def test_digest_verification_against_artifacts_json(self):
        item = pms.load_expected_artifact(ROOT, pms.BINARY_REL)
        self.assertEqual(item['sha256'], pms.EXPECTED_SHA256)
        self.assertEqual(item['size'], pms.EXPECTED_SIZE)

        with self.assertRaises(pms.EvidenceError):
            pms.check_digest(b'corrupted binary payload', root=ROOT)

        with self.assertRaises(pms.EvidenceError):
            pms.load_expected_artifact(ROOT, 'artifacts/nonexistent/hl-node')

    def test_jump_table_constants(self):
        self.assertEqual(len(pms.MODES), 5)
        self.assertEqual(len(pms.JUMP_TABLE_BYTES), 20)
        for i in range(5):
            disp = struct.unpack_from('<i', pms.JUMP_TABLE_BYTES, i * 4)[0]
            self.assertEqual(disp, pms.MODES[i]['disp'])
            self.assertEqual(pms.JUMP_TABLE_VA + disp, pms.MODES[i]['target_va'])

    def test_mode_0_no_requirement(self):
        self.assertEqual(pms.compute_position_margin(10, 1000, 50, 50, 0), 0)
        self.assertEqual(pms.compute_position_margin(1_000_000, 50_000, 50, 20, 0), 0)

    def test_mode_1_simple_max_leverage(self):
        # notional = 10 * 1000 = 10000, max_leverage = 50 -> 10000 // 50 = 200
        self.assertEqual(pms.compute_position_margin(10, 1000, 50, 50, 1), 200)
        self.assertEqual(pms.compute_position_margin(10, 1000, 20, 50, 1), 500)

    def test_mode_2_initial_margin_50_cutoff(self):
        # < 50: built-in single tier, divisor = 2 * user_leverage
        # notional = 10000, user_leverage = 20 -> 10000 // (2 * 20) = 250
        self.assertEqual(pms.compute_position_margin(10, 1000, 50, 20, 2), 250)
        # user_leverage = 49 -> 10000 // 98 = 102
        self.assertEqual(pms.compute_position_margin(10, 1000, 50, 49, 2), 102)

        # >= 50: custom margin table lookup
        # user_leverage = 50, tier_leverage = 50, tier_prior = 0 -> 10000 // 100 = 100
        self.assertEqual(pms.compute_position_margin(10, 1000, 50, 50, 2, tier_leverage=50, tier_prior=0), 100)
        # user_leverage = 50, tier_leverage = 50, tier_prior = 40 -> 100 - 40 = 60
        self.assertEqual(pms.compute_position_margin(10, 1000, 50, 50, 2, tier_leverage=50, tier_prior=40), 60)
        # Underflow saturation at zero: prior > divided
        self.assertEqual(pms.compute_position_margin(10, 1000, 50, 50, 2, tier_leverage=50, tier_prior=200), 0)

    def test_mode_3_maintenance_margin_50_cutoff(self):
        # < 50: built-in single tier, formula: (2 * notional) // (6 * user_leverage)
        # notional = 10000, user_leverage = 20 -> 20000 // (6 * 20) = 20000 // 120 = 166
        self.assertEqual(pms.compute_position_margin(10, 1000, 50, 20, 3), 166)
        # user_leverage = 49 -> 20000 // (6 * 49) = 20000 // 294 = 68
        self.assertEqual(pms.compute_position_margin(10, 1000, 50, 49, 3), 68)

        # >= 50: custom margin table lookup
        # user_leverage = 50, tier_leverage = 50, tier_prior = 0 -> 20000 // 300 = 66
        self.assertEqual(pms.compute_position_margin(10, 1000, 50, 50, 3, tier_leverage=50, tier_prior=0), 66)
        # user_leverage = 50, tier_leverage = 50, tier_prior = 50 -> rhs = 4 * 50 * 50 = 10000 -> (20000 - 10000) // 300 = 33
        self.assertEqual(pms.compute_position_margin(10, 1000, 50, 50, 3, tier_leverage=50, tier_prior=50), 33)
        # Underflow saturation at zero: 4 * lev * prior > 2 * notional
        self.assertEqual(pms.compute_position_margin(10, 1000, 50, 50, 3, tier_leverage=50, tier_prior=200), 0)

    def test_mode_4_capped_leverage(self):
        # notional = 10000
        # max_leverage = 50, cap = 20 -> effective = min(50, 20) = 20 -> 10000 // 20 = 500
        self.assertEqual(pms.compute_position_margin(10, 1000, 50, 50, 4, cap_leverage=20), 500)
        # max_leverage = 10, cap = 20 -> effective = min(10, 20) = 10 -> 10000 // 10 = 1000
        self.assertEqual(pms.compute_position_margin(10, 1000, 10, 50, 4, cap_leverage=20), 1000)

    def test_overflow_and_error_branches(self):
        # Negative position size must be rejected
        with self.assertRaises(ValueError):
            pms.compute_position_margin(-1, 1000, 50, 50, 1)

        # Signed 64-bit multiplication overflow must be rejected
        with self.assertRaises(ValueError):
            pms.compute_position_margin(1 << 32, 1 << 32, 50, 50, 1)

        # Invalid margin mode
        with self.assertRaises(ValueError):
            pms.compute_position_margin(10, 1000, 50, 50, 5)

        with self.assertRaises(ValueError):
            pms.compute_position_margin(10, 1000, 50, 50, -1)


class PositionMarginBinaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT / pms.BINARY_REL).read_bytes()
        cls.result, cls.vectors = pms.analyse(cls.data, root=ROOT)

    def test_summary_metrics(self):
        summary = self.result['summary']
        self.assertTrue(summary['all_fde_bounds_verified'])
        self.assertTrue(summary['all_jump_table_entries_verified'])
        self.assertTrue(summary['all_instruction_controls_verified'])
        self.assertTrue(summary['all_panic_records_verified'])
        self.assertEqual(summary['fde_size'], 1349)
        self.assertEqual(summary['jump_table_entries'], 5)
        self.assertEqual(summary['controls_verified'], 16)
        self.assertEqual(summary['cutoff_threshold'], 50)
        self.assertEqual(summary['sample_vectors_verified'], len(self.vectors))

    def test_fde_bounds_and_sha256(self):
        fde = self.result['fde']
        self.assertEqual(fde['start'], '0x3717480')
        self.assertEqual(fde['end'], '0x37179c5')
        self.assertEqual(fde['size'], 1349)
        self.assertEqual(fde['sha256'], pms.FDE_SHA256)

    def test_jump_table_entries(self):
        entries = self.result['jump_table']['entries']
        self.assertEqual(len(entries), 5)
        targets = [e['target_va'] for e in entries]
        expected_targets = ['0x3717888', '0x37174cb', '0x371751f', '0x37175b6', '0x37174f0']
        self.assertEqual(targets, expected_targets)

    def test_negative_controls_jump_table_corruption(self):
        img = pms.Image(self.data)
        bad_data = bytearray(self.data)
        offset = img.off(pms.JUMP_TABLE_VA)
        bad_data[offset] ^= 0x01
        bad_img = pms.Image(bytes(bad_data))
        with self.assertRaises(pms.EvidenceError) as ctx:
            pms.verify_jump_table(bad_img)
        self.assertIn('jump table bytes mismatch', str(ctx.exception))

    def test_negative_controls_control_opcodes(self):
        img = pms.Image(self.data)
        # Corrupt Mode 2 threshold (0x3717524: cmp ebp, 0x32)
        bad_data = bytearray(self.data)
        offset = img.off(0x3717524)
        bad_data[offset + 2] = 0x64  # change 50 to 100
        bad_img = pms.Image(bytes(bad_data))
        with self.assertRaises(pms.EvidenceError) as ctx:
            pms.verify_controls(bad_img)
        self.assertIn('0x3717524', str(ctx.exception))

        # Corrupt Jump dispatch LEA (0x37174bb)
        bad_data2 = bytearray(self.data)
        offset2 = img.off(0x37174bb)
        bad_data2[offset2 + 1] ^= 0x01
        bad_img2 = pms.Image(bytes(bad_data2))
        with self.assertRaises(pms.EvidenceError) as ctx:
            pms.verify_controls(bad_img2)
        self.assertIn('0x37174bb', str(ctx.exception))

        # Corrupt Overflow branch opcode (0x37174a5: jo -> jno)
        bad_data3 = bytearray(self.data)
        offset3 = img.off(0x37174a5)
        bad_data3[offset3 + 1] ^= 0x01
        bad_img3 = pms.Image(bytes(bad_data3))
        with self.assertRaises(pms.EvidenceError) as ctx:
            pms.verify_controls(bad_img3)
        self.assertIn('0x37174a5', str(ctx.exception))

    def test_packet_generation(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            self.assertEqual(pms.main(['--out', str(tmp_path)]), 0)
            for fname in GENERATED:
                self.assertTrue((tmp_path / fname).is_file(), f'missing {fname}')

            # Validate MANIFEST.sha256
            manifest_lines = (tmp_path / 'MANIFEST.sha256').read_text().splitlines()
            for line in manifest_lines:
                if not line.strip():
                    continue
                expected_sha, fname = line.split('  ', 1)
                actual_sha = hashlib.sha256((tmp_path / fname).read_bytes()).hexdigest()
                self.assertEqual(actual_sha, expected_sha, f'manifest hash mismatch for {fname}')


if __name__ == '__main__':
    unittest.main()
