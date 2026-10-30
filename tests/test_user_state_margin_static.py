import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import user_state_margin_static as usms

GENERATED = ['evidence.json', 'vectors.tsv', 'MANIFEST.sha256']


class UserStateMarginDecoderTests(unittest.TestCase):
    def test_digest_verification_against_artifacts_json(self):
        item = usms.load_expected_artifact(ROOT, usms.BINARY_REL)
        self.assertEqual(item['sha256'], usms.EXPECTED_SHA256)
        self.assertEqual(item['size'], usms.EXPECTED_SIZE)

        with self.assertRaises(usms.EvidenceError):
            usms.check_digest(b'corrupted binary payload', root=ROOT)

        with self.assertRaises(usms.EvidenceError):
            usms.load_expected_artifact(ROOT, 'artifacts/nonexistent/hl-node')

    def test_reciprocal_modulo_arithmetic(self):
        # Verify the fast reciprocal algorithm implemented in binary:
        # movabs rsi, 0x346dc5d63886594b; mul rsi; shr rdx, 0xb; imul rax, rdx, 0x2710; sub rdi, rax
        RECIPROCAL = 0x346dc5d63886594b

        def fast_mod_10000(asset: int) -> int:
            prod = asset * RECIPROCAL
            high = prod >> 64
            quot = high >> 11
            return asset - (quot * 10000)

        test_assets = [0, 1, 9999, 10000, 10001, 20000, 25432, 99999, 1234567, 10_000_000]
        for a in test_assets:
            self.assertEqual(fast_mod_10000(a), a % 10000)

    def test_saturating_arithmetic(self):
        I64_MAX = (1 << 63) - 1
        I64_MIN = -(1 << 63)

        self.assertEqual(usms.saturating_sub(100, 40), 60)
        self.assertEqual(usms.saturating_sub(40, 100), -60)
        self.assertEqual(usms.saturating_sub(I64_MAX, 1), I64_MAX - 1)
        self.assertEqual(usms.saturating_sub(I64_MIN, -1), I64_MIN + 1)

        # Underflow / overflow clamping
        self.assertEqual(usms.saturating_sub(I64_MIN, 10), I64_MIN)
        self.assertEqual(usms.saturating_sub(I64_MAX, -10), I64_MAX)
        self.assertEqual(usms.saturating_sub(-1 << 62, 1 << 62), I64_MIN)

    def test_margin_delta_and_aggregation(self):
        # Scenario 1: Cross surplus (+5000), 2 isolated positions (one surplus, one deficit)
        cross_eq = 15000
        cross_req = 10000
        iso_positions = [
            {'asset': 1, 'margin_raw': 5000, 'requirement': 2000},  # surplus +3000
            {'asset': 2, 'margin_raw': 1000, 'requirement': 3000},  # deficit -2000
        ]
        deficits = usms.aggregate_position_margin_summary(cross_eq, cross_req, iso_positions)
        self.assertEqual(len(deficits), 1)
        self.assertEqual(deficits[0]['tag'], 1)
        self.assertEqual(deficits[0]['asset'], 2)
        self.assertEqual(deficits[0]['amount'], -2000)

        # Scenario 2: Cross deficit (-2000) and isolated deficit (-1000)
        cross_eq = 8000
        cross_req = 10000
        iso_positions = [
            {'asset': 5, 'margin_raw': 500, 'requirement': 1500},
        ]
        deficits = usms.aggregate_position_margin_summary(cross_eq, cross_req, iso_positions)
        self.assertEqual(len(deficits), 2)
        self.assertEqual(deficits[0]['tag'], 0)
        self.assertEqual(deficits[0]['type'], 'CrossDeficit')
        self.assertEqual(deficits[0]['amount'], -2000)
        self.assertEqual(deficits[1]['tag'], 1)
        self.assertEqual(deficits[1]['asset'], 5)
        self.assertEqual(deficits[1]['amount'], -1000)

        # Scenario 3: All healthy (0 deficits)
        deficits = usms.aggregate_position_margin_summary(10000, 5000, [
            {'asset': 1, 'margin_raw': 1000, 'requirement': 500}
        ])
        self.assertEqual(len(deficits), 0)


class UserStateMarginBinaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT / usms.BINARY_REL).read_bytes()
        cls.result, cls.vectors = usms.analyse(cls.data, root=ROOT)

    def test_summary_metrics(self):
        summary = self.result['summary']
        self.assertTrue(summary['all_fde_bounds_verified'])
        self.assertTrue(summary['all_instruction_controls_verified'])
        self.assertTrue(summary['all_relocations_verified'])
        self.assertTrue(summary['all_panic_records_verified'])
        self.assertEqual(summary['fdes_verified'], 2)
        self.assertEqual(summary['controls_verified'], 9)
        self.assertEqual(summary['relocations_verified'], 4)
        self.assertEqual(summary['panic_records_verified'], 6)
        self.assertEqual(summary['assets_per_dex'], 10000)
        self.assertEqual(summary['sample_vectors_verified'], len(self.vectors))

    def test_fde_bounds_and_sha256(self):
        fdes = self.result['fdes']
        self.assertIn('aggregate_position_margin_summary', fdes)
        self.assertIn('margin_delta_for_asset', fdes)

        agg = fdes['aggregate_position_margin_summary']
        self.assertEqual(agg['start'], '0x37d7360')
        self.assertEqual(agg['end'], '0x37d77d8')
        self.assertEqual(agg['size'], 1144)
        self.assertEqual(agg['sha256'], usms.FDES['aggregate_position_margin_summary']['sha256'])

        delta = fdes['margin_delta_for_asset']
        self.assertEqual(delta['start'], '0x37d77e0')
        self.assertEqual(delta['end'], '0x37d79e0')
        self.assertEqual(delta['size'], 512)
        self.assertEqual(delta['sha256'], usms.FDES['margin_delta_for_asset']['sha256'])

    def test_relocations(self):
        relocs = self.result['relocations']
        for slot_va, expected_target in usms.RELOCATIONS.items():
            self.assertEqual(relocs[hex(slot_va)], hex(expected_target))

    def test_panic_records(self):
        records = self.result['panic_records']
        for va, spec in usms.PANIC_RECORDS.items():
            self.assertEqual(records[hex(va)]['file'], spec['file'])
            self.assertEqual(records[hex(va)]['line'], spec['line'])
            self.assertEqual(records[hex(va)]['col'], spec['col'])

    def test_negative_controls_control_opcodes(self):
        img = usms.Image(self.data)
        bad_data = bytearray(self.data)
        target_va = 0x37d77f8
        offset = img.off(target_va)
        bad_data[offset] ^= 0x01
        bad_img = usms.Image(bytes(bad_data))
        with self.assertRaises(usms.EvidenceError) as ctx:
            usms.verify_controls(bad_img)
        self.assertIn('control opcode mismatch', str(ctx.exception))

    def test_packet_generation(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_path = Path(tmp_dir)
            usms.write(out_path, self.result, self.vectors)
            for fname in GENERATED:
                self.assertTrue((out_path / fname).is_file())

            evidence = json.loads((out_path / 'evidence.json').read_text())
            self.assertTrue(evidence['summary']['all_fde_bounds_verified'])


if __name__ == '__main__':
    unittest.main()
