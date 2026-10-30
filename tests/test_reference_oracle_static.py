#!/usr/bin/env python3
"""Unit tests for RE-007 (Part 4): Reference Oracle Price Distance & Bounds static verification."""

import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import reference_oracle_static as ros

GENERATED = ['evidence.json', 'string_refs.tsv', 'panics.tsv', 'controls.tsv', 'vectors.tsv', 'MANIFEST.sha256']


class ReferenceOracleDecoderTests(unittest.TestCase):
    def test_digest_verification_against_artifacts_json(self):
        meta = ros.load_expected_artifact(ROOT, ros.BINARY_REL)
        self.assertEqual(meta['sha256'], ros.EXPECTED_SHA256)
        self.assertEqual(meta['size'], ros.EXPECTED_SIZE)

        with self.assertRaises(ros.EvidenceError):
            ros.check_digest(b'corrupted binary payload', root=ROOT)

        with self.assertRaises(ros.EvidenceError):
            ros.load_expected_artifact(ROOT, 'artifacts/nonexistent/hl-node')

    def test_reference_oracle_distance_math(self):
        # Exact match -> distance 0
        res = ros.check_reference_oracle_distance(100.0, 100.0, max_distance=0.01)
        self.assertEqual(res['status'], 'ok')
        self.assertAlmostEqual(res['distance'], 0.0)

        # 1% price rise (price 101, ref 100) -> distance = |101/100 - 1| = 0.01
        res = ros.check_reference_oracle_distance(101.0, 100.0, max_distance=0.01)
        self.assertEqual(res['status'], 'ok')
        self.assertAlmostEqual(res['distance'], 0.01)

        # 1% price drop (price 99, ref 100) -> distance = |99/100 - 1| = 0.01
        res = ros.check_reference_oracle_distance(99.0, 100.0, max_distance=0.01)
        self.assertEqual(res['status'], 'ok')
        self.assertAlmostEqual(res['distance'], 0.01)

    def test_tolerance_distance_thresholds(self):
        # Within max_distance 0.02
        res = ros.check_reference_oracle_distance(101.5, 100.0, max_distance=0.02)
        self.assertEqual(res['status'], 'ok')

        # Exceeds max_distance 0.02 -> raises EvidenceError ("Price moved too far...")
        with self.assertRaises(ros.EvidenceError) as ctx:
            ros.check_reference_oracle_distance(103.0, 100.0, max_distance=0.02)
        self.assertIn('Price moved too far from reference oracle', str(ctx.exception))

        # Exceeds max_distance but bypass is True -> succeeds with bypassed status
        res = ros.check_reference_oracle_distance(105.0, 100.0, max_distance=0.02, bypass=True)
        self.assertEqual(res['status'], 'ok')
        self.assertTrue(res['bypassed'])

    def test_missing_reference_oracle_and_exemptions(self):
        # Missing reference oracle for normal asset -> raises EvidenceError
        with self.assertRaises(ros.EvidenceError) as ctx:
            ros.check_reference_oracle_distance(100.0, None, max_distance=0.01, asset_id=0, perp_type=0)
        self.assertIn('Missing reference oracle', str(ctx.exception))

        # Missing reference oracle with bypass -> allowed
        res = ros.check_reference_oracle_distance(100.0, None, max_distance=0.01, bypass=True)
        self.assertEqual(res['status'], 'bypassed_missing')

        # perp_type == 3 exemptions: asset 152 and 159
        res152 = ros.check_reference_oracle_distance(100.0, None, max_distance=0.01, asset_id=152, perp_type=3)
        self.assertEqual(res152['status'], 'exempt_missing')
        res159 = ros.check_reference_oracle_distance(100.0, None, max_distance=0.01, asset_id=159, perp_type=3)
        self.assertEqual(res159['status'], 'exempt_missing')

        # perp_type != 3 exemptions: asset 125 and 135
        res125 = ros.check_reference_oracle_distance(100.0, None, max_distance=0.01, asset_id=125, perp_type=0)
        self.assertEqual(res125['status'], 'exempt_missing')
        res135 = ros.check_reference_oracle_distance(100.0, None, max_distance=0.01, asset_id=135, perp_type=1)
        self.assertEqual(res135['status'], 'exempt_missing')

        # Non-exempt assets raise error
        with self.assertRaises(ros.EvidenceError):
            ros.check_reference_oracle_distance(100.0, None, max_distance=0.01, asset_id=152, perp_type=0)
        with self.assertRaises(ros.EvidenceError):
            ros.check_reference_oracle_distance(100.0, None, max_distance=0.01, asset_id=125, perp_type=3)

    def test_negative_values_rejected(self):
        with self.assertRaises(ros.EvidenceError):
            ros.check_reference_oracle_distance(-100.0, 100.0, max_distance=0.01)
        with self.assertRaises(ros.EvidenceError):
            ros.check_reference_oracle_distance(100.0, -100.0, max_distance=0.01)


class ReferenceOracleBinaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bin_path = ROOT / ros.BINARY_REL
        if not cls.bin_path.exists():
            raise unittest.SkipTest(f'Binary {cls.bin_path} not found')
        cls.data = cls.bin_path.read_bytes()
        cls.result, cls.vectors = ros.analyse(cls.data, root=ROOT)

    def test_fde_bounds_and_sha256(self):
        fde = self.result['fde']
        self.assertEqual(fde['start'], hex(ros.FDE_START))
        self.assertEqual(fde['end'], hex(ros.FDE_END))
        self.assertEqual(fde['size'], ros.FDE_SIZE)
        self.assertEqual(fde['sha256'], ros.FDE_SHA256)

    def test_string_refs_in_rodata(self):
        srefs = self.result['string_references']
        self.assertIn(hex(0x58466d), srefs)
        self.assertEqual(srefs[hex(0x58466d)]['string'], 'Price moved too far from reference oracle')
        self.assertIn(hex(0x584655), srefs)
        self.assertEqual(srefs[hex(0x584655)]['string'], 'Missing reference oracle')

    def test_panic_records(self):
        panics = self.result['panic_records']
        self.assertEqual(len(panics), 3)

        p1 = panics[hex(0x56df7b0)]
        self.assertEqual(p1['file'], '/home/ubuntu/hl/code_Mainnet/l1/src/clearinghouse/oracle/oracle.rs')
        self.assertEqual(p1['line'], 627)
        self.assertEqual(p1['col'], 35)

        p2 = panics[hex(0x56f21c0)]
        self.assertEqual(p2['file'], '/home/ubuntu/hl/code_Mainnet/l1/src/perp_meta.rs')
        self.assertEqual(p2['line'], 194)
        self.assertEqual(p2['col'], 38)

        p3 = panics[hex(0x56f3350)]
        self.assertEqual(p3['file'], '/home/ubuntu/hl/code_Mainnet/l1/src/perp_meta.rs')
        self.assertEqual(p3['line'], 319)
        self.assertEqual(p3['col'], 28)

    def test_control_opcodes(self):
        controls = self.result['fde']['controls']
        self.assertEqual(len(controls), 12)
        for va, op in ros.CONTROLS.items():
            self.assertIn(hex(va), controls)
            self.assertEqual(controls[hex(va)], op)

    def test_summary_metrics(self):
        summary = self.result['summary']
        self.assertTrue(summary['all_fde_bounds_verified'])
        self.assertTrue(summary['all_panic_records_verified'])
        self.assertEqual(summary['fde_size'], 650)
        self.assertEqual(summary['controls_verified'], 12)
        self.assertEqual(summary['string_refs_verified'], 2)
        self.assertEqual(summary['panic_records_count'], 3)
        self.assertGreater(summary['sample_vectors_verified'], 200)

    def test_negative_controls_opcode_mutation(self):
        img = ros.Image(self.data)
        va = 0x32612fe
        original = ros.CONTROLS[va]
        try:
            ros.CONTROLS[va] = '90909090'
            with self.assertRaises(ros.EvidenceError):
                ros.verify_controls(img, ros.CONTROLS)
        finally:
            ros.CONTROLS[va] = original

    def test_negative_controls_string_ref_mutation(self):
        img = ros.Image(self.data)
        original = ros.STRING_REFS[0x58466d]['expected']
        try:
            ros.STRING_REFS[0x58466d]['expected'] = 'Tampered string'
            with self.assertRaises(ros.EvidenceError):
                ros.verify_string_refs(img)
        finally:
            ros.STRING_REFS[0x58466d]['expected'] = original

    def test_packet_generation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir)
            ros.write(out, self.result, self.vectors)

            for fname in GENERATED:
                self.assertTrue((out / fname).exists(), f'Missing generated file {fname}')

            manifest = (out / 'MANIFEST.sha256').read_text(encoding='utf-8')
            for line in manifest.strip().splitlines():
                digest, name = line.split()
                p = out / name
                self.assertEqual(hashlib.sha256(p.read_bytes()).hexdigest(), digest)


if __name__ == '__main__':
    unittest.main()
