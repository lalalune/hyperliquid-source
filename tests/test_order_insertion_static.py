#!/usr/bin/env python3
"""Unit tests for RE-006: Order Book Transition and Resting Order Insertion static verification."""

import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import order_insertion_static as ois

GENERATED = ['evidence.json', 'status_codes.tsv', 'panics.tsv', 'controls.tsv', 'vectors.tsv', 'MANIFEST.sha256']


class OrderInsertionDecoderTests(unittest.TestCase):
    def test_digest_verification_against_artifacts_json(self):
        meta = ois.load_expected_artifact(ROOT, ois.BINARY_REL)
        self.assertEqual(meta['sha256'], ois.EXPECTED_SHA256)
        self.assertEqual(meta['size'], ois.EXPECTED_SIZE)

        with self.assertRaises(ois.EvidenceError):
            ois.check_digest(b'corrupted binary payload', root=ROOT)

        with self.assertRaises(ois.EvidenceError):
            ois.load_expected_artifact(ROOT, 'artifacts/nonexistent/hl-node')

    def test_signed_price_key_derivation(self):
        # Buy orders must produce negative price key (best bid first in ascending BTreeMap)
        self.assertEqual(ois.derive_signed_price_key(100, is_buy=True), -100)
        self.assertEqual(ois.derive_signed_price_key(50_000, is_buy=True), -50_000)
        self.assertEqual(ois.derive_signed_price_key(ois.MAX_LIMIT_PX, is_buy=True), -ois.MAX_LIMIT_PX)

        # Sell orders must produce positive price key (best ask first in ascending BTreeMap)
        self.assertEqual(ois.derive_signed_price_key(100, is_buy=False), 100)
        self.assertEqual(ois.derive_signed_price_key(50_000, is_buy=False), 50_000)
        self.assertEqual(ois.derive_signed_price_key(ois.MAX_LIMIT_PX, is_buy=False), ois.MAX_LIMIT_PX)

        # Negative price rejected
        with self.assertRaises(ois.EvidenceError):
            ois.derive_signed_price_key(-100, is_buy=True)

    def test_min_notional_floor(self):
        # Floor is 0x0098967f = 9,999,999 ticks ($10 minus 1 tick at 6 decimals)
        self.assertEqual(ois.MIN_NOTIONAL_FLOOR, 0x0098967f)
        self.assertEqual(ois.MIN_NOTIONAL_FLOOR, 9_999_999)

        # 9,999,999 or less rejected with STATUS_NOTIONAL (0x8000000000000001)
        res_fail1 = ois.validate_order_insertion(px=1, sz=9_999_999, is_buy=True)
        self.assertEqual(res_fail1['status'], 'error')
        self.assertEqual(res_fail1['status_code'], 0x8000000000000001)

        res_fail2 = ois.validate_order_insertion(px=1000, sz=9999, is_buy=True)
        self.assertEqual(res_fail2['status'], 'error')
        self.assertEqual(res_fail2['status_code'], 0x8000000000000001)

        # Exactly 10,000,000 ticks accepted with STATUS_OK (0x8000000000000018)
        res_ok = ois.validate_order_insertion(px=1, sz=10_000_000, is_buy=True)
        self.assertEqual(res_ok['status'], 'ok')
        self.assertEqual(res_ok['status_code'], 0x8000000000000018)
        self.assertEqual(res_ok['signed_price_key'], -1)

        # Allowed sub-min notional (e.g. liquidation or IOC fill)
        res_sub = ois.validate_order_insertion(px=1, sz=100, is_buy=True, allow_sub_min_notional=True)
        self.assertEqual(res_sub['status'], 'ok')

    def test_max_limit_px_ceiling(self):
        self.assertEqual(ois.MAX_LIMIT_PX, 1_000_000_000_000_000)

        # Price at ceiling is accepted
        res_ok = ois.validate_order_insertion(px=ois.MAX_LIMIT_PX, sz=1, is_buy=False, allow_sub_min_notional=True)
        self.assertEqual(res_ok['status'], 'ok')
        self.assertEqual(res_ok['signed_price_key'], ois.MAX_LIMIT_PX)

        # Price exceeding ceiling is rejected with STATUS_PRICE_OR_TICK (0x8000000000000000)
        res_fail = ois.validate_order_insertion(px=ois.MAX_LIMIT_PX + 1, sz=1, is_buy=False, allow_sub_min_notional=True)
        self.assertEqual(res_fail['status'], 'error')
        self.assertEqual(res_fail['status_code'], 0x8000000000000000)

    def test_invalid_price_and_size(self):
        res_px0 = ois.validate_order_insertion(px=0, sz=1000, is_buy=True)
        self.assertEqual(res_px0['status'], 'error')
        self.assertEqual(res_px0['status_code'], 0x8000000000000000)

        res_sz0 = ois.validate_order_insertion(px=1000, sz=0, is_buy=True)
        self.assertEqual(res_sz0['status'], 'error')
        self.assertEqual(res_sz0['status_code'], 0x8000000000000005)


class OrderInsertionBinaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bin_path = ROOT / ois.BINARY_REL
        if not cls.bin_path.exists():
            raise unittest.SkipTest(f'Binary {cls.bin_path} not found')
        cls.data = cls.bin_path.read_bytes()
        cls.result, cls.vectors = ois.analyse(cls.data, root=ROOT)

    def test_fde_bounds_and_sha256(self):
        fde = self.result['fde']
        self.assertEqual(fde['start'], hex(ois.FDE_START))
        self.assertEqual(fde['end'], hex(ois.FDE_END))
        self.assertEqual(fde['size'], ois.FDE_SIZE)
        self.assertEqual(fde['sha256'], ois.FDE_SHA256)

    def test_panic_records(self):
        panics = self.result['panic_records']
        self.assertEqual(len(panics), 4)

        expected_locs = {
            hex(0x56bd8b8): (167, 17),
            hex(0x56bd888): (445, 56),
            hex(0x56bd858): (514, 43),
            hex(0x56bd870): (517, 59),
        }
        for va, (line, col) in expected_locs.items():
            self.assertIn(va, panics)
            p = panics[va]
            self.assertEqual(p['file'], '/home/ubuntu/hl/code_Mainnet/l1/src/book/book/impl_insert_order.rs')
            self.assertEqual(p['line'], line)
            self.assertEqual(p['col'], col)

    def test_control_opcodes(self):
        controls = self.result['fde']['controls']
        self.assertEqual(len(controls), 8)
        for va, op in ois.CONTROLS.items():
            self.assertIn(hex(va), controls)
            self.assertEqual(controls[hex(va)], op)

    def test_summary_metrics(self):
        summary = self.result['summary']
        self.assertTrue(summary['all_fde_bounds_verified'])
        self.assertTrue(summary['all_panic_records_verified'])
        self.assertEqual(summary['fde_size'], 16720)
        self.assertEqual(summary['controls_verified'], 8)
        self.assertEqual(summary['panic_records_count'], 4)
        self.assertEqual(summary['min_notional_floor'], 9_999_999)
        self.assertEqual(summary['max_limit_px'], 10**15)

    def test_negative_controls_opcode_mutation(self):
        img = ois.Image(self.data)
        va = 0x26ec53d
        original = ois.CONTROLS[va]
        try:
            ois.CONTROLS[va] = '90909090'
            with self.assertRaises(ois.EvidenceError):
                ois.verify_controls(img, ois.CONTROLS)
        finally:
            ois.CONTROLS[va] = original

    def test_negative_controls_panic_mutation(self):
        img = ois.Image(self.data)
        va = 0x56bd8b8
        original_line = ois.PANIC_RECORDS[va]['line']
        try:
            ois.PANIC_RECORDS[va]['line'] = 9999
            with self.assertRaises(ois.EvidenceError):
                ois.verify_panic_records(self.data, img)
        finally:
            ois.PANIC_RECORDS[va]['line'] = original_line

    def test_packet_generation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir)
            ois.write(out, self.result, self.vectors)

            for fname in GENERATED:
                self.assertTrue((out / fname).exists(), f'Missing generated file {fname}')

            manifest = (out / 'MANIFEST.sha256').read_text(encoding='utf-8')
            for line in manifest.strip().splitlines():
                digest, name = line.split()
                p = out / name
                self.assertEqual(hashlib.sha256(p.read_bytes()).hexdigest(), digest)


if __name__ == '__main__':
    unittest.main()
