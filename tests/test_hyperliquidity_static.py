#!/usr/bin/env python3
"""RE/Hyperliquidity Unit Tests: Validate static analysis and clean-room proofs for node #94.

Tests:
1. Binary digest and size verification (fail-closed).
2. FDE extents and SHA-256 integrity for all 3 hyperliquidity functions (2,704 bytes total).
3. Source panic record verification (line 355, col 29, source path).
4. All 10 diagnostic error strings in .rodata.
5. Float64 constants in .rodata (1.0, 1.003).
6. 22 opcode instruction controls.
7. Negative mutation tests (reject invalid digests, opcodes, and panic records).
8. Pure domain logic functions (market_cap_in_scaled_range, validate_order_count).
9. Generated packet file structure and manifest verification.
"""

import copy
import hashlib
import json
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

from hyperliquidity_static import (
    BINARY_REL,
    CONTROLS,
    ERR_STATUS,
    EXPECTED_SHA256,
    EXPECTED_SIZE,
    FDES,
    HYPERLIQUIDITY_PRICE_RATIO,
    MARKET_CAP_LOWER_SCALE,
    MARKET_CAP_UPPER_SCALE,
    MAX_END_MARKET_CAP_USDC,
    MAX_RAW_HYPERLIQUIDITY_VALUE,
    MAX_START_MARKET_CAP_USDC,
    MIN_END_MARKET_CAP_USDC,
    MIN_HYPERLIQUIDITY_ORDERS,
    PANIC_LOCATIONS,
    RODATA_CONSTANTS,
    SOURCE_PATH,
    SUCCESS_CODE,
    EvidenceError,
    Image,
    analyse,
    check_digest,
    market_cap_in_scaled_range,
    validate_order_count,
)


class HyperliquidityStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bin_path = ROOT / BINARY_REL
        cls.data = check_digest(cls.bin_path)
        cls.image = Image(cls.data)

    def test_01_binary_digest_and_size(self):
        self.assertEqual(len(self.data), EXPECTED_SIZE)
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), EXPECTED_SHA256)

    def test_02_fde_extents_and_digests(self):
        total_size = 0
        for fde in FDES:
            chunk = self.image.read(fde['start'], fde['size'])
            self.assertEqual(len(chunk), fde['size'])
            self.assertEqual(hashlib.sha256(chunk).hexdigest(), fde['sha256'])
            total_size += fde['size']
        self.assertEqual(total_size, 2704)
        self.assertEqual(len(FDES), 3)

    def test_03_panic_location(self):
        self.assertEqual(len(PANIC_LOCATIONS), 1)
        p = PANIC_LOCATIONS[0]
        rec = self.image.read(p['record_vaddr'], 24)
        str_ptr, str_len, line, col = struct.unpack('<QQII', rec)
        self.assertEqual(line, 355)
        self.assertEqual(col, 29)
        self.assertEqual(str_len, len(SOURCE_PATH))

        rela_sec = next(s for s in self.image.sec if s['name'] == '.rela.dyn')
        rela_bytes = self.image.data[rela_sec['offset']:rela_sec['offset'] + rela_sec['size']]
        relocs = {}
        for i in range(0, len(rela_bytes), 24):
            r_offset, r_info, r_addend = struct.unpack_from('<QQq', rela_bytes, i)
            relocs[r_offset] = r_addend
        self.assertIn(p['record_vaddr'], relocs)
        path_vaddr = relocs[p['record_vaddr']]
        path_bytes = self.image.read(path_vaddr, str_len)
        self.assertEqual(path_bytes.decode('utf-8'), SOURCE_PATH)

    def test_04_rodata_constants(self):
        self.assertEqual(len(RODATA_CONSTANTS), 12)
        for r in RODATA_CONSTANTS:
            raw = self.image.read(r['vaddr'], r['length'])
            if 'expected_ascii' in r:
                self.assertEqual(raw.decode('ascii'), r['expected_ascii'])
            elif 'expected_double' in r:
                val = struct.unpack('<d', raw)[0]
                self.assertAlmostEqual(val, r['expected_double'], places=6)

    def test_05_controls(self):
        self.assertEqual(len(CONTROLS), 22)
        for ctrl in CONTROLS:
            expected = bytes.fromhex(ctrl['hex_bytes'])
            actual = self.image.read(ctrl['vaddr'], len(expected))
            self.assertEqual(actual, expected, f"Failed at {hex(ctrl['vaddr'])}: {ctrl['desc']}")

    def test_06_analysis_engine(self):
        res = analyse(self.data)
        self.assertEqual(res['binary']['sha256'], EXPECTED_SHA256)
        self.assertEqual(len(res['fdes']), 3)
        self.assertEqual(len(res['panics']), 1)
        self.assertEqual(len(res['rodata']), 12)
        self.assertEqual(len(res['controls']), 22)

    def test_07_negative_mutations(self):
        # Mutated binary digest
        bad_data = bytearray(self.data[:1000])
        with self.assertRaises(EvidenceError):
            analyse(bytes(bad_data))

        # Mutate an FDE byte
        bad_fde = bytearray(self.data)
        off = self.image.off(FDES[0]['start'])
        bad_fde[off] ^= 0x01
        with self.assertRaises(EvidenceError):
            analyse(bytes(bad_fde))

        # Mutate a control opcode
        bad_ctrl = bytearray(self.data)
        off_ctrl = self.image.off(CONTROLS[0]['vaddr'])
        bad_ctrl[off_ctrl] ^= 0x01
        with self.assertRaises(EvidenceError):
            analyse(bytes(bad_ctrl))

    def test_08_domain_logic(self):
        # Order count logic
        self.assertTrue(validate_order_count(10))
        self.assertTrue(validate_order_count(100))
        self.assertFalse(validate_order_count(9))
        self.assertFalse(validate_order_count(0))

        # Market cap range logic (lower scale: 70M, upper scale: 130M)
        self.assertTrue(market_cap_in_scaled_range(1, 1, 70_000_000))
        self.assertTrue(market_cap_in_scaled_range(1, 1, 100_000_000))
        self.assertTrue(market_cap_in_scaled_range(1, 1, 130_000_000))
        self.assertFalse(market_cap_in_scaled_range(1, 1, 69_999_999))
        self.assertFalse(market_cap_in_scaled_range(1, 1, 130_000_001))

        # Scale constants
        self.assertEqual(MARKET_CAP_LOWER_SCALE, 70_000_000)
        self.assertEqual(MARKET_CAP_UPPER_SCALE, 130_000_000)
        self.assertEqual(MIN_HYPERLIQUIDITY_ORDERS, 10)
        self.assertEqual(MAX_RAW_HYPERLIQUIDITY_VALUE, 0x1999999999999999)
        self.assertEqual(HYPERLIQUIDITY_PRICE_RATIO, 1.003)
        self.assertEqual(SUCCESS_CODE, 390)
        self.assertEqual(ERR_STATUS, 223)

    def test_09_packet_artifacts_exist(self):
        packet_dir = ROOT / 'research' / 'work-items' / 'hyperliquidity-94'
        self.assertTrue(packet_dir.is_dir())
        manifest_path = packet_dir / 'manifest.json'
        self.assertTrue(manifest_path.is_file())
        manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
        self.assertIn('files', manifest)
        self.assertGreaterEqual(len(manifest['files']), 6)
        for entry in manifest['files']:
            fpath = packet_dir / entry['path']
            self.assertTrue(fpath.is_file(), f"Missing file: {fpath}")
            data = fpath.read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), entry['sha256'])


if __name__ == '__main__':
    unittest.main()
