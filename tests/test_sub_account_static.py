"""Unit tests for Node #94 sub-account static analysis tool."""

import hashlib
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

from sub_account_static import (
    BINARY_REL,
    CONTROLS,
    DISPLAY_USD_DIVISOR,
    ERR_FULL_NAME_TOO_LONG,
    ERR_SUB_ACCOUNT_INVALID_NAME,
    ERR_SUB_ACCOUNTS_NOT_ELIGIBLE,
    ERR_TOO_MANY_SUB_ACCOUNTS,
    EXPECTED_SHA256,
    EXPECTED_SIZE,
    EvidenceError,
    FDES,
    Image,
    MAX_NAME_BYTES,
    MAX_WIRE_NAME_BYTES,
    MIN_CREATE_EQUITY_RAW,
    PACKET,
    PANIC_LOCATIONS,
    RODATA_CONSTANTS,
    SUB_ACCOUNT_CAP_BASE,
    SUB_ACCOUNT_CAP_EQUITY_STEP_RAW,
    SUB_ACCOUNT_CAP_MAX_BONUS,
    SUCCESS_CODE,
    analyse,
    check_digest,
    generate_packet,
    max_sub_accounts_for_equity,
    validate_create_eligibility,
    validate_sub_account_name,
)


class SubAccountStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary_path = ROOT / BINARY_REL
        cls.data = check_digest(cls.binary_path)

    def test_binary_digest(self):
        self.assertEqual(len(self.data), EXPECTED_SIZE)
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), EXPECTED_SHA256)

    def test_fde_extents_and_digests(self):
        image = Image(self.data)
        total_bytes = 0
        self.assertEqual(len(FDES), 11)
        for fde in FDES:
            chunk = image.read(fde['start'], fde['size'])
            total_bytes += fde['size']
            digest = hashlib.sha256(chunk).hexdigest()
            self.assertEqual(
                digest,
                fde['sha256'],
                f"Digest mismatch in FDE {fde['name']} ({hex(fde['start'])}..{hex(fde['end'])})"
            )
        self.assertEqual(total_bytes, 6992)

    def test_panic_records(self):
        image = Image(self.data)
        for p in PANIC_LOCATIONS:
            rec = image.read(p['record_vaddr'], 24)
            import struct
            ptr, length, line, col = struct.unpack_from('<QQII', rec, 0)
            self.assertEqual(line, p['line'])
            self.assertEqual(col, p['col'])

    def test_rodata_constants(self):
        image = Image(self.data)
        for r in RODATA_CONSTANTS:
            raw = image.read(r['vaddr'], r['length'])
            if 'expected_ascii' in r:
                self.assertEqual(raw.decode('ascii'), r['expected_ascii'])
            elif 'expected_double' in r:
                import struct
                val = struct.unpack('<d', raw)[0]
                self.assertEqual(val, r['expected_double'])

    def test_controls(self):
        image = Image(self.data)
        for ctrl in CONTROLS:
            expected = bytes.fromhex(ctrl['hex_bytes'])
            actual = image.read(ctrl['vaddr'], len(expected))
            self.assertEqual(actual, expected, f"Control mismatch at {hex(ctrl['vaddr'])}: {ctrl['desc']}")

    def test_negative_control_mutation(self):
        ctrl = CONTROLS[0]
        image = Image(self.data)
        off = image.off(ctrl['vaddr'])
        mutated = bytearray(self.data)
        mutated[off] ^= 0xff
        with self.assertRaises(EvidenceError):
            analyse(bytes(mutated))

    def test_capacity_model(self):
        # 0 equity -> base 10
        self.assertEqual(max_sub_accounts_for_equity(0), 10)
        # Below step -> base 10
        self.assertEqual(max_sub_accounts_for_equity(9_999_999_999), 10)
        # 1 step (10B) -> 11
        self.assertEqual(max_sub_accounts_for_equity(10_000_000_000), 11)
        # 2 steps (20B) -> 12
        self.assertEqual(max_sub_accounts_for_equity(20_000_000_000), 12)
        # 40 steps (400B) -> 50 (max bonus = 40 + base 10)
        self.assertEqual(max_sub_accounts_for_equity(400_000_000_000), 50)
        # > 40 steps (1T) -> clamped to 50
        self.assertEqual(max_sub_accounts_for_equity(1_000_000_000_000), 50)

    def test_eligibility_validation(self):
        # Ineligible if equity < 10M
        self.assertEqual(
            validate_create_eligibility(count=0, equity_raw=MIN_CREATE_EQUITY_RAW - 1),
            ERR_SUB_ACCOUNTS_NOT_ELIGIBLE,
        )
        # Eligible at 10M with count < 10
        self.assertEqual(
            validate_create_eligibility(count=0, equity_raw=MIN_CREATE_EQUITY_RAW),
            SUCCESS_CODE,
        )
        self.assertEqual(
            validate_create_eligibility(count=9, equity_raw=MIN_CREATE_EQUITY_RAW),
            SUCCESS_CODE,
        )
        # At capacity 10 with 10M -> TooManySubAccounts
        self.assertEqual(
            validate_create_eligibility(count=10, equity_raw=MIN_CREATE_EQUITY_RAW),
            ERR_TOO_MANY_SUB_ACCOUNTS,
        )
        # At 10B equity, capacity is 11, count 10 is eligible
        self.assertEqual(
            validate_create_eligibility(count=10, equity_raw=10_000_000_000),
            SUCCESS_CODE,
        )
        self.assertEqual(
            validate_create_eligibility(count=11, equity_raw=10_000_000_000),
            ERR_TOO_MANY_SUB_ACCOUNTS,
        )

    def test_name_validation(self):
        # Empty name is invalid
        self.assertEqual(validate_sub_account_name(''), ERR_SUB_ACCOUNT_INVALID_NAME)
        # 1 char valid
        self.assertEqual(validate_sub_account_name('a'), SUCCESS_CODE)
        # 16 chars valid
        self.assertEqual(validate_sub_account_name('a' * 16), SUCCESS_CODE)
        # 17 chars invalid
        self.assertEqual(validate_sub_account_name('a' * 17), ERR_SUB_ACCOUNT_INVALID_NAME)

    def test_manifest_verification(self):
        manifest_path = PACKET / 'MANIFEST.sha256'
        self.assertTrue(manifest_path.is_file(), 'MANIFEST.sha256 missing')
        lines = manifest_path.read_text(encoding='utf-8').strip().split('\n')
        self.assertGreater(len(lines), 0)
        for line in lines:
            if not line.strip():
                continue
            expected_sha, rel_path = line.split(maxsplit=1)
            file_path = PACKET / rel_path
            self.assertTrue(file_path.is_file(), f'File missing: {file_path}')
            actual_sha = hashlib.sha256(file_path.read_bytes()).hexdigest()
            self.assertEqual(actual_sha, expected_sha, f'Hash mismatch on {rel_path}')

    def test_packet_regeneration(self):
        generate_packet(self.data)
        manifest_path = PACKET / 'MANIFEST.sha256'
        lines = manifest_path.read_text(encoding='utf-8').strip().split('\n')
        for line in lines:
            if not line.strip():
                continue
            expected_sha, rel_path = line.split(maxsplit=1)
            file_path = PACKET / rel_path
            actual_sha = hashlib.sha256(file_path.read_bytes()).hexdigest()
            self.assertEqual(actual_sha, expected_sha, f'Hash mismatch after regeneration on {rel_path}')


if __name__ == '__main__':
    unittest.main()
