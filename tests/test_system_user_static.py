#!/usr/bin/env python3
"""RE/SystemUser Unit Tests: Validate static analysis and clean-room proofs for node #94.

Tests:
1. Binary digest and size verification (fail-closed).
2. FDE extents and SHA-256 integrity for all 3 system user routines (8,110 bytes total).
3. Source panic record verification (line 3, col 23, source path via .rela.dyn).
4. Privileged system user 20-entry table verification (indices 7..=26, non-numeric order).
5. Reserved address constants in .rodata.
6. 24 opcode instruction controls.
7. Negative mutation tests (reject invalid digests, opcodes, and table entries).
8. Pure domain logic simulation (SystemUserIndexIter, privilege check, bitmask).
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

from system_user_static import (
    BINARY_REL,
    CONTROLS,
    EXPECTED_SHA256,
    EXPECTED_SIZE,
    FDES,
    FIRST_PRIVILEGED_SYSTEM_USER_INDEX,
    LAST_PRIVILEGED_SYSTEM_USER_INDEX,
    NUM_SYSTEM_USERS,
    PANIC_LOCATIONS,
    PRIVILEGED_SYSTEM_USER_BITMASK,
    PRIVILEGED_SYSTEM_USER_COUNT,
    PRIVILEGED_SYSTEM_USERS_TABLE_LEN,
    PRIVILEGED_SYSTEM_USERS_TABLE_VADDR,
    RODATA_CONSTANTS,
    SOURCE_PATH,
    SYSTEM_USER_END_SENTINEL,
    EvidenceError,
    Image,
    SystemUserIndexIter,
    analyse,
    check_digest,
    is_privileged_system_index,
)


class SystemUserStaticTests(unittest.TestCase):
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
        self.assertEqual(total_size, 8110)
        self.assertEqual(len(FDES), 3)

    def test_03_panic_location(self):
        self.assertEqual(len(PANIC_LOCATIONS), 1)
        p = PANIC_LOCATIONS[0]
        rec = self.image.read(p['record_vaddr'], 24)
        str_ptr, str_len, line, col = struct.unpack('<QQII', rec)
        self.assertEqual(line, 3)
        self.assertEqual(col, 23)
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

    def test_04_privileged_users_table(self):
        table_raw = self.image.read(PRIVILEGED_SYSTEM_USERS_TABLE_VADDR, PRIVILEGED_SYSTEM_USERS_TABLE_LEN)
        expected_addrs = [
            0x0800, 0x0813, 0x0801, 0x0802, 0x0803, 0x0804, 0x0805, 0x0806, 0x0807, 0x0808,
            0x0809, 0x080a, 0x080b, 0x080c, 0x080d, 0x080e, 0x080f, 0x0810, 0x0811, 0x0812
        ]
        self.assertEqual(len(expected_addrs), PRIVILEGED_SYSTEM_USER_COUNT)
        for i, val in enumerate(expected_addrs):
            entry = table_raw[i*24 : i*24 + 20]
            exp = (b'\x00' * 18) + val.to_bytes(2, 'big')
            self.assertEqual(entry, exp, f"Mismatch at table index {i}")

    def test_05_rodata_constants(self):
        self.assertEqual(len(RODATA_CONSTANTS), 11)
        for r in RODATA_CONSTANTS:
            raw = self.image.read(r['vaddr'], r['length'])
            self.assertEqual(raw.hex(), r['expected_hex'], f"Mismatch at {hex(r['vaddr'])}: {r['desc']}")

    def test_06_controls(self):
        self.assertEqual(len(CONTROLS), 24)
        for ctrl in CONTROLS:
            expected = bytes.fromhex(ctrl['hex_bytes'])
            actual = self.image.read(ctrl['vaddr'], len(expected))
            self.assertEqual(actual, expected, f"Failed at {hex(ctrl['vaddr'])}: {ctrl['desc']}")

    def test_07_analysis_engine(self):
        res = analyse(self.data)
        self.assertEqual(res['binary']['sha256'], EXPECTED_SHA256)
        self.assertEqual(len(res['fdes']), 3)
        self.assertEqual(len(res['panics']), 1)
        self.assertEqual(len(res['privileged_table']), 20)
        self.assertEqual(len(res['rodata']), 11)
        self.assertEqual(len(res['controls']), 24)

    def test_08_negative_mutations(self):
        # Truncated binary size
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

        # Mutate table entry
        bad_table = bytearray(self.data)
        off_table = self.image.off(PRIVILEGED_SYSTEM_USERS_TABLE_VADDR)
        bad_table[off_table + 19] ^= 0x01
        with self.assertRaises(EvidenceError):
            analyse(bytes(bad_table))

    def test_09_domain_logic_and_simulation(self):
        # Iterator stepping without allowance
        it = SystemUserIndexIter(0, 0)
        indices = []
        while True:
            idx = it.next_index_with_offset(0)
            if idx == SYSTEM_USER_END_SENTINEL:
                break
            indices.append(idx)
        self.assertEqual(indices, list(range(30)))

        # Iterator with tail allowance 5
        it2 = SystemUserIndexIter(0, 5)
        indices2 = []
        while True:
            idx = it2.next_index_with_offset(0)
            if idx == SYSTEM_USER_END_SENTINEL:
                break
            indices2.append(idx)
        self.assertEqual(len(indices2), 25)

        # Overflow checks
        it3 = SystemUserIndexIter(0xFFFFFFFFFFFFFFFF, 0)
        with self.assertRaises(OverflowError):
            it3.next_index_with_offset(1)

        # Privilege check logic
        for idx in range(35):
            expected = 7 <= idx <= 26
            self.assertEqual(is_privileged_system_index(idx), expected)

        # Bitmask verification
        mask = PRIVILEGED_SYSTEM_USER_BITMASK
        self.assertEqual(mask, 0x40006000)
        self.assertTrue((mask >> 13) & 1)
        self.assertTrue((mask >> 14) & 1)
        self.assertTrue((mask >> 30) & 1)
        self.assertFalse((mask >> 10) & 1)

        # Constants consistency
        self.assertEqual(NUM_SYSTEM_USERS, 30)
        self.assertEqual(SYSTEM_USER_END_SENTINEL, 30)
        self.assertEqual(FIRST_PRIVILEGED_SYSTEM_USER_INDEX, 7)
        self.assertEqual(PRIVILEGED_SYSTEM_USER_COUNT, 20)
        self.assertEqual(LAST_PRIVILEGED_SYSTEM_USER_INDEX, 26)

    def test_10_packet_artifacts_exist(self):
        packet_dir = ROOT / 'research' / 'work-items' / 'system-user-94'
        self.assertTrue(packet_dir.is_dir())
        manifest_path = packet_dir / 'manifest.json'
        self.assertTrue(manifest_path.is_file())
        manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
        self.assertIn('files', manifest)
        self.assertGreaterEqual(len(manifest['files']), 7)
        for entry in manifest['files']:
            fpath = packet_dir / entry['path']
            self.assertTrue(fpath.is_file(), f"Missing file: {fpath}")
            data = fpath.read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), entry['sha256'])


if __name__ == '__main__':
    unittest.main()
