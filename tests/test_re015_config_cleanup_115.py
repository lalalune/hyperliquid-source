import csv
import json
from pathlib import Path
import struct
import tempfile
import unittest

from tools import re015_config_cleanup_115 as scan


class ConfigCleanup115Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.blob = (scan.ROOT / 'artifacts/node/115/hl-node').read_bytes()
        cls.image = scan.Image(cls.blob)
        cls.tmp = tempfile.TemporaryDirectory()
        cls.out = Path(cls.tmp.name)
        cls.summary = scan.produce(cls.image, cls.out)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_authenticated_capture_and_corruption(self):
        scan.verify_digest(self.blob)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            scan.verify_digest(self.blob, '0' * 64)
        damaged = bytearray(self.blob)
        damaged[123] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            scan.verify_digest(damaged)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            scan.verify_digest(b'wrong length')

    def test_full_body_mutation_is_rejected(self):
        start, end, digest = scan.FUNCTIONS[2][1:]
        body = bytearray(self.image.read(start, end - start, True))
        scan.verify_body(body, digest)
        body[17] ^= 1
        with self.assertRaisesRegex(ValueError, 'body changed'):
            scan.verify_body(body, digest)

    def test_address_mapping_rejects_nobits_crossings_and_ambiguity(self):
        normal = {'name': '.data', 'type': 1, 'flags': 2, 'address': 0x1000,
                  'offset': 0x80, 'size': 16}
        nobits = dict(normal, name='.bss', type=8, address=0x2000)
        self.assertEqual(scan.file_offset([normal, nobits], 0x1004, 4), (0x84, '.data'))
        for va, size in ((0x2000, 1), (0xfff, 1), (0x100f, 2), (0x1000, 0)):
            with self.subTest(va=va, size=size), self.assertRaises(ValueError):
                scan.file_offset([normal, nobits], va, size)
        with self.assertRaises(ValueError):
            scan.file_offset([normal, dict(normal, name='.other')], 0x1000)
        with self.assertRaises(ValueError):
            scan.file_offset([normal], 0x1000, executable=True)

    def test_extent_and_relocation_corruption(self):
        fde = {'start': 0x10, 'end': 0x20, 'fde': 0x30}
        index = {'start': 0x10, 'fde': 0x30}
        scan.check_extent(fde, index, 0x10, 0x20)
        for bad_fde, bad_index in ((dict(fde, end=0x1f), index),
                                   (fde, dict(index, fde=0x31)),
                                   (dict(fde, start=0x11), index)):
            with self.subTest(fde=bad_fde, index=bad_index), self.assertRaises(ValueError):
                scan.check_extent(bad_fde, bad_index, 0x10, 0x20)
        one = struct.pack('<QQq', 0x1234, 8, 0x5678)
        self.assertEqual(scan.relocation_index(one, 0, len(one))[0x1234][:3], (8, 0, 0x5678))
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            scan.relocation_index(one + one, 0, len(one) * 2)
        with self.assertRaisesRegex(ValueError, 'truncated'):
            scan.relocation_index(one, 0, len(one) - 1)

    def test_policy_all_mode_and_name_bytes(self):
        raw = self.image.read(0x1563fc9, 46, True)
        mode, bound, mask = scan.policy_operands(raw)
        self.assertEqual((mode, bound, mask), (2, 33, 0x2000800a1))
        protected = {0, 5, 7, 19, 33}
        for m in range(256):
            for name in range(256):
                self.assertEqual(scan.wants_directory(m, name, mode, bound, mask),
                                 m == 2 and name not in protected, (m, name))
        for invalid in ((-1, 0), (256, 0), (2, -1), (2, 256)):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                scan.wants_directory(*invalid, mode, bound, mask)

    def test_changed_mask_bound_and_branch_fail(self):
        original = self.image.read(0x1563fc9, 46, True)
        mode, bound, mask = scan.policy_operands(original)
        altered_mask = mask ^ (1 << 33) ^ (1 << 32)
        self.assertFalse(scan.wants_directory(2, 33, mode, bound, mask))
        self.assertTrue(scan.wants_directory(2, 33, mode, bound, altered_mask))
        for position, replacement in ((32, original[32] ^ 1),
                                      (27, original[27] - 1),
                                      (44, 0x72), (45, original[45] ^ 1),
                                      (0, 0x90)):
            changed = bytearray(original)
            changed[position] = replacement
            with self.subTest(position=position), self.assertRaises(ValueError):
                scan.policy_operands(changed)
        with self.assertRaises(ValueError):
            scan.policy_operands(original[:-1])

    def test_historical_mask_is_not_safe_to_reuse(self):
        mode, bound, current = scan.policy_operands(self.image.read(0x1563fc9, 46, True))
        historical_mask = 0x1000400a1
        self.assertTrue(scan.wants_directory(2, 32, mode, bound, current))
        self.assertFalse(scan.wants_directory(2, 32, mode, bound, historical_mask))
        self.assertFalse(scan.wants_directory(2, 33, mode, bound, current))
        self.assertTrue(scan.wants_directory(2, 33, mode, bound, historical_mask))

    def test_name_boundaries_and_release_drift(self):
        expected = {0: 'Ec', 5: 'NodeTestnet', 7: 'NodeTestnet3',
                    19: 'SoloTestnet', 32: 'SoloSandbox',
                    33: 'NvTestnet', 34: 'NvTestnet2', 78: 'EbHlPerp'}
        for index, name in expected.items():
            self.assertEqual(scan.name_entry(self.image, scan.NAME_TABLE_115, index)['text'], name)
        with self.assertRaises(ValueError):
            scan.name_entry(self.image, scan.NAME_TABLE_115, -1)
        with self.assertRaises(ValueError):
            self.image.relative(0)
        slot = scan.NAME_TABLE_115 + 33 * 16
        saved = self.image.relocs[slot]
        try:
            self.image.relocs[slot] = (6, 0, 0, saved[3])
            with self.assertRaises(ValueError):
                scan.name_entry(self.image, scan.NAME_TABLE_115, 33)
        finally:
            self.image.relocs[slot] = saved

    def test_branch_and_transfer_corruptions(self):
        site = 0x1563fe5
        original = self.image.read(site, 6, True)
        self.assertEqual(scan.checked_branch(original, site, 0x1564059, 'a'), (2, 'a', 0x1564059))
        for raw in (b'', b'\x0f\x87\x00', b'\x90\x00', bytes([original[0], original[1] ^ 1])):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                scan.checked_branch(raw, site, 0x1564059, 'a')
        call_site = 0x1564091
        call = self.image.read(call_site, 5, True)
        self.assertEqual(scan.transfer(call, call_site, 'call', 0x1561530), (5, 0x1561530))
        with self.assertRaises(ValueError):
            scan.transfer(call[:-1], call_site, 'call', 0x1561530)
        with self.assertRaises(ValueError):
            scan.transfer(call, call_site, 'call', 0x1561531)

    def test_exception_table_bounds_and_encodings(self):
        valid = bytes.fromhex('ffff010400010200')
        parsed = scan.exception_sites(valid, 0, len(valid), 0x100, 0x110)
        self.assertEqual([(r['start'], r['end'], r['landing'], r['action']) for r in parsed['rows']],
                         [(0x100, 0x101, 0x102, 0)])
        invalid = (valid[:-1], bytes.fromhex('ffff020400010200'),
                   bytes.fromhex('ffff01040f020200'),
                   bytes.fromhex('ffff010400012000'),
                   bytes.fromhex('ff9b7f0100'))
        for blob in invalid:
            with self.subTest(blob=blob), self.assertRaises(ValueError):
                scan.exception_sites(blob, 0, len(blob), 0x100, 0x110)

    def test_pool_entry_and_reference_controls(self):
        site, target = 0x5a08117, 0x448b77
        insn = self.image.read(site, 7, True)
        self.assertEqual(scan.decode_lea(insn, site, target), target)
        broken = bytearray(insn)
        broken[-1] ^= 1
        with self.assertRaises(ValueError):
            scan.decode_lea(broken, site, target)
        slot = 0x64e0918
        for site in (0x5a080d8, 0x1563fcf):
            load = self.image.read(site, 7, True)
            self.assertEqual(scan.decode_rip_load(load, site, slot), slot)
            broken = bytearray(load)
            broken[-1] ^= 1
            with self.assertRaises(ValueError):
                scan.decode_rip_load(broken, site, slot)
            broken = bytearray(load)
            broken[1] ^= 1
            with self.assertRaises(ValueError):
                scan.decode_rip_load(broken, site, slot)
        raw = self.image.read(target, 10)
        self.assertEqual(scan.template(raw, b'/data/', True), '/data/')
        for broken in (raw[:-1], raw[:-1] + b'X', raw[:1] + b'\x05' + raw[2:]):
            with self.subTest(broken=broken), self.assertRaises(ValueError):
                scan.template(broken, b'/data/', True)

    def test_hour_thresholds_and_finite_quotient(self):
        top, factor, bits, limit = scan.time_operands(self.image)
        for value, expected in ((0, 0), (3599, 0), (3600, 1), (7199, 1),
                                (7200, 2), (86399, 23), (86400, 24), (89999, 24)):
            self.assertEqual(scan.hour_case(value, top, factor, bits, limit)[1], expected)
        self.assertEqual(scan.hour_case(7199, top, factor, bits, limit)[2], 'skip')
        self.assertEqual(scan.hour_case(7200, top, factor, bits, limit)[2], 'consider_cleanup')
        self.assertEqual(scan.hour_case(90000, top, factor, bits, limit)[0], 'range_diagnostic')
        self.assertEqual(scan.hour_case(921600, top, factor, bits, limit)[0], 'overflow_diagnostic')
        for value in (-1, 1 << 32):
            with self.assertRaises(ValueError):
                scan.hour_case(value, top, factor, bits, limit)

    def test_short_zero_result_boundaries(self):
        self.assertEqual(scan.c_string_case(b''), ('no_zero', 1, 1, ''))
        self.assertEqual(scan.c_string_case(b'\0'), ('terminal_zero', 0, '', 0))
        for size in (1, 2, 15, 16, 17, 383, 384):
            self.assertEqual(scan.c_string_case(b'a' * size + b'\0')[0], 'terminal_zero')
            for zero in (0, size // 2, size - 1):
                sample = b'a' * zero + b'\0' + b'a' * (size - zero)
                self.assertEqual(scan.c_string_case(sample), ('interior_zero', 1, 0, zero))

    def test_retry_outcomes_and_invalid_parameters(self):
        expected = ((1, 0, 'success'), (2, 1, 'success'), (3, 2, 'success'),
                    (4, 3, 'success'), (4, 3, 'error_object'))
        self.assertEqual(tuple(scan.retry_case(n, 3) for n in (1, 2, 3, 4, None)), expected)
        self.assertEqual(scan.retry_case(5, 3), (4, 3, 'error_object'))
        self.assertEqual(scan.retry_case(None, 0), (1, 0, 'error_object'))
        for args in ((None, -1), (0, 3)):
            with self.assertRaises(ValueError):
                scan.retry_case(*args)

    def test_static_filesystem_branch_cases(self):
        self.assertEqual(scan.directory_case(2, 1, 0x4000), 'false')
        self.assertEqual(scan.directory_case(1, 2, 0x4000), 'false')
        self.assertEqual(scan.directory_case(1, 1, 0x4000), 'true')
        self.assertEqual(scan.directory_case(1, 1, 0xa000), 'false')
        self.assertEqual(scan.root_case(2, 0xa000), 'metadata_error')
        self.assertEqual(scan.root_case(3, 0xa000, True), 'lstat_error')
        self.assertEqual(scan.root_case(3, 0xa000, False), 'unlink')
        self.assertEqual(scan.root_case(1, 0x4000), 'tree')
        for child in (0, 1):
            self.assertEqual(scan.open_failure_case(child, 4), 'retry_open')
            for error in (20, 40):
                self.assertEqual(scan.open_failure_case(child, error),
                                 'unlink_child' if child else 'return_error')
            self.assertEqual(scan.open_failure_case(child, 13), 'return_error')
        for typ in range(256):
            self.assertEqual(scan.entry_case(b'.', typ), 'skip')
            self.assertEqual(scan.entry_case(b'..', typ), 'skip')
            self.assertEqual(scan.entry_case(b'x', typ), 'recurse' if typ in (0, 4) else 'unlink_child')
        self.assertEqual(scan.child_result_case(0), 'continue')
        self.assertEqual(scan.child_result_case((2 << 32) | 2), 'continue')
        self.assertEqual(scan.child_result_case((3 << 32) | 2), 'return_error')
        with self.assertRaises(ValueError):
            scan.child_result_case(-1)
        self.assertEqual(scan.close_case(0, 13), 'return')
        self.assertEqual(scan.close_case(-1, 4), 'return')
        self.assertEqual(scan.close_case(-1, 13), 'diagnostic_boundary')

    def test_output_is_bound_to_witnesses(self):
        self.assertEqual(self.summary['binary_sha256'], scan.DIGEST_115)
        self.assertEqual((self.summary['selected_fde_count'], self.summary['selected_branch_count'],
                          self.summary['selected_transfer_count']), (14, 84, 45))
        self.assertEqual(self.summary['selected_lsda_call_site_count'], 58)
        self.assertEqual(self.summary['selected_global_load_count'], 2)
        self.assertEqual(self.summary['protected_name_indices'], [0, 5, 7, 19, 33])
        self.assertEqual(self.summary['retry_delay_binary64_values'], [0.001, 0.05, 1.0])
        with (self.out / 'name-cases.tsv').open(encoding='utf-8', newline='') as f:
            rows = list(csv.DictReader(f, delimiter='\t'))
        self.assertEqual(len(rows), 512)
        self.assertEqual(sum(r['selected_route'] == 'release' for r in rows if r['mode'] == '2'), 5)
        with (self.out / 'summary.json').open(encoding='utf-8') as f:
            self.assertEqual(json.load(f), self.summary)


if __name__ == '__main__':
    unittest.main()
