"""Target-bound static controls for the node-94 delayer codec extraction."""
import unittest

from tools import delayer_snapshot94 as codec


class Overlay:
    """Copy-on-read corruption below the separately tested digest gate."""
    def __init__(self, image, changes):
        self.image = image
        self.changes = changes
        self.fdes = image.fdes

    def read(self, va, size):
        data = bytearray(self.image.read(va, size))
        for address, value in self.changes.items():
            if va <= address < va + size:
                data[address - va] = value
        return bytes(data)

    def code(self, start):
        row = self.fdes[start]
        return self.read(start, row['end'] - start)

    def offset(self, va, size=1):
        return self.image.offset(va, size)


class DelayerSnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = codec.Image(codec.BINARY.read_bytes())
        cls.records = codec.evidence(cls.image)
        cls.paths = cls.records['byte_matcher_paths']

    def test_digest_gate(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            codec.Image(b'corrupted node image')
        corrupted = bytearray(self.image.data)
        corrupted[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            codec.Image(corrupted)

    def test_actual_fde_records_and_selected_ranges(self):
        fdes = self.records['fdes']
        self.assertEqual(len(fdes), 8)
        self.assertEqual([f['start_va'] for f in fdes], [hex(x) for x in codec.STARTS])
        for f in fdes:
            self.assertGreater(f['size'], 0)
            self.assertEqual(int(f['end_va_exclusive'], 16) - int(f['start_va'], 16), f['size'])
            self.assertEqual(len(f['sha256']), 64)

    def test_address_bounds_exclude_nobits(self):
        with self.assertRaises(ValueError):
            self.image.read(-1, 1)
        with self.assertRaises(ValueError):
            self.image.read(0, 0)
        with self.assertRaises(ValueError):
            self.image.read(1 << 64, 1)
        bss = next(s for s in self.image.sections if s['name'] == '.bss' and s['type'] == 8)
        with self.assertRaises(ValueError):
            self.image.read(bss['address'], 1)

    def test_both_matchers_extract_identical_names(self):
        fast = self.records['fast_matcher_paths']
        self.assertEqual([(x['tag'], x['key']) for x in self.paths],
                         [(x['tag'], x['key']) for x in fast])
        self.assertEqual([x['tag'] for x in self.paths], list(range(8)))
        self.assertEqual(len(self.records['matcher_length_table']), 15)
        self.assertEqual(len(self.records['fast_matcher_length_table']), 15)
        self.assertEqual(sum(len(x['comparisons']) for x in self.paths), 128)

    def test_all_key_bytes_have_negative_controls(self):
        count = 0
        for path in self.paths:
            name = path['key'].encode('ascii')
            self.assertEqual(codec.decode_key_rules(self.paths, name), path['tag'])
            for position in range(len(name)):
                for value in range(256):
                    if value == name[position]:
                        continue
                    altered = bytearray(name)
                    altered[position] = value
                    self.assertEqual(codec.decode_key_rules(self.paths, bytes(altered)), 8)
                    count += 1
            self.assertEqual(codec.decode_key_rules(self.paths, name[:-1]), 8)
            self.assertEqual(codec.decode_key_rules(self.paths, name + b'x'), 8)
        self.assertEqual(count, 33405)
        for key in (b'', b'x', b'vty_trackers\x00', b'Delay_scale', b'\x00' * 25, b'\xff' * 26):
            self.assertEqual(codec.decode_key_rules(self.paths, key), 8)

    def test_byte_matcher_instruction_corruption(self):
        data = bytearray(self.image.code(0x22ecd20))
        data[0x22ecd41 - 0x22ecd20] ^= 1
        with self.assertRaises(ValueError):
            codec.extract_byte_path(bytes(data), 0x22ecd41, 11)

    def test_byte_matcher_conditional_corruption(self):
        data = bytearray(self.image.code(0x22ecd20))
        data[0x22ecd44 - 0x22ecd20 + 1] ^= 1
        with self.assertRaises(ValueError):
            codec.extract_byte_path(bytes(data), 0x22ecd41, 11)

    def test_wrong_key_compare_immediate_is_detected_cross_matcher(self):
        original = self.image.read(0x22ecd43, 1)[0]
        altered = Overlay(self.image, {0x22ecd43: original ^ 1})
        with self.assertRaises(ValueError):
            codec.evidence(altered)

    def test_fast_simd_constant_corruption(self):
        original = self.image.read(0x207730, 1)[0]
        altered = Overlay(self.image, {0x207730: original ^ 1})
        with self.assertRaises(ValueError):
            codec.fast_key_paths(altered)

    def test_fast_length_table_corruption(self):
        slot = 0x3da204
        altered = Overlay(self.image, {slot: self.image.read(slot, 1)[0] ^ 1})
        with self.assertRaises(ValueError):
            codec.fast_key_paths(altered)

    def test_reader_case_table_corruption(self):
        altered = Overlay(self.image, {0x2b92f8: self.image.read(0x2b92f8, 1)[0] ^ 0xff})
        with self.assertRaises(ValueError):
            codec.field_records(altered, self.paths)

    def test_duplicate_branch_corruption(self):
        altered = Overlay(self.image, {0x176a9a2: self.image.read(0x176a9a2, 1)[0] ^ 1})
        with self.assertRaises(ValueError):
            codec.field_records(altered, self.paths)

    def test_missing_and_duplicate_key_corruption(self):
        for address in (0x3b041d, 0x3b0495):
            altered = Overlay(self.image, {address: self.image.read(address, 1)[0] ^ 1})
            with self.assertRaises(ValueError):
                codec.field_records(altered, self.paths)

    def test_all_missing_presence_branches_reject_corruption(self):
        checks = self.records['reader_missing_checks']
        self.assertEqual(len(checks), 6)
        for check in checks:
            address = int(check['branch_va'], 16)
            if check['branch_opcode'].startswith('0f'):
                address += 1
            altered = Overlay(self.image, {address: self.image.read(address, 1)[0] ^ 1})
            with self.assertRaises(ValueError):
                codec.evidence(altered)

    def test_sequence_length_and_optional_corruption(self):
        sequence = self.records['sequence']
        self.assertEqual([r['index'] for r in sequence['required_prefix']], list(range(6)))
        for address in (0x17687af, 0x17687d9, 0x1768927, 0x1768970,
                        0x16fde8d, 0x16fdec7, 0x17698c6):
            altered = Overlay(self.image, {address: self.image.read(address, 1)[0] ^ 1})
            with self.assertRaises(ValueError):
                codec.sequence_decisions(altered)

    def test_writer_offset_and_scale_corruption(self):
        for address in (0x2311f31, 0x20a730, 0x2311f3b, 0x2311f29,
                        0x3bfac7, 0x23d8e36, 0x23d8e83):
            altered = Overlay(self.image, {address: self.image.read(address, 1)[0] ^ 1})
            with self.assertRaises(ValueError):
                codec.evidence(altered)

    def test_field_contract_and_static_limits(self):
        fields = self.records['writer_and_reader_fields']
        self.assertEqual([f['object_offset'] for f in fields],
                         ['0x30', '0x48', '0x60', '0x68', '0x70', '0x20', '0x0', '0x88'])
        self.assertEqual(sum(f['missing'] is not None for f in fields), 6)
        self.assertTrue(all(f['duplicate_template_va'] == '0x1e0fd5' for f in fields))
        self.assertEqual(self.records['scale_default']['bits_le'], '000000000000f03f')
        self.assertEqual(self.records['nested']['status_guard_type']['name'], 'BucketGuard')
        self.assertEqual(self.records['nested']['mode']['tag_one_key'], 'PerAsset')
        self.assertEqual(self.records['nested']['mode']['other_key'], 'Enabled')
        self.assertEqual(len(self.records['reader_dispatch_table']), 9)
        self.assertEqual(len(self.records['writer_branches']), 15)

    def test_branch_decoder_rejects_truncation_and_nonbranch(self):
        for data in (b'\xe8', b'\x0f\x85\x00', b'\x90'):
            with self.assertRaises(ValueError):
                codec.branch(data, 0x1000, 0x1000)
        with self.assertRaises(ValueError):
            codec.branch(b'\xeb\x00', 0x1000, 0x1002)


if __name__ == '__main__':
    unittest.main()
