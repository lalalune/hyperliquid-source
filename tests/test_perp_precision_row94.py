import hashlib
import unittest

from tools import perp_precision_row94 as p


class PrecisionRowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = p.TARGET.read_bytes()
        cls.evidence = p.analyse(cls.data)
        cls.sec = p.sections(cls.data)

    def test_fde_and_body_binding(self):
        self.assertEqual(len(self.evidence['functions']), 7)
        for row in self.evidence['functions']:
            self.assertEqual(hashlib.sha256(bytes.fromhex(row['bytes'])).hexdigest(), row['sha256'])

    def test_calls_are_byte_decoded(self):
        for site, target in p.CALLS:
            self.assertEqual(p.decode_call(self.data, self.sec, site), target)

    def test_unsigned_arithmetic_branches(self):
        branches = self.evidence['branches']
        self.assertEqual(len(branches), 28)
        self.assertEqual([(x['name'], x['target_va']) for x in branches[:4]],
                         [('multiply_overflow', '0x2a226d8'), ('addition_overflow', '0x2a226e7'),
                          ('index_increment_wrap', '0x2a226f6'), ('key_writer_error', '0x2a2bf6c')])
        max_dex = p.MASK // 10000
        last = p.MASK % 10000
        self.assertEqual(p.id_step(max_dex, last), ('row', p.MASK))
        self.assertEqual(p.id_step(max_dex, last + 1), ('addition_overflow', None))
        self.assertEqual(p.id_step(max_dex + 1, 0), ('multiply_overflow', None))

    def test_every_byte_value(self):
        for n in range(256):
            self.assertEqual(p.identity_byte(n), n)
            self.assertEqual(p.replay_byte_path(self.data, self.sec, n), n)
        for n in (-1, 256):
            with self.assertRaises(ValueError):
                p.identity_byte(n)

    def test_corrupt_target_hash(self):
        with self.assertRaises(ValueError):
            p.checked_target(self.data[:-1] + bytes([self.data[-1] ^ 1]))

    def test_corrupt_precision_load(self):
        data = bytearray(self.data)
        va, expected = p.WINDOWS['builder_byte_load']
        data[p.file_offset(self.sec, va, 4) + 3] ^= 1
        with self.assertRaises(ValueError):
            p.checked_window(data, self.sec, va, expected)
        with self.assertRaises(ValueError):
            p.replay_byte_path(data, self.sec, 37)

    def test_corrupt_precision_store(self):
        data = bytearray(self.data)
        va, expected = p.WINDOWS['builder_byte_store']
        data[p.file_offset(self.sec, va, len(bytes.fromhex(expected))) + 13] ^= 1
        with self.assertRaises(ValueError):
            p.checked_window(data, self.sec, va, expected)

    def test_corrupt_branch_and_call(self):
        data = bytearray(self.data)
        data[p.file_offset(self.sec, 0x2a225b3, 6) + 1] ^= 1
        with self.assertRaises(ValueError):
            p.decode_jcc(data, self.sec, 0x2a225b3, 0x80)
        data = bytearray(self.data)
        data[p.file_offset(self.sec, 0x2a2bf99, 2)] ^= 1
        with self.assertRaises(ValueError):
            p.decode_short_jcc(data, self.sec, 0x2a2bf99, 0x74)
        data = bytearray(self.data)
        site, target = p.CALLS[0]
        data[p.file_offset(self.sec, site, 5) + 1] ^= 1
        self.assertNotEqual(p.decode_call(data, self.sec, site), target)

    def test_all_keyed_fields(self):
        fields = self.evidence['fields']
        self.assertEqual(len(fields), 9)
        self.assertEqual([x['key'] for x in self.evidence['outer_keys']],
                         ['universe', 'marginTables', 'collateralToken'])
        self.assertEqual([f['key'] for f in fields], [
            'szDecimals', 'name', 'maxLeverage', 'marginTableId', 'onlyIsolated',
            'isDelisted', 'marginMode', 'growthMode', 'lastGrowthModeChangeTime'])
        self.assertEqual([f['row_offset'] for f in fields], [45, 0, 44, 24, 40, 41, 42, 43, 28])

    def test_unbacked_address_and_bad_ranges(self):
        with self.assertRaises(ValueError):
            p.file_offset(self.sec, 1 << 63, 8)
        with self.assertRaises(ValueError):
            p.file_offset(self.sec, 0, -1)
        with self.assertRaises(ValueError):
            p.id_step(-1, 0)

    def test_key_and_writer_offset(self):
        self.assertEqual(self.evidence['key']['text'], 'szDecimals')
        self.assertEqual(self.evidence['dataflow']['source_row_byte_offset'], 42)
        self.assertEqual(self.evidence['dataflow']['output_row_byte_offset'], 45)
        self.assertEqual(self.evidence['dataflow']['row_stride'], 48)
