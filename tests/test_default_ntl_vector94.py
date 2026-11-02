import hashlib
import struct
import unittest
from fractions import Fraction
from pathlib import Path

from tools import default_ntl_vector94 as item


class DefaultNtlVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = bytearray(item.TARGET.read_bytes())
        cls.secs = item.sections(cls.data)
        cls.result = item.qualify(cls.data)

    def test_digest_and_fde_windows(self):
        item.check_digest(self.data)
        self.assertEqual([(x['start_va'], x['end_va']) for x in self.result['functions']],
                         [('0x2a10250', '0x2a10584'), ('0x2a44500', '0x2a44562')])
        self.assertEqual([len(bytes.fromhex(x['bytes'])) for x in self.result['functions']], [820, 98])

    def test_default_values_and_exact_float_results(self):
        self.assertEqual([(x['tag'], x['raw']) for x in self.result['rows']],
                         [(25, 30_000_000_000_000), (20, 5_000_000_000_000),
                          (10, 2_000_000_000_000), (1, 500_000_000_000)])
        for row in self.result['rows']:
            bits = item.scaled_bits(row['raw'])
            self.assertEqual(item.bits_fraction(bits), Fraction(row['raw'], 1_000_000))

    def test_independent_host_float_at_representative_boundaries(self):
        # Python's binary64 cast/divide provides a separately implemented oracle
        # under the host's default nearest-even environment.
        cases = [0, 1, 999999, 1000000, (1 << 53) - 1, (1 << 53) + 1,
                 (1 << 63) - 1, (1 << 63), (1 << 64) - 1]
        for x in cases:
            with self.subTest(x=x):
                expected = struct.unpack('<Q', struct.pack('<d', float(x) / 1_000_000.0))[0]
                self.assertEqual(item.scaled_bits(x), expected)
        x = (1 << 53) + 1
        self.assertNotEqual(item.scaled_bits(x), item.round_ratio_bits(x, 1_000_000))

    def test_round_ratio_midpoints(self):
        self.assertEqual(item.round_ratio_bits((1 << 53) + 1, 1), 0x4340000000000000)
        self.assertEqual(item.round_ratio_bits((1 << 53) + 3, 1), 0x4340000000000002)
        self.assertEqual(item.bits_fraction(item.round_ratio_bits(1, 2)), Fraction(1, 2))
        with self.assertRaises(ValueError):
            item.scaled_bits(-1)
        with self.assertRaises(ValueError):
            item.scaled_bits(1 << 64)

    def test_count_and_failure_boundaries(self):
        self.assertEqual(item.count_plan(1, 3, 1, 1),
                         {'status': 'allocate', 'capacity': 4, 'output_len': 4,
                          'pair_iterations': 1, 'odd_base': 1})
        self.assertEqual(item.count_plan(0, 3, 0, 1)['status'], 'empty')
        self.assertEqual(item.count_plan(1, 4, 1, 0)['output_len'], 4)
        self.assertEqual(item.count_plan(1, 4, 1, 2)['output_len'], 5)
        self.assertEqual(item.count_plan(1, 1, 1, item.U64_MAX)['status'], 'count-overflow')
        self.assertEqual(item.count_plan(1, (1 << 59) - 1, 0, 0)['status'], 'allocate')
        self.assertEqual(item.count_plan(1, 1 << 59, 0, 0)['status'], 'allocation-size-overflow')
        with self.assertRaises(ValueError):
            item.count_plan(1, 1 << 60, 0, 0)

    def test_all_listed_branch_destinations_within_fde(self):
        self.assertEqual(len(self.result['branches']), 20)
        for edge in self.result['branches']:
            self.assertTrue(0x2a10250 <= int(edge['target'], 16) < 0x2a10584)
            self.assertTrue(0x2a10250 <= int(edge['fallthrough'], 16) < 0x2a10584)

    def test_default_success_path_decisions(self):
        edges = {int(row['source'], 16): row['default_model_edge'] for row in self.result['branches']}
        self.assertEqual(len([e for e in edges.values() if e != 'unreached']), 17)
        self.assertEqual(edges[0x2a1028b], 'taken')
        self.assertEqual(edges[0x2a102f5], 'fallthrough')
        self.assertEqual(edges[0x2a103af], 'taken')
        self.assertEqual(edges[0x2a10469], 'fallthrough')
        self.assertEqual(edges[0x2a10475], 'fallthrough')
        self.assertEqual(edges[0x2a10569], 'unreached')
        plan = self.result['constructor_object']['predicted_plan']
        self.assertEqual((plan['capacity'], plan['output_len'], plan['requested_allocation_bytes']),
                         (4, 4, 64))
        self.assertEqual((plan['pair_iterations'], plan['odd_base']), (1, 1))

    def test_bad_digest_is_rejected_before_other_parsing(self):
        damaged = b'X' + bytes(self.data[1:])
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            item.generate(damaged)
        self.assertNotEqual(hashlib.sha256(damaged).hexdigest(), item.SHA256)

    def test_changed_instruction_branch_pointer_and_data_are_rejected(self):
        # Each probe mutates actual ELF bytes and always restores them.
        for va in (0x2a1026e, 0x2a10400, 0x2a104a6, 0x2a4452a,
                   0x2a4453a, 0x421bc0, 0x5995e0, 0x20ae60,
                   0x203e80, 0x202ea0):
            offset = item.section_offset(self.secs, va, 1)
            old = self.data[offset]
            self.data[offset] ^= 1
            try:
                with self.subTest(va=hex(va)):
                    with self.assertRaises(ValueError):
                        item.qualify(self.data, verify_digest=False)
            finally:
                self.data[offset] = old

    def test_changed_fde_extent_is_rejected(self):
        fde_va = int(self.result['functions'][0]['fde_va'], 16)
        offset = item.section_offset(self.secs, fde_va + 12, 1)
        old = self.data[offset]
        self.data[offset] ^= 1
        try:
            with self.assertRaises(ValueError):
                item.qualify(self.data, verify_digest=False)
        finally:
            self.data[offset] = old

    def test_lift_matches_integer_rational_model(self):
        prefix = bytes.fromhex(self.result['simd_prefix_bytes'])
        bias = bytes.fromhex(self.result['simd_bias_bytes'])
        divisor = bytes.fromhex(self.result['divisor_bytes'])
        for power in range(0, 64):
            for delta in (-1, 0, 1):
                x = (1 << power) + delta
                if 0 <= x <= item.U64_MAX:
                    self.assertEqual(item.lifted_scale_bits(x, prefix, bias, divisor), item.scaled_bits(x))
        # Unlike the integer-rational model, the lift consumes the literal bytes.
        altered = struct.pack('<d', 2_000_000.0)
        self.assertNotEqual(item.lifted_scale_bits(1_000_000, prefix, bias, altered),
                            item.scaled_bits(1_000_000))

    def test_changed_and_duplicate_relocations_are_rejected(self):
        offset = int(self.result['constructor_relocation']['rela_file_offset'], 16)
        # Change the actual addend and then reuse a neighboring record's slot.
        old = bytes(self.data[offset + 16:offset + 24])
        self.data[offset + 16] ^= 1
        try:
            with self.assertRaises(ValueError):
                item.qualify(self.data, verify_digest=False)
        finally:
            self.data[offset + 16:offset + 24] = old
        neighbor = offset + 24
        old = bytes(self.data[neighbor:neighbor + 8])
        self.data[neighbor:neighbor + 8] = struct.pack('<Q', 0x5774f98)
        try:
            with self.assertRaises(ValueError):
                item.qualify(self.data, verify_digest=False)
        finally:
            self.data[neighbor:neighbor + 8] = old

    def test_branch_decoder_negative_controls(self):
        with self.assertRaises(ValueError):
            item.branch(self.data, self.secs, 0x2a10250)  # push, not a branch
        condition, target, size = item.branch(self.data, self.secs, 0x2a1026e)
        self.assertEqual((condition, target, size), (4, 0x2a102a6, 2))

    def test_unmapped_and_nobits_rejected(self):
        with self.assertRaises(ValueError):
            item.read_va(self.data, self.secs, 0xffffffffffffffff, 1)
        bss = next(s for s in self.secs if s['name'] == '.bss')
        with self.assertRaises(ValueError):
            item.read_va(self.data, self.secs, bss['address'], 1)
        with self.assertRaises(ValueError):
            item.read_va(self.data, self.secs, -1, 4)

    def test_result_files_have_expected_names(self):
        files = item.generate(self.data)
        self.assertEqual(set(files), {'evidence.json', 'default-rows.tsv', 'numeric-model.tsv',
                                      'count-model.tsv', 'branches.tsv'})



if __name__ == '__main__':
    unittest.main()
