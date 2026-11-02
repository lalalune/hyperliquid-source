"""Controls for digest-bound quantity float scale observations."""
import hashlib
from fractions import Fraction
from pathlib import Path
import sys
import struct
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import qty_float_scale94 as q


class QuantityFloatScaleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = q.TARGET.read_bytes()
        q.checked_target(cls.data)
        cls.secs = q.sections(cls.data)
        cls.frames = q.fde_map(cls.data, cls.secs)
        cls.code = q.check_code(cls.data, cls.secs, cls.frames)
        cls.insns, cls.branches = q.instructions(cls.data, cls.secs, cls.code)
        cls.rels = q.relocations(cls.data, cls.secs)

    def test_binary_identity_and_function_extents(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), q.SHA256)
        self.assertEqual(len(self.code), 2)
        for name, desc in q.FUNCS.items():
            self.assertEqual(len(self.frames[desc['start']]), 1)
            self.assertEqual(self.frames[desc['start']][0]['end'], desc['end'])
            self.assertEqual(hashlib.sha256(self.code[name]['raw']).hexdigest(), desc['sha256'])

    def test_bad_sha_and_truncated_binary_fail_closed(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            q.checked_target(self.data[:-1])
        changed = bytearray(self.data)
        changed[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            q.checked_target(changed)

    def test_any_function_byte_corruption_rejected(self):
        for desc in q.FUNCS.values():
            changed = bytearray(self.data)
            changed[q.file_offset(self.secs, desc['start'] + 3)] ^= 1
            with self.assertRaisesRegex(ValueError, 'instruction bytes changed'):
                q.check_code(changed, self.secs, self.frames)

    def test_fde_end_and_duplicate_are_rejected(self):
        desc = q.FUNCS['direct_nonnegative']
        bad = dict(self.frames)
        row = dict(bad[desc['start']][0])
        row['end'] += 1
        bad[desc['start']] = [row]
        with self.assertRaisesRegex(ValueError, 'FDE extent'):
            q.check_code(self.data, self.secs, bad)
        bad[desc['start']] = [row, row]
        with self.assertRaisesRegex(ValueError, 'FDE extent'):
            q.check_code(self.data, self.secs, bad)

    def test_unbacked_nobits_and_cross_section_addresses_rejected(self):
        with self.assertRaisesRegex(ValueError, 'file-backed'):
            q.read_va(self.data, self.secs, 0, 1)
        nobits = next(s for s in self.secs if s['type'] == 8 and s['size'] and s['address'])
        with self.assertRaisesRegex(ValueError, 'file-backed'):
            q.file_offset([nobits], nobits['address'])
        section = next(s for s in self.secs if s['name'] == '.text')
        with self.assertRaisesRegex(ValueError, 'file-backed'):
            q.file_offset([section], section['address'] + section['size'] - 1, 2)

    def test_branch_decoding_and_negative_controls(self):
        self.assertEqual(q.branch_target(0x100, bytes.fromhex('7802')), 0x104)
        self.assertEqual(q.branch_target(0x100, bytes.fromhex('0f88faffffff')), 0x100)
        with self.assertRaisesRegex(ValueError, 'branch encoding'):
            q.branch_target(0x100, bytes.fromhex('7402'))
        self.assertEqual(len(self.branches), 10)

    def test_rip_operands_and_displacement_corruption(self):
        rows = q.rip_targets(self.insns)
        self.assertEqual(len(rows), 15)
        changed = list(self.insns)
        for i, (name, va, raw, text) in enumerate(changed):
            if va == 0x3c06193:
                b = bytearray.fromhex(raw)
                b[-1] ^= 1
                changed[i] = name, va, b.hex(), text
                break
        with self.assertRaisesRegex(ValueError, 'RIP-relative'):
            q.rip_targets(changed)

    def test_location_binding_and_missing_relocation(self):
        for d in q.FUNCS.values():
            loc = q.location(self.data, self.secs, self.rels, d['location'])
            self.assertEqual((loc['line'], loc['column']), (843, 1))
        with self.assertRaisesRegex(ValueError, 'relocation missing'):
            q.location(self.data, self.secs, {}, q.FUNCS['direct_nonnegative']['location'])

    def test_round_to_even_ties_and_precision(self):
        self.assertEqual(q.round_binary64(Fraction((1 << 53) + 1)), 0x4340000000000000)
        self.assertEqual(q.round_binary64(Fraction((1 << 53) + 3)), 0x4340000000000002)
        self.assertEqual(q.round_binary64(Fraction(1, 1 << 1075)), 0)
        self.assertEqual(q.round_binary64(Fraction(3, 1 << 1075)), 2)
        self.assertEqual(q.round_binary64(-Fraction(1, 1 << 1075)), q.SIGN)

    def test_subnormal_normal_and_finite_infinite_boundaries(self):
        self.assertEqual(q.round_binary64(q.fraction(0x000fffffffffffff)), 0x000fffffffffffff)
        self.assertEqual(q.round_binary64(q.fraction(0x0010000000000000)), 0x0010000000000000)
        self.assertEqual(q.round_binary64(q.fraction(0x7fefffffffffffff)), 0x7fefffffffffffff)
        self.assertEqual(q.round_binary64(Fraction(1 << 1024)), q.INF)
        with self.assertRaisesRegex(ValueError, 'non-finite'):
            q.fraction(q.INF)

    def test_complement_is_rounded_before_multiplication(self):
        self.assertEqual(q.complement(0x3ff8000000000000), 0xbfe0000000000000)
        self.assertEqual(q.complement(q.ONE), 0)
        self.assertEqual(q.complement(q.INF), q.SIGN | q.INF)
        self.assertEqual(q.complement(0x7ff0000000000001), 0x7ff8000000000001)

    def test_input_integer_rounds_before_multiplication(self):
        value = q.calculate('direct_nonnegative', (1 << 53) + 1, q.ONE)
        self.assertEqual(value['converted_bits'], 0x4340000000000000)
        self.assertEqual(value['result'], 1 << 53)

    def test_negative_input_enters_error_before_factor_handling(self):
        for name in q.FUNCS:
            for factor in (0, q.INF, q.QNAN):
                self.assertEqual(q.calculate(name, q.SIGN, factor)['status'], 'error_edge')

    def test_finite_outputs_and_toward_zero(self):
        self.assertEqual(q.calculate('direct_nonnegative', 7, 0x3ff8000000000000)['result'], 10)
        self.assertEqual(q.calculate('direct_nonnegative', 7, 0xbfe0000000000000)['result'], 0)
        self.assertEqual(q.calculate('complement_signed', 7, 0x3ff8000000000000)['result'], -3)
        self.assertEqual(q.calculate('complement_signed', 7, 0x3fe0000000000000)['result'], 3)

    def test_nonfinite_product_is_zero_not_max(self):
        for name in q.FUNCS:
            for factor in (q.INF, q.SIGN | q.INF, q.QNAN, 0x7ff0000000000001):
                for quantity in (0, 1, q.I64MAX):
                    result = q.calculate(name, quantity, factor)
                    self.assertEqual(result['result'], 0)
                    self.assertIn('nonfinite_to_zero', result['coverage'])
        self.assertEqual(q.product(q.INF, 0), q.SIGN | q.QNAN)

    def test_finite_overflow_and_nonfinite_overflow_differ(self):
        finite = q.calculate('direct_nonnegative', 1, 0x43e0000000000000)
        self.assertEqual(finite['result'], q.I64MAX)
        overflow = q.calculate('direct_nonnegative', 2, 0x7fefffffffffffff)
        self.assertEqual(overflow['product_bits'], q.INF)
        self.assertEqual(overflow['result'], 0)

    def test_signed_conversion_edges(self):
        for bits, expected in [(0x43dfffffffffffff, (1 << 63) - 1024),
                               (0x43e0000000000000, q.I64MAX),
                               (0xc3e0000000000000, q.I64MIN),
                               (0xc3e0000000000001, q.I64MIN)]:
            self.assertEqual(q.machine_tail(bits, False)[0], expected)
            self.assertEqual(q.machine_tail(bits, False)[0], q.specification(bits, False))

    def test_invalid_public_input(self):
        for quantity, factor in [(-1, 0), (1 << 64, 0), (0, -1), (0, 1 << 64)]:
            with self.assertRaisesRegex(ValueError, '64-bit'):
                q.calculate('direct_nonnegative', quantity, factor)

    def test_symbolic_intervals_cover_all_and_reject_changed_bound(self):
        rows = q.prove_tail_intervals(q.INF - 1, 0x43e0000000000000,
                                      0x43dfffffffffffff, 0xc3e0000000000000)
        self.assertEqual(len(rows), 8)
        self.assertEqual(sum(row[3] for row in rows), 1 << 64)
        for args in [(q.INF - 2, 0x43e0000000000000, 0x43dfffffffffffff, 0xc3e0000000000000),
                     (q.INF - 1, 0x43e0000000000000, 0x43dffffffffffffe, 0xc3e0000000000000),
                     (q.INF - 1, 0x43e0000000000000, 0x43dfffffffffffff, 0xc3e0000000000001)]:
            with self.assertRaises(ValueError):
                q.prove_tail_intervals(*args)

    def test_complete_exponent_partition_sample(self):
        samples = 0
        for bits in q.bit_patterns():
            for nonnegative in (False, True):
                self.assertEqual(q.machine_tail(bits, nonnegative)[0], q.specification(bits, nonnegative))
                samples += 1
        self.assertEqual(samples, 32768)

    def test_instruction_walk_matches_semantics_and_stops_on_error(self):
        result = q.execute('direct_nonnegative', 7, 0x3ff8000000000000, self.insns)
        self.assertEqual(result['result'], 10)
        self.assertEqual(result['status'], 'return')
        self.assertIn((0x3c0619f, False), result['edges'])
        err = q.execute('direct_nonnegative', q.SIGN, q.ONE, self.insns)
        self.assertEqual(err['status'], 'error_edge')
        self.assertNotIn(0x3c06204, err['visited'])

    def test_interpretation_mutation_changes_walk(self):
        altered = list(self.insns)
        for i, (name, va, raw, op) in enumerate(altered):
            if va == 0x3c06191:
                altered[i] = name, va, raw, 'jmp convert'
                break
        wrong = q.execute('direct_nonnegative', 7, 0x3ff8000000000000, altered)
        right = q.calculate('direct_nonnegative', 7, 0x3ff8000000000000)
        self.assertNotEqual(wrong['result'], right['result'])

    def test_rounding_order_counterexample(self):
        n, bits = 8791338280601638520, 0x3fee1506db4daeb5
        actual = q.calculate('complement_signed', n, bits)
        self.assertEqual(actual['result'], 526893509556257408)
        rounded_n = q.round_binary64(Fraction(n))
        other_product = q.product(bits, n)
        other = q.round_binary64(q.fraction(rounded_n) - q.fraction(other_product))
        self.assertEqual(q.specification(other, False), 526893509556257792)

    def test_soft_arithmetic_against_host_binary64_on_finite_samples(self):
        # Independent standard-library cross-check; the generator itself never
        # uses host floating-point arithmetic and does not depend on this test.
        state = 0x62ab901d13421177
        for _ in range(4096):
            state ^= (state << 13) & q.MASK
            state ^= state >> 7
            state ^= (state << 17) & q.MASK
            bits = state & q.MASK
            if not q.finite(bits):
                continue
            number = struct.unpack('<d', struct.pack('<Q', bits))[0]
            quantity = state & q.I64MAX
            host_product = struct.unpack('<Q', struct.pack('<d', number * float(quantity)))[0]
            host_complement = struct.unpack('<Q', struct.pack('<d', 1.0 - number))[0]
            self.assertEqual(q.product(bits, quantity), host_product)
            self.assertEqual(q.complement(bits), host_complement)

    def test_generator_and_deterministic_files(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            first = q.generate(self.data, Path(a))
            second = q.generate(self.data, Path(b))
            self.assertEqual(first, second)
            self.assertEqual(first['tail_encodings_partitioned'], str(1 << 64))
            self.assertEqual(first['vector_count'], 2856)
            names = {p.name for p in Path(a).iterdir()}
            self.assertEqual(names, {p.name for p in Path(b).iterdir()})
            for name in names:
                self.assertEqual((Path(a) / name).read_bytes(), (Path(b) / name).read_bytes())
                retained = Path(__file__).resolve().parents[1] / 'research/work-items/RE-004-float-quantity-scale-94' / name
                self.assertEqual((Path(a) / name).read_bytes(), retained.read_bytes())


if __name__ == '__main__':
    unittest.main()
