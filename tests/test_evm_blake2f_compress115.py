"""Controls for the node #115 BLAKE2 F compression precompile packet."""
import hashlib
from pathlib import Path
import sys
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'tools'))
import evm_blake2f_compress115 as T


class Fixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = T.load_image()
        cls.rig = T.Rig(cls.image)


class ModelTests(Fixture):
    def test_single_block_digests_match_the_standard_library(self):
        for length in (0, 1, 3, 64, 127, 128):
            data, reference = T.digest_case(length)
            self.assertEqual(T.run_model(data, 12), ('ok', reference, 12))

    def test_error_order_is_length_then_gas_then_flag(self):
        good = T.make_input(5, bytes(64), bytes(128), bytes(16), 0)
        self.assertEqual(T.run_model(good[:-1], 5)[1], T.ERR_LENGTH)
        self.assertEqual(T.run_model(good + b'\0', 5)[1], T.ERR_LENGTH)
        self.assertEqual(T.run_model(good, 4)[1], T.ERR_OUT_OF_GAS)
        self.assertEqual(T.run_model(good, 5)[0], 'ok')
        bad = T.make_input(5, bytes(64), bytes(128), bytes(16), 2)
        self.assertEqual(T.run_model(bad, 4)[1], T.ERR_OUT_OF_GAS)
        self.assertEqual(T.run_model(bad, 5)[1], T.ERR_FLAG)
        self.assertEqual(T.run_model(T.make_input(5, bytes(64), bytes(128), bytes(16), 255), 5)[1], T.ERR_FLAG)

    def test_rounds_are_big_endian_and_gas_equals_rounds(self):
        data = T.make_input(0x0102, bytes(64), bytes(128), bytes(16), 1)
        self.assertEqual(T.run_model(data, 0x0101)[1], T.ERR_OUT_OF_GAS)
        self.assertEqual(T.run_model(data, 0x0102)[2], 0x0102)

    def test_zero_rounds_return_h_xor_iv_pairs(self):
        h = [1, 2, 3, 4, 5, 6, 7, 8]
        out = T.blake2_f(0, h, [0] * 16, [0, 0], 0)
        self.assertEqual(out, [h[i] ^ h[i] ^ T.IV[i] for i in range(8)])

    def test_nonzero_flag_word_is_final_block(self):
        args = ([3] * 8, list(range(16)), [9, 10])
        self.assertEqual(T.blake2_f(4, *args, 1), T.blake2_f(4, *args, 2))
        self.assertNotEqual(T.blake2_f(4, *args, 0), T.blake2_f(4, *args, 1))

    def test_every_model_mutant_is_detected_on_the_generated_cases(self):
        seen = {name: False for name in T.MODEL_MUTANTS}
        for index, (kind, data, gas, scenario, parity) in enumerate(T.run_cases()):
            if index % 3 or kind == 'digest':
                continue
            want = T.expected_run(self.rig, data, gas, scenario, parity)
            for name in T.MODEL_MUTANTS:
                if not seen[name] and T.expected_run(self.rig, data, gas, scenario, parity, name) != want:
                    seen[name] = True
        self.assertEqual([name for name, hit in seen.items() if not hit], [])

    def test_generators_are_deterministic(self):
        first = [(k, d, g, s, p) for k, d, g, s, p in list(T.run_cases())[:50]]
        second = [(k, d, g, s, p) for k, d, g, s, p in list(T.run_cases())[:50]]
        self.assertEqual(first, second)
        self.assertEqual(T.Rng(1).next(), T.Rng(1).next())
        self.assertNotEqual(T.Rng(1).next(), T.Rng(2).next())


class MachineTests(Fixture):
    def check(self, data, gas, scenario, parity):
        got = self.rig.call_run(data, gas, scenario, parity)
        self.assertEqual(got, T.expected_run(self.rig, data, gas, scenario, parity))
        return got

    def test_accepted_call_fills_the_bytes_value(self):
        data = T.make_input(12, bytes(range(64)), bytes(range(128)), bytes(16), 1)
        for scenario in range(4):
            for parity in (0, 1):
                got = self.check(data, 12, scenario, parity)
                self.assertEqual(got[0], 'ok')
                self.assertEqual(got[5], 0x40)
                self.assertEqual(got[6], got[4] | 1)
                self.assertEqual(got[3], self.rig.odd_vtable if parity else self.rig.even_vtable)
                self.assertEqual(got[8], (0x40,))

    def test_routes_follow_the_scenarios(self):
        data = T.make_input(2, bytes(64), bytes(128), bytes(16), 1)
        routes = [self.check(data, 2, s, 0)[7] for s in range(4)]
        self.assertEqual(routes, ['-', 'feature-init', 'avx2(2,1)', 'provider-init'])

    def test_errors_never_allocate_or_route(self):
        for data, gas in ((bytes(10), 99), (T.make_input(9, bytes(64), bytes(128), bytes(16), 0), 8),
                          (T.make_input(1, bytes(64), bytes(128), bytes(16), 9), 8)):
            got = self.check(data, gas, 3, 1)
            self.assertEqual(got[0], 'err')
            self.assertEqual(got[2:], ('-', 0))

    def test_error_codes_come_from_the_bytes(self):
        self.assertEqual(self.check(bytes(3), 0, 0, 0)[1], T.ERR_LENGTH)
        self.assertEqual(self.check(T.make_input(3, bytes(64), bytes(128), bytes(16), 0), 2, 0, 0)[1], T.ERR_OUT_OF_GAS)
        self.assertEqual(self.check(T.make_input(3, bytes(64), bytes(128), bytes(16), 4), 3, 0, 0)[1], T.ERR_FLAG)

    def test_digest_anchor_runs_on_the_recorded_bytes(self):
        data, reference = T.digest_case(5)
        self.assertEqual(self.rig.call_run(data, 12, 0, 0)[1], reference)

    def test_compression_body_matches_the_model(self):
        for rounds, h, mm, t, f in list(T.compress_cases())[:120]:
            self.assertEqual(self.rig.call_compress(rounds, h, mm, t, f), T.blake2_f(rounds, h, mm, t, f))

    def test_compression_flag_is_any_nonzero_word(self):
        h, mm, t = [7] * 8, list(range(16)), [3, 4]
        base = self.rig.call_compress(5, h, mm, t, 1)
        for f in (2, 0x100, 0x80000000, 0xFFFFFFFF):
            self.assertEqual(self.rig.call_compress(5, h, mm, t, f), base)
        self.assertNotEqual(self.rig.call_compress(5, h, mm, t, 0), base)

    def test_zero_and_large_round_counts(self):
        h, mm, t = [1] * 8, [2] * 16, [3, 4]
        self.assertEqual(self.rig.call_compress(0, h, mm, t, 0), T.blake2_f(0, h, mm, t, 0))
        self.assertEqual(self.rig.call_compress(40, h, mm, t, 1), T.blake2_f(40, h, mm, t, 1))


class NegativeControlTests(Fixture):
    def survives(self, va, mask):
        offset = self.image.offset(va)
        rig = T.Rig(self.image, {va: self.image.blob[offset] ^ mask})
        for data, gas, scenario, parity in T.control_suite():
            try:
                if rig.call_run(data, gas, scenario, parity) != T.expected_run(rig, data, gas, scenario, parity):
                    return False
            except T.FAULTS:
                return False
        return True

    def test_listed_byte_corruptions_are_caught(self):
        listed = T.corruption_controls(self.image)
        self.assertGreaterEqual(len(listed), 30)
        for label, va, mask in listed[:14]:
            self.assertFalse(self.survives(va, mask), label)

    def test_compression_corruption_is_caught_by_direct_calls(self):
        va = 0x5C3896D
        rig = T.Rig(self.image, {va: self.image.blob[self.image.offset(va)] ^ 1})
        cases = list(T.compress_cases())[:20]
        self.assertTrue(any(rig.call_compress(*c) != T.blake2_f(*c) for c in cases))

    def test_a_wrong_expectation_is_reported_as_a_difference(self):
        data = T.make_input(2, bytes(64), bytes(128), bytes(16), 0)
        got = self.rig.call_run(data, 2, 0, 0)
        self.assertNotEqual(got, T.expected_run(self.rig, data, 2, 0, 0, 'gas-used-plus-one'))
        self.assertNotEqual(got, T.expected_run(self.rig, data, 2, 0, 1))

    def test_loader_rejects_a_different_digest(self):
        with self.assertRaises(T.EvidenceError):
            T.load_image(expected='0' * 64)
        self.assertTrue(T.digest_rejected())

    def test_addresses_outside_file_backed_sections_are_refused(self):
        for va in (0, 0x1, 0x6500098, 0x7FFFFFFFFFFF):
            with self.assertRaises(T.EvidenceError):
                self.image.offset(va)
        with self.assertRaises(T.Halt):
            self.rig.m.memory.bytes_at(0x10, 8)

    def test_unmodelled_call_target_halts(self):
        rig = T.Rig(self.image)
        rig.m.slots.pop(rig.alloc_slot)
        data = T.make_input(1, bytes(64), bytes(128), bytes(16), 0)
        with self.assertRaises(T.Halt):
            rig.call_run(data, 1, 0, 0)


class EvidenceTests(Fixture):
    def test_vtable_slot_0x58_is_the_dispatcher(self):
        rows = {row[0]: row for row in T.vtable_rows(self.image)}
        self.assertEqual(rows[0x58][3], T.DISPATCH)
        self.assertEqual(rows[0x58][4], 0x68)
        self.assertEqual(rows[0x10][2], 'raw')
        self.assertEqual(len(rows), T.SLOT_COUNT)

    def test_constants_are_found_in_the_compression_body(self):
        rows = {row[0]: row for row in T.constant_rows(self.image)}
        for index in range(8):
            self.assertNotEqual(rows['iv%d' % index][2], '-')
        self.assertNotEqual(rows['iv6-inverted'][2], '-')
        self.assertEqual(rows['vector-arm-decodable-by-core'][1], 'no')
        self.assertEqual(rows['provider-state-initial'][1], '3')

    def test_function_extents_come_from_unwind_records(self):
        self.assertEqual(self.image.fde_ends[T.RUN] - T.RUN, 0x213)
        self.assertEqual(self.image.fde_ends[T.COMPRESS] - T.COMPRESS, 0x4E1)
        self.assertEqual(self.image.fde_ends[T.AVX2_BODY] - T.AVX2_BODY, 0xC9A)

    def test_relative_slots_bind_the_expected_targets(self):
        rel = self.image.relative()
        self.assertEqual(rel[T.VTABLE + 0x58], T.DISPATCH)
        self.assertEqual(rel[0x64EC358], T.CELL)
        self.assertEqual(rel[T.FLAG_POINTER_SLOT], 0x6500098)


class CoverageAndScopeTests(Fixture):
    def test_rng_is_splitmix64(self):
        rng = T.Rng(0)
        self.assertEqual(rng.next(), 0xE220A8397B1DCDAF)
        self.assertEqual(rng.next(), 0x6E789E6AA1B965F4)

    def test_case_counts_match_the_declared_denominators(self):
        kinds = {}
        for kind, *_ in T.run_cases():
            kinds[kind] = kinds.get(kind, 0) + 1
        self.assertEqual(kinds, {'length': 700, 'gas': 700, 'flag': 700, 'accept': 5800, 'alloc-failure': 240, 'digest': 129})
        self.assertEqual(len(list(T.compress_cases())), 3200)

    def test_huge_round_counts_are_refused_before_any_compression(self):
        data = T.make_input(0xFFFFFFFF, bytes(64), bytes(128), bytes(16), 1)
        got = self.rig.call_run(data, 0xFFFFFFFE, 0, 0)
        self.assertEqual(got, ('err', T.ERR_OUT_OF_GAS, '-', 0))
        self.assertEqual(self.rig.m.steps > 0, True)

    def test_allocation_failure_reaches_the_failure_handler_with_size_and_align(self):
        data = T.make_input(1, bytes(64), bytes(128), bytes(16), 0)
        for scenario in range(4):
            got = self.rig.call_run(data, 1, scenario, 2)
            self.assertEqual(got[:3], ('alloc-failure', 1, 0x40))
            self.assertEqual(got, T.expected_run(self.rig, data, 1, scenario, 2))

    def test_all_single_block_digests_run_on_the_bytes(self):
        for length in range(129):
            data, reference = T.digest_case(length)
            self.assertEqual(self.rig.call_run(data, 12, length % 4, length % 2)[1], reference)

    def test_every_conditional_jump_of_the_three_bodies_has_both_arms_after_a_mixed_run(self):
        rig = T.Rig(self.image)
        picked = [c for i, c in enumerate(T.run_cases()) if i % 17 == 0]
        for kind, data, gas, scenario, parity in picked:
            if kind == 'digest':
                data, _ = T.digest_case(gas)
                gas = 12
            rig.call_run(data, gas, scenario, parity)
        for case in list(T.compress_cases())[:60]:
            rig.call_compress(*case)
        rows = T.branch_rows(self.image, (rig,))
        self.assertEqual(len(rows), 9)
        self.assertEqual([r for r in rows if not (r[4] and r[5])], [])

    def test_each_model_mutant_has_a_distinguishing_case(self):
        rig = self.rig
        cases = [c for i, c in enumerate(T.run_cases()) if (i % 5 == 0 or c[0] == 'flag') and c[0] != 'digest']
        for name in T.MODEL_MUTANTS:
            with self.subTest(mutant=name):
                hit = any(T.expected_run(rig, d, g, s, p, name) != T.expected_run(rig, d, g, s, p) for _, d, g, s, p in cases)
                self.assertTrue(hit)

    def test_direct_mutant_changes_compression_for_nonone_flags(self):
        args = ([4] * 8, list(range(16)), [1, 2])
        self.assertNotEqual(T.blake2_f(3, *args, 2), T.blake2_f(3, *args, 2, 'flag-only-one'))
        self.assertEqual(T.blake2_f(3, *args, 1), T.blake2_f(3, *args, 1, 'flag-only-one'))

    def test_summary_text_is_stable_for_ok_and_error_results(self):
        data = T.make_input(0, bytes(64), bytes(128), bytes(16), 0)
        ok = self.rig.call_run(data, 0, 0, 0)
        self.assertTrue(T.ok_summary(ok).startswith('ok:'))
        self.assertEqual(T.ok_summary(('err', 5, '-', 0)), 'err:5:-:0')
        self.assertEqual(T.ok_summary(('alloc-failure', 1, 64, '-')), 'alloc-failure:1:64:-')

    def test_corruption_list_has_distinct_addresses(self):
        listed = T.corruption_controls(self.image)
        self.assertEqual(len({(va, mask) for _, va, mask in listed}), len(listed))
        for _, va, _ in listed:
            self.assertTrue(T.RUN <= va < self.image.fde_ends[T.RUN] or T.DISPATCH <= va < self.image.fde_ends[T.DISPATCH]
                            or T.COMPRESS <= va < self.image.fde_ends[T.COMPRESS])


class MatrixTests(Fixture):
    """Scenario by outcome matrices, one sub-test per cell."""

    def inputs(self):
        zero = (bytes(64), bytes(128), bytes(16))
        return {
            'short': (bytes(212), 9),
            'long': (bytes(214), 9),
            'out-of-gas': (T.make_input(6, *zero, 0), 5),
            'bad-flag': (T.make_input(6, *zero, 2), 6),
            'bad-flag-and-gas': (T.make_input(6, *zero, 3), 5),
            'ok-zero-rounds': (T.make_input(0, *zero, 0), 0),
            'ok-final': (T.make_input(12, *zero, 1), 100),
            'ok-ten': (T.make_input(10, *zero, 0), 10),
            'ok-eleven': (T.make_input(11, *zero, 0), 11),
        }

    def test_every_input_in_every_scenario_and_parity(self):
        for name, (data, gas) in self.inputs().items():
            for scenario in range(4):
                for parity in (0, 1, 2):
                    with self.subTest(case=name, scenario=scenario, parity=parity):
                        got = self.rig.call_run(data, gas, scenario, parity)
                        self.assertEqual(got, T.expected_run(self.rig, data, gas, scenario, parity))

    def test_error_precedence_cells(self):
        want = {'short': T.ERR_LENGTH, 'long': T.ERR_LENGTH, 'out-of-gas': T.ERR_OUT_OF_GAS, 'bad-flag': T.ERR_FLAG,
                'bad-flag-and-gas': T.ERR_OUT_OF_GAS}
        for name, code in want.items():
            data, gas = self.inputs()[name]
            with self.subTest(case=name):
                self.assertEqual(self.rig.call_run(data, gas, 0, 0)[1], code)

    def test_gas_is_charged_exactly_the_round_count(self):
        for name in ('ok-zero-rounds', 'ok-final', 'ok-ten', 'ok-eleven'):
            data, gas = self.inputs()[name]
            with self.subTest(case=name):
                self.assertEqual(self.rig.call_run(data, gas, 0, 0)[2], int.from_bytes(data[:4], 'big'))

    def test_each_listed_byte_corruption_changes_a_result(self):
        for label, va, mask in T.corruption_controls(self.image):
            with self.subTest(control=label):
                offset = self.image.offset(va)
                rig = T.Rig(self.image, {va: self.image.blob[offset] ^ mask})
                changed = False
                for data, gas, scenario, parity in T.control_suite():
                    try:
                        if rig.call_run(data, gas, scenario, parity) != T.expected_run(rig, data, gas, scenario, parity):
                            changed = True
                            break
                    except T.FAULTS:
                        changed = True
                        break
                if not changed:
                    for case in list(T.compress_cases())[:300]:
                        try:
                            if rig.call_compress(*case) != T.blake2_f(*case):
                                changed = True
                                break
                        except T.FAULTS:
                            changed = True
                            break
                self.assertTrue(changed)


if __name__ == '__main__':
    unittest.main()
