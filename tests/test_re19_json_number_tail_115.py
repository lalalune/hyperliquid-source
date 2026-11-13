import math
import pathlib
import random
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import re19_json_number_tail_115 as t  # noqa: E402

TABLE = [float("1e%d" % i) for i in range(t.TABLE_LEN)]
ENV = dict(table=TABLE, table_va=0x945558, scale=1e308, sign=1 << 63, magic_a=b"", magic_b=b"")
ACTIONS = {b: 0x3EF2D52 for b in range(0x5B, 0x7C)}
ACTIONS.update({0x5B: 0x3EF2D36, 0x7B: 0x3EF2D2D, 0x66: 0x3EF2AF8, 0x74: 0x3EF2BF7, 0x6E: 0x3EF2C6B})
M64 = (1 << 64) - 1


def call(data, idx, acc, dl, o=t.DEFAULT):
    return t.tail_model(data, idx, acc, dl, ENV, o)


class CodeReader:
    """A fake image serving hand-assembled bytes, so the interpreter runs without the node binary."""

    def __init__(self, code, base=0x1000):
        self.code = code
        self.base = base

    def offset(self, va):
        if not self.base <= va < self.base + len(self.code):
            raise t.EvidenceError("outside")
        return va - self.base


class SmallMachine(t.Machine):
    def read_code(self, va, count):
        start = va - self.image.base
        data = bytearray((self.image.code + b"\x90" * 16)[start:start + count])
        for index in range(count):
            if va + index in self.patches:
                data[index] = self.patches[va + index]
        return data


class IntegerPaths(unittest.TestCase):
    def test_positive_integer_is_passed_through(self):
        self.assertEqual(call(b"", 0, 77, 1)[:2], (1, 77))

    def test_negative_integer_is_twos_complement(self):
        self.assertEqual(call(b"", 0, 5, 0)[:2], (2, (-5) & M64))

    def test_negative_limit_is_two_to_the_63(self):
        self.assertEqual(call(b"", 0, 1 << 63, 0)[:2], (2, 1 << 63))
        tag, bits = call(b"", 0, (1 << 63) + 1, 0)[:2]
        self.assertEqual(tag, 0)
        self.assertEqual(bits, t.fbits(float((1 << 63) + 1)) | 1 << 63)

    def test_negative_zero_is_a_float(self):
        self.assertEqual(call(b"", 0, 0, 0)[:2], (0, 1 << 63))

    def test_index_past_end_takes_the_integer_path(self):
        self.assertEqual(call(b"ab", 9, 4, 1)[:2], (1, 4))

    def test_low_byte_of_dl_decides_the_sign(self):
        self.assertEqual(call(b"", 0, 5, 0x100)[0], 2)
        self.assertEqual(call(b"", 0, 5, 0x80)[0], 1)


class FractionPaths(unittest.TestCase):
    def test_simple_fraction(self):
        tag, bits, idx, trace = call(b"1.5", 1, 1, 1)
        self.assertEqual((tag, t.fval(bits), idx, trace), (0, 1.5, 3, []))

    def test_negative_fraction(self):
        tag, bits, idx, trace = call(b"1.25", 1, 1, 0)
        self.assertEqual((tag, t.fval(bits)), (0, -1.25))

    def test_dot_at_end_is_eof_error(self):
        tag, payload, idx, trace = call(b"1.", 1, 1, 1)
        self.assertEqual((tag, idx, trace), (3, 2, [("at", 5, 2)]))

    def test_dot_without_digit_is_invalid_number(self):
        self.assertEqual(call(b"1.x", 1, 1, 1)[3], [("at", 0xD, 2)])

    def test_exponent_after_digits_passes_negative_count(self):
        trace = call(b"1.25e3", 1, 1, 1)[3]
        self.assertEqual(trace, [("exp", 125, -2, 1, 4)])

    def test_exponent_directly_passes_zero_count(self):
        self.assertEqual(call(b"5e2", 1, 5, 1)[3], [("exp", 5, 0, 1, 1)])
        self.assertEqual(call(b"5E2", 1, 5, 1)[3], [("exp", 5, 0, 1, 1)])

    def test_accumulator_limit_boundary(self):
        limit = t.LIMIT
        self.assertEqual(call(b".5", 0, limit + 1, 1)[3], [])
        self.assertEqual(call(b".6", 0, limit + 1, 1)[3][0][0], "slow")
        self.assertEqual(call(b".0", 0, limit + 2, 1)[3][0][0], "slow")
        self.assertEqual(call(b".9", 0, limit, 1)[3], [])

    def test_slow_path_records_digit_count(self):
        trace = call(b".11" + b"9" * 20, 0, t.LIMIT, 1)[3]
        self.assertEqual(trace[0][0], "slow")
        self.assertLess(trace[0][2], 0)

    def test_scaling_matches_division_by_power_of_ten(self):
        tag, bits, _, _ = call(b".123", 0, 0, 1)
        self.assertEqual(t.fval(bits), 123 / 1000.0)

    def test_digit_run_past_the_limit_leaves_through_the_slow_path(self):
        data = b"." + b"1" * 320
        tag, bits, idx, trace = call(data, 0, 0, 1)
        self.assertEqual([x[0] for x in trace], ["slow"])
        self.assertEqual(trace[0][2], -20)


class FinishPaths(unittest.TestCase):
    def finish(self, acc, e, dl=1, o=t.DEFAULT):
        return t.finish_want(acc, e, dl, ENV, o)

    def test_zero_survives_every_scale(self):
        for e in (-1, -400, -1000, 5000):
            tag, bits, _, trace = self.finish(0, e)
            self.assertEqual((tag, bits, trace), (0, 0, []))

    def test_negative_zero(self):
        self.assertEqual(self.finish(0, -400, 0)[1], 1 << 63)

    def test_positive_exponent_overflow_is_error_14(self):
        tag, payload, _, trace = self.finish(10 ** 18, 300)
        self.assertEqual((tag, trace), (3, [("peek", 0xE, 0)]))

    def test_positive_exponent_large_count_is_error_14(self):
        self.assertEqual(self.finish(5, 400)[3], [("peek", 0xE, 0)])

    def test_two_step_threshold(self):
        a = self.finish(1, -0x134)
        b = self.finish(1, -0x135)
        self.assertEqual(t.fval(a[1]), 1 / 1e308)
        self.assertEqual(t.fval(b[1]), (1 / 1e308) / TABLE[1])

    def test_sign_applies_after_scaling(self):
        pos = self.finish(7, -2, 1)[1]
        neg = self.finish(7, -2, 0)[1]
        self.assertEqual(neg, pos | 1 << 63)

    def test_e_is_32_bit_signed(self):
        self.assertEqual(self.finish(7, (-2) & 0xFFFFFFFF), self.finish(7, -2))


class Mutants(unittest.TestCase):
    def sweep(self):
        rng = random.Random(7)
        cases = list(t.boundary_cases())
        gen = t.all_cases(0, 99)
        for _ in range(4000):
            cases.append(next(gen))
        return cases, list(t.fragment_cases(random.Random(8), 2000))

    def test_every_model_mutant_is_separated_by_the_case_families(self):
        cases, frags = self.sweep()
        for name, change in t.MUTANTS:
            o = dict(t.DEFAULT)
            o.update(change)
            found = False
            for data, idx, acc, dl in cases:
                try:
                    if call(data, idx, acc, dl, o) != call(data, idx, acc, dl):
                        found = True
                        break
                except (IndexError, KeyError, t.EvidenceError):
                    found = True
                    break
            if not found:
                for acc, e, dl in frags:
                    try:
                        if t.finish_want(acc, e, dl, ENV, o) != t.finish_want(acc, e, dl, ENV):
                            found = True
                            break
                    except (IndexError, KeyError, t.EvidenceError):
                        found = True
                        break
            self.assertTrue(found, name)

    def test_mutant_names_are_unique_and_change_something(self):
        names = [n for n, _ in t.MUTANTS]
        self.assertEqual(len(names), len(set(names)))
        for _, change in t.MUTANTS:
            for key, value in change.items():
                self.assertIn(key, t.DEFAULT)
                self.assertNotEqual(t.DEFAULT[key], value)

    def test_agrees_rejects_each_field(self):
        want = (0, 5, 3, [("at", 5, 3)])
        base = (0, 5, 3, (("at", 5, 3),), t.DATA, 4)
        self.assertTrue(t.agrees(base, want))
        for bad in ((1, 5, 3, (("at", 5, 3),), t.DATA, 4), (0, 6, 3, (("at", 5, 3),), t.DATA, 4), (0, 5, 4, (("at", 5, 3),), t.DATA, 4),
                    (0, 5, 3, (("at", 5, 4),), t.DATA, 4), (0, 5, 3, (), t.DATA, 4), (0, 5, 3, (("at", 5, 3),), t.DATA + 1, 4)):
            self.assertFalse(t.agrees(bad, want))


class PeekModel(unittest.TestCase):
    def peek(self, data, idx=0, o=t.DEFAULT_PEEK):
        return t.peek_model(data, idx, 11, 22, ACTIONS, o)

    def test_eof_is_value_error_with_fixup(self):
        rax, idx, slot, trace = self.peek(b"", 0)
        self.assertEqual([x[0] for x in trace], ["at", "fix"])
        self.assertEqual(trace[0][1], 0xA)

    def test_literals_advance_and_report_unexpected(self):
        for word, tag, b1, end in ((b"false", 0, 0, 5), (b"true", 0, 1, 4), (b"null", 7, 0, 4)):
            rax, idx, slot, trace = self.peek(word)
            self.assertEqual(idx, end)
            self.assertEqual(trace[0][:3], ("unexp", tag, b1))
            self.assertEqual(trace[1][0], "fix")

    def test_literal_truncation_and_mismatch_codes(self):
        self.assertEqual(self.peek(b"fals")[3][-1], ("peek", 5, 4))
        self.assertEqual(self.peek(b"falsx")[3][-1], ("peek", 9, 5))
        self.assertEqual(self.peek(b"tx")[3][-1], ("peek", 9, 2))

    def test_brackets_do_not_advance(self):
        self.assertEqual(self.peek(b"[")[1], 0)
        self.assertEqual(self.peek(b"[")[3][0][1], 0xA)
        self.assertEqual(self.peek(b"{")[3][0][1], 0xB)

    def test_minus_advances_and_digit_does_not(self):
        self.assertEqual(self.peek(b"-1")[1], 1)
        self.assertEqual(self.peek(b"1")[1], 0)
        self.assertEqual(self.peek(b"-1")[3][0], ("num", 0, 1))
        self.assertEqual(self.peek(b"1")[3][0], ("num", 1, 0))

    def test_string_clears_slot(self):
        rax, idx, slot, trace = self.peek(b"\"x")
        self.assertEqual((idx, slot), (1, 0))
        self.assertEqual(trace[0][0], "str")
        o = dict(t.DEFAULT_PEEK, string_clear=False)
        self.assertEqual(self.peek(b"\"x", 0, o)[2], t.SLOT10)

    def test_other_bytes_are_value_errors(self):
        for ch in (0x20, 0x41, 0x5D, 0x7D, 0xFF, 0x2F, 0x3A):
            self.assertEqual(self.peek(bytes([ch]))[3][0], ("at", 0xA, 0))

    def test_every_peek_mutant_is_separated(self):
        rng = random.Random(3)
        cases = list(t.peek_cases(rng, 800))
        for name, change in t.PEEK_MUTANTS:
            o = dict(t.DEFAULT_PEEK)
            o.update(change)
            self.assertTrue(any(self.peek_diff(c, o) for c in cases), name)

    def peek_diff(self, case, o):
        data, idx, rsi, rdx = case
        return t.peek_model(data, idx, rsi, rdx, ACTIONS) != t.peek_model(data, idx, rsi, rdx, ACTIONS, o)

    def test_peek_agrees_rejects_each_field(self):
        run = (5, 1, 0, (("fix", 1, 1),), t.DATA)
        want = (5, 1, 0, [("fix", 1, 1)])
        self.assertTrue(t.peek_agrees(run, want))
        for bad in ((6, 1, 0, run[3], t.DATA), (5, 2, 0, run[3], t.DATA), (5, 1, 1, run[3], t.DATA), (5, 1, 0, (), t.DATA), (5, 1, 0, run[3], 0)):
            self.assertFalse(t.peek_agrees(bad, want))


class Helpers(unittest.TestCase):
    def test_mix_depends_on_every_argument(self):
        base = t.mix(1, 2, 3)
        self.assertNotEqual(base, t.mix(2, 2, 3))
        self.assertNotEqual(base, t.mix(1, 3, 3))
        self.assertNotEqual(base, t.mix(1, 2, 4))
        self.assertNotEqual(base, t.mix(1, 2, 3, 0))

    def test_float_bit_helpers_round_trip(self):
        for x in (0.0, -0.0, 1.5, 1e308, 5e-324):
            self.assertEqual(t.fbits(t.fval(t.fbits(x))), t.fbits(x))
        self.assertEqual(t.fbits(-0.0), 1 << 63)

    def test_stub_result_covers_both_tags(self):
        tags = {t.stub_result(1, a, 0, 1, 0)[0] for a in range(64)}
        self.assertEqual(tags, {0, 1})

    def test_s64(self):
        self.assertEqual(t.s64(M64), -1)
        self.assertEqual(t.s64(1 << 63), -(1 << 63))
        self.assertEqual(t.s64(5), 5)

    def test_table_actions_reads_signed_offsets(self):
        entries = [0x10 * i - 0x40 for i in range(t.TABLE_COUNT)]
        blob = bytearray(0x40) + struct.pack("<%di" % t.TABLE_COUNT, *entries)

        class Fake:
            def offset(self, va):
                return 0x40 + va - t.JUMP_TABLE

        Fake.blob = bytes(blob)
        got = t.table_actions(Fake())
        self.assertEqual(got[0x5B], t.JUMP_TABLE - 0x40)
        self.assertEqual(got[0x7B], t.JUMP_TABLE + entries[-1])
        self.assertEqual(len(got), 33)

    def test_tsv_writes_header_and_rows(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "x.tsv"
            t.tsv(path, ["a", "b"], [(1, "x"), (2, "y")])
            self.assertEqual(path.read_text(), "a\tb\n1\tx\n2\ty\n")

    def test_load_image_rejects_wrong_digest(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "blob"
            path.write_bytes(b"not an elf")
            with self.assertRaises(t.EvidenceError):
                t.load_image(path)

    def test_read_environment_requires_relocation(self):
        class Fake:
            def relative(self):
                return {}

        with self.assertRaises(t.EvidenceError):
            t.read_environment(Fake())


class Interpreter(unittest.TestCase):
    def run_code(self, code, args):
        machine = SmallMachine(CodeReader(code))
        return machine.run(0x1000, args)

    def test_add_and_ret(self):
        # lea rax,[rdi+rsi]; ret
        self.assertEqual(self.run_code(bytes.fromhex("488d0437c3"), {t.RDI: 5, t.RSI: 7}), 12)

    def test_conditional_jump(self):
        # cmp rdi,rsi; jae +3; mov eax,1 ; ret ; (target) mov eax,2 ; ret
        code = bytes.fromhex("4839f7") + bytes.fromhex("7306") + bytes.fromhex("b801000000c3") + bytes.fromhex("b802000000c3")
        self.assertEqual(self.run_code(code, {t.RDI: 1, t.RSI: 2}), 1)
        self.assertEqual(self.run_code(code, {t.RDI: 3, t.RSI: 2}), 2)

    def test_patch_flips_the_branch(self):
        code = bytes.fromhex("4839f7") + bytes.fromhex("7306") + bytes.fromhex("b801000000c3") + bytes.fromhex("b802000000c3")
        machine = SmallMachine(CodeReader(code), {0x1003: 0x72})
        self.assertEqual(machine.run(0x1000, {t.RDI: 1, t.RSI: 2}), 2)

    def test_unmodelled_call_halts(self):
        code = bytes.fromhex("e8fb0f0000c3")
        with self.assertRaises(t.Halt):
            self.run_code(code, {})

    def test_decode_reports_jcc_target(self):
        rows = []
        code = bytes.fromhex("7405")
        row = t.decode(lambda va, n: code[va - 0x1000:va - 0x1000 + n], 0x1000)
        rows.append(row)
        self.assertEqual((rows[0].op, rows[0].target), ("jcc", 0x1007))


class PatchCandidates(unittest.TestCase):
    def test_jcc_and_immediates_are_listed(self):
        code = bytes.fromhex("740583f90a48b8" + "ff" * 8 + "c3")
        blob = bytearray(code)

        class Fake:
            pass

        image = Fake()
        image.blob = bytes(blob)
        image.offset = lambda va: va - 0x1000
        rows = []
        va = 0x1000
        while va < 0x1000 + len(code):
            row = t.decode(lambda a, n: code[a - 0x1000:a - 0x1000 + n], va)
            rows.append(row)
            va = row.next
        names = [c[0] for c in t.patch_candidates(image, rows)]
        self.assertIn("invert-jcc-1000", names)
        self.assertTrue(any(n.startswith("bump-immediate") for n in names))
        self.assertTrue(any(n.startswith("bump-constant") for n in names))
        got = {c[0]: c[1:] for c in t.patch_candidates(image, rows)}
        self.assertEqual(got["invert-jcc-1000"], (0x1000, 0x74, 0x75))
        self.assertEqual(got["bump-immediate-1002"], (0x1004, 0x0A, 0x0B))


class DecimalFastPath(unittest.TestCase):
    """For at most 15 significant digits (here 1 + 14) and a scale up to 22 a single division is the correctly rounded decimal value."""

    def test_model_matches_python_decimal_parse(self):
        rng = random.Random(5)
        for _ in range(3000):
            whole = rng.randint(0, 9)
            count = rng.randint(1, 14)
            digits = "".join(rng.choice("0123456789") for _ in range(count))
            data = (str(whole) + "." + digits).encode()
            for dl in (0, 1):
                tag, bits, idx, trace = call(data, 1, whole, dl)
                self.assertEqual(tag, 0)
                self.assertEqual(trace, [])
                self.assertEqual(idx, len(data))
                want = float(data.decode())
                self.assertEqual(t.fval(bits), want if dl else -want, data)

    def test_trailing_garbage_stops_the_run_without_error(self):
        for tail in (b"x", b",", b"}", b" ", b"\xb0"):
            tag, bits, idx, trace = call(b"3.14" + tail, 1, 3, 1)
            self.assertEqual((tag, t.fval(bits), idx), (0, 3.14, 4))

    def test_index_tracks_last_consumed_digit(self):
        self.assertEqual(call(b"1.234x", 1, 1, 1)[2], 5)
        self.assertEqual(call(b"1.x", 1, 1, 1)[2], 2)
        self.assertEqual(call(b"1.", 1, 1, 1)[2], 2)

    def test_accumulator_wraps_into_slow_path_exactly_at_the_limit(self):
        digits = b"1844674407370955161"
        acc = int(digits[:-1])
        self.assertEqual(call(b"." + digits[-1:], 0, acc, 1)[3], [])
        self.assertEqual(call(b".9", 0, acc, 1)[3], [])
        tag, bits, idx, trace = call(b"." + b"55", 0, acc * 10 + 5, 1)
        self.assertEqual([x[0] for x in trace], ["slow"])


class StubContract(unittest.TestCase):
    def test_error_words_are_tagged_and_distinct(self):
        words = {t.error_word(kind, code, idx) for kind in (1, 2, 3, 4) for code in (5, 9, 0xA, 0xD, 0xE) for idx in (0, 1, 2)}
        self.assertEqual(len(words), 60)
        self.assertTrue(all(w >> 63 for w in words))

    def test_fixword_changes_with_position(self):
        self.assertNotEqual(t.fixword(5, 1), t.fixword(5, 2))
        self.assertNotEqual(t.fixword(5, 1), t.fixword(6, 1))
        self.assertEqual(t.fixword(5, 1) >> 62 & 1, 1)

    def test_stub_results_are_deterministic_and_error_values_are_marked(self):
        for acc in range(50):
            first = t.stub_result(3, acc, -4, 1, 99)
            self.assertEqual(first, t.stub_result(3, acc, -4, 1, 99))
            if first[0] == 1:
                self.assertEqual(first[1] >> 60, 0xE)

    def test_stub_result_depends_on_kind_and_scale(self):
        seen = {t.stub_result(kind, 7, scale, 1, 0) for kind in (1, 3) for scale in (0, -1, -2)}
        self.assertGreater(len(seen), 3)


class CaseFamilies(unittest.TestCase):
    def test_boundary_cases_are_fixed(self):
        cases = list(t.boundary_cases())
        self.assertEqual(len(cases), 9 * 8 * 2 + 2 * 7 * 2)
        self.assertIn((b".5", 0, t.LIMIT + 1, 1), cases)
        self.assertIn((b"", 0, 1 << 63, 0), cases)

    def test_generation_is_deterministic_and_seeded(self):
        a = [next(t.all_cases(0, 1)) for _ in range(3)]
        first = t.all_cases(0, 1)
        second = t.all_cases(0, 1)
        self.assertEqual([next(first) for _ in range(300)], [next(second) for _ in range(300)])
        self.assertEqual(a[0], a[1])
        other = t.all_cases(0, 2)
        skip = len(list(t.boundary_cases()))
        left, right = t.all_cases(0, 1), t.all_cases(0, 2)
        rows = [(next(left), next(right)) for _ in range(skip + 50)][skip:]
        self.assertTrue(any(x != y for x, y in rows))
        self.assertIsNotNone(other)

    def test_fragment_counts_stay_in_32_bit_range(self):
        cases = list(t.fragment_cases(random.Random(1), 500))
        self.assertEqual(len(cases), 500)
        for acc, e, dl in cases:
            self.assertTrue(0 <= acc <= M64)
            self.assertTrue(-4000 <= e <= 5000)
            self.assertIn(dl, (0, 1, 3, 0x80))

    def test_peek_cases_cover_every_first_byte(self):
        firsts = {data[0] for data, idx, rsi, rdx in t.peek_cases(random.Random(2), 0) if data and idx == 0}
        self.assertEqual(firsts & set(range(256)), set(range(256)))

    def test_peek_cases_have_64_bit_arguments(self):
        for data, idx, rsi, rdx in t.peek_cases(random.Random(4), 200):
            self.assertTrue(0 <= rsi <= M64 and 0 <= rdx <= M64)
            self.assertGreaterEqual(idx, 0)

    def test_outcome_names(self):
        self.assertEqual([t.outcome((tag,)) for tag in range(5)], ["float", "unsigned", "signed", "error", "tag4"])


class ControlsAreAccounted(unittest.TestCase):
    def test_equivalent_reasons_name_existing_mutants(self):
        names = {n for n, _ in t.MUTANTS}
        for key in t.EQUIVALENT_REASON:
            self.assertIn(key, names)

    def test_constants_are_consistent(self):
        self.assertEqual(t.LIMIT, 0x1999999999999998)
        self.assertEqual(t.TABLE_LEN, 309)
        self.assertEqual(t.TABLE_COUNT, 33)
        self.assertEqual(t.SLOT10, 0x77)
        self.assertEqual(len(t.TABLE_LEN * [0]), len(TABLE))

    def test_default_knobs_match_the_recovered_constants(self):
        d = t.DEFAULT
        self.assertEqual((d["limit"], d["last_digit"], d["empty_code"], d["eof_code"]), (t.LIMIT, 5, 0xD, 5))
        self.assertEqual((d["big_threshold"], d["step"], d["neg_limit"]), (0x135, 0x134, 1 << 63))
        p = t.DEFAULT_PEEK
        self.assertEqual((p["eof_code"], p["mismatch_code"], p["value_code"]), (5, 9, 0xA))
        self.assertEqual((p["seq_tag"], p["map_tag"], p["str_tag"], p["null_tag"]), (0xA, 0xB, 5, 7))


if __name__ == "__main__":
    unittest.main()
