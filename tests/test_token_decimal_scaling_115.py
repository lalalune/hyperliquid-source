import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import decimal_scaled_u64 as cpu  # noqa: E402
import token_decimal_scaling_115 as t  # noqa: E402

DATA = t.TARGET.read_bytes()
IMAGE = cpu.Image(DATA)
FOLDER = ROOT / "research/work-items/exchange-token-decimal-scaling-115"
U64 = t.U64


def real(case):
    got, trace, _ = t.execute(IMAGE, case)
    return got, trace


def muldiv(a, b, toks, tok):
    return real(dict(kind="muldiv", a=a, b=b, toks=toks, tok=tok))[0]


def percent(a, b, toks, tok, up=0):
    return real(dict(kind="percent", a=a, b=b, toks=toks, tok=tok, up=up))[0]


def scaler(exp, value):
    return real(dict(kind="scaler", exp=exp, value=value))[0]


class Digest(unittest.TestCase):
    def test_digest(self):
        self.assertTrue(t.check_digest(DATA))

    def test_flipped_byte_fails(self):
        damaged = bytearray(DATA)
        damaged[1000] ^= 0x40
        self.assertFalse(t.check_digest(bytes(damaged)))

    def test_extents(self):
        for fn, size in t.SIZES.items():
            self.assertEqual(t.body_extent(IMAGE, fn), size)

    def test_inner_address_is_not_a_start(self):
        with self.assertRaises(cpu.ToolError):
            t.body_extent(IMAGE, t.PERCENT + 1)

    def test_locations(self):
        self.assertEqual(t.decode_location(IMAGE, 0x6476a48)[1:], (1206, 57))
        self.assertEqual(t.decode_location(IMAGE, 0x64768d8)[1:], (119, 33))
        with self.assertRaises(cpu.ToolError):
            t.decode_location(IMAGE, 0x400100)
        with self.assertRaises(cpu.ToolError):
            t.panic_name(IMAGE, 0x400100)


class MulDiv(unittest.TestCase):
    TOKS = [(0, 0), (2, 8), (5, 5), (8, 3), (0, 19), (0, 20)]

    def test_token_zero_is_unscaled_even_without_rows(self):
        self.assertEqual(muldiv(6, 7, [], 0), ("ok", 1, 42))

    def test_scaled_product(self):
        self.assertEqual(muldiv(10 ** 6, 3 * 10 ** 4, self.TOKS, 1), ("ok", 1, 3 * 10 ** 4))

    def test_equal_decimals_do_not_scale(self):
        self.assertEqual(muldiv(9, 9, self.TOKS, 2), ("ok", 1, 81))

    def test_floor_division(self):
        self.assertEqual(muldiv(1, 999999, self.TOKS, 1), ("ok", 1, 0))
        self.assertEqual(muldiv(1, 10 ** 6, self.TOKS, 1), ("ok", 1, 1))

    def test_underflow_panics(self):
        self.assertEqual(muldiv(1, 1, self.TOKS, 3), ("panic", "scale_range"))

    def test_scale_above_u64_panics(self):
        self.assertEqual(muldiv(1, 1, self.TOKS, 4), ("ok", 1, 0))
        self.assertEqual(muldiv(1, 1, self.TOKS, 5), ("panic", "scale_range"))

    def test_row_bound(self):
        self.assertEqual(muldiv(1, 1, self.TOKS, 6), ("panic", "tokens_oob"))
        self.assertEqual(muldiv(1, 1, self.TOKS, 10 ** 12), ("panic", "tokens_oob"))

    def test_overflow_falls_back_to_divide_first(self):
        self.assertEqual(muldiv(U64, 2, self.TOKS, 0), ("ok", 0, (U64 * 2) & U64))
        self.assertEqual(muldiv(10 ** 19, 10 ** 19, self.TOKS, 4), ("ok", 1, 10 ** 19))

    def test_specification_agrees_on_edge_scales(self):
        for diff in range(0, 40):
            case = dict(kind="muldiv", toks=[(0, 0), (1, (1 + diff) & 0xff)], tok=1, a=U64 // 3, b=5)
            self.assertEqual(real(case)[0], t.spec(case)[0], diff)


class Percent(unittest.TestCase):
    TOKS = [(0, 0), (0, 2), (6, 1)]

    def test_plain_percent(self):
        self.assertEqual(percent(5000, 200, self.TOKS, 0), ("ok", 1, 10000))

    def test_scale_and_percent(self):
        self.assertEqual(percent(10 ** 6, 10 ** 6, self.TOKS, 1), ("ok", 1, 10 ** 12 // 10 ** 4))

    def test_round_up_only_when_inexact(self):
        self.assertEqual(percent(1, 150, self.TOKS, 0, up=1), ("ok", 1, 2))
        self.assertEqual(percent(1, 150, self.TOKS, 0, up=0), ("ok", 1, 1))
        self.assertEqual(percent(1, 200, self.TOKS, 0, up=1), ("ok", 1, 2))

    def test_flag_is_the_low_byte(self):
        self.assertEqual(percent(1, 150, self.TOKS, 0, up=0x100), ("ok", 1, 1))
        self.assertEqual(percent(1, 150, self.TOKS, 0, up=0x1ff), ("ok", 1, 2))

    def test_bound_is_two_pow_64_over_100(self):
        self.assertEqual(t.PCT_BOUND, (1 << 64) // 100)
        self.assertEqual(percent(t.PCT_BOUND - 1, 100, self.TOKS, 0), ("ok", 1, t.PCT_BOUND - 1))
        self.assertEqual(percent(t.PCT_BOUND, 100, self.TOKS, 0), ("ok", 0, t.PCT_BOUND))

    def test_no_zero_row_shortcut(self):
        self.assertEqual(percent(1, 1, [], 0), ("panic", "tokens_oob"))

    def test_underflow_and_bound_panics(self):
        self.assertEqual(percent(1, 1, self.TOKS, 2), ("panic", "scale_range"))
        self.assertEqual(percent(1, 1, self.TOKS, 3), ("panic", "tokens_oob"))

    def test_division_goes_through_the_statically_linked_helper(self):
        case = dict(kind="percent", a=3, b=300, toks=self.TOKS, tok=0, up=0)
        got, trace = real(case)
        self.assertEqual(trace, [("udiv128", 900, 100)])
        self.assertEqual(got, ("ok", 1, 9))


class Scaler(unittest.TestCase):
    def test_zero_exponent_divides_by_one(self):
        self.assertEqual(scaler(0, 12345), ("ok", 1, 12345, 12345))

    def test_positive_exponent_divides_in_place(self):
        self.assertEqual(scaler(3, 12345678), ("ok", 1, 12345, 12345))

    def test_negative_exponent_multiplies_without_touching_the_input(self):
        self.assertEqual(scaler(-3, 12345), ("ok", 1, 12345000, 12345))

    def test_failed_divide_check_still_stored_the_quotient(self):
        got = scaler(1, t.SIGNED_BOUND * 10 + 9)
        self.assertEqual(got, ("ok", 0, None, t.SIGNED_BOUND))
        self.assertEqual(scaler(1, t.SIGNED_BOUND * 10 - 1), ("ok", 1, t.SIGNED_BOUND - 1, t.SIGNED_BOUND - 1))

    def test_bound(self):
        self.assertEqual(t.SIGNED_BOUND, (1 << 63) // 10)
        self.assertEqual(scaler(0, t.SIGNED_BOUND)[1], 0)
        self.assertEqual(scaler(0, t.SIGNED_BOUND - 1)[1], 1)

    def test_magnitude_limits(self):
        self.assertEqual(scaler(-19, 1)[1], 0)  # 10 ** 19 is above the bound
        self.assertEqual(scaler(-18, 0)[1], 1)
        self.assertEqual(scaler(-20, 0)[1], 0)
        self.assertEqual(scaler(20, 0)[1], 0)
        self.assertEqual(scaler(-32, 0)[1], 0)
        self.assertEqual(scaler(127, 0)[1], 0)
        self.assertEqual(scaler(-128, 0)[1], 0)

    def test_multiply_overflow_refuses(self):
        self.assertEqual(scaler(-10, t.U256 // 10 ** 10 + 1)[1], 0)

    def test_high_words_are_part_of_the_value(self):
        self.assertEqual(scaler(0, 1 << 64)[1], 0)
        self.assertEqual(scaler(10, 1 << 64), ("ok", 1, 1844674407, 1844674407))

    def test_division_runs_the_real_body(self):
        value = 10 ** 40 + 12345
        got, trace = real(dict(kind="scaler", exp=5, value=value))
        self.assertEqual(trace, [("div256", value, 10 ** 5)])
        self.assertEqual(got[3], value // 10 ** 5)
        self.assertEqual(got[1], 0)

    def test_multiply_trace_names_both_operands(self):
        self.assertEqual(real(dict(kind="scaler", exp=-4, value=77))[1], [("mul256", 77, 10 ** 4)])

    def test_imported_memcpy_and_memset_are_reached(self):
        seen = set()
        for i in range(600):
            case = t.make_case(i)
            if case["kind"] == "scaler":
                seen |= set(t.execute(IMAGE, case)[2])
        self.assertIn(t.DIV256, seen)
        self.assertIn(t.MUL256, seen)
        self.assertTrue({t.MEMCPY_SLOT, t.MEMSET_SLOT} & seen)

    def test_memset_model_fills_and_returns(self):
        m = t.Recorder(IMAGE)
        m.setup({})
        m.set_reg(cpu.RSP, t.STACK_TOP - 16)
        m.put_mem(t.STACK_TOP - 16, 0x1234)
        m.set_reg(cpu.RDI, t.VAL)
        m.set_reg(cpu.RSI, 0x1ff)
        m.set_reg(cpu.RDX, 4)
        m.pc = t.MEMSET_MARK
        m.step()
        self.assertEqual([m.mem[t.VAL + i] for i in range(4)], [0xff] * 4)
        self.assertEqual(m.pc, 0x1234)
        m.pc = t.MEMSET_MARK
        m.set_reg(cpu.RSI, 0)
        m.set_reg(cpu.RDI, t.VAL)
        m.set_reg(cpu.RDX, 5000)
        with self.assertRaises(cpu.ToolError):
            m.step()

    def test_i8_domain(self):
        with self.assertRaises(ValueError):
            t.spec_scaler(dict(kind="scaler", exp=128, value=0))


class Machinery(unittest.TestCase):
    def test_words_round_trip(self):
        self.assertEqual(t.unwords(t.words(t.U256 - 12345)), t.U256 - 12345)

    def test_wide_store_is_refused(self):
        m = t.Recorder(IMAGE)
        m.setup({})
        with self.assertRaises(OverflowError):
            m.put_mem(0x10, 1 << 64)

    def test_unknown_call_target_is_refused(self):
        m = t.Recorder(IMAGE)
        m.setup({})
        with self.assertRaises(cpu.ToolError):
            m.call(0x1234, 0)

    def test_call_sites_are_found_by_byte_pattern(self):
        rows = t.call_sites(IMAGE)
        self.assertEqual({r[0] for r in rows}, {t.MULDIV})
        self.assertEqual(len(rows), 10)
        self.assertIn(0x38bc873, [r[1] for r in rows])


class Cases(unittest.TestCase):
    def test_case_generator_is_deterministic(self):
        self.assertEqual([t.make_case(i) for i in range(300)], [t.make_case(i) for i in range(300)])

    def test_every_kind_appears(self):
        self.assertEqual({t.make_case(i)["kind"] for i in range(40)}, {"muldiv", "percent", "scaler"})

    def test_first_cases_match(self):
        self.assertIsNone(t.run_cases(IMAGE, 400))

    def test_directed_cases_match(self):
        for n in range(80):
            ok, got, _ = t.compare(IMAGE, t.directed(n))
            self.assertTrue(ok, (n, got))


class Controls(unittest.TestCase):
    def test_every_spec_mutant_is_caught(self):
        for name, _, kind in t.SPEC_MUTANTS:
            self.assertIsNotNone(t.run_cases(IMAGE, t.CONTROL_CASES, (name,), only=kind), name)

    def test_unmutated_spec_is_not_flagged(self):
        for kind in ("muldiv", "percent", "scaler"):
            self.assertIsNone(t.run_cases(IMAGE, 300, (), only=kind))

    def test_byte_patches_apply_and_change_one_byte(self):
        for patch in t.BYTE_PATCHES:
            clone = t.patched_image(IMAGE, patch)
            off = IMAGE.file_offset(patch[1])
            window = bytes(DATA[off:off + t.SIZES[patch[1]]])
            now = bytes(clone.data[off:off + t.SIZES[patch[1]]])
            self.assertEqual(sum(1 for a, b in zip(window, now) if a != b), 1, patch[0])

    def test_byte_patches_are_caught(self):
        for patch in t.BYTE_PATCHES:
            clone = t.patched_image(IMAGE, patch)
            caught = False
            for i in range(t.CONTROL_CASES * 3):
                case = t.make_case(i)
                if case["kind"] != patch[6]:
                    continue
                try:
                    ok, _, _ = t.compare(clone, case)
                except t.FAULTS:
                    ok = False
                if not ok:
                    caught = True
                    break
            self.assertTrue(caught, patch[0])

    def test_missing_pattern_is_refused(self):
        with self.assertRaises(cpu.ToolError):
            t.patched_image(IMAGE, ("x", t.MULDIV, b"\xde\xad\xbe\xef\xde\xad", 0, 0, "", "muldiv"))

    def test_misc_controls_all_detect(self):
        self.assertTrue(all(ok for _, _, ok in t.misc_controls(IMAGE)))


class Generated(unittest.TestCase):
    def test_regeneration_matches_committed_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = sys.argv
            sys.argv = ["x", "--out", tmp]
            try:
                t.main()
            finally:
                sys.argv = old
            names = sorted(p.name for p in Path(tmp).iterdir())
            self.assertEqual(names, sorted(p.name for p in FOLDER.iterdir() if p.name not in ("README.md", "MANIFEST.sha256")))
            for name in names:
                self.assertEqual((Path(tmp) / name).read_bytes(), (FOLDER / name).read_bytes(), name)

    def test_measure_counts(self):
        m = json.loads((FOLDER / "measure.json").read_text())
        self.assertGreaterEqual(m["cases"], 10000)
        self.assertGreaterEqual(m["negative_controls"], 30)
        self.assertEqual(m["negative_controls"], m["negative_detected"])
        self.assertEqual(m["mismatches"], 0)

    def test_manifest(self):
        for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)


if __name__ == "__main__":
    unittest.main()
