import hashlib
import json
import pathlib
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import bole_rate115 as tool  # noqa: E402

WORK = ROOT / "research" / "work-items" / "RE-004-bole-rate-curve-115"


class RateCurveTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image()
        cls.harness = tool.Harness(cls.image)
        cls.cases = tool.named_cases()
        cls.table = {target: tool.decode_range(cls.image, *cls.image.exact_fde(target)) for target in tool.TARGETS}

    def run_case(self, case, variant=frozenset()):
        before, got = self.harness.run(case)
        return got, tool.spec_run(case, before, variant)

    def test_digest_is_checked_first(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "hl-node"
            path.write_bytes(b"\x7fELF" + bytes(100))
            with self.assertRaises(tool.EvidenceError):
                tool.load_image(path)

    def test_binary_digest_constant(self):
        self.assertEqual(tool.SHA256, "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
        self.assertEqual(hashlib.sha256(self.image.blob).hexdigest(), tool.SHA256)

    def test_function_extents(self):
        sizes = {target: self.image.exact_fde(target)[1] - target for target in tool.TARGETS}
        self.assertEqual(sizes, {0x36A08B0: 312, 0x36A09F0: 309, 0x36A0B30: 578, 0x36A0D80: 598})

    def test_interior_address_is_not_a_function(self):
        for va in (tool.RATE_INT + 1, tool.RATE - 1, 0x459230, 0x7FFFFFFFFF):
            with self.assertRaises(tool.EvidenceError):
                self.image.exact_fde(va)

    def test_decoder_ends_on_fde_end(self):
        for target, rows in self.table.items():
            self.assertEqual(rows[-1].next, self.image.exact_fde(target)[1])
            self.assertEqual(rows[0].va, target)

    def test_slots_hold_the_targets(self):
        relative = self.image.relative()
        self.assertEqual(relative[tool.SLOT_RATE], tool.RATE)
        self.assertEqual(relative[tool.SLOT_UTIL_F64], tool.UTIL_F64)
        self.assertNotEqual(relative.get(tool.SLOT_RATE), tool.RATE_INT)

    def test_named_cases_match_the_rule_list(self):
        for case in self.cases:
            got, want = self.run_case(case)
            self.assertEqual(got, want, case.name)

    def test_grid_matches_the_rule_list(self):
        count = tool.check_stream(self.harness, list(tool.grid_cases())[::3])
        self.assertGreater(count, 400)

    def test_vectors_match_the_rule_list(self):
        self.assertEqual(tool.check_stream(self.harness, tool.vector_cases(600)), 600)
        self.assertEqual(tool.check_stream(self.harness, tool.vector_cases(300, seed=99)), 300)

    def test_every_variant_is_refused(self):
        sample = self.cases + list(tool.vector_cases(120, seed=0x77))
        for name in tool.VARIANTS:
            self.assertIsNotNone(tool.first_failure(self.harness, sample, frozenset((name,))), name)

    def test_every_variant_can_agree_somewhere(self):
        # A switch that never changes a rule would be refused for the wrong reason; each one must agree with the bytes on the plain half market.
        case = next(c for c in self.cases if c.name == "half used" and c.kind == tool.UTIL_WORD)
        agreeing = [name for name in tool.VARIANTS if self.run_case(case, frozenset((name,)))[0] == self.run_case(case, frozenset((name,)))[1]]
        self.assertGreaterEqual(len(agreeing), 8)

    def test_old_rule_list_disagrees_only_on_the_supply_side(self):
        rows = tool.delta_rows(self.harness, self.cases)
        self.assertEqual(len(rows), 24)
        self.assertEqual({row[1] for row in rows}, {"borrow overflow with supply overflow", "supply one past the word", "supply just past the word",
                                                    "supply product exactly at the guard", "no supply shares with a quotient", "no supply shares with a quotient, zero debt"})
        for row in rows:
            if row[1].startswith("no supply shares with a quotient") and row[1].endswith("quotient"):
                self.assertEqual(row[2], "result differs")

    def test_supply_divide_runs_even_when_the_product_is_too_big(self):
        rec = tool.record(a=5, b=1 << 63, ib=2 * tool.E14)
        for kind, divides in ((tool.UTIL_WORD, 2), (tool.UTIL_F64, 2), (tool.RATE_INT, 4), (tool.RATE, 4)):
            before, got = self.harness.run(tool.Case("probe", kind, rec=rec))
            self.assertEqual(len(got[2]), divides, hex(kind))
            self.assertEqual(got[2][1], ((1 << 63) * 2 * tool.E14, tool.E14))

    def test_zero_supply_shares_are_not_special(self):
        # With b = 0 and an injected non-zero supply quotient the #115 bodies go on to the ratio divide.
        rec = tool.record(a=4, b=0)
        before, got = self.harness.run(tool.Case("probe", tool.UTIL_WORD, rec=rec, faults={1: 5}))
        self.assertEqual(got[1][0], 0)
        self.assertEqual(len(got[2]), 3)
        self.assertEqual(got[2][2][1], 5)

    def test_utilization_edges(self):
        div = tool.Div({})
        self.assertEqual(tool.util_result(tool.record(a=50, b=100), div), (0, tool.E14 // 2))
        self.assertEqual(tool.util_result(tool.record(a=300, b=100), tool.Div({})), (0, tool.E14))
        self.assertEqual(tool.util_result(tool.record(a=184468, b=1), tool.Div({})), (1, 3))
        self.assertEqual(tool.util_result(tool.record(a=184467, b=1), tool.Div({})), (0, tool.E14))
        self.assertEqual(tool.util_result(tool.record(a=3, b=0), tool.Div({})), (0, 0))
        self.assertEqual(tool.util_result(tool.record(a=tool.TOP, ia=tool.TOP, b=1), tool.Div({})), (1, 3))

    def test_curve_worked_example(self):
        rec = tool.record(a=50, b=100, mn=0, mx=tool.E14, kr=5 * 10 ** 12, k=8 * 10 ** 13)
        before, got = self.harness.run(tool.Case("probe", tool.RATE, rec=rec))
        self.assertEqual(tool.to_float(got[1]), 0.03125)
        rec = dict(rec, a=90)
        before, got = self.harness.run(tool.Case("probe", tool.RATE, rec=rec))
        self.assertEqual(tool.to_float(got[1]), 0.525)
        rec = dict(rec, a=150)
        before, got = self.harness.run(tool.Case("probe", tool.RATE, rec=rec))
        self.assertEqual(tool.to_float(got[1]), 1.0)

    def test_rate_word_is_the_kink_rate_at_the_bend(self):
        rec = tool.record(a=80, b=100, mn=7, mx=900, kr=123456, k=8 * 10 ** 13)
        before, got = self.harness.run(tool.Case("probe", tool.RATE_INT, rec=rec))
        self.assertEqual(got[1], 123456 // tool.E10)

    def test_reciprocal_constants_are_in_the_bytes(self):
        body = lambda target: b"".join(row.data for row in self.table[target])
        self.assertIn(struct.pack("<Q", tool.MUL_RATE), body(tool.RATE_INT))
        self.assertIn(struct.pack("<Q", tool.MUL_UTIL), body(tool.UTIL_WORD))
        self.assertIn(struct.pack("<Q", tool.E14), body(tool.RATE))

    def test_reciprocal_bounds_hold_and_fail_when_edited(self):
        rows = tool.reciprocal_rows()
        self.assertEqual({row[0] for row in rows}, {"rate_e10", "utilization_e10"})
        self.assertEqual(tool.MUL_UTIL * tool.E10 - (1 << tool.SHIFT_UTIL), rows[1][3])
        spare = (tool.MUL_UTIL + 10 ** 6) * tool.E10 - (1 << tool.SHIFT_UTIL)
        self.assertGreaterEqual((tool.E14) * spare, 1 << tool.SHIFT_UTIL)

    def test_shadowed_guard_bound(self):
        self.assertLess(tool.E14 * tool.TOP, tool.GUARD)
        self.assertEqual(tool.EDGE_LEFT * tool.EDGE_RIGHT, tool.GUARD - 1)

    def test_flipped_conditions_are_killed(self):
        seen = set(self.harness.machine.seen) | {row.va for rows in self.table.values() for row in rows}
        killed = 0
        edits = tool.edits_for(self.image, self.table[tool.UTIL_WORD], seen)
        plain = [c for c in self.cases if c.kind == tool.UTIL_WORD]
        for va, kind, patch in edits[:12]:
            harness = tool.Harness(self.image, patch)
            harness.machine.step_limit = tool.MUTANT_STEP_LIMIT
            if tool.first_failure(harness, plain) is not None:
                killed += 1
        self.assertGreaterEqual(killed, 10)

    def test_unedited_image_passes_under_the_mutant_limit(self):
        harness = tool.Harness(self.image)
        harness.machine.step_limit = tool.MUTANT_STEP_LIMIT
        self.assertIsNone(tool.first_failure(harness, self.cases))

    def test_a_corrupted_constant_is_caught(self):
        rows = self.table[tool.UTIL_WORD]
        row = next(r for r in rows if r.op == "mov" and r.size == 10 and struct.unpack_from("<Q", r.data, 2)[0] == tool.E14 - 1)
        patch = {row.va + 2: row.data[2] ^ 1}
        harness = tool.Harness(self.image, patch)
        harness.machine.step_limit = tool.MUTANT_STEP_LIMIT
        edge = tool.Case("edge", tool.UTIL_WORD, rec=tool.record(a=5, b=tool.EDGE_LEFT, ib=tool.EDGE_RIGHT))
        self.assertIsNotNone(tool.first_failure(harness, [edge]))

    def test_wrong_kind_is_caught(self):
        case = next(c for c in self.cases if c.name == "half used" and c.kind == tool.RATE_INT)
        before, got = self.harness.run(tool.Case("probe", tool.UTIL_WORD, rec=case.rec))
        self.assertNotEqual(got, tool.spec_run(case, before))

    def test_word_wider_than_64_bits_is_caught_by_the_compare(self):
        # The fixture keeps 64 bits per word, so a 65 bit input makes the bytes and the 128 bit rule list disagree.
        rec = tool.record(a=(1 << 64) + 50, b=100)
        case = tool.Case("probe", tool.UTIL_WORD, rec=rec)
        before, got = self.harness.run(case)
        self.assertNotEqual(got, tool.spec_run(case, before))

    def test_divide_by_zero_in_a_stub_is_a_halt(self):
        harness = tool.Harness(self.image)
        harness.case = tool.Case("probe", tool.UTIL_WORD, rec=tool.record())
        harness.log = []

        class Machine:
            regs = [0] * 16
            keep_rdx = False

        with self.assertRaises(tool.Halt):
            harness.on_div(Machine)

    def test_site_rows_name_both_call_forms(self):
        rows = tool.site_rows(self.image)
        forms = {row[0]: row[3] for row in rows}
        self.assertEqual(forms["rate_f64"], "slot")
        self.assertEqual(forms["rate_e10"], "direct")
        self.assertEqual(dict((row[0], row[4]) for row in rows)["rate_e10"], "0x38e6830")
        self.assertEqual(dict((row[0], row[4]) for row in rows)["utilization_e10"], "0x38e6845")

    def test_constant_rows_read_the_f64_pool(self):
        rows = tool.constant_rows(self.image, self.table)
        values = {row[3] for row in rows if row[2].startswith("rip")}
        self.assertIn("100000000000000.0", values)

    def test_structural_controls_all_detected(self):
        rows = tool.structural_controls(self.image, self.harness, self.cases)
        self.assertTrue(all(row[1] == "detected" for row in rows), rows)

    def test_measure_counts_follow_the_rows(self):
        result = tool.analyse(self.image, vectors=60, mutate=False)
        files = tool.render(result)
        measure = json.loads(files["measure.json"])
        self.assertEqual(measure["negative_controls"], len(result["variants"]) + len(result["structural"]))
        self.assertEqual(measure["negative_detected"], measure["negative_controls"])
        self.assertEqual(measure["cases"], len(result["cases"]) + result["grid_count"] + 60)

    @unittest.skipUnless(WORK.is_dir(), "evidence folder not present")
    def test_committed_evidence_is_regenerated_exactly(self):
        with tempfile.TemporaryDirectory() as folder:
            files = tool.render(tool.analyse(self.image))
            for name, text in files.items():
                self.assertEqual((WORK / name).read_text(encoding="ascii"), text, name)
            self.assertEqual(sorted(p.name for p in WORK.iterdir() if p.is_file()), sorted(list(files) + ["MANIFEST.sha256", "README.md"]))


class PropertyTest(unittest.TestCase):
    """Properties of the bytes themselves, stated without the rule list: run the four bodies and compare entries with each other."""

    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image()
        cls.harness = tool.Harness(cls.image)
        cls.table = {target: tool.decode_range(cls.image, *cls.image.exact_fde(target)) for target in tool.TARGETS}

    def value(self, kind, rec, faults=None):
        return self.harness.run(tool.Case("probe", kind, rec=rec, faults=faults))[1]

    def util(self, rec):
        out = self.value(tool.UTIL_WORD, rec)[1]
        return None if out[0] else struct.unpack_from("<Q", out, 8)[0]

    def util_f64(self, rec):
        out = self.value(tool.UTIL_F64, rec)[1]
        return None if out[0] else tool.to_float(struct.unpack_from("<Q", out, 8)[0])

    def rate_word(self, rec):
        return self.value(tool.RATE_INT, rec)[1]

    def rate_f64(self, rec):
        return tool.to_float(self.value(tool.RATE, rec)[1])

    def test_entries_agree_on_the_same_record(self):
        # u as a word / 1e10 and as an f64 / 1e14 come from the same ratio; the f64 must be the word to within the 1e10 floor.
        checked = 0
        for i in range(1, 200):
            rec = tool.record(a=(i * 7919) % 10 ** 6, b=(i * 104729) % 10 ** 6 + 1, ia=tool.E14 + i, ib=tool.E14 + 3 * i)
            word, real = self.util(rec), self.util_f64(rec)
            self.assertEqual(word is None, real is None)
            if word is None:
                continue
            self.assertLessEqual(word * tool.E10, round(real * tool.E14))
            self.assertLess(round(real * tool.E14) - word * tool.E10, tool.E10 + 1)
            checked += 1
        self.assertGreater(checked, 150)

    def test_rate_entries_agree_on_the_same_record(self):
        checked = 0
        for case in tool.vector_cases(400, seed=6):
            rec = case.rec
            word, real = self.rate_word(rec), self.rate_f64(rec)
            self.assertLessEqual(abs(real - word * tool.E10 / tool.E14), 1.0 * tool.E10 / tool.E14 + 1e-9 * max(1.0, real))
            checked += 1
        self.assertEqual(checked, 400)

    def test_rate_does_not_decrease_with_use(self):
        for config in ((0, tool.E14, 5 * 10 ** 12, 8 * 10 ** 13), (10 ** 12, 6 * 10 ** 13, 2 * 10 ** 13, 5 * 10 ** 13), (0, 10 ** 15, 10 ** 14, 10 ** 13)):
            mn, mx, kr, k = config
            previous = -1
            for percent in range(0, 201, 5):
                rec = tool.record(a=percent, b=100, mn=mn, mx=mx, kr=kr, k=k)
                word = self.rate_word(rec)
                self.assertGreaterEqual(word, previous, (config, percent))
                previous = word

    def test_rate_stays_between_the_end_rates_when_they_are_ordered(self):
        for percent in range(0, 201, 7):
            rec = tool.record(a=percent, b=100, mn=3 * 10 ** 12, mx=9 * 10 ** 13, kr=2 * 10 ** 13, k=4 * 10 ** 13)
            word = self.rate_word(rec) * tool.E10
            self.assertLessEqual(3 * 10 ** 12 - tool.E10, word)
            self.assertLessEqual(word, 9 * 10 ** 13)

    def test_scaling_both_sides_keeps_the_utilization(self):
        for a, b in ((1, 3), (7, 9), (50, 100), (13, 17), (99, 100)):
            base = self.util(tool.record(a=a, b=b))
            for factor in (10, 1000, 10 ** 6):
                self.assertEqual(self.util(tool.record(a=a * factor, b=b * factor)), base, (a, b, factor))

    def test_borrow_rounds_up_and_supply_rounds_down(self):
        # One unit of borrow index above 1e14 adds one borrowed unit; the same unit on the supply index adds nothing until a full unit accrues.
        plain = self.util_f64(tool.record(a=300000, ia=tool.E14, b=1000000, ib=tool.E14))
        borrow_up = self.util_f64(tool.record(a=300000, ia=tool.E14 + 1, b=1000000, ib=tool.E14))
        supply_up = self.util_f64(tool.record(a=300000, ia=tool.E14, b=1000000, ib=tool.E14 + 1))
        self.assertEqual(plain, 0.3)
        self.assertEqual(borrow_up, 300001 / 1000000)
        self.assertEqual(supply_up, plain)
        supply_full = self.util_f64(tool.record(a=300000, ia=tool.E14, b=1000000, ib=tool.E14 + tool.E14 // 1000000))
        self.assertEqual(supply_full, 300000 * tool.E14 // 1000001 / tool.E14)

    def test_utilization_is_capped_and_refuses_overflow(self):
        self.assertEqual(self.util(tool.record(a=500, b=100)), tool.E14 // tool.E10)
        self.assertIsNone(self.util(tool.record(a=184468, b=1)))
        out = self.value(tool.UTIL_WORD, tool.record(a=184468, b=1))[1]
        self.assertEqual((out[0], out[1]), (1, 3))
        out = self.value(tool.UTIL_WORD, tool.record(a=tool.TOP, ia=tool.TOP, b=1))[1]
        self.assertEqual((out[0], out[1]), (1, 3))

    def test_error_leaves_the_payload_bytes_alone(self):
        before, got = self.harness.run(tool.Case("probe", tool.UTIL_WORD, rec=tool.record(a=184468, b=1)))
        out = got[1]
        self.assertEqual(out[2:], before[tool.OUT - tool.HEAP_BASE + 2:tool.OUT - tool.HEAP_BASE + tool.OUT_SIZE])

    def test_ok_leaves_the_code_byte_alone(self):
        before, got = self.harness.run(tool.Case("probe", tool.UTIL_F64, rec=tool.record(a=50, b=100)))
        self.assertEqual(got[1][1], before[tool.OUT - tool.HEAP_BASE + 1])
        self.assertEqual(got[1][0], 0)

    def test_rate_at_zero_use_is_the_min_rate(self):
        for mn in (0, 5, 10 ** 12, tool.TOP - 5):
            rec = tool.record(mn=mn, kr=max(mn, 7), mx=tool.TOP)
            self.assertEqual(self.rate_word(rec), mn // tool.E10)

    def test_rate_at_full_use_is_the_max_rate(self):
        for mx in (10 ** 12, 10 ** 14, 5 * 10 ** 14):
            rec = tool.record(a=100, b=100, mn=0, kr=10 ** 12, mx=mx, k=8 * 10 ** 13)
            self.assertEqual(self.rate_word(rec), mx // tool.E10)

    def test_both_end_rates_below_the_bend_give_the_bend(self):
        rec = tool.record(a=1, b=10, mn=9 * 10 ** 12, kr=10 ** 12, k=5 * 10 ** 13)
        self.assertEqual(self.rate_word(rec), 10 ** 12 // tool.E10)

    def test_bodies_have_one_return_and_no_stray_indirect_jumps(self):
        for target, rows in self.table.items():
            self.assertEqual(sum(1 for row in rows if row.op == "ret"), 1, hex(target))
            self.assertEqual([row.va for row in rows if row.op == "jmpi"], [], hex(target))

    def test_divide_call_counts_per_body(self):
        counts = {target: sum(1 for row in rows if row.op == "calli") for target, rows in self.table.items()}
        self.assertEqual(counts, {tool.UTIL_WORD: 3, tool.UTIL_F64: 3, tool.RATE_INT: 7, tool.RATE: 7})

    def test_divide_requests_per_plain_case(self):
        for kind, most in ((tool.UTIL_WORD, 3), (tool.UTIL_F64, 3), (tool.RATE_INT, 7), (tool.RATE, 7)):
            sizes = set()
            for case in tool.vector_cases(200, seed=11):
                sizes.add(len(self.harness.run(tool.Case("probe", kind, rec=case.rec))[1][2]))
            self.assertLessEqual(max(sizes), most, hex(kind))
            self.assertGreaterEqual(min(sizes), 2, hex(kind))

    def test_every_divide_request_has_a_nonzero_divisor_on_plain_input(self):
        for case in tool.vector_cases(300, seed=13):
            for kind in tool.KINDS:
                for num, den in self.harness.run(tool.Case("probe", kind, rec=case.rec))[1][2]:
                    self.assertGreater(den, 0)

    def test_numerators_are_products_of_record_words(self):
        rec = tool.record(a=123, ia=tool.E14 + 7, b=456, ib=tool.E14 + 9, mn=1, mx=2, kr=1, k=8 * 10 ** 13)
        log = self.value(tool.UTIL_WORD, rec)[2]
        self.assertEqual(log[0], (123 * (tool.E14 + 7), tool.E14))
        self.assertEqual(log[1], (456 * (tool.E14 + 9), tool.E14))
        self.assertEqual(log[2][1], 456 * (tool.E14 + 9) // tool.E14)

    def test_render_is_deterministic(self):
        first = tool.render(tool.analyse(self.image, vectors=40, mutate=False))
        second = tool.render(tool.analyse(self.image, vectors=40, mutate=False))
        self.assertEqual(first, second)

    def test_every_listed_edit_changes_one_byte(self):
        seen = {row.va for rows in self.table.values() for row in rows}
        for target in (tool.UTIL_F64, tool.RATE_INT):
            for va, kind, patch in tool.edits_for(self.image, self.table[target], seen):
                self.assertEqual(len(patch), 1, (hex(va), kind))
                (at, value), = patch.items()
                self.assertNotEqual(bytes([value]), self.image.blob[self.image.offset(at):self.image.offset(at) + 1])


from fractions import Fraction  # noqa: E402
import math  # noqa: E402


def closed_u(rec):
    """Utilization from the stated rule, with exact fractions instead of the rule list's integer steps. None means a refusal."""
    borrowed = math.ceil(Fraction(rec["a"] * rec["ia"], tool.E14))
    supplied = (rec["b"] * rec["ib"]) // tool.E14
    if borrowed >= 1 << 64 or rec["b"] * rec["ib"] >= tool.E14 << 64 or (rec["a"] == 0 and borrowed):
        return None
    if supplied % (1 << 64) == 0 and supplied < 1 << 64:
        return 0
    q = borrowed * tool.E14 // supplied
    if q >= 1 << 64:
        return None
    return min(q, tool.E14)


def closed_rate(rec):
    u = closed_u(rec)
    u = 0 if u is None else u
    mn, mx, kr, k = rec["mn"], rec["mx"], rec["kr"], rec["k"]
    if u == k:
        return kr
    if u < k:
        if kr < mn:
            return kr
        return mn + (u * tool.E14 // k) * (kr - mn) // tool.E14
    if k > tool.E14 - 1 or mx < kr:
        return mx
    return kr + ((u - k) * tool.E14 // (tool.E14 - k)) * (mx - kr) // tool.E14


class ClosedFormTest(unittest.TestCase):
    """A third statement of the rules, in exact fractions, checked against the bytes on plain records (no injected quotients)."""

    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image()
        cls.harness = tool.Harness(cls.image)

    def records(self):
        curves = ((0, tool.E14, 5 * 10 ** 12, 8 * 10 ** 13), (2 * 10 ** 12, 5 * 10 ** 13, 10 ** 13, 9 * 10 ** 13), (0, 10 ** 15, 10 ** 12, 10 ** 13), (7, 11, 13, 17))
        for mn, mx, kr, k in curves:
            for a in (0, 1, 2, 7, 49, 50, 79, 80, 81, 99, 100, 101, 250, 10 ** 6):
                for b in (0, 1, 3, 100, 10 ** 6):
                    for ia, ib in ((tool.E14, tool.E14), (tool.E14 + 3, tool.E14 + 11), (2 * tool.E14, tool.E14 // 2)):
                        yield tool.record(a=a, b=b, ia=ia, ib=ib, mn=mn, mx=mx, kr=kr, k=k)

    def test_utilization_word_matches_the_closed_form(self):
        count = 0
        for rec in self.records():
            out = self.harness.run(tool.Case("probe", tool.UTIL_WORD, rec=rec))[1][1]
            want = closed_u(rec)
            if want is None:
                self.assertEqual((out[0], out[1]), (1, 3), rec)
            else:
                self.assertEqual((out[0], struct.unpack_from("<Q", out, 8)[0]), (0, want // tool.E10), rec)
            count += 1
        self.assertGreater(count, 700)

    def test_utilization_f64_matches_the_closed_form(self):
        for rec in self.records():
            out = self.harness.run(tool.Case("probe", tool.UTIL_F64, rec=rec))[1][1]
            want = closed_u(rec)
            if want is not None:
                self.assertEqual(struct.unpack_from("<Q", out, 8)[0], tool.to_bits(float(want) / 1e14), rec)

    def test_rate_word_matches_the_closed_form(self):
        for rec in self.records():
            got = self.harness.run(tool.Case("probe", tool.RATE_INT, rec=rec))[1][1]
            self.assertEqual(got, closed_rate(rec) // tool.E10, rec)

    def test_rate_f64_matches_the_closed_form(self):
        for rec in self.records():
            got = self.harness.run(tool.Case("probe", tool.RATE, rec=rec))[1][1]
            self.assertEqual(got, tool.to_bits(float(closed_rate(rec)) / 1e14), rec)

    def test_closed_form_is_itself_checked_by_a_wrong_curve(self):
        wrong = 0
        for rec in self.records():
            got = self.harness.run(tool.Case("probe", tool.RATE_INT, rec=rec))[1][1]
            if (closed_rate(dict(rec, kr=rec["kr"] + 10 ** 11)) // tool.E10) != got:
                wrong += 1
        self.assertGreater(wrong, 30)

    def test_closed_form_refuses_what_the_bytes_refuse(self):
        for rec, refused in ((tool.record(a=184468, b=1), True), (tool.record(a=184467, b=1), False), (tool.record(a=tool.TOP, ia=tool.TOP, b=1), True),
                             (tool.record(a=5, b=1 << 63, ib=2 * tool.E14), True), (tool.record(a=5, b=tool.EDGE_LEFT, ib=tool.EDGE_RIGHT), False)):
            self.assertEqual(closed_u(rec) is None, refused, rec)
            out = self.harness.run(tool.Case("probe", tool.UTIL_WORD, rec=rec))[1][1]
            self.assertEqual(out[0] == 1, refused, rec)


if __name__ == "__main__":
    unittest.main()
