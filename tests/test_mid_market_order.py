import hashlib
import pathlib
import struct
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import mid_market_order as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-006-mid-market-order-94"
IMAGE = tool.load_image()
HARNESS = tool.Harness(IMAGE)
PLAIN = 2500000


def build(copy=0, side=0, first=PLAIN, second=PLAIN, **options):
    return tool.BuilderCase("t", tool.Tree(first), tool.Tree(second), side=side, **options)


def limit_of(result):
    return struct.unpack_from("<Q", result["insert"][2], 0x80)[0]


def patched(patches):
    return tool.Harness(IMAGE, patches)


def branch_flip(va):
    """Patch that inverts the conditional jump at va, short or near."""
    at = IMAGE.offset(va)
    byte = IMAGE.blob[at]
    if 0x70 <= byte <= 0x7F:
        return {va: byte ^ 1}
    return {va + 1: IMAGE.blob[at + 1] ^ 1}


def find_row(start, wanted):
    begin, end = IMAGE.exact_fde(start)
    for row in tool.decode_range(IMAGE, begin, end):
        if wanted(row):
            return row
    raise AssertionError("no such row")


class IdentityTests(unittest.TestCase):
    def test_wrong_digest_is_rejected(self):
        with self.assertRaisesRegex(tool.EvidenceError, "SHA-256 mismatch"):
            tool.load_image(expected="0" * 64)

    def test_non_elf_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Expected ELF64"):
            tool.Image(b"\0" * 128)

    def test_interior_address_is_not_a_function_start(self):
        with self.assertRaisesRegex(tool.EvidenceError, "not an FDE start"):
            IMAGE.exact_fde(tool.BUILDERS[0] + 1)

    def test_address_past_the_fde_end_is_rejected(self):
        end = IMAGE.exact_fde(tool.ROUND)[1]
        with self.assertRaisesRegex(tool.EvidenceError, "outside every FDE"):
            IMAGE.fde(end + 1)

    def test_nobits_address_has_no_file_offset(self):
        with self.assertRaisesRegex(tool.EvidenceError, "outside file-backed"):
            IMAGE.offset(IMAGE.named[".bss"]["address"] + 0x10)

    def test_every_function_decodes_to_its_fde_end(self):
        for start in tool.BUILDERS + tool.LOOPS + (tool.PRODUCER, tool.BEST, tool.ROUND, tool.TICK):
            begin, end = IMAGE.exact_fde(start)
            self.assertEqual(tool.decode_range(IMAGE, begin, end)[-1].next, end)


class BuilderTests(unittest.TestCase):
    def test_all_cases_match_on_all_copies(self):
        cases = tool.builder_cases()
        for copy in range(4):
            self.assertEqual([row for row in (tool.compare_builder(HARNESS, copy, case) for case in cases) if row], [])

    def test_buy_keeps_the_rounded_down_tick(self):
        self.assertEqual(limit_of(HARNESS.run_builder(0, build(side=0))), 2575000)

    def test_sell_always_adds_one_tick(self):
        # 0.97 * 2500000 is 2425000, an exact multiple of the tick 100.
        self.assertEqual(limit_of(HARNESS.run_builder(0, build(side=1))), 2425100)

    def test_liquidation_copies_use_the_wide_factors(self):
        self.assertEqual(limit_of(HARNESS.run_builder(3, build(side=0))), 3000000)
        self.assertEqual(limit_of(HARNESS.run_builder(3, build(side=1))), 2000100)

    def test_midpoint_floors_without_overflow(self):
        top = tool.SIGN[8]
        result = HARNESS.run_builder(0, build(side=1, first=top, second=top - 1))
        self.assertEqual(limit_of(result), tool.spec_limit(top - 1, 1, 0, (1.03, 0.97)))

    def test_keys_are_read_through_their_absolute_value(self):
        self.assertEqual(limit_of(HARNESS.run_builder(0, build(first=(-PLAIN) & tool.MASK[8]))), 2575000)
        self.assertEqual(tool.spec_best(tool.Tree(tool.MASK[8])), 1)
        self.assertEqual(tool.spec_best(tool.Tree(tool.SIGN[8])), tool.SIGN[8])

    def test_empty_side_writes_the_no_price_word_and_calls_nothing(self):
        result = HARNESS.run_builder(0, tool.BuilderCase("t", tool.Tree(root=False), tool.Tree(PLAIN)))
        self.assertEqual(result, {"out": (tool.TAG_NONE, tool.NO_PRICE), "drops": [tool.ERROR_WORD]})

    def test_record_carries_size_user_and_copy_constants(self):
        record = HARNESS.run_builder(1, build(side=1, size=0x1234))["insert"][2]
        self.assertEqual(struct.unpack_from("<Q", record, 8)[0], 0x1234)
        self.assertEqual(record[0xB8:0xCC], bytes(range(1, 21)))
        self.assertEqual((record[0x70], record[0xCC], record[0xA2]), (6, 1, 1))
        record = HARNESS.run_builder(2, build())["insert"][2]
        self.assertEqual((record[0x70], record[0xCC]), (1, 4))

    def test_only_the_low_side_byte_chooses_the_price(self):
        self.assertEqual(limit_of(HARNESS.run_builder(0, build(side=0x100))), 2575000)

    def test_ladder_uses_the_market_row_dex(self):
        case = tool.BuilderCase("t", tool.Tree(PLAIN), tool.Tree(PLAIN), asset=10003, markets=2, market_dex=0)
        self.assertEqual(HARNESS.run_builder(0, case)["stop"], ("panic", tool.LOCATION_LADDER))

    def test_unwrap_comes_before_the_tree_reads(self):
        case = tool.BuilderCase("t", tool.Tree(PLAIN, 1, [1, 0], [0, 1]), tool.Tree(PLAIN), asset=10000)
        self.assertEqual(HARNESS.run_builder(0, case), {"stop": ("unwrap", tool.LOCATION_BUILDER, tool.ERROR_WORD, tool.UNWRAP_MESSAGE)})

    def test_inverted_side_branch_is_detected(self):
        harness = patched(branch_flip(0x43040FF))
        self.assertIn("differs", tool.compare_builder(harness, 0, build(side=0)))

    def test_wrong_factor_constant_is_detected(self):
        harness = tool.Harness(IMAGE)
        harness.machine.memory.statics[tool.FACTOR_BUY_AT] = tool.to_bits(1.02)
        self.assertIn("differs", tool.compare_builder(harness, 0, build(side=0)))

    def test_the_three_percent_constants_are_read_from_the_file(self):
        self.assertEqual(struct.unpack_from("<d", IMAGE.blob, IMAGE.offset(tool.FACTOR_BUY_AT))[0], 1.03)
        self.assertEqual(struct.unpack_from("<d", IMAGE.blob, IMAGE.offset(tool.FACTOR_SELL_AT))[0], 0.97)

    def test_wrong_expected_factors_are_refused(self):
        rows = ((0x4304010, 0, 0x4311140, 6, 1, (1.2, 0.8)),)
        with mock.patch.object(tool, "BUILDER_ROWS", rows):
            with self.assertRaisesRegex(tool.EvidenceError, "price factors"):
                tool.builder_pins(IMAGE)

    def test_wrong_expected_insert_is_refused(self):
        rows = ((0x4304010, 0, 0x4314DA0, 6, 1, (1.03, 0.97)),)
        with mock.patch.object(tool, "BUILDER_ROWS", rows):
            with self.assertRaisesRegex(tool.EvidenceError, "insert target"):
                tool.builder_pins(IMAGE)

    def test_wrong_expected_record_constant_is_refused(self):
        rows = ((0x4304010, 0, 0x4311140, 1, 1, (1.03, 0.97)),)
        with mock.patch.object(tool, "BUILDER_ROWS", rows):
            with self.assertRaisesRegex(tool.EvidenceError, "record constants"):
                tool.builder_pins(IMAGE)


class SpecificationTests(unittest.TestCase):
    def test_round_is_half_away_from_zero_on_positive_inputs(self):
        self.assertEqual(tool.spec_round(2.5), 3.0)
        self.assertEqual(tool.spec_round(0.49999999999999994), 0.0)
        self.assertEqual(tool.spec_round(2.0 ** 52 + 1), 2.0 ** 52 + 1)

    def test_round_bytes_agree_on_the_tie_that_breaks_naive_rounding(self):
        # 0.49999999999999994 + 0.5 is 1.0 in f64, which is why the routine adds the predecessor of 0.5.
        self.assertEqual(int(0.49999999999999994 + 0.5), 1)
        self.assertEqual(int(tool.spec_round(0.49999999999999994)), 0)

    def test_tick_is_five_significant_digits_under_the_decimals_cap(self):
        self.assertEqual(tool.spec_tick(99999, 0), 1)
        self.assertEqual(tool.spec_tick(100000, 0), 10)
        self.assertEqual(tool.spec_tick(10 ** 12, 5), 10)

    def test_block_time_clamps_at_zero(self):
        self.assertEqual(tool.spec_millis((1970 << 13 | 1 << 4, 1, 2000000)), 1002)
        self.assertEqual(tool.spec_millis((1969 << 13 | 365 << 4, 0, 0)), 0)


class RoundTests(unittest.TestCase):
    def test_all_values_match(self):
        self.assertEqual([row for row in (tool.compare_round(HARNESS, value) for value in tool.round_cases()) if row], [])

    def test_truncation_is_detected_by_the_direct_run(self):
        harness = patched(branch_flip(0x565F476))
        self.assertIn("differs", tool.compare_round(harness, 0.75))


class EquivalenceTests(unittest.TestCase):
    def test_sell_limit_stays_under_the_top_of_u64(self):
        # The all-ones limit needs (floor + 1) * tick past 2^64.
        for factors in ((1.03, 0.97), (1.2, 0.8)):
            price = int(tool.spec_round(float(tool.MASK[8]) * factors[1]))
            tick = tool.spec_tick(price, 0)
            self.assertLess((price // tick + 1) * tick, 1 << 64)

    def test_the_rounded_price_of_the_smallest_midpoint_is_one(self):
        for factor in (1.03, 0.97, 1.2, 0.8):
            self.assertEqual(tool.spec_round(1.0 * factor), 1.0)

    def test_year_zero_and_earlier_clamp_to_zero(self):
        for year in (0, -1, -399, -400, -401, -262144):
            word = ((year << 13) | (366 << 4)) & tool.MASK[4]
            self.assertEqual(tool.spec_millis((word, 86399, 999999999)), 0)

    def test_every_listed_equivalent_is_a_surviving_row(self):
        rows = [line.split("\t") for line in (FOLDER / "mutations.tsv").read_text().splitlines()[1:]]
        self.assertEqual({int(row[1], 16) for row in rows if row[3] == "survived"}, set(tool.EQUIVALENT))


class LoopTests(unittest.TestCase):
    def test_all_cases_match_on_both_copies(self):
        cases = tool.loop_cases()
        for copy in range(2):
            self.assertEqual([row for row in (tool.compare_loop(HARNESS, copy, case) for case in cases) if row], [])

    def kinds(self, case, copy=0):
        return [row[0] for row in HARNESS.run_loop(copy, case)["events"]]

    def test_notional_floor_is_inclusive(self):
        self.assertNotIn("builder", self.kinds(tool.LoopCase("t", [(1, 0, 9999999)])))
        self.assertIn("builder", self.kinds(tool.LoopCase("t", [(1, 0, 10000000)])))

    def test_overflow_counts_as_large(self):
        self.assertIn("builder", self.kinds(tool.LoopCase("t", [(0, 0, 1 << 62)], prices=(4,))))

    def test_tag_two_ends_the_list(self):
        kinds = self.kinds(tool.LoopCase("t", [(0, 2, 3), (0, 1, 3)]))
        self.assertNotIn("builder", kinds)

    def test_a_builder_error_skips_apply_but_not_finish(self):
        kinds = self.kinds(tool.LoopCase("t", [(0, 1, 3)], outcomes=[tool.Outcome(error=tool.NO_PRICE)]))
        self.assertNotIn("apply", kinds)
        self.assertIn("finish", kinds)

    def test_absent_answer_returns_without_the_final_drop(self):
        self.assertEqual(self.kinds(tool.LoopCase("t", absent=True)), ["drop", "producer"])

    def test_second_copy_reads_its_own_fields(self):
        case = tool.LoopCase("t", [(0, 1, 3)])
        events = HARNESS.run_loop(1, case)["events"]
        self.assertIn(("builder", tool.BOOKS, tool.USER, 1, 3, tool.LARGER, 0xD0, 0x98, (0, 8, 0)), events)

    def test_changed_floor_is_detected(self):
        row = find_row(tool.LOOPS[0], lambda item: item.op == "cmp" and item.b == ("i", tool.NOTIONAL_FLOOR))
        at = row.va + row.imm_at
        harness = patched({at: IMAGE.blob[IMAGE.offset(at)] ^ 1})
        self.assertIn("differs", tool.compare_loop(harness, 0, tool.LoopCase("t", [(1, 0, 9999999)])))

    def test_inverted_floor_branch_is_detected(self):
        row = find_row(tool.LOOPS[0], lambda item: item.op == "cmp" and item.b == ("i", tool.NOTIONAL_FLOOR))
        harness = patched(branch_flip(row.next))
        self.assertIn("differs", tool.compare_loop(harness, 0, tool.LoopCase("t", [(1, 0, 9999999)])))


class PositionTests(unittest.TestCase):
    def test_all_cases_match(self):
        self.assertEqual([row for row in (tool.compare_positions(HARNESS, case) for case in tool.position_cases()) if row], [])

    def test_long_gets_side_one_and_short_side_zero(self):
        case = tool.PositionCase("t", [3], [(7, 100), (8, tool.signed(-100))])
        self.assertEqual(HARNESS.run_positions(case), {"rows": [(7, 1, 50), (8, 0, 50)]})

    def test_fraction_must_be_inside_the_open_interval(self):
        for fraction in (0.0, -0.5, 1.0, 2.0):
            self.assertEqual(HARNESS.run_positions(tool.PositionCase("t", [3], [(7, 100)], fraction=fraction)), {"none": True})

    def test_nan_fraction_gives_an_empty_answer(self):
        case = tool.PositionCase("t", [3], [(7, 100)], fraction=float("nan"))
        self.assertEqual(HARNESS.run_positions(case), {"rows": [], "vector": (0, 8)})

    def test_inverted_side_test_is_detected(self):
        row = find_row(tool.PRODUCER, lambda item: item.op == "cmp" and item.a == ("r", tool.RDX) and item.b == ("i", 1) and item.width == 4)
        harness = patched(branch_flip(row.next))
        case = tool.PositionCase("t", [3], [(7, 100)])
        self.assertIn("differs", tool.compare_positions(harness, case))


class CopyTests(unittest.TestCase):
    def test_builder_differences_are_only_the_named_fields(self):
        rows = tool.copy_differences(IMAGE, tool.BUILDERS[0], tool.BUILDERS[3])
        self.assertEqual(len(rows), 4)
        rows = tool.copy_differences(IMAGE, tool.BUILDERS[0], tool.BUILDERS[1])
        self.assertEqual(len(rows), 3)

    def test_size_mismatch_is_refused(self):
        with self.assertRaisesRegex(tool.EvidenceError, "differ in size"):
            tool.copy_differences(IMAGE, tool.BUILDERS[0], tool.LOOPS[0])

    def test_each_builder_and_loop_has_one_direct_caller(self):
        sites = tool.direct_sites(IMAGE, tool.BUILDERS + tool.LOOPS)
        self.assertEqual({len(rows) for rows in sites.values()}, {1})

    def test_producer_slot_has_the_two_loops_and_one_other_caller(self):
        sites = tool.slot_sites(IMAGE, tool.SLOT_PRODUCER)
        self.assertEqual(sorted(IMAGE.fde(site)[0] for site in sites), sorted(tool.LOOPS + (tool.THIRD_LOOP,)))


class PacketTests(unittest.TestCase):
    def test_manifest_matches_the_folder(self):
        names = set()
        for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ")
            names.add(name)
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)
        self.assertEqual(names, {path.name for path in FOLDER.iterdir()} - {"MANIFEST.sha256"})

    def test_static_files_regenerate(self):
        files = tool.render(tool.analyse(IMAGE, full=False))
        files.pop("mutations.tsv")
        files.pop("evidence.json")
        with tempfile.TemporaryDirectory() as folder:
            tool.write_outputs(folder, files)
            for name in files:
                self.assertEqual((pathlib.Path(folder) / name).read_bytes(), (FOLDER / name).read_bytes(), name)

    def test_mutation_counts_match_the_evidence(self):
        rows = (FOLDER / "mutations.tsv").read_text().splitlines()[1:]
        document = tool.json.loads((FOLDER / "evidence.json").read_text())
        for result, count in document["mutations"].items():
            self.assertEqual(sum(1 for row in rows if row.split("\t")[3] == result), count, result)

    def test_every_survivor_and_unreached_row_has_a_written_reason(self):
        rows = [line.split("\t") for line in (FOLDER / "mutations.tsv").read_text().splitlines()[1:]]
        self.assertEqual([row for row in rows if row[3] != "killed" and not row[5]], [])


if __name__ == "__main__":
    unittest.main()
