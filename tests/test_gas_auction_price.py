"""Tests for tools/gas_auction_price.py: real node #94 bytes with corruption controls."""

import copy
import hashlib
import importlib.util
import json
import math
import pathlib
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FOLDER = ROOT / "research" / "work-items" / "RE-004-gas-auction-price-94"
spec_ = importlib.util.spec_from_file_location("gas_auction_price", ROOT / "tools" / "gas_auction_price.py")
tool = importlib.util.module_from_spec(spec_)
sys.modules["gas_auction_price"] = tool
spec_.loader.exec_module(tool)

IMAGE = None
HARNESS = None
RESULT = None
LISTS = None


def setUpModule():
    global IMAGE, HARNESS, RESULT, LISTS
    IMAGE = tool.load_image()
    HARNESS = tool.Harness(IMAGE)
    RESULT = tool.analyse(IMAGE)
    LISTS = RESULT["lists"]


def price(**fields):
    case = tool.Case("t", tool.PRICE, **fields)
    got = HARNESS.run(case)
    assert got == tool.spec_run(case)
    return struct.unpack_from("<H", got[1], 0)[0], struct.unpack_from("<Q", got[1], 8)[0]


def named(target, name):
    return next(case for case in LISTS[target] if case.name == name)


def corrupted(va, value):
    bad = copy.copy(IMAGE)
    data = bytearray(IMAGE.blob)
    data[IMAGE.offset(va)] = value
    bad.blob = bytes(data)
    bad.relative_map = None
    return bad


class Identity(unittest.TestCase):
    def test_digest_is_the_target(self):
        self.assertEqual(hashlib.sha256(IMAGE.blob).hexdigest(), tool.SHA256)

    def test_wrong_digest_fails(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_nobits_section_does_not_resolve(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.offset(IMAGE.named[".bss"]["address"])

    def test_fdes_are_exact(self):
        self.assertEqual(IMAGE.exact_fde(tool.PRICE), (0x325CCB0, 0x325CF3C))
        self.assertEqual(IMAGE.exact_fde(tool.RESTART), (0x33742D0, 0x33747D8))
        self.assertEqual(IMAGE.exact_fde(tool.ROLLS[0]), (0x2702060, 0x2702325))
        self.assertEqual(IMAGE.exact_fde(tool.GATES[0]), (0x2744020, 0x2744346))
        self.assertEqual(IMAGE.exact_fde(tool.SHORT_GATES[0]), (0x46CE080, 0x46CE1FB))
        for target in tool.TARGETS:
            with self.assertRaises(tool.EvidenceError):
                IMAGE.exact_fde(target + 1)

    def test_address_past_the_text_fails(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.offset(1 << 40)


class Files(unittest.TestCase):
    def test_tool_output_matches_the_folder(self):
        files = tool.render(RESULT)
        for name, text in files.items():
            self.assertEqual((FOLDER / name).read_text(encoding="ascii"), text, name)
        on_disk = {p.name for p in FOLDER.iterdir()} - {"README.md", "MANIFEST.sha256"}
        self.assertEqual(on_disk, set(files))

    def test_manifest_matches(self):
        rows = (FOLDER / "MANIFEST.sha256").read_text().splitlines()
        names = set()
        for row in rows:
            digest, name = row.split("  ")
            names.add(name)
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)
        self.assertEqual(names, {p.name for p in FOLDER.iterdir()} - {"MANIFEST.sha256"})

    def test_main_writes_files(self):
        original = tool.analyse
        tool.analyse = lambda image: RESULT
        try:
            with tempfile.TemporaryDirectory() as folder:
                self.assertEqual(tool.main(["--out", folder]), 0)
                self.assertTrue((pathlib.Path(folder) / "evidence.json").exists())
        finally:
            tool.analyse = original

    def test_summary_counts_the_lists(self):
        summary = json.loads(tool.render(RESULT)["evidence.json"])
        self.assertEqual(summary["named_cases"], sum(len(rows) for rows in LISTS.values()))
        self.assertEqual(summary["mutations"]["total"], summary["mutations"]["killed"] + summary["mutations"]["survived"])
        self.assertTrue(summary["divide_by_1000"]["exact_for_all_u64"])


class Curve(unittest.TestCase):
    def test_start_at_zero_elapsed(self):
        self.assertEqual(price(seconds=0.0), (tool.TAG_OK, 1000))

    def test_linear_points(self):
        self.assertEqual(price(seconds=15.0)[1], 775)
        self.assertEqual(price(seconds=30.0)[1], 550)
        self.assertEqual(price(seconds=45.0)[1], 325)

    def test_floor_at_and_after_the_end(self):
        self.assertEqual(price(seconds=60.0)[1], 100)
        self.assertEqual(price(seconds=1e9)[1], 100)

    def test_truncates_toward_the_floor(self):
        self.assertEqual(price(seconds=59.999)[1], 100)
        self.assertEqual(price(seconds=59.0)[1], 115)

    def test_milliseconds_round_half_away(self):
        auction = tool.Auction(millis=1000, start=1000000, floor=0)
        self.assertEqual(price(seconds=0.0005, auction=auction)[1], 999000)
        self.assertEqual(price(seconds=0.00049, auction=auction)[1], 1000000)

    def test_status_order(self):
        bad = tool.Auction(start=1, floor=2)
        self.assertEqual(price(auction=bad.copy(tag=1))[0], tool.TAG_COMPLETED)
        self.assertEqual(price(auction=bad, time=tool.NEXT_DAY)[0], tool.TAG_NOT_STARTED)
        self.assertEqual(price(auction=bad)[0], tool.TAG_SUB)

    def test_same_instant_is_started(self):
        self.assertEqual(price(time=tool.T_NOW, seconds=0.0)[0], tool.TAG_OK)
        self.assertEqual(price(time=tool.LATER_NANO)[0], tool.TAG_NOT_STARTED)

    def test_rounding_can_exceed_start(self):
        self.assertEqual(price(seconds=0.0, auction=tool.Auction(start=(1 << 53) + 3, floor=0))[1], (1 << 53) + 4)

    def test_sum_overflow_gives_floor(self):
        self.assertEqual(price(seconds=0.0, auction=tool.Auction(start=tool.MASK[8], floor=1))[1], 1)

    def test_zero_duration_gives_floor(self):
        self.assertEqual(price(seconds=0.0, auction=tool.Auction(millis=0))[1], 100)
        self.assertEqual(price(seconds=5.0, auction=tool.Auction(millis=0))[1], 100)

    def test_infinite_elapsed_counts_as_zero(self):
        self.assertEqual(price(round_bits=tool.to_bits(math.inf))[1], 1000)
        self.assertEqual(price(round_bits=tool.to_bits(1e300))[1], 100)
        self.assertEqual(price(round_bits=tool.to_bits(math.nan))[1], 1000)

    def test_auction_is_not_written(self):
        case = named(tool.PRICE, "quarter")
        self.assertEqual(HARNESS.run(case)[3], case.auction.data())

    def test_factor_stays_within_the_guard(self):
        for numerator in (0, 1, 7, 60000, 1 << 63, tool.MASK[8]):
            for denominator in (0, 1, 60000, tool.MASK[8]):
                factor = 1.0 - tool.fdiv(float(numerator), float(denominator))
                factor = factor if factor > 0.0 else 0.0
                self.assertTrue(0.0 <= factor <= 1.0)


class Stages(unittest.TestCase):
    def test_all_patterns_are_covered(self):
        for label in ("elapsed", "product"):
            rows = [row for row in RESULT["pieces"] if row[0] == label]
            rows.sort(key=lambda row: int(row[1], 16))
            self.assertEqual(int(rows[0][1], 16), 0)
            self.assertEqual(int(rows[-1][2], 16), tool.MASK[8])
            for left, right in zip(rows, rows[1:]):
                self.assertEqual(int(left[2], 16) + 1, int(right[1], 16))

    def test_closed_form(self):
        self.assertEqual(tool.saturate(math.inf), 0)
        self.assertEqual(tool.saturate(math.nan), 0)
        self.assertEqual(tool.saturate(-1.0), 0)
        self.assertEqual(tool.saturate(1.9), 1)
        self.assertEqual(tool.saturate(tool.TWO64), tool.MASK[8])
        self.assertEqual(tool.saturate(18446744073709549568.0), 18446744073709549568)

    def test_a_wrong_stage_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.refine(lambda bits: ((), 7), "elapsed")

    def test_a_mutated_stage_changes(self):
        patch = {tool.STAGE_TWO[0] + 8: 0x74 ^ 1}
        harness = tool.Harness(IMAGE, patch)
        with self.assertRaises(tool.EvidenceError):
            tool.refine(harness.product_stage, "product")

    def test_divide_rule_edges(self):
        multiplier = tool.division_bound()[0]
        for value in (0, 999, 1000, 1999, tool.MASK[8], tool.MASK[8] - tool.MASK[8] % 1000, tool.MASK[8] - tool.MASK[8] % 1000 - 1):
            self.assertEqual(((value >> 3) * multiplier) >> 68, value // 1000)


class Restart(unittest.TestCase):
    def state(self, name):
        case = named(tool.RESTART, name)
        got = HARNESS.run(case)
        self.assertEqual(got, tool.spec_run(case))
        return struct.unpack("<8Q", got[3])

    def test_no_roll_writes_nothing(self):
        case = named(tool.RESTART, "no_roll")
        self.assertEqual(HARNESS.run(case)[3], case.auction.data())
        self.assertEqual(HARNESS.run(case)[4], 0)

    def test_no_sale_sets_min_gas(self):
        words = self.state("no_sale_gives_floor")
        self.assertEqual(words[5], 321)
        self.assertEqual(words[0], 0)

    def test_sale_multiplies(self):
        self.assertEqual(self.state("sale_doubles")[5], 18)

    def test_no_floor_on_a_sale(self):
        self.assertEqual(self.state("sale_below_floor_stays_below")[5], 6)
        self.assertEqual(self.state("sale_ratio_zero")[5], 0)

    def test_overflow_keeps_the_old_start_and_clears_the_sale(self):
        words = self.state("product_overflows_by_one")
        self.assertEqual(words[5], 1000)
        self.assertEqual(words[0], 0)
        self.assertEqual(words[1], 1 << 63)

    def test_top_of_range_fits(self):
        self.assertEqual(self.state("product_top")[5], tool.MASK[8])

    def test_tag_is_a_32_bit_compare(self):
        self.assertEqual(self.state("tag_high_word_ignored")[5], 18)
        self.assertEqual(self.state("tag_word_is_two")[5], 6)


class Roll(unittest.TestCase):
    def test_visit_order(self):
        for kind in tool.ROLLS:
            got = HARNESS.run(named(kind, "all_roll"))
            bases = [event[5] - tool.STATE for event in got[1] if event[0] == "restart"]
            self.assertEqual(tuple(bases), tool.LAYOUTS[kind]["order"])

    def test_equal_bucket_does_not_roll(self):
        got = HARNESS.run(named(tool.ROLLS[0], "none_roll"))
        self.assertEqual([event[3] for event in got[1] if event[0] == "restart"], [0, 0, 0, 0])

    def test_bucket_only_moves_forward(self):
        case = named(tool.ROLLS[0], "equal_minus_one")
        states = HARNESS.run(case)[2]
        bucket = tool.bucket_of(tool.T_NOW, 60000)
        self.assertEqual([struct.unpack_from("<Q", row, 0x18)[0] for row in states], [bucket, bucket, bucket + 1, bucket])

    def test_disabled_is_skipped(self):
        got = HARNESS.run(named(tool.ROLLS[0], "all_disabled"))
        self.assertEqual([event[0] for event in got[1]], ["gossip"])

    def test_borrow_word_skips_the_slots(self):
        got = HARNESS.run(named(tool.ROLLS[1], "borrowed"))
        self.assertNotIn("gossip", [event[0] for event in got[1]])

    def test_zero_bucket_traps(self):
        case = named(tool.ROLLS[0], "all_roll")
        case = copy.copy(case)
        case.auctions = tool.roll_auctions(millis=(0, 1, 1, 1))
        with self.assertRaises(tool.Halt):
            HARNESS.run(case)

    def test_date_reference_points(self):
        self.assertEqual(tool.millis_of((1970 << 13 | 1 << 4, 0, 0)), 0)
        self.assertEqual(tool.millis_of((1970 << 13 | 2 << 4, 1, 1000000)), 86401001)
        self.assertEqual(tool.millis_of((1969 << 13 | 365 << 4, 86399, 0)), 0)

    def test_second_layout_differs(self):
        self.assertNotEqual(tool.LAYOUT_FIRST["order"], tool.LAYOUT_SECOND["order"])
        rows = {row[0]: row[3] for row in RESULT["rolls"]}
        self.assertIn("0x3d28", rows["0x4cee5e0"])
        self.assertIn("0x32a8", rows["0x4cee310"])


class Gates(unittest.TestCase):
    def out(self, target, name):
        case = named(target, name)
        got = HARNESS.run(case)
        self.assertEqual(got, tool.spec_run(case))
        return got[1]

    def test_status_words(self):
        for target in tool.GATES + tool.SHORT_GATES:
            self.assertEqual(struct.unpack_from("<H", self.out(target, "plain"), 0)[0], tool.TAG_OK)
            self.assertEqual(struct.unpack_from("<H", self.out(target, "max_over"), 0)[0], tool.TAG_OVER_MAX)
            self.assertEqual(struct.unpack_from("<H", self.out(target, "one_short"), 0)[0], tool.TAG_NO_BALANCE)

    def test_exact_balance_is_enough(self):
        self.assertEqual(struct.unpack_from("<Q", self.out(tool.GATES[0], "exact_balance"), 8)[0], 900)

    def test_max_equal_passes(self):
        self.assertEqual(struct.unpack_from("<H", self.out(tool.GATES[1], "max_equal"), 0)[0], tool.TAG_OK)

    def test_order_of_first_checks(self):
        self.assertEqual(self.out(tool.GATES[0], "zero_user_before_disabled")[0x18], 2)
        self.assertEqual(struct.unpack_from("<H", self.out(tool.GATES[0], "disabled_before_exempt"), 0)[0], tool.TAG_DISABLED)
        self.assertEqual(self.out(tool.GATES[0], "exempt_skips_price")[0x18], 2)

    def test_keep_uses_the_recorded_price(self):
        out = self.out(tool.GATES[0], "keep_completed_ignores_max")
        self.assertEqual(struct.unpack_from("<H", out, 0)[0], tool.TAG_OK)
        self.assertEqual(struct.unpack_from("<Q", out, 8)[0], 37)
        self.assertEqual(out[0x18], 1)

    def test_refusal_words_differ_between_copies(self):
        price_word = [struct.unpack_from("<Q", self.out(target, "one_short"), 8)[0] for target in tool.GATES + tool.SHORT_GATES]
        token_word = [struct.unpack_from("<Q", self.out(target, "one_short"), 0x10)[0] for target in tool.GATES + tool.SHORT_GATES]
        fill = 0xCCCCCCCCCCCCCCCC
        self.assertEqual(price_word, [901, fill, fill, fill])
        self.assertEqual(token_word, [7, 7, fill, fill])

    def test_copy_sizes(self):
        self.assertEqual(IMAGE.exact_fde(tool.GATES[1])[1] - tool.GATES[1], 802)
        self.assertEqual(IMAGE.exact_fde(tool.GATES[0])[1] - tool.GATES[0], 806)

    def test_absent_row_needs_zero_price(self):
        self.assertEqual(struct.unpack_from("<H", self.out(tool.GATES[0], "empty_map_zero_price"), 0)[0], tool.TAG_OK)
        self.assertEqual(struct.unpack_from("<H", self.out(tool.GATES[0], "empty_map_one"), 0)[0], tool.TAG_NO_BALANCE)

    def test_hold_overflow_is_refused(self):
        self.assertEqual(struct.unpack_from("<H", self.out(tool.SHORT_GATES[0], "hold_overflow"), 0)[0], tool.TAG_NO_BALANCE)
        self.assertEqual(struct.unpack_from("<H", self.out(tool.SHORT_GATES[0], "hold_exact_top"), 0)[0], tool.TAG_OK)


class Info(unittest.TestCase):
    def run_case(self, name):
        case = named(tool.INFO, name)
        got = HARNESS.run(case)
        self.assertEqual(got, tool.spec_run(case))
        return got

    def test_open_row(self):
        got = self.run_case("open")
        self.assertEqual(got[1], 775 / 1e8)
        self.assertIsNone(got[2])
        self.assertEqual(got[4], 60)
        self.assertEqual(got[5], 1000 / 1e8)

    def test_completed_row(self):
        got = self.run_case("completed")
        self.assertIsNone(got[1])
        self.assertEqual(got[2], 12345 / 1e8)

    def test_failed_price_is_a_null(self):
        self.assertIsNone(self.run_case("sub_error")[1])
        self.assertIsNone(self.run_case("not_started")[1])

    def test_token_bound_panics(self):
        self.assertEqual(self.run_case("token_at_length")[0], "panic")

    def test_seconds_clamp(self):
        self.assertEqual(self.run_case("before_epoch_seconds")[3], 0)
        self.assertEqual(self.run_case("epoch_seconds")[3], 1)


class Evidence(unittest.TestCase):
    def test_field_rows(self):
        self.assertEqual({row[0]: row[2] for row in RESULT["fields"]}, {"bucket_guard": "0x10", "start_gas_wei": "0x28", "end_gas_wei": "0x0", "token": "0x30",
                                                                        "initial_gas_to_last_auction_gas_ratio": "0x20", "min_gas": "0x38"})

    def test_a_corrupted_key_fails(self):
        with self.assertRaises(tool.EvidenceError):
            tool.field_rows(corrupted(0x3DFEF4, 0x58))

    def test_a_corrupted_field_row_fails(self):
        with self.assertRaises(tool.EvidenceError):
            tool.field_rows(corrupted(0x230BCC7 + 3, 0x29))

    def test_a_corrupted_auction_key_fails(self):
        with self.assertRaises(tool.EvidenceError):
            tool.auction_rows(corrupted(0x598928, 0x58))

    def test_a_corrupted_power_fails(self):
        with self.assertRaises(tool.EvidenceError):
            tool.constant_rows(corrupted(tool.POW10 + 8 * 3 + 1, 0x41))

    def test_a_corrupted_status_arm_fails(self):
        arm = int(RESULT["statuses"][0][1], 16)
        with self.assertRaises(tool.EvidenceError):
            tool.status_rows(corrupted(arm + 18, 0x90))

    def test_a_corrupted_roll_offset_fails(self):
        with self.assertRaises(tool.EvidenceError):
            tool.roll_rows(corrupted(0x2702071 + 3, 0x98))

    def test_status_text(self):
        rows = {row[0]: row[2] for row in RESULT["statuses"]}
        self.assertEqual(rows["0x176"], "Gas auction completed. Try again later.")
        self.assertEqual(rows["0x17a"], "Deploys are currently disabled")

    def test_call_sites(self):
        rows = {row[1]: row[2] for row in RESULT["sites"]}
        self.assertEqual(rows["price"], 8)
        self.assertEqual(rows["restart"], 5)
        self.assertEqual(rows["gate_b"], 6)

    def test_a_spec_miss_is_refused(self):
        case = copy.copy(named(tool.PRICE, "quarter"))
        original = tool.spec_run
        tool.spec_run = lambda row: ("price", b"", (), b"")
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.check_cases(HARNESS, [case])
        finally:
            tool.spec_run = original

    def test_an_edited_guard_is_caught(self):
        harness = tool.Harness(IMAGE, {0x325CDE7 + 1: 0x83})
        self.assertIsNotNone(tool.first_failure(harness, LISTS[tool.PRICE]))

    def test_every_listed_survivor_survived(self):
        survived = {(row[0], row[1]) for row in RESULT["mutations"] if row[2] == "survived"}
        self.assertEqual(survived, set(tool.EXPECTED_SURVIVORS))

    def test_no_unexplained_survivor(self):
        self.assertFalse([row for row in RESULT["mutations"] if row[3] == "UNEXPLAINED"])

    def test_only_expected_rows_stay_unreached(self):
        self.assertEqual(RESULT["unreached"][tool.PRICE], [0x325CEDA])
        for target in tool.GATES + tool.SHORT_GATES + (tool.INFO, tool.RESTART):
            self.assertEqual(RESULT["unreached"][target], [])


if __name__ == "__main__":
    unittest.main()
