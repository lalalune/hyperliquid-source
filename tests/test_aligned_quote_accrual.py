"""Tests for tools/aligned_quote_accrual.py: real node #94 bytes with corruption controls."""

import copy
import hashlib
import importlib.util
import json
import pathlib
import struct
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FOLDER = ROOT / "research" / "work-items" / "RE-004-aligned-quote-accrual-94"
spec_ = importlib.util.spec_from_file_location("aligned_quote_accrual", ROOT / "tools" / "aligned_quote_accrual.py")
tool = importlib.util.module_from_spec(spec_)
sys.modules["aligned_quote_accrual"] = tool
spec_.loader.exec_module(tool)

IMAGE = None
HARNESS = None
Row = tool.Row
DAY = tool.DAY
CUT = tool.CUT_MAIN
BEFORE = tool.add_days(DAY, -1)
TOP = tool.TOP
YEAR = tool.YEAR_SECONDS
BITS = tool.bits


def setUpModule():
    global IMAGE, HARNESS
    IMAGE = tool.load_image()
    tool.RealCode.ALL = tool.collect_real(IMAGE)
    HARNESS = tool.Harness(IMAGE)


def run(**fields):
    case = tool.Case("t", **fields)
    before, got = HARNESS.run(case)
    want = tool.spec_run(case, before)
    text = tool.mismatch(case, got, want, before)
    assert text is None, text
    return got


def daily(got, token=5, flag=0):
    return dict(got["maps"][flag, token])


def payouts(got):
    return [event for event in got["events"] if event[0] == "transfer"]


def drops(got):
    return [event for event in got["events"] if event[0] == "drop"]


def corrupted(va, value):
    bad = copy.copy(IMAGE)
    data = bytearray(IMAGE.blob)
    data[IMAGE.offset(va)] = value
    bad.blob = bytes(data)
    bad.relative_map = None
    return bad


def mutated(patch, case):
    harness = tool.Harness(IMAGE, patch)
    return tool.first_failure(harness, [case]) is not None


def vote(who, rate, when=(DAY, 3550, 0)):
    return who, BITS(rate), when


LIVE = dict(kind="median", guard=tool.time_ms((DAY, 3600, 7000)) // 60000 - 1)


class Accrual(unittest.TestCase):
    def test_amount_times_rate_times_seconds_over_a_year(self):
        for index in range(3):
            got = run(copy=index, dt=86400.0, rate=0.04, rows=(Row(5, 10 ** 12),))
            self.assertEqual(daily(got), {DAY: int(float(10 ** 12) * (86400.0 * 0.04 / YEAR))})

    def test_the_key_is_todays_date_and_adds_to_it(self):
        got = run(dt=YEAR, rate=0.5, rows=(Row(5, 1000, ((DAY, 7), (tool.LATER, 9))),))
        self.assertEqual(daily(got), {DAY: 507, tool.LATER: 9})

    def test_no_median_is_rate_zero_and_still_inserts_the_key(self):
        got = run(dt=YEAR, tag=0, rate=0.9, rows=(Row(5, 1000),))
        self.assertEqual(daily(got), {DAY: 0})

    def test_below_one_second_accrues_nothing_and_keeps_the_time(self):
        got = run(dt=0.999, last=(DAY, 100, 200), rows=(Row(5, 10 ** 12),))
        self.assertEqual(got["last"], (DAY, 100, 200))
        self.assertEqual(daily(got), {})
        self.assertNotIn(("builder",), got["events"])

    def test_exactly_one_second_samples(self):
        got = run(dt=1.0, rate=YEAR, rows=(Row(5, 3),))
        self.assertEqual(daily(got), {DAY: 3})

    def test_first_sample_sets_the_time_without_accrual(self):
        got = run(dt=0.0, last=(0, 0, 0), rows=(Row(5, 10 ** 12),))
        self.assertEqual(got["last"], (DAY, 3600, 7000))
        self.assertEqual(daily(got), {})

    def test_fraction_above_1_01_is_skipped_but_time_moves(self):
        got = run(dt=YEAR * 1.02, rate=1.0, rows=(Row(5, 1000),))
        self.assertEqual(daily(got), {})
        self.assertEqual(got["last"], (DAY, 3600, 7000))

    def test_fraction_1_01_passes(self):
        got = run(dt=YEAR * 1.01, rate=1.0, rows=(Row(5, 1000),))
        self.assertEqual(daily(got), {DAY: tool.owed(1000, YEAR * 1.01 * 1.0 / YEAR)})

    def test_negative_rate_panics_only_with_rows(self):
        self.assertEqual(run(dt=86400.0, rate=-0.01, rows=(Row(5, 1),))["panic"], "assertion failed: self >= 0.")
        self.assertIsNone(run(dt=86400.0, rate=-0.01, rows=())["panic"])

    def test_clamp_at_two_to_the_64(self):
        self.assertEqual(daily(run(dt=YEAR * 1.01, rate=1.0, rows=(Row(5, TOP),))), {DAY: TOP})

    def test_add_saturates_through_the_recorder(self):
        got = run(dt=YEAR, rate=1.0, rows=(Row(5, 1 << 62, ((DAY, TOP - 5),)),))
        self.assertEqual(daily(got), {DAY: TOP})
        self.assertIn(("recorder",), got["events"])

    def test_cast_rule(self):
        self.assertEqual(tool.owed(TOP, 1.0), TOP)
        self.assertEqual(tool.owed(TOP, tool.value_of(BITS(1.0) - 1)), (1 << 64) - 2048)
        self.assertEqual(tool.owed(0, 1.0), 0)
        self.assertEqual(tool.owed(3, 0.5), 1)

    def test_full_leaf_splits(self):
        items = tuple((tool.add_days(DAY, -slot - 1), slot) for slot in range(11))
        self.assertEqual(len(daily(run(dt=86400.0, rows=(Row(5, 10 ** 12, items),)))), 12)


class Payout(unittest.TestCase):
    def test_a_new_date_pays_the_key_45_days_back_and_removes_it(self):
        for index in range(3):
            got = run(copy=index, dt=0.5, prev=BEFORE, rows=(Row(5, 1, ((CUT, 1234), (tool.BEFORE, 9)), who=4),))
            self.assertEqual(payouts(got), [("transfer", tool.address(4), 5, 1234)])
            self.assertEqual(daily(got), {tool.BEFORE: 9})

    def test_chain_two_uses_2_days(self):
        cut = tool.CUT_TWO
        got = run(dt=0.5, prev=BEFORE, chain=2, rows=(Row(5, 1, ((cut, 8), (CUT, 3))),))
        self.assertEqual(payouts(got), [("transfer", tool.address(1), 5, 8)])
        self.assertEqual(daily(got), {CUT: 3})

    def test_same_date_never_pays(self):
        self.assertEqual(payouts(run(dt=0.5, rows=(Row(5, 1, ((CUT, 8),)),))), [])

    def test_keys_older_than_the_cutoff_are_never_paid(self):
        older = tool.add_days(CUT, -1)
        got = run(dt=0.5, prev=BEFORE, rows=(Row(5, 1, ((older, 8),)),))
        self.assertEqual(payouts(got), [])
        self.assertEqual(daily(got), {older: 8})

    def test_value_at_the_cap_logs_and_stays(self):
        got = run(dt=0.5, prev=BEFORE, rows=(Row(5, 1, ((CUT, tool.CAP),)),))
        self.assertEqual(drops(got), [("drop", tool.TAG_NUMBER, tool.CAP)])
        self.assertEqual(daily(got), {CUT: tool.CAP})

    def test_token_bound_logs_and_stays(self):
        got = run(dt=0.5, prev=BEFORE, count=5, rows=(Row(5, 1, ((CUT, 8),)),))
        self.assertEqual(drops(got), [("drop", tool.TAG_TOKEN, 8)])

    def test_refused_transfer_keeps_the_row_and_goes_on(self):
        got = run(dt=0.5, prev=BEFORE, refuse=(3,), rows=(Row(3, 1, ((CUT, 8),)), Row(9, 1, ((CUT, 4),), who=2)))
        self.assertEqual(daily(got, 3), {CUT: 8})
        self.assertEqual(daily(got, 9), {})

    def test_flag_one_row_lives_in_the_second_map(self):
        got = run(dt=0.5, prev=BEFORE, rows=(Row(6, 1, ((CUT, 55),), flag=1, who=3),))
        self.assertEqual(payouts(got), [("transfer", tool.address(3), 6, 55)])
        self.assertEqual(daily(got, 6, 1), {})

    def test_year_edge_uses_the_real_date_helper(self):
        now = tool.date_word(2027, 3)
        cut = tool.add_days(now, -45)
        self.assertEqual(tool.word_to_date(cut).isoformat(), "2026-11-19")
        self.assertEqual(payouts(run(dt=0.5, date=now, prev=tool.date_word(2027, 2), rows=(Row(5, 1, ((cut, 8),)),))), [("transfer", tool.address(1), 5, 8)])

    def test_state_word_zero_during_the_transfer_and_restored(self):
        before = bytes(HARNESS.machine.memory.heap[:8])
        got = run(dt=0.5, prev=BEFORE, rows=(Row(5, 1, ((CUT, 8),)),))
        self.assertEqual(got["heap"][tool.S - tool.HEAP_BASE:tool.S - tool.HEAP_BASE + 8], tool.HEAP_FILL[tool.S - tool.HEAP_BASE:tool.S - tool.HEAP_BASE + 8])
        self.assertEqual(len(before), 8)


class Median(unittest.TestCase):
    def test_bucket_gate_runs_nothing(self):
        got = run(kind="median", guard=LIVE["guard"] + 1, votes=(vote(1, 0.1),), stakes=((1, 10),), old=0.5)
        self.assertEqual(got["value"], BITS(0.5))

    def test_three_equal_stakes(self):
        got = run(votes=(vote(1, 0.3), vote(2, 0.1), vote(3, 0.2)), stakes=((1, 10), (2, 10), (3, 10)), **LIVE)
        self.assertEqual((got["tag"], got["value"]), (1, BITS(0.2)))

    def test_half_exact_moves_to_the_next_row(self):
        got = run(votes=(vote(1, 0.1), vote(2, 0.2), vote(3, 0.3)), stakes=((1, 5), (2, 5), (3, 0)), **LIVE)
        self.assertEqual(got["value"], BITS(0.2))
        got = run(votes=(vote(1, 0.1), vote(2, 0.2)), stakes=((1, 5), (2, 5)), **LIVE)
        self.assertEqual(got["value"], BITS(0.2))

    def test_no_usable_rows_keep_the_old_value(self):
        got = run(votes=(vote(1, float("nan")), vote(2, -0.5)), stakes=((1, 5), (2, 5)), old=0.25, **LIVE)
        self.assertEqual((got["tag"], got["value"]), (1, BITS(0.25)))

    def test_old_votes_leave_the_map_and_do_not_count(self):
        got = run(votes=(vote(1, 0.9, (DAY, 1000, 0)), vote(2, 0.2)), stakes=((1, 100), (2, 1)), **LIVE)
        self.assertEqual((got["value"], got["rows"]), (BITS(0.2), [2]))

    def test_age_limit_is_exclusive(self):
        self.assertEqual(run(votes=(vote(1, 0.1, (DAY, 3540, 7000)),), stakes=((1, 1),), **LIVE)["rows"], [])
        self.assertEqual(run(votes=(vote(1, 0.1, (DAY, 3540, 7001)),), stakes=((1, 1),), **LIVE)["rows"], [1])

    def test_vote_from_a_non_validator_stays_but_does_not_count(self):
        got = run(votes=(vote(7, 0.9), vote(1, 0.2)), stakes=((1, 3),), **LIVE)
        self.assertEqual((got["value"], got["rows"]), (BITS(0.2), [1, 7]))

    def test_total_overflow_gives_no_median(self):
        got = run(votes=(vote(1, 0.1), vote(2, 0.2)), stakes=((1, TOP), (2, 1)), old=0.25, **LIVE)
        self.assertEqual(got["value"], BITS(0.25))

    def test_minus_zero_is_a_vote(self):
        got = run(votes=(vote(1, -0.0),), stakes=((1, 3),), old=0.25, **LIVE)
        self.assertEqual(got["value"], BITS(-0.0))

    def test_large_list_goes_through_the_library_sort(self):
        votes = tuple(vote(slot + 1, 0.01 * (slot + 1)) for slot in range(24))
        got = run(votes=votes, stakes=tuple((slot + 1, 1) for slot in range(24)), **LIVE)
        self.assertEqual(got["value"], BITS(0.13))


class Dates(unittest.TestCase):
    def test_packed_dates_round_trip(self):
        for year, ordinal in ((2024, 60), (2026, 1), (2027, 365), (2028, 366)):
            self.assertEqual(tool.date_to_word(tool.word_to_date(tool.date_word(year, ordinal))), tool.date_word(year, ordinal))

    def test_time_ms(self):
        self.assertEqual(tool.time_ms((tool.date_word(1970, 2), 1, 2000000)), 86400000 + 1002)


class Bytes(unittest.TestCase):
    def test_serde_keys(self):
        rows = {row[6]: row[5] for row in tool.key_rows(IMAGE)}
        self.assertEqual((rows["active"], rows["evm_minted_supply"], rows["daily_wei_owed"]), ("0x2c", "0x0", "0x8"))
        self.assertEqual(rows["last_aqa_sample_time"], "0x1f9c")

    def test_serializer_shift_joins_two_known_offsets(self):
        rows = {row[6]: int(row[5], 16) for row in tool.key_rows(IMAGE)}
        self.assertEqual(rows["last_aqa_sample_time"] + 0x1B20, tool.COPIES[0].time_at)
        self.assertEqual(rows["validator_l1_stream_tracker"] + 0x1B20, tool.COPIES[0].tracker)
        self.assertEqual(rows["quote_token_to_aligned_quote_token_info"] + 0x90, 0x2B0)
        self.assertEqual(rows["ta2"] + 0x90, 0x2F8)

    def test_corrupt_key_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.key_rows(corrupted(0x598517, 0x58))

    def test_corrupt_field_row_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.key_rows(corrupted(0x375D875, 0x30))

    def test_pins(self):
        self.assertEqual(len(tool.pin_rows(IMAGE)), len(tool.PINS))

    def test_corrupt_pin_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.pin_rows(corrupted(0x3BAEE8D, 0xE3))

    def test_constants(self):
        rows = {row[3]: row[2] for row in tool.constant_rows(IMAGE)}
        self.assertEqual(rows["seconds in a Julian year"], "31557600.0")
        self.assertEqual(rows["days back, every other chain byte"], "-45")

    def test_corrupt_constant_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.constant_rows(corrupted(0x20A4D6, 0x7F))

    def test_corrupt_reader_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.constant_rows(corrupted(0x2763BC4, 0x11))

    def test_serde_texts(self):
        self.assertEqual([row[1] for row in tool.serde_rows(IMAGE)], [item.decode() for item in tool.SERDE])

    def test_corrupt_serde_text_is_refused(self):
        bad = copy.copy(IMAGE)
        bad.blob = bytes(IMAGE.blob).replace(tool.SERDE[0], b"X" * len(tool.SERDE[0]))
        with self.assertRaises(tool.EvidenceError):
            tool.serde_rows(bad)

    def test_panic_texts(self):
        self.assertIn("assertion failed: self >= 0.", [row[1] for row in tool.text_rows(IMAGE)])

    def test_corrupt_text_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.text_rows(corrupted(0x219D71, 0x58))

    def test_subjects_are_fde_starts(self):
        for target in tool.SUBJECTS:
            self.assertEqual(IMAGE.exact_fde(target)[0], target)

    def test_address_outside_an_fde_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.exact_fde(tool.GUARD + 1)

    def test_bad_digest_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)


class Controls(unittest.TestCase):
    def test_unedited_case_passes_the_same_check(self):
        self.assertFalse(mutated({}, tool.Case("c", dt=2.0, rows=(Row(5, 1),))))

    def test_one_second_gate_edit_is_seen(self):
        self.assertTrue(mutated({0x276382D: 0x83}, tool.Case("c", dt=2.0, rows=(Row(5, 10 ** 12),))))

    def test_day_count_edit_is_seen(self):
        self.assertTrue(mutated({0x2763E7D: 0xD4}, tool.Case("c", dt=0.5, prev=BEFORE, rows=(Row(5, 1, ((CUT, 8),)),))))

    def test_value_bound_edit_is_seen(self):
        self.assertTrue(mutated({0x27641DD: 0xCD}, tool.Case("c", dt=0.5, prev=BEFORE, rows=(Row(5, 1, ((CUT, tool.CAP),)),))))

    def test_half_edit_is_seen(self):
        self.assertTrue(mutated({0x336D42D: 0xE5}, tool.Case("c", votes=(vote(1, 0.3), vote(2, 0.1), vote(3, 0.2)), stakes=((1, 10), (2, 10), (3, 10)), **LIVE)))

    def test_age_compare_edit_is_seen(self):
        self.assertTrue(mutated({0x3265CF4: 0x73}, tool.Case("c", votes=(vote(1, 0.1, (DAY, 3540, 7000)),), stakes=((1, 1),), **LIVE)))

    def test_copy_c_tracker_edit_is_seen(self):
        self.assertTrue(mutated({0x4D91BBE: 0xD8}, tool.Case("c", copy=2, dt=86400.0, rows=(Row(5, 10 ** 12),))))

    def test_a_bad_parent_link_is_refused(self):
        harness = tool.Harness(IMAGE)
        harness.fresh(tool.Case("c", rows=(Row(5, 1, tuple((tool.add_days(DAY, -slot - 1), slot) for slot in range(14))),)))
        header = harness.headers[0, 5]
        memory = harness.machine.memory
        root = memory.read(header, 8)
        kid = memory.read(root + tool.L_DAILY.edge_at, 8)
        memory.write(kid, 8, 1)
        with self.assertRaises(tool.Halt):
            harness.read_daily(header)

    def test_a_changed_heap_byte_fails_the_check(self):
        case = tool.Case("c", dt=2.0, rows=(Row(5, 1),))
        harness = tool.Harness(IMAGE)
        before, got = harness.run(case)
        want = tool.spec_run(case, before)
        self.assertTrue(tool.same(case, got, want, before))
        heap = bytearray(got["heap"])
        heap[0x40] ^= 1
        got["heap"] = bytes(heap)
        self.assertFalse(tool.same(case, got, want, before))

    def test_stub_refuses_a_wrong_time_word(self):
        harness = tool.Harness(IMAGE, {0x27637C6: 0x85})
        case = tool.Case("c", dt=2.0, rows=(Row(5, 1),))
        self.assertIsNotNone(tool.first_failure(harness, [case]))


class Evidence(unittest.TestCase):
    def test_summary_matches_the_run(self):
        data = json.loads((FOLDER / "evidence.json").read_text())
        self.assertEqual(data["sha256"], tool.SHA256)
        self.assertEqual(data["named_cases"], len(tool.base_cases()))
        mutants = data["mutations"]
        self.assertEqual(mutants["killed"] + mutants["survived"], mutants["total"])

    def test_every_survivor_is_labelled(self):
        lines = (FOLDER / "mutations.tsv").read_text().splitlines()[1:]
        survivors = [line.split("\t") for line in lines if line.split("\t")[2] == "survived"]
        self.assertTrue(survivors)
        self.assertEqual({row[3] for row in survivors}, {tool.UNCLASSIFIED})

    def test_rows_hold_the_real_bytes(self):
        for name in ("function-rows.tsv", "window-rows.tsv"):
            for line in (FOLDER / name).read_text().splitlines()[1:]:
                _, addr, size, data, _ = line.split("\t")
                at = IMAGE.offset(int(addr, 16))
                self.assertEqual(bytes(IMAGE.blob[at:at + int(size)]).hex(), data)

    def test_manifest(self):
        for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_folder_holds_only_the_generated_set(self):
        names = {path.name for path in FOLDER.iterdir()}
        self.assertEqual(names, {"README.md", "MANIFEST.sha256", "evidence.json", "function-rows.tsv", "window-rows.tsv", "copies.tsv", "keys.tsv", "pins.tsv", "constants.tsv", "texts.tsv", "serde.tsv", "outcomes.tsv", "mutations.tsv"})

    def test_no_external_tool_is_called(self):
        text = (ROOT / "tools" / "aligned_quote_accrual.py").read_text()
        self.assertNotIn("subprocess", text)


if __name__ == "__main__":
    unittest.main()
