"""Tests for tools/hyperliquidity_refresh.py: ladder refresh and level cursor of node #94."""

import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import hyperliquidity_refresh as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-006-hyperliquidity-refresh-94"
SHARED = {}


def shared():
    if not SHARED:
        SHARED["image"] = tool.load_image()
        SHARED["evidence"] = tool.analyse(SHARED["image"], full=False)
        SHARED["harness"] = tool.Harness(SHARED["image"])
    return SHARED


def orders(run):
    rows = []
    for event in run["events"]:
        if event[0] == "place":
            fields = dict(event[4])
            rows.append((fields[0x80], fields[0x08], event[5]))
    return rows


def cancels(run):
    return [event[3] for event in run["events"] if event[0] == "cancel one"]


def run_ladder(*args, **options):
    return shared()["harness"].run(tool.ladder_case("t", *args, **options))


def cursor(balance, size=1000, levels=10, tokens=((2, 2),)):
    case = tool.Case("t", [tool.Ladder(0, tuple(range(1000, 1000 + levels)), size)], tokens=tokens, balances=((0, balance),))
    return shared()["harness"].run_cursor(case)


P = tool.PRICES


class IdentityTests(unittest.TestCase):
    def test_wrong_hash_is_refused(self):
        with self.assertRaisesRegex(tool.EvidenceError, "SHA-256 mismatch"):
            tool.load_image(expected="0" * 64)

    def test_hash_constant(self):
        self.assertEqual(tool.SHA256, "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f")

    def test_function_extents(self):
        image = shared()["image"]
        self.assertEqual(image.exact_fde(tool.ENSURE), (0x26CB280, 0x26CC72C))
        self.assertEqual(image.exact_fde(tool.CURSOR), (0x3263760, 0x32639B9))

    def test_outside_every_fde_is_refused(self):
        with self.assertRaisesRegex(tool.EvidenceError, "not an FDE start"):
            shared()["image"].exact_fde(tool.ENSURE + 1)

    def test_nobits_never_resolves(self):
        image = shared()["image"]
        bss = image.named[".bss"]
        with self.assertRaisesRegex(tool.EvidenceError, "outside file-backed"):
            image.offset(bss["address"] + bss["size"] - 8)

    def test_callers_are_pinned(self):
        rows = shared()["evidence"]["callers"]["refresh"]
        self.assertEqual(sorted(row["site"] for row in rows), ["0x2229404", "0x26fef91"])

    def test_changed_call_bytes_fail(self):
        image = shared()["image"]
        at = image.offset(tool.SPAN_SITE + 1)
        blob = bytearray(image.blob)
        blob[at] ^= 1
        broken = tool.Image.__new__(tool.Image)
        broken.__dict__.update(image.__dict__)
        broken.blob = bytes(blob)
        with self.assertRaisesRegex(tool.EvidenceError, "refresh sites differ"):
            tool.check_callers(broken)

    def test_pins_have_their_counts(self):
        rows = shared()["evidence"]["pins"]
        self.assertEqual(len(rows), len(tool.PINS))
        self.assertEqual(len(next(row for row in rows if "0x63" in row["meaning"])["sites"]), 3)

    def test_a_wrong_pin_count_fails(self):
        image = shared()["image"]
        kept = tool.PINS
        try:
            tool.PINS = ((tool.ENSURE, "no such bytes", b"\x90\x90\x90\x90\x90\x90\x90\x90\xf1", 1),)
            with self.assertRaisesRegex(tool.EvidenceError, "has 0 sites"):
                tool.read_pins(image)
        finally:
            tool.PINS = kept

    def test_constants(self):
        constants = shared()["evidence"]["constants"]
        self.assertEqual(constants["span_name"]["text"], "hyperliquidity_ensure_orders")
        self.assertEqual(constants["user_tail_mask"]["bytes"], "ff" * 4 + "00" * 12)

    def test_corrupt_mask_fails(self):
        image = shared()["image"]
        blob = bytearray(image.blob)
        blob[image.offset(tool.USER_TAIL)] ^= 1
        broken = tool.Image.__new__(tool.Image)
        broken.__dict__.update(image.__dict__)
        broken.blob = bytes(blob)
        with self.assertRaisesRegex(tool.EvidenceError, "user tail mask"):
            tool.read_constants(broken)

    def test_locations_stay_below_the_crate(self):
        for row in shared()["evidence"]["locations"]:
            self.assertFalse(row["path"].startswith("/"), row)


class EvaluatorTests(unittest.TestCase):
    def test_no_mismatch(self):
        evidence = shared()["evidence"]
        self.assertEqual(evidence["mismatches"], 0, evidence["first_mismatch"])

    def test_every_outcome_occurs(self):
        outcomes = shared()["evidence"]["refresh_outcomes"]
        self.assertEqual(sorted(outcomes), ["cancels and new orders", "cancels only", "flat ladder, all cancelled", "new orders only", "no ladder read", "nothing to change", "panic"])
        self.assertTrue(all(outcomes.values()))

    def test_most_of_each_function_runs(self):
        for row in shared()["evidence"]["functions"][:2]:
            self.assertGreaterEqual(row["instructions_stepped"] / row["instructions"], 0.85, row)

    def test_the_copies_run_all_but_their_inline_map_drop(self):
        for row in shared()["evidence"]["functions"][2:]:
            self.assertGreaterEqual(row["instructions_stepped"] / row["instructions"], 0.7, row)
        for row in shared()["evidence"]["copies"]:
            self.assertEqual(row["mismatches"], 0)

    def test_a_corrupted_constant_is_seen(self):
        harness = tool.Harness(shared()["image"])
        at = tool.find_all(shared()["image"], tool.ENSURE, b"\x48\x83\x7c\x24\x18\x63")[0]
        harness.machine.patches = {at + 5: 0x20}
        case = tool.ladder_case("x", 60, prices=tuple(1000 + at for at in range(64)), book=tool.Book(None, None))
        self.assertRegex(tool.compare_run(harness, case) or "", "differs")

    def test_a_wrong_spec_is_seen(self):
        harness = tool.Harness(shared()["image"])
        run = harness.run(tool.ladder_case("x", 3))
        wrong = tool.spec_run(tool.copy_case(tool.ladder_case("x", 4)))
        self.assertNotEqual(run["events"], wrong["events"])

    def test_a_mutated_branch_is_seen(self):
        image = shared()["image"]
        harness = tool.Harness(image)
        # Flip the jb of the ask crossing test.
        site = 0x26CB949
        harness.machine.patches = {site + 1: image.blob[image.offset(site + 1)] ^ 1}
        self.assertRegex(tool.compare_run(harness, tool.ladder_case("x", 5, book=tool.Book(-1100, 1400))) or "", "differs")

    def test_spec_and_run_share_no_levels(self):
        case = tool.ladder_case("x", 3)
        tool.spec_run(tool.copy_case(case))
        self.assertTrue(all(level.tag == 0 for level in case.ladders[0].levels))


class CursorTests(unittest.TestCase):
    def test_whole_orders_count_from_the_top(self):
        self.assertEqual(cursor(3000)["out"], (7, 0, None))

    def test_remainder_takes_one_more_level(self):
        self.assertEqual(cursor(3500)["out"], (6, 1, 500))

    def test_no_balance_is_the_top_of_the_ladder(self):
        self.assertEqual(cursor(0)["out"], (10, 0, None))

    def test_full_ladder(self):
        self.assertEqual(cursor(10000)["out"], (0, 0, None))

    def test_more_than_the_ladder_with_remainder_stays_at_zero(self):
        self.assertEqual(cursor(25007)["out"], (0, 1, 7))

    def test_order_size_zero_is_the_top(self):
        self.assertEqual(cursor(5000, size=0)["out"], (10, 0, None))

    def test_scale_uses_both_decimals(self):
        self.assertEqual(cursor(3000 * tool.UNIT + tool.UNIT - 1, tokens=((3, 8),))["out"], (7, 0, None))

    def test_scale_19_works_and_20_panics(self):
        self.assertIsNone(cursor(1 << 63, tokens=((0, 19),))["stop"])
        self.assertEqual(cursor(1 << 63, tokens=((0, 20),))["stop"], ("panic", tool.LOCATION_DECIMALS))

    def test_scale_32_panics(self):
        self.assertEqual(cursor(1 << 63, tokens=((0, 32),))["stop"], ("panic", tool.LOCATION_DECIMALS))

    def test_negative_scale_panics(self):
        self.assertEqual(cursor(5, tokens=((4, 3),))["stop"], ("panic", tool.LOCATION_DECIMALS))

    def test_table_is_monotone(self):
        rows = shared()["evidence"]["worked_example"]["cursor_table"]
        self.assertEqual([row["index"] for row in rows], sorted((row["index"] for row in rows), reverse=True))


class RefreshTests(unittest.TestCase):
    def test_empty_book_three_whole(self):
        run = run_ladder(3, book=tool.Book(None, None))
        self.assertEqual(orders(run), [(P[at], 1000, 0) for at in range(6, -1, -1)] + [(P[at], 1000, 1) for at in range(7, 10)])

    def test_first_ask_is_the_remainder(self):
        run = run_ladder(3, 500, book=tool.Book(None, None))
        self.assertEqual(orders(run)[:6], [(P[at], 1000, 0) for at in range(5, -1, -1)])
        self.assertEqual(orders(run)[6:], [(P[6], 500, 1)] + [(P[at], 1000, 1) for at in range(7, 10)])

    def test_asks_above_the_bid_only(self):
        run = run_ladder(5, book=tool.Book(-1201, None))
        self.assertEqual([row[0] for row in orders(run) if row[2]], [P[6], P[7], P[8], P[9]])

    def test_equal_to_the_bid_is_skipped(self):
        run = run_ladder(5, book=tool.Book(-P[5], None))
        self.assertEqual([row[0] for row in orders(run) if row[2]], [P[6], P[7], P[8], P[9]])

    def test_bids_below_the_ask_only(self):
        run = run_ladder(5, book=tool.Book(None, P[3]))
        self.assertEqual([row[0] for row in orders(run) if not row[2]], [P[2], P[1], P[0]])

    def test_skip_loses_the_remainder_size(self):
        run = run_ladder(5, 11, book=tool.Book(-P[4], None))
        self.assertEqual([row for row in orders(run) if row[2]][0], (P[5], 1000, 1))

    def test_kept_order_stays(self):
        levels = tool.resting(*[(1 if at == 7 else 0, 301, P[at]) for at in range(10)])
        run = run_ladder(5, levels=levels, book=tool.Book(None, None, [tool.Slot(side=1)], [(301, 0)]))
        self.assertEqual(cancels(run), [])
        self.assertNotIn((P[7], 1000, 1), orders(run))

    def test_wrong_size_is_replaced(self):
        levels = tool.resting(*[(1 if at == 7 else 0, 301, P[at]) for at in range(10)])
        run = run_ladder(5, levels=levels, book=tool.Book(None, None, [tool.Slot(side=1, size=9)], [(301, 0)]))
        self.assertEqual(cancels(run), [301])
        self.assertIn((P[7], 1000, 1), orders(run))

    def test_stranger_is_not_cancelled(self):
        levels = tool.resting(*[(1 if at == 7 else 0, 301, P[at]) for at in range(10)])
        run = run_ladder(5, levels=levels, book=tool.Book(None, None, [tool.Slot(side=1, user=b"\x01" * 20)], [(301, 0)]))
        self.assertEqual(cancels(run), [])
        self.assertIn((P[7], 1000, 1), orders(run))

    def test_cancels_run_before_places(self):
        levels = tool.resting(*[(1 if at == 7 else 0, 301, P[at]) for at in range(10)])
        run = run_ladder(5, levels=levels, book=tool.Book(None, None, [tool.Slot(side=1, size=9)], [(301, 0)]))
        kinds = [event[0] for event in run["events"]]
        self.assertLess(kinds.index("cancel one"), kinds.index("place"))

    def test_placed_id_is_stored(self):
        run = run_ladder(9, prices=P[:10], book=tool.Book(None, None))
        self.assertEqual(int.from_bytes(run["levels"][0][0][:8], "little"), 1)
        self.assertEqual(int.from_bytes(run["levels"][0][0][8:16], "little"), tool.PLACED_ID)

    def test_failed_place_leaves_the_level(self):
        run = run_ladder(9, places={0: tool.PlaceResult(failed=True)}, book=tool.Book(None, None))
        self.assertEqual(int.from_bytes(run["levels"][0][0][:8], "little"), 0)

    def test_cap_of_one_hundred(self):
        many = tuple(1000 + at * 8 for at in range(260))
        run = run_ladder(130, prices=many, book=tool.Book(None, None))
        rows = orders(run)
        self.assertEqual(sum(1 for row in rows if not row[2]), 100)
        self.assertEqual(sum(1 for row in rows if row[2]), 100)

    def test_orders_past_the_cap_are_cancelled(self):
        many = tuple(1000 + at * 8 for at in range(130))
        levels = tool.resting(*[(1, 2000 + at, many[at]) for at in range(130)])
        slots = [tool.Slot(side=0) for _ in range(130)]
        run = run_ladder(0, levels=levels, book=tool.Book(None, None, slots, [(2000 + at, at) for at in range(130)]))
        self.assertEqual(cancels(run), [2000 + at for at in range(29, -1, -1)])
        self.assertEqual(orders(run), [])

    def test_flat_ladder_cancels_all(self):
        run = run_ladder(0, prices=(1000,))
        self.assertEqual([event[0] for event in run["events"]], ["cancel all"])
        self.assertEqual(run["events"][0][2:], ("ff" * 20, 1, tool.EX, tool.CONTEXT, 2))

    def test_empty_ladder_reads_the_cursor_and_does_nothing(self):
        self.assertEqual([event[0] for event in run_ladder(0, prices=())["events"]], ["lookup"])

    def test_no_ladder_row_is_skipped_before_the_book_bound(self):
        case = tool.Case("t", [tool.Ladder(99, tool.PRICES, none=True)])
        self.assertIsNone(shared()["harness"].run(case)["stop"])

    def test_book_bound_panics(self):
        case = tool.Case("t", [tool.Ladder(5, tool.PRICES)], book_count=5, balances=tool.balance_for(3))
        self.assertEqual(shared()["harness"].run(case)["stop"], ("panic", tool.LOCATION_BOOKS))

    def test_time_goes_into_the_record(self):
        run = run_ladder(3, book=tool.Book(None, None))
        record = dict(next(event for event in run["events"] if event[0] == "place")[4])
        self.assertEqual(record[0x88], tool.time_millis(tool.NOW))
        self.assertEqual(tool.time_millis(tool.NOW) % 1000, 789)

    def test_user_in_the_record(self):
        run = run_ladder(3, book=tool.Book(None, None))
        self.assertEqual(next(event for event in run["events"] if event[0] == "place")[6], "ff" * 20)


class OutputTests(unittest.TestCase):
    def test_stored_packet_matches(self):
        stored = json.loads((FOLDER / "evidence.json").read_text())
        fresh = dict(shared()["evidence"])
        for key in ("mutations", "_sites", "_results"):
            fresh.pop(key)
        for key, value in fresh.items():
            self.assertEqual(stored[key], json.loads(json.dumps(value)), key)

    def test_mutation_rows_have_reasons(self):
        for line in (FOLDER / "mutations.tsv").read_text().splitlines()[1:]:
            row = line.split("\t")
            if row[3] != "killed":
                self.assertTrue(row[5], line)

    def test_render_is_ascii_and_ends_in_newline(self):
        files = tool.render(shared()["evidence"])
        for name, text in files.items():
            self.assertTrue(text.isascii(), name)
            self.assertTrue(text.endswith("\n"), name)

    def test_write_outputs(self):
        with tempfile.TemporaryDirectory() as folder:
            tool.write_outputs(folder, {"x.txt": "a\n"})
            self.assertEqual((pathlib.Path(folder) / "x.txt").read_text(), "a\n")


if __name__ == "__main__":
    unittest.main()
