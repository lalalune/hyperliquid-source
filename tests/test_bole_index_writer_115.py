import hashlib
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import bole_index_writer_115 as tool  # noqa: E402

E14 = tool.E14
NOW = tool.NOW


def image():
    if not hasattr(image, "cached"):
        image.cached = tool.load_image()
    return image.cached


class SpecificationTests(unittest.TestCase):
    def test_epoch_and_round_trip(self):
        self.assertEqual(tool.unix_millis(*tool.time_word(1970, 1, 0, 0)), 0)
        self.assertEqual(tool.unix_millis(*tool.time_word(1970, 2, 1, 5000000)), 86400000 + 1000 + 5)
        for millis in (0, 1, 999, 86399999, 86400000, 1700000000123, 253402300799999):
            self.assertEqual(tool.unix_millis(*tool.time_from_millis(millis)), millis)

    def test_leap_years_by_integer_ordinals(self):
        self.assertEqual(tool.jan1_ordinal(1), 1)
        self.assertEqual(tool.jan1_ordinal(1970), 719163)
        for year in (1, 4, 100, 400, 1900, 2000, 2024, 9999):
            import datetime
            self.assertEqual(tool.jan1_ordinal(year), datetime.date(year, 1, 1).toordinal())

    def test_scaled_guard(self):
        self.assertEqual(tool.scaled(E14, E14), E14)
        self.assertEqual(tool.scaled(2 * (E14 - 1) + 1, 1 << 63), ((2 * (E14 - 1) + 1) << 63) // E14)
        self.assertIsNone(tool.scaled(2 * E14, 1 << 63))

    def test_rate_curve_arms(self):
        row = tool.token()
        self.assertEqual(tool.rate_of(row, row["k"]), row["bend"])
        self.assertEqual(tool.rate_of(row, 0), row["min"])
        self.assertEqual(tool.rate_of(row, E14), row["max"])
        self.assertTrue(row["min"] < tool.rate_of(row, row["k"] // 2) < row["bend"])
        self.assertTrue(row["bend"] < tool.rate_of(row, (row["k"] + E14) // 2) < row["max"])

    def test_same_time_only_settles(self):
        before = tool.token(NOW, balance=100, pending=30, paid=5)
        after, logs = tool.accrue_spec(before, NOW, E14 // 10)
        self.assertEqual((after["balance"], after["pending"], after["paid"]), (70, 0, 35))
        self.assertEqual((after["ia"], after["ib"], logs), (before["ia"], before["ib"], []))

    def test_guard_leaves_row_untouched(self):
        before = tool.token(b=1 << 63, ib=4 * E14, balance=100, pending=30)
        after, logs = tool.accrue_spec(before, NOW, 0)
        self.assertEqual(after, before)
        self.assertEqual(logs, [])

    def test_growth_is_monotone_and_balances_conserve(self):
        for case in tool.generated_cases(400):
            after, _ = tool.accrue_spec(case["row"], case["time"], case["keep"])
            before = case["row"]
            self.assertGreaterEqual(after["ia"], before["ia"])
            self.assertGreaterEqual(after["ib"], before["ib"])
            if after["time"] == case["time"] and not (before["paid"] + before["pending"]) >> 64:
                moved = before["balance"] - after["balance"]
                self.assertEqual(after["paid"] - before["paid"], moved)

    def test_one_day_worked_example(self):
        row = tool.token(a=5 * 10 ** 7, b=10 ** 8)
        after, _ = tool.accrue_spec(row, NOW, 0)
        use = 5 * 10 ** 7 * E14 // (10 ** 8)
        rate = tool.rate_of(row, use)
        elapsed = 86400000
        grown = tool.scaled(elapsed * rate // tool.YEAR_MS, row["ia"])
        self.assertEqual(after["ia"], row["ia"] + grown)

    def test_every_flaw_changes_some_outcome(self):
        cases = tool.hand_cases() + list(tool.generated_cases(600))
        for flaw in tool.FLAWS:
            differs = False
            for case in cases:
                want = tool.accrue_spec(case["row"], case["time"], case["keep"])
                got = tool.accrue_spec(case["row"], case["time"], case["keep"], flaw)
                if tool.row_key(want[0]) != tool.row_key(got[0]) or len(want[1]) != len(got[1]):
                    differs = True
                    break
            self.assertTrue(differs, flaw)


class ByteTests(unittest.TestCase):
    def test_binary_is_the_authenticated_node(self):
        self.assertEqual(hashlib.sha256(tool.BINARY.read_bytes()).hexdigest(), tool.SHA256)

    def test_wrong_digest_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(tool.BINARY, "0" * 64)

    def test_extent_and_boundaries(self):
        img = image()
        self.assertEqual(img.exact_fde(tool.ACCRUE), (0x36A0200, 0x36A08AD))
        with self.assertRaises(tool.EvidenceError):
            img.exact_fde(tool.ACCRUE + 1)
        with self.assertRaises(tool.EvidenceError):
            img.offset(0x10)
        relative = {slot: addend for slot, kind, addend, _ in img.relocations() if kind == 8}
        self.assertEqual(relative[tool.SLOT_ACCRUE], tool.ACCRUE)
        self.assertEqual(relative[tool.SLOT_UDIV], tool.UDIV)
        self.assertEqual(relative[tool.SLOT_LOG], tool.OVERFLOW_LOG)

    def test_boundary_evidence(self):
        img = image()
        relative = {slot: addend for slot, kind, addend, _ in img.relocations() if kind == 8}
        begin, end, rows, data = tool.function_facts(img, tool.ACCRUE)
        self.assertEqual(len(tool.indirect_calls(img, rows, relative)), 15)
        sites = tool.log_locations(img, rows, relative)
        self.assertEqual([(s["path"], s["line"], s["column"]) for s in sites], [("l1/src/qtys/mod.rs", 835, 1)] * 2)
        self.assertEqual(tool.caller_boundary(img, relative)["call_sites"], ["0x369a69f"])
        self.assertGreater(len(tool.immediate_sites(begin, data, E14)), 5)
        self.assertTrue(tool.immediate_sites(begin, data, tool.YEAR_MS))

    def test_engine_matches_spec_on_hand_cases(self):
        harness = tool.Harness(image())
        for case in tool.hand_cases():
            self.assertEqual(tool.compare(harness, case), "", case["label"])

    def test_engine_matches_spec_on_generated_and_calendar_cases(self):
        harness = tool.Harness(image())
        for case in list(tool.generated_cases(600)) + list(tool.calendar_cases())[::6]:
            self.assertEqual(tool.compare(harness, case), "", case["label"])

    def test_overflow_logs_are_counted(self):
        harness = tool.Harness(image())
        case = [c for c in tool.hand_cases() if c["label"] == "pending add saturates"][0]
        self.assertEqual(tool.compare(harness, case), "")
        self.assertEqual(len(harness.logs), 1)

    def test_wide_divide_is_called_through_the_slot(self):
        harness = tool.Harness(image())
        harness.run(tool.hand_cases()[3])
        self.assertGreater(harness.divides, 5)


class NegativeControlTests(unittest.TestCase):
    def test_flawed_specifications_are_detected_by_the_bytes(self):
        harness = tool.Harness(image())
        pool = tool.hand_cases()
        pool += list(tool.generated_cases(tool.FLAW_CACHE))[:tool.FLAW_CACHE - len(pool)]
        real = [(case, harness.run(case), len(harness.logs)) for case in pool]
        for flaw in tool.FLAWS:
            caught = False
            for case, got, logs in real:
                want, want_logs = tool.accrue_spec(case["row"], case["time"], case["keep"], flaw)
                if tool.row_diff(got, want) or logs != len(want_logs):
                    caught = True
                    break
            self.assertTrue(caught, flaw)

    def test_corrupted_bytes_are_detected(self):
        img = image()
        harness = tool.Harness(img)
        rows = tool.decode_range(img, *img.exact_fde(tool.ACCRUE))
        hand = tool.hand_cases()
        reached = []
        for case in hand:
            harness.machine.seen = set()
            self.assertEqual(tool.compare(harness, case), "")
            reached.append(frozenset(harness.machine.seen))
        results = tool.run_mutants(img, rows, hand, reached)
        killed = [row for row in results if row["result"] == "killed"]
        self.assertGreater(len(killed), 80)
        self.assertTrue(any(row["kind"] == "branch" for row in killed))
        self.assertTrue(any(row["kind"] == "offset" for row in killed))

    def test_input_corruptions_are_refused(self):
        controls = tool.corruption_controls(image())
        self.assertEqual(len(controls), 10)
        for _, name, detected, _ in controls:
            self.assertTrue(detected, name)

    def test_out_of_range_input_is_not_accepted_silently(self):
        harness = tool.Harness(image())
        with self.assertRaises(tool.Halt):
            harness.machine.memory.read(0x10, 8)
        with self.assertRaises(tool.Halt):
            harness.machine.run(tool.ACCRUE, {tool.RDI: 0x10, tool.RSI: 0x20, tool.RDX: 0})


class OutputTests(unittest.TestCase):
    def test_analysis_is_deterministic_and_clean(self):
        first = tool.analyse(image(), generated=120, full=False)[0]
        second = tool.analyse(image(), generated=120, full=False)[0]
        self.assertEqual(json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True))
        self.assertEqual(first["mismatches"], 0)
        self.assertEqual(first["cases"]["generated"], 120)

    def test_sample_rows_agree_and_files_are_written(self):
        harness = tool.Harness(image())
        row = tool.case_row(harness, tool.hand_cases()[3])
        self.assertEqual(row[-1], "yes")
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "x.tsv"
            tool.write_tsv(path, ("a", "b"), [(1, 2)])
            self.assertEqual(path.read_text(), "a\tb\n1\t2\n")


if __name__ == "__main__":
    unittest.main()
