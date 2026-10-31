"""Tests for tools/bole_liquidation_step.py: real bytes against the specification, with negative controls."""

import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("bole_liquidation_step", ROOT / "tools" / "bole_liquidation_step.py")
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)
PACKET = ROOT / "research" / "work-items" / "RE-007-bole-liquidation-step-94"
IMAGE = tool.load_image()
EVIDENCE, _ = tool.analyse(IMAGE, full=False)
CASES = {(case["kind"], case["label"], case.get("copy")): case for case in tool.all_cases()}


def case_named(kind, label, copy=None):
    return CASES[kind, label, copy]


def broken(va, xor):
    harness = tool.Harness(IMAGE)
    harness.machine.patches = {va: IMAGE.blob[IMAGE.offset(va)] ^ xor}
    return harness


class Identity(unittest.TestCase):
    def test_wrong_digest_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_changed_bytes_are_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "copy"
            path.write_bytes(b"not the target")
            with self.assertRaises(tool.EvidenceError):
                tool.load_image(path=path)

    def test_address_inside_a_function_is_not_an_fde_start(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.exact_fde(tool.ACCRUE + 1)

    def test_section_without_file_bytes_is_refused(self):
        bss = IMAGE.named[".bss"]
        with self.assertRaises(tool.EvidenceError):
            IMAGE.offset(bss["address"])


class Static(unittest.TestCase):
    def test_three_copies_call_the_sweep_after_the_step(self):
        rows = EVIDENCE["call_map"]
        self.assertEqual([row["copy"] for row in rows], ["primary", "second", "recording"])
        self.assertEqual([row["sweep"] for row in rows], ["0x26fdf20", "0x4ce64c0", "0x4ce6db0"])

    def test_recording_copy_wraps_the_sweep_in_two_markers(self):
        rows = EVIDENCE["call_map"]
        self.assertEqual([row["tag"] for row in rows[2]["marker_tags"]], [0x10, 0x11])
        self.assertEqual(rows[0]["marker_tags"], [])

    def test_year_is_365_and_a_quarter_days(self):
        self.assertEqual(EVIDENCE["constants"]["year_millis"], 36525 * 864000)

    def test_mode_table_has_four_arms(self):
        self.assertEqual([row["target"] for row in EVIDENCE["token_rows"]["mode_table"]], ["0x373b4d0", "0x373b710", "0x373b4f2", "0x373b51c"])

    def test_skip_mask_names_three_tokens(self):
        self.assertEqual(EVIDENCE["token_rows"]["low_bits"], [0x5DF, 0x607, 0x608])

    def test_budget_key(self):
        self.assertEqual(EVIDENCE["fields"]["budget_key"], "pmn")

    def test_changed_error_text_is_refused(self):
        original = tool.ERROR_ROWS
        tool.ERROR_ROWS = ((original[0][0], b"spot py"),)
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.error_strings(IMAGE)
        finally:
            tool.ERROR_ROWS = original

    def test_changed_field_offset_is_refused(self):
        original = tool.FIELD_ROWS
        tool.FIELD_ROWS = ((0x275C133, 0x3A70, "wrong"),)
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.field_names(IMAGE)
        finally:
            tool.FIELD_ROWS = original

    def test_changed_step_name_is_refused(self):
        original = tool.STEP_NAME
        tool.STEP_NAME = b"apply_bole_liquidationz"
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.call_map(IMAGE)
        finally:
            tool.STEP_NAME = original


class Runs(unittest.TestCase):
    def test_all_cases_match(self):
        self.assertEqual((EVIDENCE["mismatches"], EVIDENCE["first_mismatch"]), (0, ""))

    def test_year_gap_leaves_the_row_alone(self):
        case = case_named("accrue", "one millisecond past a year")
        after = tool.Harness(IMAGE).run_accrue(case)
        self.assertEqual(after["time"], case["row"]["time"])
        self.assertEqual(after["ia"], case["row"]["ia"])

    def test_exact_year_moves_the_row(self):
        case = case_named("accrue", "exactly one year")
        after = tool.Harness(IMAGE).run_accrue(case)
        self.assertEqual(after["time"], case["time"])
        self.assertGreater(after["ia"], case["row"]["ia"])

    def test_range_error_still_writes_the_price(self):
        case = case_named("refresh", "range error still writes the price")
        harness = tool.Harness(IMAGE)
        rows = harness.run_refresh(case)
        self.assertEqual(harness.inserted[0][1], ["unexpected range"])
        self.assertNotEqual(rows[0xC5]["px"], 7)

    def test_flag_keeps_its_value_between_eighty_percent_and_the_cap(self):
        table = {(gap, before): after for _, gap, before, after in tool.debt_samples(IMAGE)}
        self.assertEqual((table[800, 1], table[801, 1], table[801, 0], table[1000, 1], table[1001, 0]), (0, 1, 0, 1, 1))

    def test_budget_counts_users_without_debt(self):
        case = case_named("sweep", "visited without debt still moves the cursor", "primary")
        harness = tool.Harness(IMAGE)
        flag, cursor = harness.run_sweep(case, tool.BY_NAME["primary"])
        self.assertEqual(harness.picked, [])
        self.assertEqual((flag, cursor), (1, min(case["users"])))


class NegativeControls(unittest.TestCase):
    def assert_caught(self, va, xor, case, layout=None):
        self.assertEqual(tool.compare_run(tool.Harness(IMAGE), case), "")
        self.assertNotEqual(tool.compare_run(broken(va, xor), case), "")

    def test_gate_store_branch(self):
        self.assert_caught(0x222AA00, 1, case_named("gate", "first bucket after a large gap", "primary"))

    def test_cap_compare(self):
        self.assert_caught(0x222CDE3 + 1, 1, case_named("step", "gap past the cap sets", "primary"))

    def test_release_compare(self):
        self.assert_caught(0x222D107 + 1, 1, case_named("step", "gap at 80 percent clears", "primary"))

    def test_year_guard(self):
        self.assert_caught(0x3740D7A + 1, 1, case_named("accrue", "one millisecond past a year"))

    def test_spread_guard(self):
        self.assert_caught(0x373B9DF, 1, case_named("refresh", "three prices, top past 1 percent"))

    def test_budget_offset(self):
        self.assert_caught(0x26FDF31 + 3, 8, case_named("sweep", "no cursor, budget of one", "primary"))

    def test_second_word_guard(self):
        self.assert_caught(0x3734115 + 1, 1, case_named("collect", "second word at the guard"))

    def test_harness_refuses_a_wrong_exchange(self):
        harness = tool.Harness(IMAGE)
        harness.begin(case_named("step", "all clear, no gap", "primary"), tool.COPIES[0])
        harness.machine.regs[tool.RDI] = tool.EXCHANGE + 8
        with self.assertRaises(tool.Halt):
            harness.on_second(harness.machine)


class Packet(unittest.TestCase):
    def test_manifest(self):
        rows = (PACKET / "MANIFEST.sha256").read_text().splitlines()
        self.assertTrue(rows)
        for row in rows:
            digest, name = row.split("  ")
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), digest, name)

    def test_saved_evidence_matches_a_run(self):
        saved = json.loads((PACKET / "evidence.json").read_text())
        for key in ("functions", "call_map", "constants", "token_rows", "error_strings", "fields", "locations", "cases"):
            self.assertEqual(saved[key], json.loads(json.dumps(EVIDENCE[key])), key)

    def test_every_open_mutant_has_a_reason(self):
        rows = (PACKET / "mutations.tsv").read_text().splitlines()[1:]
        self.assertTrue(rows)
        for row in rows:
            cells = row.split("\t")
            self.assertTrue(cells[3] == "killed" or cells[5], row)


if __name__ == "__main__":
    unittest.main()
