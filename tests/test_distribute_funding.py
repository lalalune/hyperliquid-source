"""Tests for tools/distribute_funding.py: real bytes against the specification, with negative controls."""

import importlib.util
import json
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("distribute_funding", ROOT / "tools" / "distribute_funding.py")
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)
PACKET = ROOT / "research" / "work-items" / "RE-007-distribute-funding-94"
IMAGE = tool.load_image()
EVIDENCE, _ = tool.analyse(IMAGE, full=False)
CASES = {(case["label"], case.get("copy")): case for case in tool.all_cases()}


def case_named(label, copy=None):
    return CASES[label, copy]


def patched(va, xor):
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

    def test_address_outside_every_fde(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.exact_fde(tool.WORK + 1)

    def test_section_without_file_bytes_is_refused(self):
        bss = IMAGE.named[".bss"]
        with self.assertRaises(tool.EvidenceError):
            IMAGE.offset(bss["address"])


class Static(unittest.TestCase):
    def test_step_name_at_all_three_gates(self):
        self.assertEqual([row["step_name"] for row in EVIDENCE["call_map"]["copies"]], ["distribute_funding"] * 3)

    def test_update_funding_rates_runs_next(self):
        self.assertTrue(all(row["next_call_names_update_funding_rates"] for row in EVIDENCE["call_map"]["copies"]))

    def test_user_state_fields(self):
        fields = {row["name"]: row["dex_offset"] for row in EVIDENCE["user_state_fields"]}
        self.assertEqual(fields["users_with_positions"], "0x158")
        self.assertEqual(fields["check_all_users_for_liquidatables"], "0x1a0")
        self.assertEqual(fields["aru"], "0x188")

    def test_changed_field_row_is_refused(self):
        original = tool.FIELD_ROWS
        tool.FIELD_ROWS = ((original[1][0], b"users_with_position_", original[1][2], "lea", 0x60),)
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.field_names(IMAGE)
        finally:
            tool.FIELD_ROWS = original

    def test_changed_guard_offset_is_refused(self):
        original = tool.GUARD_ROWS
        tool.GUARD_ROWS = ((0x275BA19, 0x275BA20, 0x37C8),)
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.guard_names(IMAGE)
        finally:
            tool.GUARD_ROWS = original

    def test_changed_slot_is_refused(self):
        original = tool.SLOT_WORK
        tool.SLOT_WORK = tool.SLOT_RATE
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.call_map(IMAGE)
        finally:
            tool.SLOT_WORK = original


class Behaviour(unittest.TestCase):
    def test_all_cases_match(self):
        self.assertEqual(EVIDENCE["mismatches"], 0, EVIDENCE["first_mismatch"])
        self.assertEqual(EVIDENCE["cases"]["total"], len(tool.all_cases()))

    def test_gate_stores_only_a_later_bucket(self):
        case = case_named("last bucket ahead of the clock", "primary")
        gate, last = tool.Harness(IMAGE).run_gate(case, tool.BY_NAME["primary"])
        self.assertEqual(gate["run"], 0)
        self.assertEqual(last, case["last_bucket"])

    def test_gate_has_no_zero_guard(self):
        for name in ("zero width with a 32-bit clock", "zero width with a 64-bit clock"):
            with self.assertRaises(tool.Halt):
                tool.Harness(IMAGE).run_gate(case_named(name, "second"), tool.BY_NAME["second"])

    def test_none_rate_enters_the_map_as_zero(self):
        spec = tool.builder_spec(case_named("None below 10000, not listed", "primary"))
        self.assertEqual(spec["inserted"][0], (0, tool.to_bits(0.0)))
        self.assertEqual(spec["missing"], [0])

    def test_residual_lands_on_the_largest_row(self):
        rows = EVIDENCE["worked"][0]["users_after"]
        self.assertEqual([row["balance_after"] - row["balance_before"] for row in rows], [0, -7, 0])

    def test_isolated_position_takes_it_in_margin(self):
        row = EVIDENCE["worked"][1]["users_after"][1]
        self.assertEqual((row["balance_after"], row["margin_after"]), (6000, 902))

    def test_tie_goes_to_the_lower_address(self):
        rows = EVIDENCE["worked"][2]["users_after"]
        self.assertEqual([row["balance_after"] - row["balance_before"] for row in rows], [-4, 0])

    def test_rows_reach_the_writer_only_in_the_recording_copy(self):
        for name, wanted in (("primary", 0), ("second", 0), ("recording", 1)):
            harness = tool.Harness(IMAGE)
            harness.run_host(case_named("one dex, residual", name), tool.BY_NAME[name])
            self.assertEqual(len(harness.seen_rows), wanted)

    def test_premium_vectors_empty_and_capacity_stays(self):
        harness = tool.Harness(IMAGE)
        harness.run_host(case_named("premium tree depth 1", "primary"), tool.BY_NAME["primary"])
        node, slot = harness.premiums[0][2]
        memory = harness.machine.memory
        self.assertEqual(memory.read(node + 0x70 + 24 * slot, 8), 0)
        self.assertEqual(memory.read(node + 0x60 + 24 * slot, 8), 16)

    def test_third_argument_is_not_read(self):
        self.assertEqual(EVIDENCE["third_argument_overwritten_at"], "0x3703f47")


class Controls(unittest.TestCase):
    def test_flipped_margin_tag_branch_is_seen(self):
        self.assertTrue(tool.compare_run(patched(0x370443B, 1), case_named("positive residual, cross")))

    def test_flipped_tie_branch_is_seen(self):
        self.assertTrue(tool.compare_run(patched(0x37043B1, 1), case_named("first of equal maxima wins")))

    def test_flipped_zero_sum_branch_is_seen(self):
        self.assertTrue(tool.compare_run(patched(0x3704234 + 1, 1), case_named("sum is zero")))

    def test_flipped_bucket_compare_is_seen(self):
        self.assertTrue(tool.compare_run(patched(0x22299E5, 1), case_named("one bucket on", "primary")))

    def test_flipped_rate_result_is_seen(self):
        self.assertTrue(tool.compare_run(patched(0x275EEFA, 1), case_named("one dex, all rates", "primary")))

    def test_changed_premium_length_field_is_seen(self):
        self.assertTrue(tool.compare_run(patched(0x222C0BF, 8), case_named("one dex, no rows", "primary")))

    def test_wrong_specification_is_seen(self):
        original = tool.saturate
        tool.saturate = lambda value: value - 1
        try:
            failed = tool.compare_run(tool.Harness(IMAGE), case_named("positive residual, cross"))
        finally:
            tool.saturate = original
        self.assertTrue(failed)


class Packet(unittest.TestCase):
    def test_static_evidence_matches_the_stored_file(self):
        stored = json.loads((PACKET / "evidence.json").read_text(encoding="utf-8"))
        stored.pop("mutations")
        self.assertEqual(json.loads(json.dumps(EVIDENCE, sort_keys=True)), stored)

    def test_mutation_table_totals(self):
        stored = json.loads((PACKET / "evidence.json").read_text(encoding="utf-8"))["mutations"]
        rows = (PACKET / "mutations.tsv").read_text(encoding="utf-8").splitlines()[1:]
        self.assertEqual(len(rows), sum(stored.values()))
        for row in rows:
            fields = row.split("\t")
            self.assertTrue(fields[3] == "killed" or fields[5], row)


if __name__ == "__main__":
    unittest.main()
