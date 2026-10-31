"""Tests for tools/bridge_retention_prune.py: rule list against real bytes, and negative controls."""
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import bridge_retention_prune as tool  # noqa: E402


FOLDER = ROOT / "research" / "work-items" / "bridge-retention-prune-94"


def scenario_named(name):
    return next(item for item in tool.named_scenarios() if item.name == name)


def blocks(trace):
    rows = trace[1][0][0]
    return [int.from_bytes(row[0][:8], "little") for row in rows]


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image()
        cls.harness = tool.Harness(cls.image)

    def run_named(self, name):
        return self.harness.run(scenario_named(name))


class Rules(Base):
    def test_named_scenarios_match(self):
        self.assertGreater(len(tool.check_all(self.harness, tool.named_scenarios())), 400)

    def test_generated_scenarios_match(self):
        self.assertEqual(len(tool.check_all(self.harness, tool.vector_scenarios(100))), 100)

    def test_time_equal_to_the_cut_is_old(self):
        trace = self.run_named("cut_equal_is_old")[0]
        self.assertEqual(blocks(trace), [])
        self.assertEqual(trace[1][1], 100)
        self.assertEqual(self.run_named("cut_equal_withdrawal_is_old")[0][1][0][1], ())

    def test_one_nanosecond_later_stays(self):
        trace = self.run_named("nanos_above_is_new")[0]
        self.assertEqual(blocks(trace), [100])
        self.assertEqual(len(trace[1][0][1]), 1)

    def test_new_row_in_a_lower_block_is_removed(self):
        trace = self.run_named("new_row_in_lower_block_goes")[0]
        self.assertEqual(blocks(trace), [130])
        self.assertEqual(trace[1][1], 120)

    def test_floor_never_falls(self):
        self.assertEqual(self.run_named("last_above_blocks_is_kept")[0][1][1], 500)

    def test_block_compare_is_unsigned(self):
        trace = self.run_named("block_top_bit_is_unsigned")[0]
        self.assertEqual(trace[1][1], 1 << 63)
        self.assertEqual(blocks(trace), [(1 << 63) + 1])

    def test_drained_map_keeps_its_root(self):
        self.assertEqual(blocks(self.run_named("one_old_deposit")[0]), [])
        self.assertNotEqual(self.harness.read(self.harness.bridge + tool.B_DEPOSITS), 0)
        self.assertEqual(self.harness.read(self.harness.bridge + tool.B_DEPOSITS + 16), 0)

    def test_signed_date(self):
        self.assertEqual(self.run_named("negative_date_row_is_old")[0][1][0], ((), ()))

    def test_maps_do_not_touch_each_other(self):
        trace = self.run_named("maps_are_independent")[0]
        self.assertEqual(blocks(trace), [100])
        self.assertEqual(len(trace[1][0][1]), 1)
        self.assertEqual(trace[1][1], 0)

    def test_rest_of_the_bridge_is_unchanged(self):
        for scenario, trace in tool.check_all(self.harness, tool.edge_scenarios()):
            for step in trace:
                self.assertTrue(step[1][2], scenario.name)

    def test_gate_runs_once_for_a_new_date(self):
        for copy in "abc":
            self.assertEqual(self.run_named("gate_%s_same_day_does_nothing" % copy)[0][0], ())
            self.assertEqual(len(self.run_named("gate_%s_new_day_chain_0" % copy)[0][0]), 1)

    def test_span_is_long_only_on_chain_three(self):
        for copy in "abc":
            self.assertEqual(self.run_named("gate_%s_new_day_chain_3_day_old_stays" % copy)[0][1][1], 0)
            self.assertEqual(self.run_named("gate_%s_new_day_chain_0" % copy)[0][1][1], 100)
            self.assertEqual(self.run_named("gate_%s_new_day_chain_ff" % copy)[0][1][1], 100)

    def test_floor_date_panics(self):
        for copy in "abc":
            self.assertEqual(self.run_named("gate_%s_floor_date_panics" % copy)[0], ("panic", tool.EXPECT_TEXT, ()))

    def test_rule_date_round_trip(self):
        for number in (1, 365, 366, 730000, 739000, -1000, -500000, 40000000):
            self.assertEqual(tool.day_number(tool.word_of_day(number)), number)


class Negative(Base):
    def test_wrong_hash_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_address_outside_every_function_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            self.image.exact_fde(tool.PRUNE + 1)

    def patched(self, va, flip, name):
        offset = self.image.offset(va)
        harness = tool.Harness(self.image, {va: self.image.blob[offset] ^ flip})
        scenario = scenario_named(name)
        want = tool.spec_run(scenario)
        try:
            return harness.run(scenario) != want
        except (tool.Halt, tool.EvidenceError, tool.Panicked):
            return True

    def test_flipped_cut_compare_is_caught(self):
        self.assertTrue(self.patched(0x374F3F3, 1, "cut_equal_is_old"))

    def test_flipped_floor_cmov_is_caught(self):
        self.assertTrue(self.patched(0x374F1EE, 1, "last_above_blocks_is_kept"))

    def test_flipped_deposit_drain_is_caught(self):
        self.assertTrue(self.patched(0x3314E59, 1, "one_old_deposit"))

    def test_changed_span_is_caught(self):
        self.assertTrue(self.patched(0x2229FB9, 1, "gate_a_new_day_chain_3_week_edge"))

    def test_flipped_gate_is_caught(self):
        self.assertTrue(self.patched(0x2229F95, 1, "gate_a_new_day_chain_0"))

    def test_broken_length_word_is_caught(self):
        scenario = scenario_named("one_old_deposit")
        self.harness.fresh(scenario)
        self.harness.write(self.harness.bridge + tool.B_DEPOSITS + 16, 5)
        with self.assertRaises(tool.Halt):
            self.harness.dump()

    def test_broken_parent_link_is_caught(self):
        scenario = scenario_named("withdrawals_40_even_none")
        self.harness.fresh(scenario)
        root = self.harness.read(self.harness.bridge + tool.B_WITHDRAWALS)
        child = self.harness.read(root + tool.WITHDRAWAL_NODE.size)
        self.harness.write(child + tool.WITHDRAWAL_NODE.parent, 0)
        with self.assertRaises(tool.Halt):
            self.harness.dump()

    def test_rule_list_rejects_a_wrong_rule(self):
        scenario = scenario_named("new_row_in_lower_block_goes")
        wrong = tool.Model.prune
        tool.Model.prune = lambda self, cut: None
        try:
            self.assertNotEqual(self.harness.run(scenario), tool.spec_run(scenario))
        finally:
            tool.Model.prune = wrong

    def test_key_row_moved_fails(self):
        rows = tool.KEY_ROWS
        tool.KEY_ROWS = ((0x374F3F4, "inside a row", "jcc"),)
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.key_rows(self.image, {})
        finally:
            tool.KEY_ROWS = rows

    def test_moved_field_fails(self):
        rows = tool.FIELDS
        tool.FIELDS = ((0x2215675, 0x3D693E, "finished_deposits_data", 0x2215693, 0x100),)
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.field_rows(self.image)
        finally:
            tool.FIELDS = rows


class Output(Base):
    def test_files_match_the_tool_without_mutation_rows(self):
        files = tool.render(tool.analyse(self.image, mutate=False, vectors=200))
        for name, text in files.items():
            if name == "evidence.json":
                continue
            self.assertEqual((FOLDER / name).read_text(encoding="ascii"), text, name)

    def test_manifest_lists_every_file(self):
        listed = {line.split("  ", 1)[1] for line in (FOLDER / "MANIFEST.sha256").read_text(encoding="ascii").splitlines()}
        present = {path.name for path in FOLDER.iterdir() if path.name != "MANIFEST.sha256"}
        self.assertEqual(listed, present)


if __name__ == "__main__":
    unittest.main()
