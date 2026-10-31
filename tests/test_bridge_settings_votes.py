"""Tests for tools/bridge_settings_votes.py: rule list against real bytes, and negative controls."""
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import bridge_settings_votes as tool  # noqa: E402


FOLDER = ROOT / "research" / "work-items" / "bridge-settings-votes-94"
SKIP = ("toggle_cap_exact", "toggle_cap_over", "list_over_cap_keeps_old", "list_cap_exact")


def scenario_named(name):
    return next(item for item in tool.named_scenarios() if item.name == name)


def fast():
    return [item for item in tool.named_scenarios() if item.name not in SKIP and "_200_" not in item.name and "_320_" not in item.name]


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image()
        cls.harness = tool.Harness(cls.image)

    def run_named(self, name):
        return self.harness.run(scenario_named(name))


class Rules(Base):
    def test_named_scenarios_match(self):
        self.assertGreater(len(tool.check_all(self.harness, tool.named_scenarios())), 150)

    def test_generated_scenarios_match(self):
        self.assertEqual(len(tool.check_all(self.harness, tool.vector_scenarios(40))), 40)

    def test_fee_limit(self):
        self.assertEqual(self.run_named("fee_limit")[0][0], (tool.TAG_LIMIT, tool.LIMIT))
        self.assertEqual(self.run_named("fee_limit")[0][2][2], tool.FEE_BEFORE)
        self.assertEqual(self.run_named("fee_limit_minus_one")[0][2][2], tool.LIMIT - 1)

    def test_clearing_halt_clears_oaw(self):
        step = self.run_named("halt_from_11_to_0")[0]
        self.assertEqual(step[2][3:], (0, 0))

    def test_setting_halt_records_and_keeps_oaw(self):
        step = self.run_named("halt_from_01_to_1")[0]
        self.assertEqual(step[1], (("recorder", 3, tool.LOCATION_HALT),))
        self.assertEqual(step[2][3:], (1, 1))

    def test_only_the_low_bit_counts(self):
        self.assertEqual(self.run_named("oaw_from_00_to_fe")[0][2][4], 0)
        self.assertEqual(self.run_named("oaw_from_00_to_ff")[0][2][4], 1)

    def test_oaw_alone_leaves_halt(self):
        self.assertEqual(self.run_named("oaw_from_10_to_1")[0][2][3:], (1, 1))

    def test_zero_flag_removes_and_other_flags_insert(self):
        self.assertEqual(self.run_named("toggle_remove_present")[0][2][0], ((), 0))
        self.assertEqual(self.run_named("toggle_flag_two_inserts")[0][2][0][1], 1)
        self.assertEqual(self.run_named("toggle_flag_ff_inserts")[0][2][0][1], 1)

    def test_all_32_key_bytes_count(self):
        self.assertEqual(self.run_named("toggle_last_byte_differs")[0][2][0][1], 1)

    def test_list_replaces(self):
        step = self.run_named("list_replaces_not_merges")[0]
        self.assertEqual(set(step[2][1][0]), set(tool.listed(3, 100)))

    def test_cap_refuses_and_keeps_the_list(self):
        step = self.run_named("list_over_cap_keeps_old")[0]
        self.assertEqual(step[0], (tool.TAG_TOO_MANY,))
        self.assertEqual(set(step[2][1][0]), set(tool.listed(3)))

    def test_cap_exact_passes(self):
        self.assertEqual(self.run_named("list_cap_exact")[0][0], (tool.TAG_OK,))


class Negative(Base):
    def test_wrong_hash_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_address_outside_every_function_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            self.image.exact_fde(tool.CHECK_LIST + 1)

    def patched(self, va, flip, name):
        offset = self.image.offset(va)
        harness = tool.Harness(self.image, {va: self.image.blob[offset] ^ flip})
        scenario = scenario_named(name)
        want = tool.spec_run(scenario)
        try:
            return harness.run(scenario) != want
        except (tool.Halt, tool.EvidenceError, tool.Panicked):
            return True

    def test_flipped_fee_limit_is_caught(self):
        self.assertTrue(self.patched(0x2356C57, 1, "fee_zero"))

    def test_changed_fee_offset_is_caught(self):
        self.assertTrue(self.patched(0x2356C71, 8, "fee_one_usdc"))

    def test_flipped_toggle_branch_is_caught(self):
        self.assertTrue(self.patched(0x2358267, 1, "toggle_insert_one"))

    def test_changed_list_offset_is_caught(self):
        self.assertTrue(self.patched(0x23594B6, 8, "list_one"))

    def test_flipped_halt_clear_is_caught(self):
        self.assertTrue(self.patched(0x235B443, 1, "halt_from_11_to_0"))

    def test_changed_case_table_row_is_refused(self):
        arm = tool.ARM_LIST
        tool.ARM_LIST = arm + 1
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.case_rows(self.image)
        finally:
            tool.ARM_LIST = arm

    def test_broken_tree_is_caught(self):
        scenario = scenario_named("list_one")
        self.harness.fresh(scenario)
        self.harness.write(tool.STATE + tool.S_VOTERS + 16, 3)
        self.harness.write(tool.STATE + tool.S_VOTERS, tool.ARENA)
        self.harness.live[tool.ARENA] = tool.VOTER_NODE.size
        self.harness.write(tool.ARENA + tool.VOTER_NODE.count, 1, 2)
        with self.assertRaises(tool.Halt):
            self.harness.dump()

    def test_rule_list_rejects_a_wrong_rule(self):
        scenario = scenario_named("halt_from_11_to_0")
        wrong = tool.Model.apply

        def lazy(model, op):
            model.halt = op.value & 1
            return (tool.TAG_OK,), ()

        tool.Model.apply = lazy
        try:
            self.assertNotEqual(self.harness.run(scenario), tool.spec_run(scenario))
        finally:
            tool.Model.apply = wrong

    def test_key_row_moved_fails(self):
        rows = tool.KEY_ROWS
        tool.KEY_ROWS = ((0x2356C56, "wrong operation", "mov"),)
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.key_rows(self.image)
        finally:
            tool.KEY_ROWS = rows

    def test_moved_field_fails(self):
        rows = tool.FIELDS
        tool.FIELDS = ((0x370C8C5, 0x370C8CC, "bridge2_withdraw_fee", 0x258, "per-dex record"),)
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
