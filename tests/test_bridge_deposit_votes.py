"""Tests for tools/bridge_deposit_votes.py: rule list against real bytes, and negative controls."""
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import bridge_deposit_votes as tool  # noqa: E402


FOLDER = ROOT / "research" / "work-items" / "bridge-deposit-votes-94"


def scenario_named(name):
    return next(item for item in tool.named_scenarios() if item.name == name)


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image()
        cls.harness = tool.Harness(cls.image)

    def run_named(self, name):
        return self.harness.run(scenario_named(name))


class Rules(Base):
    def test_named_scenarios_match(self):
        self.assertGreater(len(tool.check_all(self.harness, tool.named_scenarios())), 60)

    def test_generated_scenarios_match(self):
        self.assertEqual(len(tool.check_all(self.harness, tool.vector_scenarios(30))), 30)

    def test_finish_moves_key_and_raises_bal(self):
        trace = self.run_named("core_three_of_four_finish")
        rows, finished, bal = trace[-1][2]
        self.assertEqual(rows, {})
        self.assertEqual(finished[tool.KEY], (tool.USD, tool.NOW, tool.USER))
        self.assertEqual(bal, 500 + tool.USD)
        self.assertEqual(trace[-1][0], (tool.TAG_OK, 1))

    def test_below_level_finishes_without_bal(self):
        trace = self.run_named("core_below_minimum_finishes_no_bal")
        self.assertEqual(trace[-1][0], (tool.TAG_OK, 0))
        self.assertEqual(trace[-1][2][2], 500)
        self.assertIn(tool.KEY, trace[-1][2][1])

    def test_level_itself_raises_bal(self):
        trace = self.run_named("core_at_minimum_raises_bal")
        self.assertEqual(trace[-1][2][2], 500 + tool.MINIMUM)

    def test_second_vote_after_finish_is_refused(self):
        self.assertEqual(self.run_named("core_vote_after_finish_refused")[-1][0], (tool.TAG_FINISHED,))

    def test_equal_block_is_too_old(self):
        self.assertEqual(self.run_named("core_pruned_equal")[-1][0], (tool.TAG_PRUNED,))
        self.assertEqual(self.run_named("core_pruned_below")[-1][0], (tool.TAG_OK, 0))

    def test_ratio_blocks_a_stake_quorum(self):
        trace = self.run_named("ratio_blocks_stake_quorum")
        self.assertEqual(trace[-1][2][1], {})

    def test_ratio_is_strict(self):
        self.assertEqual(self.run_named("ratio_exact_is_short")[-1][2][1], {})
        self.assertIn(tool.KEY, self.run_named("ratio_half_of_four_needs_three")[-1][2][1])

    def test_listed_vote_can_finish_when_voter_cannot(self):
        trace = self.run_named("ratio_listed_first_then_stake")
        self.assertIn(tool.KEY, trace[-1][2][1])

    def test_last_seven_key_bytes_are_not_compared(self):
        self.assertEqual(self.run_named("core_finished_key_other_tail")[-1][0], (tool.TAG_FINISHED,))

    def test_arm_84_refuses_an_unlisted_validator(self):
        self.assertEqual(self.run_named("arm_84_validator_not_listed")[-1][0], (tool.OUTCOME_ERROR, tool.TAG_NOT_LISTED))


class Negative(Base):
    def test_wrong_hash_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_address_outside_every_function_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            self.image.exact_fde(tool.CORE + 1)

    def patched(self, va, flip, name):
        offset = self.image.offset(va)
        harness = tool.Harness(self.image, {va: self.image.blob[offset] ^ flip})
        scenario = scenario_named(name)
        want = tool.spec_run(scenario)
        try:
            return harness.run(scenario) != want
        except (tool.Halt, tool.EvidenceError, tool.Panicked):
            return True

    def test_flipped_pruned_branch_is_caught(self):
        self.assertTrue(self.patched(0x374E393, 1, "core_pruned_equal"))

    def test_changed_level_is_caught(self):
        self.assertTrue(self.patched(0x374E545, 1, "core_at_minimum_raises_bal"))

    def test_changed_status_is_caught(self):
        self.assertTrue(self.patched(0x1E64830, 1, "arm_84_not_listed"))

    def test_rule_list_rejects_a_wrong_rule(self):
        scenario = scenario_named("core_three_of_four_finish")
        original = tool.spec_weight
        tool.spec_weight = lambda stakes, voters: False
        try:
            self.assertNotEqual(self.harness.run(scenario), tool.spec_run(scenario))
        finally:
            tool.spec_weight = original

    def test_key_row_moved_fails(self):
        rows = tool.KEY_ROWS
        tool.KEY_ROWS = ((tool.CORE, 0x374E335, "inside a row", "jcc"),)
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.key_rows(self.image, {tool.CORE: tool.decode_range(self.image, *self.image.exact_fde(tool.CORE))})
        finally:
            tool.KEY_ROWS = rows


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
