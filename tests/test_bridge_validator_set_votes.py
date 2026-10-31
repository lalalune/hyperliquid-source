"""Tests for tools/bridge_validator_set_votes.py: rule list against real bytes, and negative controls."""
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import bridge_validator_set_votes as tool  # noqa: E402


FOLDER = ROOT / "research" / "work-items" / "bridge-validator-set-votes-94"


def run(harness, name):
    scenario = next(item for item in tool.named_scenarios() if item.name == name)
    return scenario, harness.run(scenario)


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image()
        cls.harness = tool.Harness(cls.image)


class Rules(Base):
    def test_named_scenarios_match(self):
        done = tool.check_all(self.harness, tool.named_scenarios())
        self.assertGreater(len(done), 100)

    def test_generated_scenarios_match(self):
        self.assertEqual(len(tool.check_all(self.harness, tool.vector_scenarios(40))), 40)

    def test_quorum_moves_epoch(self):
        _, trace = run(self.harness, "final_three_of_four_moves_epoch")
        self.assertEqual([step[2][0] for step in trace], [tool.EPOCH, tool.EPOCH, tool.EPOCH + 1])

    def test_two_thirds_exactly_does_not_move(self):
        _, trace = run(self.harness, "final_exact_two_thirds_short")
        self.assertEqual([step[2][0] for step in trace], [tool.EPOCH, tool.EPOCH, tool.EPOCH + 1])

    def test_old_epoch_vote_changes_nothing(self):
        _, trace = run(self.harness, "final_old_nonce_is_noop")
        self.assertEqual(trace[-1][0], (tool.OUTCOME_OK,))
        self.assertEqual(trace[-1][2][2], {})

    def test_set_mismatch_beats_old_epoch_exit(self):
        _, trace = run(self.harness, "final_set_differs_old_nonce")
        self.assertEqual(trace[0][0], (tool.OUTCOME_ERROR, tool.TAG_SET))

    def test_old_epoch_signature_is_stored(self):
        _, trace = run(self.harness, "sign_old_nonce_accepted")
        self.assertEqual(sorted(trace[-1][2][1]), [3])
        self.assertEqual(trace[-1][2][1][3]["done"], 1)

    def test_equal_row_survives_the_prune(self):
        _, trace = run(self.harness, "final_prunes_older_rows")
        self.assertEqual(sorted(trace[-1][2][1]), [tool.EPOCH + 1, tool.EPOCH + 2])

    def test_101_rows_stay(self):
        _, trace = run(self.harness, "no_trim_101_rows")
        self.assertEqual(len(trace[-1][2][1]), 101)
        self.assertIn(("alloc", 800), trace[-1][1])

    def test_prune_output_lists_removed_keys(self):
        _, trace = run(self.harness, "prune_two_levels")
        self.assertEqual(trace[0][0], (tuple(range(100, 115)),))
        self.assertEqual(sorted(trace[0][2][1]), list(range(115, 130)))


class Negative(Base):
    def test_wrong_hash_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_address_outside_every_function_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            self.image.exact_fde(tool.ARM_SIGN + 1)

    def patched(self, target_va, flip, name):
        offset = self.image.offset(target_va)
        harness = tool.Harness(self.image, {target_va: self.image.blob[offset] ^ flip})
        scenario = next(item for item in tool.named_scenarios() if item.name == name)
        want = tool.spec_run(scenario)
        try:
            return harness.run(scenario) != want
        except (tool.Halt, tool.EvidenceError, tool.Panicked):
            return True

    def test_flipped_epoch_compare_is_caught(self):
        self.assertTrue(self.patched(0x374FA2B, 1, "final_old_nonce_is_noop"))

    def test_flipped_status_is_caught(self):
        self.assertTrue(self.patched(0x3369E03, 1, "sign_set_extra_entry"))

    def test_flipped_limit_is_caught(self):
        self.assertTrue(self.patched(0x37A1249, 1, "sign_stake_at_limit"))

    def test_rule_list_rejects_a_wrong_rule(self):
        scenario = next(item for item in tool.named_scenarios() if item.name == "final_three_of_four_moves_epoch")
        original = tool.spec_weight
        tool.spec_weight = lambda stakes, voters: False
        try:
            self.assertNotEqual(self.harness.run(scenario), tool.spec_run(scenario))
        finally:
            tool.spec_weight = original

    def test_key_row_moved_fails(self):
        rows = tool.KEY_ROWS
        tool.KEY_ROWS = ((tool.ARM_FINAL, 0x374FA28, "inside a row", "cmp"),)
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.key_rows(self.image, {tool.ARM_FINAL: tool.decode_range(self.image, *self.image.exact_fde(tool.ARM_FINAL))})
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
