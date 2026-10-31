"""Tests for tools/l1_hash_vote_path.py: rule list against real bytes, and negative controls."""
import pathlib
import struct
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import l1_hash_vote_path as tool  # noqa: E402


FOLDER = ROOT / "research" / "work-items" / "bridge-l1-hash-votes-94"


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
        self.assertGreater(len(tool.check_all(self.harness, tool.named_scenarios())), 70)

    def test_generated_scenarios_match(self):
        self.assertEqual(len(tool.check_all(self.harness, tool.vector_scenarios(30))), 30)

    def test_signed_bytes_are_an_array_of_height_and_hex_text(self):
        events = self.run_named("arm_87_first_vote")[0][1]
        message = dict((event[0], event[1]) for event in events)["signed_bytes"]
        self.assertEqual(message[:1], b"\x92")
        self.assertEqual(message[1:6], b"\xce" + struct.pack(">I", tool.HEIGHT))
        self.assertEqual(message[6:8], b"\xd9\x42")
        self.assertEqual(message[8:], b"0x" + tool.L1.hex().encode())

    def test_recovery_failure_and_other_signer(self):
        self.assertEqual(self.run_named("arm_87_bad_signature")[0][0][:2], (tool.OUTCOME_ERROR, tool.TAG_BAD_SIGNATURE))
        self.assertEqual(self.run_named("arm_87_other_signer")[0][0][:2], (tool.OUTCOME_ERROR, tool.TAG_SIGNER))

    def test_no_voter_and_no_link_is_refused(self):
        self.assertEqual(self.run_named("core_nobody")[0][0], (tool.TAG_NOT_VOTER,))

    def test_link_alone_can_vote(self):
        view, events, _ = self.run_named("core_link_only")[0]
        self.assertEqual(view, (tool.TAG_OK, 0))
        self.assertIsNone(events[0][3])
        self.assertEqual(events[0][4], tool.LINK2)

    def test_first_link_in_key_order_decides(self):
        self.assertEqual(self.run_named("core_two_links_first_in_key_order")[0][1][0][4], tool.LINK1)
        self.assertIsNone(self.run_named("core_two_links_second_listed_only")[0][1][0][4])

    def test_quorum_pushes_one_row_and_keeps_the_maximum(self):
        _, highest, rows = self.run_named("core_quorum_keeps_higher_highest")[0][2]
        self.assertEqual(highest, tool.HEIGHT + 9)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], tool.HEIGHT)

    def test_row_hash_comes_from_the_tracker_result(self):
        self.assertEqual(self.run_named("core_quorum_winner_hash_differs")[0][2][2][0][1], tool.L1B)

    def test_voter_without_hot_user_is_dropped(self):
        rows = self.run_named("hot_voter_without_user_dropped")[0][2][2]
        self.assertEqual(sorted(rows[0][2]), sorted((tool.HOT1, tool.HOT3)))

    def test_prune_floor_is_kept(self):
        self.assertEqual(self.run_named("prune_window_edge_stays")[0][2][0], [tool.HEIGHT - tool.WINDOW])
        self.assertEqual(self.run_named("prune_one_below_window")[0][2][0], [])

    def test_prune_uses_the_vote_height_not_the_highest(self):
        self.assertEqual(self.run_named("prune_uses_vote_height")[0][2][0], [tool.HEIGHT - tool.WINDOW - 1])

    def test_no_quorum_prunes_nothing(self):
        self.assertEqual(self.run_named("prune_no_quorum_no_prune")[0][2][0], [1])

    def test_filter_drops_rows_with_no_hot_user(self):
        kept = self.run_named("filter_drops_middle")[0][0][0]
        self.assertEqual([struct.unpack_from("<Q", row)[0] for row in kept], [1, 3])


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

    def test_changed_window_is_caught(self):
        self.assertTrue(self.patched(0x394B312, 1, "prune_one_below_window"))

    def test_changed_hex_mask_is_caught(self):
        self.assertTrue(self.patched(0x29ED3DC, 1, "arm_87_first_vote"))

    def test_flipped_maximum_is_caught(self):
        self.assertTrue(self.patched(0x394B185, 1, "core_quorum_keeps_higher_highest"))

    def test_changed_signer_status_is_caught(self):
        self.assertTrue(self.patched(0x1E5F0FC, 1, "arm_87_other_signer"))

    def test_rule_list_rejects_a_wrong_rule(self):
        scenario = scenario_named("prune_window_edge_stays")
        original = tool.WINDOW
        tool.WINDOW = original - 1
        try:
            self.assertNotEqual(self.harness.run(scenario), tool.spec_run(scenario))
        finally:
            tool.WINDOW = original

    def test_stand_in_digest_depends_on_every_byte(self):
        self.assertNotEqual(tool.stand_in_digest(b"\x92\x01"), tool.stand_in_digest(b"\x92\x02"))

    def test_key_row_moved_fails(self):
        rows = tool.KEY_ROWS
        tool.KEY_ROWS = ((tool.CORE, 0x394AC96, "inside a row", "jcc"),)
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.key_rows(self.image, {tool.CORE: tool.decode_range(self.image, *self.image.exact_fde(tool.CORE))})
        finally:
            tool.KEY_ROWS = rows

    def test_dispatch_row_moved_fails(self):
        arm = tool.ARM_AT
        tool.ARM_AT = arm + 1
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.dispatch_rows(self.image)
        finally:
            tool.ARM_AT = arm


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
