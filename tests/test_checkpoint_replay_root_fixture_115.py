"""Offline verification tests for RE-009-node115-checkpoint-replay-root-fixture."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research/work-items/RE-009-node115-checkpoint-replay-root-fixture"
SPEC = importlib.util.spec_from_file_location("verify_qcp_fixture_115", PACKET / "verify.py")
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class CheckpointReplayRootFixture115Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        MOD.verify_target(ROOT / MOD.TARGET_REL)
        cls.doc = json.loads((PACKET / "fixture.json").read_text(encoding="utf-8"))

    def test_all_four_prerequisite_manifests_validate(self):
        prereqs = MOD.verify_prerequisites(ROOT)
        self.assertEqual(len(prereqs), 4)

    def test_committed_fixture_hashes_and_observations_match(self):
        obs = MOD.verify_fixture_doc(self.doc)
        self.assertEqual(obs["first_replay_height"], 1_000_001)
        self.assertEqual(obs["selector_byte"], 4)
        self.assertEqual(obs["comparisons"][0]["status"], "equal")

    def test_fixture_matches_deterministic_builder(self):
        self.assertEqual(self.doc, MOD.build_fixture())

    def test_all_five_negative_controls_verified(self):
        self.assertEqual(MOD.run_negative_controls(self.doc), 5)


if __name__ == "__main__":
    unittest.main()
