from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
PACKET_DIR = REPO_ROOT / "research" / "work-items" / "RE-002-node115-private-forks-patch-analysis"
VERIFY_PATH = PACKET_DIR / "verify.py"
RECORDS_PATH = PACKET_DIR / "records.json"


def _load_verifier():
    spec = importlib.util.spec_from_file_location("re002_patch_analysis_115", VERIFY_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class TestPrivateForksPatchAnalysis115(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.verifier = _load_verifier()

    def test_all_7_elf_anchors_and_negative_controls_verify_against_node115(self) -> None:
        rec = self.verifier.build_records(self.verifier.TARGET_PATH)
        self.assertEqual(rec["target_sha256"], self.verifier.TARGET_SHA256)
        self.assertEqual(rec["anchors_verified"], 7)
        self.assertEqual(rec["negative_controls_caught"], 7)
        self.assertEqual(len(rec["fork_patch_matrix"]), 8)

    def test_committed_records_json_matches_live_derivation(self) -> None:
        committed = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))
        live = self.verifier.build_records(self.verifier.TARGET_PATH)
        self.assertEqual(committed, live)
        self.assertTrue(committed["deterministic_build_plan"]["profile_release"]["overflow-checks"])


if __name__ == "__main__":
    unittest.main()
