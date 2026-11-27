from __future__ import annotations

import importlib.util
import json
import pathlib
import tempfile
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
PACKET_DIR = REPO_ROOT / "research" / "work-items" / "RE-003-node115-offline-differential-harness"
HARNESS_PATH = PACKET_DIR / "harness.py"
RECORDS_PATH = PACKET_DIR / "records.json"


def _load_harness():
    spec = importlib.util.spec_from_file_location("re003_harness_115", HARNESS_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    import sys

    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class TestOfflineDifferentialHarness115(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.harness = _load_harness()

    def test_self_test_passes_all_controls_without_running_target(self) -> None:
        summary = self.harness.run_self_test()
        self.assertEqual(summary["target_sha256"], self.harness.NODE115_SHA256)
        self.assertEqual(summary["target_execution_status"], "not-run")
        self.assertGreaterEqual(summary["controls_passed"], 9)
        self.assertEqual(summary["controls_passed"], summary["controls_total"])
        for entry in summary["controls"]:
            self.assertTrue(entry["passed"], entry)

    def test_fail_closed_when_bwrap_missing_and_forbidden_env_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td)
            stub = p / "s.py"
            fix = p / "f.txt"
            stub.write_text("print(1)\n", encoding="utf-8")
            fix.write_text("ok\n", encoding="utf-8")
            s_sha = self.harness.sha256_file(stub)
            f_sha = self.harness.sha256_file(fix)

            no_bwrap = self.harness.execute_case(
                self.harness.CaseSpec(
                    case_id="fail_closed_no_bwrap",
                    bounded_question="fail closed check",
                    target_path=stub,
                    expected_target_sha256=s_sha,
                    independent_path=stub,
                    expected_independent_sha256=s_sha,
                    fixture_path=fix,
                    expected_fixture_sha256=f_sha,
                ),
                bwrap_path="/nonexistent/bwrap",
            )
            self.assertEqual(no_bwrap["outcome"], "failed")
            self.assertEqual(no_bwrap["admission"]["reason"], "missing_isolation_facility:bwrap")
            self.assertFalse(no_bwrap["runs"])

            bad_env = self.harness.execute_case(
                self.harness.CaseSpec(
                    case_id="reject_proxy_env",
                    bounded_question="proxy env check",
                    target_path=stub,
                    expected_target_sha256=s_sha,
                    independent_path=stub,
                    expected_independent_sha256=s_sha,
                    fixture_path=fix,
                    expected_fixture_sha256=f_sha,
                    env_allowlist=(("LC_ALL", "C"), ("HTTP_PROXY", "http://127.0.0.1:8080")),
                )
            )
            self.assertEqual(bad_env["outcome"], "rejected")
            self.assertIn("forbidden_env_var", bad_env["admission"]["reason"])
            self.assertFalse(bad_env["runs"])

    def test_records_json_matches_expected_schema(self) -> None:
        rec = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))
        self.assertEqual(rec["target_sha256"], self.harness.NODE115_SHA256)
        self.assertEqual(rec["target_execution_status"], "not-run")
        self.assertEqual(rec["controls_passed"], rec["controls_total"])
        self.assertGreaterEqual(rec["controls_total"], 10)


if __name__ == "__main__":
    unittest.main()
