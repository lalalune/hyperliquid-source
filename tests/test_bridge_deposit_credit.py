"""Tests for tools/bridge_deposit_credit.py: rule list against real bytes, and negative controls."""
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import bridge_deposit_credit as tool  # noqa: E402


FOLDER = ROOT / "research" / "work-items" / "bridge-deposit-credit-94"


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
        self.assertGreater(len(tool.check_all(self.harness, tool.named_scenarios())), 40)

    def test_generated_scenarios_match(self):
        self.assertEqual(len(tool.check_all(self.harness, tool.vector_scenarios(100))), 100)

    def test_gates_stop_before_the_core(self):
        self.assertEqual(self.run_named("gate_limit")[0][1], ())
        self.assertEqual(self.run_named("gate_kind_one")[0][1], ())

    def test_result_bit_zero_decides(self):
        self.assertEqual(self.run_named("core_result_two_bit_clear")[0][1], (("core",),))
        self.assertGreater(len(self.run_named("core_result_three_bit_set")[0][1]), 1)

    def test_new_user_is_marked_and_known_user_is_not(self):
        self.assertEqual(self.run_named("new_user")[0][2][1][tool.USER][0], 1)
        self.assertEqual(self.run_named("known_second_dex")[0][2][1][tool.USER][0], 0)

    def test_last_address_byte_is_compared(self):
        names = [event[0] for event in self.run_named("probe_last_byte_differs")[0][1]]
        self.assertIn("first_seen", names)

    def test_only_first_dex_is_credited(self):
        balance = [event for event in self.run_named("total_only_first_dex")[0][1] if event[0] == "balance"]
        self.assertEqual(balance, [("balance", True, tool.USER, tool.USD)])

    def test_row_words_rise_by_a_ten_thousandth(self):
        row = self.run_named("new_user")[0][2][1][tool.USER]
        self.assertEqual(row, (1, 7 + tool.USD // 10000, 9 + tool.USD // 10000))
        self.assertEqual(self.run_named("scale_below_one_unit")[0][2][1][tool.USER][1:], (7, 9))

    def test_row_words_saturate(self):
        trace = self.run_named("row_saturates_a")[0]
        self.assertEqual(trace[2][1][tool.USER][1], tool.I64_MAX)
        self.assertIn(("recorder", tool.LOCATION_ROW), trace[1])

    def test_ledger_record_is_f64_over_a_million(self):
        event = [event for event in self.run_named("new_user")[0][1] if event[0] == "ledger"][0]
        self.assertEqual(event[3], tool.DIGEST)
        self.assertEqual(tool.to_float(event[5]), tool.USD / 1000000.0)

    def test_empty_dex_list_panics_only_on_a_credit(self):
        self.assertEqual(self.run_named("no_dex_new_user_panics")[0][0], "panic")
        self.assertEqual(self.run_named("no_dex_result_zero_is_fine")[0][0], (tool.TAG_OK,))


class Negative(Base):
    def test_wrong_hash_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_address_outside_every_function_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            self.image.exact_fde(tool.CREDIT + 1)

    def patched(self, va, flip, name):
        offset = self.image.offset(va)
        harness = tool.Harness(self.image, {va: self.image.blob[offset] ^ flip})
        scenario = scenario_named(name)
        want = tool.spec_run(scenario)
        try:
            return harness.run(scenario) != want
        except (tool.Halt, tool.EvidenceError, tool.Panicked):
            return True

    def test_changed_multiplier_is_caught(self):
        self.assertTrue(self.patched(0x27128BA, 1, "scale_limit") or self.patched(0x27128C1, 1, "scale_limit"))

    def test_flipped_result_branch_is_caught(self):
        self.assertTrue(self.patched(0x27124A6, 1, "new_user"))

    def test_changed_status_is_caught(self):
        self.assertTrue(self.patched(0x27123FD, 1, "gate_kind_one"))

    def test_rule_list_rejects_a_wrong_rule(self):
        scenario = scenario_named("new_user")
        original = tool.I64_MAX
        wrong = tool.Model.row
        tool.Model.row = lambda self, user: self.rows.setdefault(user, [0, 0, 0])
        try:
            self.assertNotEqual(self.harness.run(scenario), tool.spec_run(scenario))
        finally:
            tool.Model.row = wrong
        self.assertEqual(original, tool.I64_MAX)

    def test_key_row_moved_fails(self):
        rows = tool.KEY_ROWS
        tool.KEY_ROWS = ((tool.CREDIT, 0x27123F2, "inside a row", "jcc"),)
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.key_rows(self.image, {tool.CREDIT: tool.decode_range(self.image, *self.image.exact_fde(tool.CREDIT))})
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
