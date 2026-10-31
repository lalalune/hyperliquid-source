"""Tests for tools/system_user_pass.py: real bytes against the specification, with negative controls."""

import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("system_user_pass", ROOT / "tools" / "system_user_pass.py")
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)
PACKET = ROOT / "research" / "work-items" / "RE-007-system-user-pass-94"
IMAGE = tool.load_image()
EVIDENCE, _ = tool.analyse(IMAGE, full=False)
CASES = {(case["kind"], case["label"], case["copy"]): case for case in tool.all_cases()}


def broken(va, xor):
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

    def test_address_inside_a_function_is_not_an_fde_start(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.exact_fde(tool.COPIES[0]["entry"] + 1)

    def test_section_without_file_bytes_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.offset(IMAGE.named[".bss"]["address"])


class Static(unittest.TestCase):
    def test_each_pass_has_one_caller(self):
        rows = {row["function"]: row for row in EVIDENCE["call_map"]}
        self.assertEqual(rows["0x2739d70"]["callers"], ["0x222caf0"])
        self.assertEqual(len(rows["0x27653a0"]["direct_calls_from"]), 2)

    def test_twin_bodies_keep_their_operation_list(self):
        self.assertTrue(all(row["same_operation_list"] for row in EVIDENCE["twins"]))

    def test_wrappers_call_snapshot_body_writer_post_check(self):
        rows = EVIDENCE["wrapper_calls"]
        self.assertEqual(rows[0]["calls"][:4], ["0x46f2be0", "0x46f7560", "0x4d3a7e0", "0x46f26f0"])
        self.assertEqual(rows[1]["calls"][:4], ["0x46f2960", "0x46f8400", "0x4d39ce0", "0x46f2480"])

    def test_constants(self):
        rows = {row["name"]: row["value"] for row in EVIDENCE["constants"]}
        self.assertEqual(rows["sell slippage f64"], 0.01)
        self.assertEqual(rows["buy slippage f64"], 0.005)
        self.assertEqual(rows["order cap numerator, recording"], 5 * 10 ** 13)

    def test_changed_constant_is_refused(self):
        original = tool.SLIP_BUY
        tool.SLIP_BUY = 0.006
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.constants(IMAGE)
        finally:
            tool.SLIP_BUY = original


class Runs(unittest.TestCase):
    def test_all_cases_match(self):
        self.assertEqual(EVIDENCE["mismatches"], 0, EVIDENCE["first_mismatch"])
        self.assertGreater(EVIDENCE["cases"]["total"], 400)

    def test_most_of_each_body_is_stepped(self):
        for row in EVIDENCE["functions"]:
            self.assertGreater(row["instructions_stepped"] / row["instructions"], 0.85, row["role"])

    def test_each_outcome_is_reached(self):
        names = EVIDENCE["cases"]["outcomes"]
        for name in ("pass: sell and buy", "pass: sell only", "pass: buy only", "pass: no order, gate released", "pass: gate closed", "order: panic"):
            self.assertGreater(names[name], 0, name)

    def test_token_with_debt_is_not_sold(self):
        case = tool.make("debt", rows=[(0, 900, 100), (1, 5 * 10 ** 7, 100)], spot={1: 900})
        sides = [event[4] for event in tool.pass_spec(case)["events"] if event[0] == "place"]
        self.assertEqual(sides, [0])

    def test_sell_of_size_zero_stops_and_buy_goes_out(self):
        sell = tool.order_spec(tool.order_case("sell", mode=1, amount=99))
        buy = tool.order_spec(tool.order_case("buy", mode=0, amount=99))
        self.assertNotIn("place", [event[0] for event in sell])
        self.assertEqual(buy[-1], ("place", 1, 0, 2 * tool.PX, 0))


class Negative(unittest.TestCase):
    """Each flipped byte must make a real run differ from the specification."""

    def expect(self, va, xor, kind, label, copy="primary"):
        self.assertTrue(tool.compare_run(broken(va, xor), CASES[kind, label, copy]), label)
        self.assertEqual(tool.compare_run(tool.Harness(IMAGE), CASES[kind, label, copy]), "")

    def test_need_against_have(self):
        self.expect(0x273A472, 1, "pass", "usdc debt over supply, sell listed")

    def test_gate_byte_compare(self):
        self.expect(0x273A02D, 1, "pass", "gate zero, finish only")

    def test_release_byte(self):
        self.expect(0x273AD9C, 1, "pass", "missing token")

    def test_guard_side(self):
        self.expect(0x27654E8, 1, "order", "sell guard above price")

    def test_cap_numerator(self):
        self.expect(0x2765526, 1, "order", "buy cap at reference 1")

    def test_buy_slippage_branch(self):
        self.expect(0x27653D2, 1, "order", "buy plain")

    def test_recording_book_table(self):
        layout = tool.BY_NAME["recording"]
        layout["books"] = 0x3388
        try:
            self.assertTrue(tool.compare_run(tool.Harness(IMAGE), CASES["order", "buy plain", "recording"]))
        finally:
            layout["books"] = 0x3E08

    def test_changed_specification_is_caught(self):
        case = dict(CASES["order", "buy plain", "primary"])
        original = tool.SLIP_BUY
        tool.SLIP_BUY = 0.006
        try:
            self.assertTrue(tool.compare_run(tool.Harness(IMAGE), case))
        finally:
            tool.SLIP_BUY = original

    def test_address_outside_the_image_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.fde(0x10)


class Packet(unittest.TestCase):
    def test_manifest(self):
        for line in (PACKET / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), digest, name)

    def test_generated_evidence_matches_this_run(self):
        stored = json.loads((PACKET / "evidence.json").read_text())
        for key in ("functions", "call_map", "constants", "twins", "wrapper_calls", "cases", "mismatches"):
            self.assertEqual(stored[key], EVIDENCE[key], key)

    def test_samples_match_this_run(self):
        rows = (PACKET / "order-samples.tsv").read_text().splitlines()[1:]
        self.assertEqual(rows, ["\t".join(str(item) for item in row) for row in tool.order_samples(IMAGE)])
        rows = (PACKET / "decision-samples.tsv").read_text().splitlines()[1:]
        self.assertEqual(rows, ["\t".join(str(item) for item in row) for row in tool.decision_samples(IMAGE)])


if __name__ == "__main__":
    unittest.main()
