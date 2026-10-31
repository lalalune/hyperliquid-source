"""Tests for tools/liquidate_path.py: real bytes against the specification, with negative controls."""

import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("liquidate_path", ROOT / "tools" / "liquidate_path.py")
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)
PACKET = ROOT / "research" / "work-items" / "RE-007-liquidate-path-94"
IMAGE = tool.load_image()
EVIDENCE, _ = tool.analyse(IMAGE, full=False)
CASES = {(case["label"], case["copy"]): case for case in tool.all_cases()}
HARNESS = tool.Harness(IMAGE)


def broken(va, xor):
    harness = tool.Harness(IMAGE)
    harness.machine.patches = {va: IMAGE.blob[IMAGE.offset(va)] ^ xor}
    return harness


def status(label, copy="primary"):
    case = CASES[(label, copy)]
    want = tool.action_spec(case)
    return want["status"] if want["tag"] == tool.RESULT_ERROR else "ok"


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
    def test_handler_has_one_caller(self):
        rows = {row["function"]: row["callers"] for row in EVIDENCE["call_map"]}
        self.assertEqual(rows["0x23e66f0"], ["0x2759240"])

    def test_executor_has_a_second_host(self):
        rows = {row["function"]: row["callers"] for row in EVIDENCE["call_map"]}
        self.assertEqual(rows["0x2725150"], ["0x23e66f0", "0x27078a0"])

    def test_route_is_reached_through_one_data_slot(self):
        rows = {row["function"]: row["callers"] for row in EVIDENCE["call_map"]}
        self.assertEqual(rows["0x3424d20"], [])
        self.assertEqual(sum(1 for target in tool.relative_slots(IMAGE).values() if target == tool.ROUTE), 1)

    def test_constant_with_other_bytes_is_refused(self):
        sites = tool.CONSTANT_SITES
        tool.CONSTANT_SITES = (("handler", "wrong", 0x23E6AEF, b"\x00\x00", 1),)
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.constants(IMAGE)
        finally:
            tool.CONSTANT_SITES = sites

    def test_every_status_word_is_in_the_constants(self):
        values = {row["value"] for row in EVIDENCE["constants"]}
        self.assertTrue({0x23, 0x24, 0x25, 0x61, 0x7C, 0x143, 0x15E} <= values)


class Behaviour(unittest.TestCase):
    def test_all_cases_match(self):
        self.assertEqual(EVIDENCE["mismatches"], 0, EVIDENCE["first_mismatch"])
        self.assertEqual(EVIDENCE["cases"]["total"], len(CASES))

    def test_no_agent_entry_is_35_not_124(self):
        self.assertEqual(status("signer differs, default not a key"), 0x23)
        self.assertEqual(status("chain ends short of the signer"), 0x7C)

    def test_agent_chain_of_any_length(self):
        self.assertEqual(status("signer three steps away"), "ok")
        self.assertIsNone(tool.compare_run(HARNESS, CASES[("signer three steps away", "primary")]))

    def test_default_in_the_list_is_found_after_the_assets(self):
        case = dict(CASES[("list, entry is default", "primary")], classify={1: (0x99, 1, 2)})
        self.assertEqual(tool.action_spec(case)["status"], 0x99)
        self.assertEqual(tool.action_spec(CASES[("list, entry is default", "primary")])["status"], 0x25)

    def test_each_list_entry_is_authorised(self):
        self.assertEqual(status("list, entry not a liquidator"), 0x23)
        self.assertEqual(status("list, entry chain misses"), 0x7C)

    def test_executor_gets_dex_index_0_for_a_dex_1_id(self):
        case = CASES[("single asset, id in dex 1", "primary")]
        self.assertIsNone(tool.compare_run(HARNESS, case))
        run = [event for event in HARNESS.events if event[0] == "run"][0]
        self.assertEqual(run[3], 10007)

    def test_refusal_word_of_a_spot_asset_is_the_asset_before_it(self):
        case = CASES[("list, spot asset", "primary")]
        self.assertEqual(tool.action_spec(case)["words"], (1,))

    def test_price_formula(self):
        price, logged = tool.limit_price(10, 3000, 1000, 500)
        self.assertEqual((price, logged), (150, 0))
        self.assertEqual(tool.limit_price(-10, -3000, 1000, 500)[0], 450)
        self.assertEqual(tool.limit_price(10, 3, 3, 0)[0], 1)
        self.assertEqual(tool.limit_price(5, 100, 100, 200)[0], 1)

    def test_every_copy_matches_the_same_cases(self):
        names = {copy for _, copy in CASES}
        self.assertEqual(names, {"primary", "second", "recording"})
        self.assertEqual(len(CASES) % 3, 0)

    def test_ids_are_taken_for_skipped_items(self):
        case = CASES[("zero size item skipped", "primary")]
        self.assertEqual(tool.run_spec(case)["counter"], 102)

    def test_whole_dex_keeps_orders_of_isolated_positions(self):
        self.assertEqual([at for at, _ in tool.cancel_ids(CASES[("position isolated, live", "primary")])], [0, 2, 3])
        self.assertEqual([at for at, _ in tool.cancel_ids(CASES[("position isolated, zero word", "primary")])], [0, 1, 2, 3])


class Controls(unittest.TestCase):
    def test_map_limit_byte(self):
        self.assertTrue(tool.compare_run(broken(0x23E6AF2, 1), CASES[("list, map length 10001", "primary")]))

    def test_dex_status_byte(self):
        self.assertTrue(tool.compare_run(broken(0x23E6C6A, 1), CASES[("single asset", "primary")]))

    def test_mode_kind_byte(self):
        self.assertTrue(tool.compare_run(broken(0x27263BE, 1), CASES[("cross hand-over, long", "primary")]))

    def test_rest_floor_branch(self):
        self.assertTrue(tool.compare_run(broken(0x2726053, 1), CASES[("rest exactly 2", "primary")]))

    def test_chain_compare(self):
        self.assertTrue(tool.compare_run(broken(0x275F190, 1), CASES[("list, entry chain misses", "primary")]))

    def test_event_divisor_is_seen(self):
        self.assertTrue(tool.compare_run(broken(0x392B7CA, 0), CASES[("single event, no items", "primary")]) is None)
        self.assertTrue(tool.compare_run(broken(0x392B7C9, 1), CASES[("single event, no items", "primary")]))

    def test_unpatched_harness_after_controls(self):
        self.assertIsNone(tool.compare_run(tool.Harness(IMAGE), CASES[("single asset", "primary")]))


class Packet(unittest.TestCase):
    def test_regeneration_matches_the_packet(self):
        with tempfile.TemporaryDirectory() as folder:
            self.assertEqual(tool.main(["--out", folder]), 0)
            names = sorted(path.name for path in pathlib.Path(folder).iterdir())
            self.assertEqual(names, ["evidence.json", "gate-samples.tsv", "mutations.tsv", "path-map.tsv", "price-samples.tsv", "reference-diffs.tsv"])
            for name in names:
                self.assertEqual((pathlib.Path(folder) / name).read_bytes(), (PACKET / name).read_bytes(), name)

    def test_manifest(self):
        lines = (PACKET / "MANIFEST.sha256").read_text().splitlines()
        self.assertTrue(lines)
        for line in lines:
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), digest)

    def test_every_survivor_has_a_reason(self):
        rows = [line.split("\t") for line in (PACKET / "mutations.tsv").read_text().splitlines()[1:]]
        self.assertFalse([row for row in rows if row[3] != "killed" and not row[5]])

    def test_evidence_binds_the_target(self):
        doc = json.loads((PACKET / "evidence.json").read_text())
        self.assertEqual(doc["target_sha256"], tool.SHA256)


if __name__ == "__main__":
    unittest.main()
