"""Tests for tools/shortfall_sweep.py: real bytes against the specification, with negative controls."""

import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("shortfall_sweep", ROOT / "tools" / "shortfall_sweep.py")
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)
PACKET = ROOT / "research" / "work-items" / "RE-007-shortfall-sweep-94"
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
    def test_each_copy_has_one_host(self):
        rows = {row["function"]: row["callers"] for row in EVIDENCE["call_map"]}
        self.assertEqual(rows, {"0x2765600": ["0x222caf0"], "0x4d96ad0": ["0x4714080"], "0x4d98480": ["0x47121b0"]})

    def test_fold_body_chain(self):
        chain = (tool.ROWS, tool.COLLECT, 0x38DBBB0, 0x34434F0, tool.FILTER)
        found = tool.direct_callers(IMAGE, chain[1:])
        for caller, callee in zip(chain, chain[1:]):
            self.assertIn(caller, {IMAGE.fde(site)[0] for site in found[callee]})

    def test_copies_have_the_same_number_of_direct_calls(self):
        self.assertEqual(len({len(row["calls"]) for row in EVIDENCE["copy_calls"]}), 1)

    def test_constants_are_read_from_the_bytes(self):
        rows = {row["name"]: row for row in EVIDENCE["constants"]}
        self.assertEqual(rows["dust limit compare"]["address"], "0x2765c5e")
        self.assertEqual(rows["scale divisor"]["value"], 10 ** 14)
        self.assertEqual(rows["epoch day count"]["value"], 719163)

    def test_a_moved_constant_is_refused(self):
        saved = tool.DUST
        tool.DUST = saved + 1
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.constants(IMAGE)
        finally:
            tool.DUST = saved


class Specification(unittest.TestCase):
    def test_every_case_matches(self):
        self.assertEqual(EVIDENCE["mismatches"], 0, EVIDENCE["first_mismatch"])
        self.assertGreater(EVIDENCE["cases"]["total"], 1200)

    def test_classes_at_their_edges(self):
        self.assertEqual([tool.user_class(score, 10, 20, 30) for score in (10, 11, 20, 21, 30, 31)], [3, 2, 2, 1, 1, 0])

    def test_filter_rows(self):
        case = dict(items=[(tool.ONE, (0, 0, 40, 10, 20, 30)), (tool.TWO, (0, 0, 25, 10, 20, 30)), (tool.THREE, (0, 0, 15, 10, 20, 30)), (tool.SYSTEM, (0, 0, 40, 10, 20, 30)), (tool.address(4), (1, 9, 0, 0, 0, 0))])
        self.assertEqual(tool.filter_spec(case), [(tool.ONE, 0, 0), (tool.TWO, 0, 0), (tool.address(4), 1, 9)])

    def test_list_stops_at_the_first_failed_row_in_key_order(self):
        case = dict(statuses=[(tool.THREE, 1, 8), (tool.ONE, 0, 1), (tool.TWO, 1, 7)])
        self.assertEqual(tool.list_spec(case), dict(failed=7))

    def test_a_bad_table_is_detected(self):
        saved = tool.user_class
        tool.user_class = lambda score, soft, mid, hard: 0
        try:
            self.assertTrue(tool.compare_run(tool.Harness(IMAGE), CASES[("sweep", "one healthy user", "primary")]))
            self.assertTrue(tool.compare_run(tool.Harness(IMAGE), CASES[("filter", "under soft", "primary")]))
        finally:
            tool.user_class = saved

    def test_a_wrong_count_is_detected(self):
        case = dict(CASES[("sweep", "all counters flag 0", "primary")], start={tool.COUNTERS + tool.LOW_GROUP: 5})
        harness = tool.Harness(IMAGE)
        self.assertEqual(tool.compare_run(harness, case), "")
        want = tool.sweep_spec(case)
        self.assertEqual(want["globals"][tool.COUNTERS + tool.LOW_GROUP + 8 * tool.INDEX_LOW], 2)
        self.assertGreater(want["globals"][tool.COUNTERS + tool.LOW_GROUP], 5)


class Negative(unittest.TestCase):
    def assert_breaks(self, va, xor, key):
        self.assertTrue(tool.compare_run(broken(va, xor), CASES[key]))
        self.assertEqual(tool.compare_run(tool.Harness(IMAGE), CASES[key]), "")

    def test_dust_limit_in_the_sweep(self):
        self.assert_breaks(0x2765C60, 1, ("sweep", "dust edge 1000000", "primary"))

    def test_tier_gate(self):
        self.assert_breaks(0x2765936, 1, ("sweep", "tier 4 word 0x5 healthy", "primary"))

    def test_kept_pair_test(self):
        self.assertEqual(IMAGE.blob[IMAGE.offset(0x373620B)], 0x0F)
        self.assert_breaks(0x373620C, 1, ("sweep", "row tags 1 0, system row, no token", "primary"))

    def test_dust_limit_in_the_filter(self):
        self.assert_breaks(0x3767332, 1, ("filter", "dust", "primary"))


class Packet(unittest.TestCase):
    def test_manifest_matches_the_files(self):
        rows = [line.split("  ") for line in (PACKET / "MANIFEST.sha256").read_text().splitlines()]
        self.assertEqual(sorted(name for _, name in rows), sorted(path.name for path in PACKET.iterdir() if path.name != "MANIFEST.sha256"))
        for digest, name in rows:
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), digest, name)

    def test_stored_evidence_matches_a_fresh_read(self):
        stored = json.loads((PACKET / "evidence.json").read_text(encoding="utf-8"))
        stored.pop("mutations")
        self.assertEqual(stored, json.loads(json.dumps(EVIDENCE)))

    def test_every_mutant_left_alive_has_a_reason(self):
        for line in (PACKET / "mutations.tsv").read_text(encoding="utf-8").splitlines()[1:]:
            row = line.split("\t")
            if row[3] != "killed":
                self.assertTrue(row[5], line)

    def test_samples_regenerate(self):
        with tempfile.TemporaryDirectory() as folder:
            base = pathlib.Path(folder)
            for name, header, rows in (("class-samples.tsv", ("label", "score", "soft", "mid", "hard", "class", "low_flag", "exchange_counters", "result"), tool.class_samples(IMAGE)),
                                       ("move-samples.tsv", ("first_tag", "second_tag", "system_token_1", "user_token_1", "user_keeps_token_2"), tool.move_samples(IMAGE)),
                                       ("amount-samples.tsv", ("label", "row_tag", "list_token_amount_share", "mode"), tool.amount_samples(IMAGE))):
                tool.write_tsv(base / name, header, rows)
                self.assertEqual((base / name).read_bytes(), (PACKET / name).read_bytes(), name)


if __name__ == "__main__":
    unittest.main()
