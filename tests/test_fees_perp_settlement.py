"""Tests for tools/fees_perp_settlement.py: the evaluated fill, negative controls on bytes, and the evidence files."""

import hashlib
import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
SPEC = importlib.util.spec_from_file_location("fees_perp_settlement", ROOT / "tools" / "fees_perp_settlement.py")
tool = importlib.util.module_from_spec(SPEC)
sys.modules["fees_perp_settlement"] = tool
SPEC.loader.exec_module(tool)
FOLDER = ROOT / "research" / "work-items" / "fees-perp-settlement-94"
IMAGE = tool.load_image()
CASES = tool.all_cases()
BY_LABEL = {case["label"]: case for case in CASES}


def flip(harness, va, xor=1):
    base = IMAGE.offset(va)
    harness.machine.patches = {va: IMAGE.blob[base] ^ xor}
    harness.machine.cache.clear()


def unpatch(harness):
    harness.machine.patches = {}
    harness.machine.cache.clear()


class Evaluated(unittest.TestCase):
    harness = tool.Harness(IMAGE)

    def run_case(self, label):
        return tool.compare_run(self.harness, BY_LABEL[label])

    def state(self, label):
        return self.harness.run(BY_LABEL[label])

    def test_all_vectors_match(self):
        failed = [case["label"] for case in CASES if tool.compare_run(self.harness, case)]
        self.assertEqual(failed, [])

    def test_vector_count_is_large(self):
        self.assertGreater(len(CASES), 800)

    def test_net_fee_leaves_the_cross_balance(self):
        got = self.state("rebate maker")
        self.assertEqual(got["rows"][tool.BUYER]["balance"], 10 ** 9 - 9000)
        self.assertEqual(got["rows"][tool.SELLER]["balance"], 10 ** 9 + 1500)

    def test_isolated_value_pays_from_margin(self):
        got = self.state("isolated")
        self.assertEqual(got["rows"][tool.BUYER]["balance"], 10 ** 9)
        self.assertEqual(got["rows"][tool.BUYER]["positions"][tool.ASSET][2], 8000 - 9000 & tool.MAX)

    def test_deposit_total_falls_by_three_words_only(self):
        got = self.state("paid words")
        self.assertEqual(got["pool"], 10 ** 12 - 2 * (40 + 100 + 70))

    def test_builder_tag_is_a_bit_and_referrer_tag_is_a_dword(self):
        self.assertEqual(self.state("builder tag 2")["pool"], 10 ** 12)
        self.assertEqual(self.state("builder tag 3")["pool"], 10 ** 12 - 500)
        self.assertEqual(self.state("referrer tag 2")["pool"], 10 ** 12)
        self.assertEqual(self.state("referrer tag 0x101")["pool"], 10 ** 12)

    def test_znfn_grows_only_on_zero_fee(self):
        self.assertEqual(self.state("no fee words")["free"], 55 + 777000)
        self.assertEqual(self.state("plain fill")["free"], 55)

    def test_znfn_follows_the_sum_not_the_gross(self):
        self.assertEqual(self.state("zero total sum")["free"], 55 + 777000)

    def test_exempt_party_has_no_fee_call_and_stops_znfn(self):
        got = self.state("exempt no fee words 0")
        self.assertEqual([row for row in got["log"] if row[0] == "fee"], [("fee", 1, 0)])
        self.assertEqual(got["free"], 55)

    def test_every_exempt_address_hits_the_real_test(self):
        for index in range(8):
            got = self.state("exempt %d" % index)
            self.assertEqual([row[1] for row in got["log"] if row[0] == "fee"], [1])

    def test_near_address_is_not_exempt(self):
        """Flip one byte of an exempt address: the real test must refuse it."""
        tool.PRIVILEGED.append(bytes([tool.PRIVILEGED[0][0] ^ 1]) + tool.PRIVILEGED[0][1:])
        try:
            case = tool.world("near", party=(-9, tool.SELLER), rows={tool.SELLER: tool.account()})
            got = self.harness.run(case)
            self.assertEqual([row[1] for row in got["log"] if row[0] == "fee"], [0, 1])
        finally:
            tool.PRIVILEGED.pop()

    def test_negative_words_panic(self):
        for name in ("gross", "rebate", "extra", "builder", "referrer"):
            self.assertEqual(self.state("negative %s 0" % name)["panic"], tool.LOC_NET)
        self.assertEqual(self.state("negative size")["panic"], tool.LOC_SZ)
        self.assertEqual(self.state("apply fails 1")["panic"], tool.LOC_APPLY)

    def test_size_signs(self):
        got = self.state("plain fill")
        moves = [row[2] for row in got["log"] if row[0] == "apply"]
        self.assertEqual(moves, [300, -300 & tool.MAX])

    def test_credit_runs_at_zero(self):
        self.assertIn(("credit", 0, 0), self.state("no fee words")["log"])

    def test_margin_sum_moves_by_the_difference(self):
        record = []
        row = tool.margin_row()
        want = 5000 + tool.margin_part(800, row, record) - tool.margin_part(0, row, record)
        self.assertEqual(self.state("margin plain")["active"]["total"], want)

    def test_margin_uses_each_side(self):
        record = []
        row = tool.margin_row(a=1000, b=600, c=10, d=20)
        self.assertEqual(tool.margin_part(5, row, record), max(1000, 30 * 10) // 5)
        self.assertEqual(tool.margin_part(-5 & tool.MAX, row, record), max(600, 100) // 5)

    def test_bad_flip_of_debit_is_seen(self):
        flip(self.harness, 0x3710F45)
        try:
            self.assertTrue(self.run_case("balance low"))
        finally:
            unpatch(self.harness)

    def test_flipped_zero_gate_is_seen(self):
        flip(self.harness, 0x371139E)
        try:
            self.assertTrue(self.run_case("plain fill"))
        finally:
            unpatch(self.harness)

    def test_size_hook_with_equal_sizes_changes_nothing(self):
        for held in (0, 1, tool.HALF - 1, tool.MAX):
            case = dict(label="same", kind="size hook", old=held, new=held, count=3, total=500, asset=33, assets=(33,), stale=())
            got = self.harness.run_hook(case)
            self.assertEqual((got["count"], got["total"]), (3, 500))

    def test_size_hook_counts_edges(self):
        for old, new, want in ((0, 5, 4), (5, 0, 2), (5, 7, 3)):
            case = dict(label="edge", kind="size hook", old=old, new=new, count=3, total=500, asset=33, assets=(33,), stale=())
            self.assertEqual(self.harness.run_hook(case)["count"], want)


class Bytes(unittest.TestCase):
    def test_wrong_hash_is_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "copy"
            path.write_bytes(IMAGE.blob[:4096])
            with self.assertRaises(tool.EvidenceError):
                tool.load_image(path)

    def test_address_outside_sections_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.offset(0x7FFFFFFFFFFF)

    def test_nobits_gives_no_file_bytes(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.offset(IMAGE.named[".bss"]["address"] + 8)

    def test_fde_bounds(self):
        self.assertEqual(IMAGE.exact_fde(tool.FILL_FN), (0x3710A70, 0x3711B9F))
        with self.assertRaises(tool.EvidenceError):
            IMAGE.exact_fde(tool.FILL_FN + 1)

    def test_decoder_lands_on_the_ends(self):
        for start in (tool.FILL_FN, tool.SIZE_HOOK, tool.PREDICATE):
            rows = tool.decode_range(IMAGE, *IMAGE.exact_fde(start))
            self.assertEqual(rows[-1].next, IMAGE.exact_fde(start)[1])

    def test_pins_refuse_a_wrong_byte(self):
        kept = tool.PINS
        tool.PINS = (("0x3710a93", "488b8218020001", "wrong"),)
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.pin_rows(IMAGE)
        finally:
            tool.PINS = kept

    def test_serde_keys(self):
        rows = {row[0]: row[1] for row in tool.serde_rows(IMAGE)}
        self.assertEqual(rows, {"0x238": "total_net_deposit", "0x240": "total_non_bridge_deposit", "0x2d8": "znfn"})

    def test_serde_refuses_a_wrong_site(self):
        kept = tool.SERDE
        tool.SERDE = ((0x370C7F3, 0x598C55, 0x11, 0x238),)
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.serde_rows(IMAGE)
        finally:
            tool.SERDE = kept

    def test_fill_callers(self):
        sites = [row[1] for row in tool.caller_rows(IMAGE) if row[0] == "fill apply"]
        self.assertEqual(sites, ["0x26ed0ec", "0x37087ed", "0x4312265", "0x4315ec5"])

    def test_exempt_list_is_8_distinct_addresses(self):
        self.assertEqual(len(set(tool.privileged_addresses(IMAGE))), 8)

    def test_survivor_without_reason_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.reason_for({"result": "survived", "va": 1})

    def test_unclassified_instruction_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.unstepped_rows({"functions": [{"start": "0x1", "unstepped": ["0x10"]}]})


class Files(unittest.TestCase):
    def test_manifest(self):
        lines = (FOLDER / "MANIFEST.sha256").read_text(encoding="utf-8").splitlines()
        names = []
        for line in lines:
            digest, name = line.split("  ", 1)
            names.append(name)
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)
        self.assertEqual(sorted(names), sorted(path.name for path in FOLDER.iterdir() if path.name != "MANIFEST.sha256"))

    def test_evidence(self):
        evidence = json.loads((FOLDER / "evidence.json").read_text(encoding="utf-8"))
        self.assertEqual(evidence["target_sha256"], tool.SHA256)
        self.assertEqual(evidence["mismatches"], 0)
        self.assertEqual(evidence["cases"]["total"], len(CASES))

    def test_every_survivor_has_a_reason(self):
        lines = (FOLDER / "mutations.tsv").read_text(encoding="utf-8").splitlines()[1:]
        for line in lines:
            parts = line.split("\t")
            if parts[3] != "killed":
                self.assertTrue(parts[5], line)

    def test_small_tables_match_the_tool(self):
        for name, rows in (("path-map.tsv", tool.path_rows()), ("fee-words.tsv", tool.word_rows()), ("margin-rule.tsv", tool.margin_rows()), ("reference-diff.tsv", tool.reference_rows())):
            lines = (FOLDER / name).read_text(encoding="utf-8").splitlines()[1:]
            self.assertEqual(lines, ["\t".join(str(item) for item in row) for row in rows], name)


if __name__ == "__main__":
    unittest.main()
