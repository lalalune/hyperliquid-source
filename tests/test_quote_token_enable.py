import hashlib
import json
import math
import pathlib
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import quote_token_enable as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-006-quote-token-enable-94"
FAR = (tool.STATUS_TEXT, tool.WORDS["far"])
EMPTY = (tool.STATUS_TEXT, tool.WORDS["empty"])
ONE = (tool.STATUS_TEXT, tool.WORDS["one"])
PAIR = (tool.STATUS_TEXT, tool.WORDS["pair"])
FEE = (tool.STATUS_TEXT, tool.WORDS["fee"])
ALLOWED = (tool.STATUS_TEXT, tool.WORDS["allowed"])
OK = (tool.STATUS_OK,)


SHARED = {}


def build(cls):
    if not SHARED:
        SHARED['image'] = tool.load_image()
        SHARED['harness'] = tool.Harness(SHARED['image'])
        SHARED['doc'] = tool.analyse(SHARED['image'], full=False)
    cls.image, cls.harness, cls.doc = SHARED['image'], SHARED['harness'], SHARED['doc']


def book(bid, ask, anchor):
    return {1: dict(bid=bid, ask=ask, anchor=anchor)}


class Base(unittest.TestCase):
    setUpClass = classmethod(build)

    def run_case(self, case, copy=tool.SECOND):
        self.harness.copy = copy
        self.harness.machine.patches = {}
        return self.harness.run(case)

    def status(self, copy=tool.SECOND, **fields):
        return self.run_case(tool.Case("test", **fields), copy)["status"]

    def mutant(self, va, at, kind, case, copy=tool.SECOND):
        """compare_run of one patched byte: None means the spec cannot tell."""
        machine = self.harness.machine
        self.harness.copy = copy
        machine.patches = tool.mutate_patch(self.image, va, at, kind)
        machine.cache.clear()
        try:
            return tool.compare_run(self.harness, case)
        finally:
            machine.patches = {}
            machine.cache.clear()


class Identity(Base):
    def test_wrong_digest_refused(self):
        with self.assertRaisesRegex(tool.EvidenceError, "SHA-256 mismatch"):
            tool.load_image(expected="0" * 64)

    def test_wrong_bytes_refused(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "work" if (ROOT / "work").is_dir() else None) as folder:
            path = pathlib.Path(folder) / "copy"
            path.write_bytes(b"\x7fELF")
            with self.assertRaisesRegex(tool.EvidenceError, "SHA-256 mismatch"):
                tool.load_image(path)

    def test_address_outside_every_fde(self):
        with self.assertRaisesRegex(tool.EvidenceError, "outside every FDE"):
            self.image.fde(0x10)

    def test_not_a_function_start(self):
        with self.assertRaisesRegex(tool.EvidenceError, "not an FDE start"):
            self.image.exact_fde(tool.SECOND["entry"] + 1)

    def test_nobits_never_resolves(self):
        bss = self.image.named[".bss"]
        with self.assertRaisesRegex(tool.EvidenceError, "outside file-backed"):
            self.image.offset(bss["address"] + 8)

    def test_function_extents(self):
        rows = {row["start"]: row for row in self.doc["functions"]}
        self.assertEqual(rows["0x4d62140"]["end"], "0x4d628fb")
        self.assertEqual(rows["0x4d62900"]["size"], 1979)
        self.assertEqual(rows["0x2747390"]["size"], 1979)
        self.assertEqual(rows["0x42fba60"]["size"], rows["0x26e0570"]["size"])


class Constants(Base):
    def test_float_bits(self):
        rows = self.doc["float_constants"]
        self.assertEqual(rows["upper"]["bits"], "0x3fc999999999999a")
        self.assertEqual(rows["lower"]["bits"], "0xbfc999999999999a")
        self.assertEqual(rows["minus one, first"]["value"], -1.0)

    def test_power_table(self):
        self.assertEqual(self.doc["power_table"], [10.0 ** index for index in range(10)])

    def test_texts(self):
        self.assertEqual({row["value"].encode() for row in self.doc["texts"]}, set(tool.WORDS.values()))

    def test_status_names(self):
        values = {row["tag"]: row["value"] for row in self.doc["status_text"]}
        self.assertEqual(values["0xfb"], "Native token does not exist")
        self.assertEqual(values["0xef"], "Invalid quote token")
        self.assertEqual(values["0x10a"], "Deployer cannot have more than $1M volume traded")

    def test_flag_sites(self):
        rows = {row["site"]: row["flag"] for row in self.doc["call_flags"]}
        self.assertEqual(sorted(rows.values()), [0, 0, 0, 1, 1, 1])
        self.assertEqual(rows["0x4ad7dd7"], 0)
        self.assertEqual(rows["0x4cace52"], 1)

    def test_flag_site_bytes_refuse_a_wrong_claim(self):
        saved = tool.COPIES[0]["sites"]
        tool.COPIES[0]["sites"] = ((0x4AD7DD7, 1), (0x4CACE52, 1))
        try:
            with self.assertRaisesRegex(tool.EvidenceError, "flag at"):
                tool.read_flag_sites(self.image)
        finally:
            tool.COPIES[0]["sites"] = saved

    def test_copy_diff_classes(self):
        diff = self.doc["copy_diff"]
        self.assertEqual(diff[0]["instructions"], [382, 382])
        self.assertEqual(len(diff[0]["rows"]), 8)
        self.assertEqual(len(diff[1]["rows"]), 17)
        self.assertFalse([row for one in diff for row in one["rows"] if row["class"] == "shape"])

    def test_no_mismatch(self):
        self.assertEqual(self.doc["mismatches"], 0)
        self.assertEqual(self.doc["first_mismatch"], "")

    def test_locations(self):
        rows = {row["slot"]: (row["path"], row["line"]) for row in self.doc["locations"]}
        self.assertEqual(rows["0x5742320"], ("l1/src/books.rs", 14))
        self.assertEqual(rows["0x56f21f0"], ("l1/src/spot_meta.rs", 113))


class Band(Base):
    def test_exact_band_to_exponent_15(self):
        for exponent in range(1, 16):
            row = tool.band_edges(exponent)
            self.assertEqual((row["lowest_pass"], row["highest_pass"]), (row["exact_low"], row["exact_high"]))

    def test_float_widens_the_band_at_exponent_17(self):
        row = tool.band_edges(17)
        self.assertLess(row["lowest_pass"], row["exact_low"])
        self.assertGreater(row["highest_pass"], row["exact_high"])

    def test_upper_edge(self):
        self.assertEqual(self.status(spot_books=book(1200000, 1200000, 1200000)), OK)
        self.assertEqual(self.status(spot_books=book(1200001, 1200001, 1200001)), FAR)

    def test_lower_edge(self):
        self.assertEqual(self.status(spot_books=book(800000, 800000, 800000)), OK)
        self.assertEqual(self.status(spot_books=book(799999, 799999, 799999)), FAR)

    def test_scale_follows_sz(self):
        rows = ((5, dict(sz=4)),)
        self.assertEqual(self.status(extra_tokens=rows, spot_books=book(10000, 10000, 10000)), OK)
        self.assertEqual(self.status(extra_tokens=rows, spot_books=book(1000000, 1000000, 1000000)), FAR)

    def test_every_copy_agrees_at_the_edges(self):
        for copy in tool.COPIES:
            self.assertEqual(self.status(copy, spot_books=book(1200000, 1200000, 1200000)), OK)
            self.assertEqual(self.status(copy, spot_books=book(1200001, 1200001, 1200001)), FAR)
            self.assertEqual(self.status(copy, spot_books=book(799999, 799999, 799999)), FAR)


class Median(Base):
    def test_outlier_top_is_outvoted(self):
        self.assertEqual(self.status(spot_books=book(700000, 1300000, 1000000)), OK)

    def test_anchor_is_outvoted(self):
        self.assertEqual(self.status(spot_books=book(1000000, 1100000, 1 << 40)), OK)

    def test_zero_anchor_counts_as_a_value(self):
        self.assertEqual(tool.spec_mid(dict(bid=900000, ask=1100000, anchor=0)), 900000)
        self.assertEqual(self.status(spot_books=book(900000, 1100000, 0)), OK)
        self.assertEqual(self.status(spot_books=book(1300000, 1400000, 0)), FAR)

    def test_one_sided_mean(self):
        self.assertEqual(tool.spec_mid(dict(bid=1000000, ask=0, anchor=1500001)), 1250000)


class Order(Base):
    def test_no_bid_says_empty_at_any_price(self):
        self.assertEqual(self.status(spot_books=book(0, 1000000, 1 << 40)), EMPTY)

    def test_no_ask_high_price_says_far_first(self):
        self.assertEqual(self.status(spot_books=book(1000000, 0, 2000000)), FAR)

    def test_no_ask_low_price_says_empty_first(self):
        self.assertEqual(self.status(spot_books=book(1000000, 0, 1)), EMPTY)

    def test_no_pair_before_quote_count(self):
        self.assertEqual(self.status(lists={5: ()}), PAIR)

    def test_book_is_read_after_the_deployer_gate(self):
        run = self.run_case(tool.Case("gate", gate_status=0x10A, spot_books=book(0, 0, 0)))
        self.assertEqual(run["status"], ("filled", 0x10A))

    def test_writer_runs_after_the_book(self):
        self.assertEqual(self.status(extra_tokens=((5, dict(share=1)),), spot_books=book(0, 0, 0)), EMPTY)
        self.assertEqual(self.status(extra_tokens=((5, dict(share=1)),)), FEE)


class Quotes(Base):
    SPOTS = ((5, 0), (3, 0), (4, 6))

    def deployed(self, who):
        return ((6, dict(deployed=1, deployer=who)),)

    def test_second_quote_of_a_deployer_refused(self):
        self.assertEqual(self.status(spots=self.SPOTS, extra_tokens=self.deployed(7)), ONE)

    def test_other_deployer_ignored(self):
        self.assertEqual(self.status(spots=self.SPOTS, extra_tokens=self.deployed(8)), OK)

    def test_usdt0_name_skipped(self):
        rows = ((6, dict(name=b"USDT0", deployed=1, deployer=7)),)
        self.assertEqual(self.status(spots=self.SPOTS, extra_tokens=rows), OK)

    def test_network_two_skips_low_ids(self):
        self.assertEqual(self.status(network=2, spots=self.SPOTS, extra_tokens=self.deployed(7)), OK)

    def test_level_four_for_a_token_already_counted(self):
        rows = ((5, dict(deployed=1, deployer=7)),)
        run = self.run_case(tool.Case("own", spots=((5, 0), (3, 0), (4, 5)), extra_tokens=rows))
        self.assertIn(4, [event[2] for event in run["events"] if event[0] == "gate"])


class Writer(Base):
    def test_flag_zero_refuses_a_listed_status(self):
        self.assertEqual(self.status(flag=0, status_rows=((5, 1),)), ALLOWED)

    def test_flag_one_passes_a_listed_status(self):
        self.assertEqual(self.status(flag=1, status_rows=((5, 1),)), OK)

    def test_flag_zero_passes_status_zero(self):
        self.assertEqual(self.status(flag=0, status_rows=((5, 0),)), OK)

    def test_wei_must_be_eight(self):
        self.assertEqual(self.status(extra_tokens=((5, dict(wei=7)),)), (tool.STATUS_INVALID,))


class Pair(Base):
    def price_of(self, **fields):
        run = self.run_case(tool.Case("price", **fields))
        return [tool.to_float(event[1]) for event in run["events"] if event[0] == "decimal"]

    def test_price_from_the_native_book(self):
        self.assertEqual(self.price_of(spot_books={0: dict(bid=2500000, ask=2600000, anchor=2550000)}), [2.55])

    def test_default_price_is_two(self):
        self.assertEqual(self.price_of(lists={3: ()}), [2.0])

    def test_existing_pair_skips_the_build(self):
        self.assertEqual(self.price_of(spots=((3, 0), (5, 0), (3, 5))), [])

    def test_row_copied_when_the_pair_exists(self):
        run = self.run_case(tool.Case("row", spots=((3, 0), (5, 0), (3, 5)), system_rows=((0, 3.0, 123456, 0.5),)))
        rows = [event for event in run["events"] if event[0] == "system"]
        self.assertEqual(rows, [("system", 2, tool.to_bits(10.0), 2, 123400, tool.to_bits(0.5))])

    def test_no_row_on_a_built_pair_without_a_lookup_hit(self):
        run = self.run_case(tool.Case("built"))
        self.assertFalse([event for event in run["events"] if event[0] == "system"])


class Mutation(Base):
    """A flipped branch or immediate must be seen; the first row of each shows the right cause."""

    def test_upper_branch(self):
        self.assertIn("differs", self.mutant(0x4D62445, 0, "branch", tool.Case("x", spot_books=book(1000000, 1000000, 1000000))))

    def test_lower_branch(self):
        self.assertIn("differs", self.mutant(0x4D624E5, 0, "branch", tool.Case("x", spot_books=book(1000000, 1000000, 1000000))))

    def test_spec_tamper_is_seen(self):
        saved = tool.UPPER
        tool.UPPER = 0.25
        try:
            self.harness.copy = tool.SECOND
            self.assertIn("differs", tool.compare_run(self.harness, tool.Case("x", spot_books=book(1210000, 1210000, 1210000))))
        finally:
            tool.UPPER = saved

    def test_mutants_all_classified(self):
        rows = [line.split("\t") for line in (FOLDER / "mutations.tsv").read_text().splitlines()[1:]]
        self.assertTrue(rows)
        self.assertFalse([row for row in rows if row[3] != "killed" and not row[5]])


class Packet(Base):
    def test_manifest(self):
        for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_manifest_detects_a_changed_digest(self):
        line = (FOLDER / "MANIFEST.sha256").read_text().splitlines()[0]
        digest, name = line.split("  ")
        self.assertNotEqual(hashlib.sha256((FOLDER / name).read_bytes() + b"x").hexdigest(), digest)

    def test_evidence_matches_a_fresh_static_pass(self):
        stored = json.loads((FOLDER / "evidence.json").read_text())
        files = tool.render({**self.doc, "_results": []})
        fresh = json.loads(files["evidence.json"])
        for key in ("functions", "copy_diff", "float_constants", "call_flags", "worked_example", "outcomes"):
            self.assertEqual(stored[key], fresh[key], key)
        self.assertEqual((FOLDER / "band.tsv").read_text(), files["band.tsv"])
        self.assertEqual((FOLDER / "call_sites.tsv").read_text(), files["call_sites.tsv"])


if __name__ == "__main__":
    unittest.main()
