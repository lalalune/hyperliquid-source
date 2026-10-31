import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import token_genesis_finish as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-006-token-genesis-book-word-94"
OK = (tool.STATUS_OK,)
LOTS = (tool.STATUS_TEXT, tool.WORDS[tool.TEXT_LOTS])
MISSING = (tool.STATUS_TEXT, tool.WORDS[tool.TEXT_MISSING])
INCORRECT = (tool.STATUS_TEXT, tool.WORDS[tool.TEXT_INCORRECT])
SUM_ERROR = (tool.STATUS_TEXT, tool.WORDS[tool.TEXT_SUPPLY_SUM])
ONE_PERCENT = (tool.STATUS_TEXT, tool.WORDS[tool.TEXT_ONE_PERCENT])
NOT_ZERO = (tool.STATUS_TEXT, tool.WORDS[tool.TEXT_NOT_ZERO])
USER = tool.user_id(7)
OTHER = tool.user_id(8)
HOLE = tool.HOLE_USER
SUPPLY = 200000000000000


SHARED = {}


def build(cls):
    if not SHARED:
        SHARED['image'] = tool.load_image()
        SHARED['harness'] = tool.Harness(SHARED['image'])
        SHARED['doc'] = tool.analyse(SHARED['image'], full=False)
    cls.image, cls.harness, cls.doc = SHARED['image'], SHARED['harness'], SHARED['doc']


def users(*rows, existing=(), black=()):
    return {5: dict(users=list(rows), existing=list(existing), black=list(black))}


class Base(unittest.TestCase):
    setUpClass = classmethod(build)

    def run_case(self, case, copy=tool.THIRD):
        self.harness.copy = copy
        self.harness.machine.patches = {}
        return self.harness.run(case)

    def status(self, copy=tool.THIRD, **fields):
        return self.run_case(tool.Case("test", **fields), copy)["status"]

    def mutant(self, va, at, kind, case, copy=tool.THIRD):
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
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "copy"
            path.write_bytes(b"\x7fELF")
            with self.assertRaisesRegex(tool.EvidenceError, "SHA-256 mismatch"):
                tool.load_image(path)

    def test_address_outside_every_fde(self):
        with self.assertRaisesRegex(tool.EvidenceError, "outside every FDE"):
            self.image.fde(0x10)

    def test_not_a_function_start(self):
        with self.assertRaisesRegex(tool.EvidenceError, "not an FDE start"):
            self.image.exact_fde(tool.THIRD["entry"] + 1)

    def test_nobits_never_resolves(self):
        bss = self.image.named[".bss"]
        with self.assertRaisesRegex(tool.EvidenceError, "outside file-backed"):
            self.image.offset(bss["address"] + 8)

    def test_function_extents(self):
        rows = {row["start"]: row for row in self.doc["functions"]}
        self.assertEqual(rows["0x4d611e0"]["end"], "0x4d618ee")
        self.assertEqual(rows["0x4d618f0"]["size"], 1819)
        self.assertEqual(rows["0x2746b40"]["size"], 1819)
        self.assertEqual(rows["0x371b950"]["size"], 4785)
        self.assertEqual(rows["0x371f6b0"]["size"], 1210)


class Static(Base):
    def test_texts(self):
        self.assertEqual({row["value"].encode() for row in self.doc["texts"]}, set(tool.WORDS.values()))

    def test_text_mismatch_refused(self):
        saved = tool.WORDS[tool.TEXT_LOTS]
        tool.WORDS[tool.TEXT_LOTS] = b"x" * len(saved)
        try:
            with self.assertRaisesRegex(tool.EvidenceError, "text at"):
                tool.read_texts(self.image)
        finally:
            tool.WORDS[tool.TEXT_LOTS] = saved

    def test_powers(self):
        self.assertEqual(self.doc["powers_of_ten"], [10.0 ** index for index in range(20)])

    def test_status_names(self):
        names = {row["tag"]: row["value"] for row in self.doc["status_text"]}
        self.assertEqual(names["0xb7"], "Failed to parse integer")
        self.assertEqual(names["0xbe"], "Add result error")
        self.assertEqual(names["0x143"], "Invalid input length")

    def test_action_arm(self):
        arm = self.doc["action_arm"]
        self.assertEqual((arm["entry"], arm["arm"], arm["host"]), (4, "0x4ad849a", "0x4ad81e0"))

    def test_action_tail_refused_when_changed(self):
        saved = tool.ACTION_TAIL
        tool.ACTION_TAIL = bytes(len(saved))
        try:
            with self.assertRaisesRegex(tool.EvidenceError, "action site bytes"):
                tool.read_call_sites(self.image)
        finally:
            tool.ACTION_TAIL = saved

    def test_six_sites(self):
        rows = self.doc["call_sites"]
        self.assertEqual(len(rows), 6)
        self.assertEqual(sum(1 for row in rows if row["flag"] == "literal 1"), 3)
        listed = [line.split("\t")[1] for line in (FOLDER / "call_sites.tsv").read_text().splitlines()[1:]]
        self.assertEqual(sorted(listed), sorted(row["site"] for row in rows))

    def test_finish_slot_callers_are_the_copies(self):
        self.assertEqual(self.doc["finish_slot"], ["0x5774bf8"])
        self.assertEqual({row["host"] for row in self.doc["finish_calls"]}, {"0x4d611e0", "0x4d618f0", "0x2746b40"})

    def test_store_sites(self):
        self.assertEqual(sorted(self.doc["anchor_sites"]["stores_in"]), ["0x2746b40", "0x4d611e0", "0x4d618f0"])

    def test_copy_diff_shape(self):
        rows = self.doc["copy_diff_second_first"]["rows"]
        self.assertEqual({row["class"] for row in rows}, {"call target", "field"})
        self.assertEqual(self.doc["copy_diff_second_first"]["instructions"], [382, 382])

    def test_location_paths_are_short(self):
        rows = {row["slot"]: row for row in self.doc["locations"]}
        self.assertEqual((rows["0x56f2270"]["path"], rows["0x56f2270"]["line"]), ("l1/src/spot_meta.rs", 1199))
        self.assertEqual((rows["0x5742338"]["path"], rows["0x5742338"]["line"]), ("l1/src/books.rs", 19))

    def test_no_external_program(self):
        text = (ROOT / "tools" / "token_genesis_finish.py").read_text()
        self.assertNotIn("import subprocess", text)
        self.assertNotIn("objdump", text.replace("No objdump or readelf output is", ""))


class Parse(Base):
    def test_kinds(self):
        for text, kind in ((b"", 0), (b"+", 1), (b"-", 1), (b"-5", 1), (b"12a", 1), (b"18446744073709551616", 2), (b"999999999999999999999", 2), (b"18446744073709551615x", 1)):
            self.assertEqual(self.status(text=text), (tool.STATUS_PARSE, kind), text)

    def test_plus_is_dropped(self):
        self.assertEqual(self.status(text=b"+200000000000000"), OK)

    def test_leading_zeros(self):
        self.assertEqual(self.status(text=b"000200000000000000"), OK)

    def test_parse_before_any_state(self):
        self.assertEqual(self.status(text=b"x", token=99), (tool.STATUS_PARSE, 1))


class Gates(Base):
    def test_default_passes(self):
        self.assertEqual(self.status(), OK)

    def test_lots_edge(self):
        self.assertEqual(self.run_case(tool.supply_case("a", 2, 8, 10 ** 14))["status"], OK)
        self.assertEqual(self.run_case(tool.supply_case("b", 2, 8, 10 ** 14 - 1))["status"], LOTS)

    def test_saturated_minimum_needs_u64_max(self):
        self.assertEqual(self.run_case(tool.supply_case("a", 0, 12, tool.MASK[8]))["status"], OK)
        self.assertEqual(self.run_case(tool.supply_case("b", 0, 12, tool.MASK[8] - 1))["status"], LOTS)

    def test_exponent_panics(self):
        for sz, wei in ((3, 2), (0, 20), (0, 32), (0, 64)):
            self.assertEqual(self.run_case(tool.supply_case("x", sz, wei, 10 ** 12))["stop"], ("panic", tool.LOC_DECIMALS))

    def test_token_bound(self):
        self.assertEqual(self.run_case(tool.Case("x", token=9, rows={}))["stop"], ("panic", tool.LOC_TOKEN))

    def test_missing_genesis(self):
        self.assertEqual(self.status(genesis={}), MISSING)
        self.assertEqual(self.status(genesis={4: users()[5]}), MISSING)

    def test_sum_must_equal(self):
        self.assertEqual(self.status(text=b"200000000000001"), INCORRECT)

    def test_sum_carry(self):
        self.assertEqual(self.status(genesis=users((USER, 1 << 63), (OTHER, 1 << 63))), SUM_ERROR)
        self.assertEqual(self.status(genesis=users((USER, 1 << 63), existing=[(3, 1 << 63)])), SUM_ERROR)

    def test_one_percent_floor(self):
        self.assertEqual(self.status(genesis=users((USER, SUPPLY - 2000000000000), (HOLE, 2000000000000))), OK)
        self.assertEqual(self.status(genesis=users((USER, SUPPLY - 1999999999999), (HOLE, 1999999999999))), ONE_PERCENT)

    def test_network_zero_skips_one_percent(self):
        self.assertEqual(self.status(network=0, genesis=users((USER, SUPPLY))), OK)
        self.assertEqual(self.status(network=2, genesis=users((USER, SUPPLY))), ONE_PERCENT)

    def test_name_exception_is_exact(self):
        rows = lambda name: {5: dict(sz=2, wei=8, name=name, spots=[0])}
        self.assertEqual(self.status(rows=rows(b"HYPE"), genesis=users((USER, SUPPLY))), OK)
        self.assertEqual(self.status(rows=rows(b"HYPES"), genesis=users((USER, SUPPLY))), ONE_PERCENT)
        self.assertEqual(self.status(rows=rows(b"HYPF"), genesis=users((USER, SUPPLY))), ONE_PERCENT)

    def test_flag_refuses_hole_balance(self):
        self.assertEqual(self.status(flag=1), NOT_ZERO)
        self.assertEqual(self.status(flag=1, genesis=users((USER, SUPPLY))), OK)
        self.assertEqual(self.status(flag=1, genesis=users((USER, SUPPLY), (HOLE, 0))), OK)


class Balances(Base):
    def credits(self, case):
        return [event for event in self.run_case(case)["events"] if event[0] == "credit"]

    def test_blocked_user_is_counted_but_not_credited(self):
        case = tool.Case("x", genesis=users((USER, 5000), (OTHER, SUPPLY - 5000 - 50000000000000), (HOLE, 50000000000000), black=[USER]))
        rows = self.credits(case)
        self.assertEqual(self.run_case(case)["status"], OK)
        self.assertNotIn(USER.hex(), [row[1] for row in rows])
        self.assertEqual(sum(row[3] for row in rows), SUPPLY - 5000)

    def test_holder_answer_merges(self):
        case = tool.Case("x", genesis=users((USER, SUPPLY - 900), (HOLE, 0), existing=[(3, 900)]), network=0, holders={3: [(USER, 600), (OTHER, 300)]})
        amounts = {row[1]: row[3] for row in self.credits(case)}
        self.assertEqual(amounts[USER.hex()], SUPPLY - 900 + 600)
        self.assertEqual(amounts[OTHER.hex()], 300)

    def test_holder_not_filtered_by_blocked_set(self):
        case = tool.Case("x", genesis=users((USER, SUPPLY - 900), existing=[(3, 900)], black=[OTHER]), network=0, holders={3: [(OTHER, 900)]})
        self.assertIn(OTHER.hex(), [row[1] for row in self.credits(case)])

    def test_merge_overflow_status(self):
        case = tool.Case("x", genesis=users((USER, SUPPLY - 900), existing=[(3, 900)]), network=0, holders={3: [(USER, tool.MASK[8])]})
        self.assertEqual(self.run_case(case)["status"], (tool.STATUS_OVERFLOW,))

    def test_holder_status_returned_whole(self):
        case = tool.Case("x", genesis=users((USER, SUPPLY - 900), existing=[(3, 900)]), network=0, holders={3: 0x161})
        self.assertEqual(self.run_case(case)["status"], ("filled", 0x161))

    def test_nothing_changes_on_refusal(self):
        case = tool.Case("x", genesis=users((USER, SUPPLY - 900), existing=[(3, 900)]), network=0, holders={3: 0x161})
        run = self.run_case(case)
        self.assertEqual(run["state"]["supplies"], case.supplies)
        self.assertEqual(run["state"]["books"][0], tool.book_mark(0))

    def test_row_amount_float(self):
        run = self.run_case(tool.Case("x"))
        rows = [event for event in run["events"] if event[0] == "row"]
        self.assertEqual(rows[0][3], tool.to_bits(1500000.0))
        self.assertEqual(rows[1][3], tool.to_bits(500000.0))


class Word(Base):
    def test_default(self):
        run = self.run_case(tool.Case("x"))
        self.assertEqual(run["state"]["books"][0], 5000)
        self.assertEqual(run["state"]["books"][3], 5000)

    def test_only_usdc_spots(self):
        run = self.run_case(tool.Case("x"))
        self.assertEqual(run["state"]["books"][1], tool.book_mark(1))
        self.assertEqual(run["state"]["books"][2], tool.book_mark(2))

    def test_upper_limit_and_drop_to_one(self):
        rows = [line.split("\t") for line in (FOLDER / "word.tsv").read_text().splitlines()[1:]]
        for exponent, _, label, _, word in rows:
            if int(exponent) <= 7:
                self.assertEqual(int(word), 10000 if label == "lowest" else 5000)
            else:
                self.assertEqual(int(word), 1)

    def test_spec_word_never_zero_past_the_gate(self):
        for exponent in range(0, 20):
            scale = 10 ** exponent
            for supply in (min(tool.MIN_LOTS * scale, tool.MASK[8]), tool.MASK[8]):
                self.assertTrue(1 <= tool.spec_word(supply, scale) <= 10000)

    def test_supply_map_written_and_replaced(self):
        self.assertEqual(self.run_case(tool.Case("x"))["state"]["supplies"], [(2, 77), (5, SUPPLY)])
        self.assertEqual(self.run_case(tool.Case("x", supplies=[(5, 3)]))["state"]["supplies"], [(5, SUPPLY)])

    def test_spot_bound_panics_after_rows(self):
        run = self.run_case(tool.Case("x", rows={5: dict(sz=2, wei=8, name=b"LEMON", spots=[0, 4])}))
        self.assertEqual(run["stop"][0], "bounds")
        self.assertIn("row", [event[0] for event in run["events"]])

    def test_book_bound_skipped_for_other_quote(self):
        self.assertEqual(self.status(spots=[(5, 1), (5, 3)], book_count=0, rows={5: dict(sz=2, wei=8, name=b"LEMON", spots=[0, 1])}), OK)


class Copies(Base):
    def with_copy(self, case, copy):
        self.harness.copy = copy
        return tool.compare_run(self.harness, case)

    def test_all_copies_agree_with_the_spec(self):
        self.assertEqual(self.doc["mismatches"], 0)
        self.assertEqual(self.doc["cases"]["runs"], self.doc["cases"]["total"] * 3)

    def test_wrong_book_field_is_caught(self):
        self.assertIsNotNone(self.with_copy(tool.Case("x"), dict(tool.COPIES[1], books=tool.THIRD["books"])))

    def test_wrong_location_is_caught(self):
        case = tool.Case("x", rows={5: dict(sz=2, wei=8, name=b"LEMON", spots=[0, 4])})
        self.assertIsNotNone(self.with_copy(case, dict(tool.COPIES[2], spot_location=tool.THIRD["spot_location"])))


class Mutants(Base):
    def test_lots_compare(self):
        self.assertIsNotNone(self.mutant(0x371B9CB, 0, "branch", tool.supply_case("x", 2, 8, 10 ** 14)))

    def test_sum_equal_gate(self):
        self.assertIsNotNone(self.mutant(0x371BBE3, None, "set", tool.Case("x", text=b"200000000000001")))

    def test_one_percent_divisor(self):
        row = next(row for row in tool.decode_range(self.image, 0x371BE0A, 0x371BE14))
        self.assertIsNotNone(self.mutant(row.va, row.imm_at, "immediate", tool.Case("x", genesis=users((USER, SUPPLY - 1999999999999), (HOLE, 1999999999999)))))

    def test_word_numerator(self):
        row = next(row for row in tool.decode_range(self.image, 0x371C751, 0x371C75B))
        self.assertIsNotNone(self.mutant(row.va, row.imm_at, "immediate", tool.supply_case("x", 0, 0, 7299270073)))

    def test_quote_field(self):
        self.assertIsNotNone(self.mutant(0x4D6176C, 4, "offset", tool.Case("x")))

    def test_book_field(self):
        self.assertIsNotNone(self.mutant(0x4D6178B, 4, "offset", tool.Case("x")))

    def test_patched_copy_not_left_behind(self):
        self.assertEqual(self.harness.machine.patches, {})
        self.assertIsNone(tool.compare_run(self.harness, tool.Case("x")))


class Packet(Base):
    def test_every_mutant_row_has_a_verdict(self):
        rows = [line.split("\t") for line in (FOLDER / "mutations.tsv").read_text().splitlines()[1:]]
        self.assertTrue(rows)
        for row in rows:
            self.assertIn(row[3], ("killed", "survived", "unreached"))
            if row[3] != "killed":
                self.assertTrue(row[5], row)

    def test_counts_match_the_rows(self):
        doc = json.loads((FOLDER / "evidence.json").read_text())
        rows = [line.split("\t") for line in (FOLDER / "mutations.tsv").read_text().splitlines()[1:]]
        for key, value in doc["mutations"].items():
            self.assertEqual(sum(1 for row in rows if row[3] == key), value)

    def test_manifest(self):
        lines = (FOLDER / "MANIFEST.sha256").read_text().splitlines()
        names = sorted(path.name for path in FOLDER.iterdir() if path.name != "MANIFEST.sha256")
        self.assertEqual(sorted(line.split("  ")[1] for line in lines), names)
        for line in lines:
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_static_rows_match_the_stored_evidence(self):
        doc = json.loads((FOLDER / "evidence.json").read_text())
        for key in ("call_sites", "action_arm", "anchor_sites", "texts", "status_text", "locations", "functions", "worked_example", "outcomes"):
            self.assertEqual(json.loads(json.dumps(self.doc[key])), doc[key], key)


if __name__ == "__main__":
    unittest.main()
