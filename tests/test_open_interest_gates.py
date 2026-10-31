"""Tests for tools/open_interest_gates.py: the node #94 open interest gates on a price update."""

import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import open_interest_gates as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-006-open-interest-gates-94"


class Shared(unittest.TestCase):
    image = None

    def prepare(cls):
        if Shared.image is None:
            Shared.image = tool.load_image()
            Shared.harness = tool.Harness(Shared.image)
            Shared.evidence = tool.analyse(Shared.image, full=False)

    setUpClass = classmethod(prepare)

    def check_case(self, **changes):
        return tool.Case("t: check", "check", tool.world(**changes))

    def host_case(self, **changes):
        return tool.Case("t: host", "host", tool.world(**changes))

    def patched(self, patches, case):
        machine = self.harness.machine
        machine.patches = patches
        machine.cache.clear()
        try:
            return tool.compare_run(self.harness, case)
        finally:
            machine.patches = {}
            machine.cache.clear()


class ImageChecks(Shared):
    def test_wrong_hash_is_refused(self):
        with self.assertRaisesRegex(tool.EvidenceError, "SHA-256 mismatch"):
            tool.load_image(expected="0" * 64)

    def test_address_outside_every_fde(self):
        with self.assertRaisesRegex(tool.EvidenceError, "outside every FDE"):
            self.image.exact_fde(0x10)

    def test_mid_function_is_not_an_fde_start(self):
        with self.assertRaisesRegex(tool.EvidenceError, "not an FDE start"):
            self.image.exact_fde(tool.HOST + 1)

    def test_bss_has_no_file_bytes(self):
        bss = self.image.named[".bss"]
        with self.assertRaisesRegex(tool.EvidenceError, "outside file-backed"):
            self.image.offset(bss["address"] + bss["size"] - 1)

    def test_function_extents(self):
        rows = {row["start"]: row["size"] for row in self.evidence["functions"]}
        self.assertEqual(rows, {"0x3709040": 1298, "0x3bfd3c0": 990, "0x3bc3630": 704, "0x3708e80": 436, "0x3be6420": 564, "0x3bfd1d0": 485})

    def test_six_slot_sites(self):
        rows = [row for row in self.evidence["_sites"] if row[0] == tool.HOST]
        self.assertEqual([row[1] for row in rows], [0x2707431, 0x2707A6B, 0x4CF2C71, 0x4CF3231, 0x4CF39BA, 0x4CF9662])
        self.assertEqual([row[2][-1] for row in rows], ["1", "0", "1", "1", "0", "0"])

    def test_call_flag_needs_exact_bytes(self):
        with self.assertRaisesRegex(tool.EvidenceError, "flag bytes"):
            tool.call_flag(self.image, tool.HOST + 0x40)


class StaticRows(Shared):
    def test_book_field_names(self):
        rows = self.evidence["serde_fields"]
        self.assertEqual(len(rows), 4)
        for row in rows:
            self.assertEqual(row["fields"]["0xd0"]["name"], "total_sz")
            self.assertEqual(row["fields"]["0x78"]["name"], "last_trade_px")

    def test_field_writer_with_no_name(self):
        self.assertIsNone(tool.name_words(self.image, tool.RETAIN))

    def test_texts(self):
        self.assertEqual(self.evidence["texts"]["0x1fa4b9"]["text"], "Asset open interest exceeded cap asset={} kind={}, oi={}")
        self.assertEqual(self.evidence["texts"]["0x1e9abe"]["text"], "Missing price, keeping old {} price asset={} oracle_kind={}")
        self.assertTrue(self.evidence["texts"]["0x1fe7ec"]["text"].startswith("Total open interest exceeded 10x"))

    def test_template_refuses_plain_text(self):
        with self.assertRaises((tool.EvidenceError, UnicodeDecodeError)):
            tool.template(self.image, 0x5B8704)

    def test_displays(self):
        self.assertEqual(self.evidence["displays"]["0x3818cf0"], {"kind 0": "Spot", "kind 1": "Mark", "other kinds": "External"})
        self.assertEqual(self.evidence["displays"]["0x3bddf10"], {"byte 0": "oracle", "other bytes": "reference"})

    def test_locations_stay_relative(self):
        for row in self.evidence["locations"]:
            self.assertTrue(row["path"].startswith("l1/src/"), row)
        names = {row["name"]: row["line"] for row in self.evidence["locations"]}
        self.assertEqual(names["book row bound"], 14)

    def test_host_bytes_refuse_a_change(self):
        rows = tool.HOST_BYTES
        tool.HOST_BYTES = ((rows[0][0], "00" * 7, "wrong"),)
        try:
            with self.assertRaisesRegex(tool.EvidenceError, "host bytes"):
                tool.read_host_bytes(self.image)
        finally:
            tool.HOST_BYTES = rows

    def test_limits_are_decimal_fractions_of_two_to_64(self):
        self.assertEqual(tool.LIMIT_HIGH, (1 << 64) // 10 + 1)
        self.assertEqual(tool.LIMIT_LOW, (1 << 64) // 100 + 1)


class SpecRules(Shared):
    def spec(self, case):
        return tool.spec_run(case)

    def test_wire_asset(self):
        rows = {0: 0, 9999: 9999, 10000: 110000, 99899999: 99999999, 99900000: 0xFFFFFFFF, 1 << 40: 0xFFFFFFFF}
        for asset, wanted in rows.items():
            self.assertEqual(tool.wire_asset(asset), wanted)

    def test_row_limit_edge(self):
        self.assertIsNone(self.spec(self.check_case(price=1, stored=tool.LIMIT_HIGH - 1, book=0))["out"])
        self.assertIsNotNone(self.spec(self.check_case(price=1, stored=tool.LIMIT_HIGH, book=0))["out"])

    def test_book_counts_like_size(self):
        self.assertIsNotNone(self.spec(self.check_case(price=1, stored=1, book=tool.LIMIT_HIGH - 1))["out"])

    def test_second_record_only_in_mode_3(self):
        low = dict(price=1, stored=tool.LIMIT_LOW, book=0)
        self.assertEqual(self.spec(self.check_case(mode=0, **low))["events"], [])
        self.assertEqual(self.spec(self.check_case(mode=3, **low))["events"], [("record", 1, tool.LOC_ROW)])

    def test_negative_price_shows_zero(self):
        found = self.spec(self.check_case(price=tool.MASK[8]))
        self.assertEqual(found["events"][0][2][2], 0)

    def test_total_gate_edge(self):
        for whole, wanted in ((1009, 0), (1010, 1)):
            case = self.host_case(cap=100, assets_word=1, wire_length=1, asset_rows=[1], sizes={0: whole}, lists=([], [(0, 1)], []))
            self.assertEqual(sum(1 for event in self.spec(case)["events"] if event[0] == "format" and event[1] == tool.TEXT_TOTAL), wanted)


class Evaluator(Shared):
    def test_no_mismatch(self):
        self.assertEqual(self.evidence["mismatches"], 0, self.evidence["first_mismatch"])
        self.assertGreater(self.evidence["cases"]["total"], 300)

    def test_only_length_cases_stop_at_the_length_gate(self):
        for case in tool.host_cases():
            if not case.label.startswith("host: length"):
                self.assertEqual(case.world["wire_length"], case.world["assets_word"], case.label)

    def test_total_gate_edge_on_the_bytes(self):
        rows = {}
        for case in tool.host_cases():
            rows[case.label] = case
        for label, wanted in (("host: tenth equals cap", 1), ("host: just below the next unit", 1), ("host: one unit over", 0), ("host: unit at zero cap", 0), ("host: below one unit at zero cap", 1)):
            found = self.harness.run(rows[label])
            self.assertEqual(found["out"], "ok", label)
            self.assertEqual(len(found["lists"][1]), wanted, label)

    def test_every_outcome_group_runs(self):
        names = " ".join(self.evidence["outcomes"])
        for word in ("check pass", "check text", "row kept", "row dropped", "retain done", "clear done", "total sum", "total none", "host ok", "host length", "host parse", "panic: bounds", "panic: unwrap"):
            self.assertIn(word, names)

    def test_wrong_limit_is_seen(self):
        case = self.check_case(price=1, stored=tool.LIMIT_HIGH - 1, book=0)
        self.assertEqual(self.patched({}, case), "")
        self.assertIn("differs", self.patched({0x3708F33: 0x99}, case))

    def test_book_offset_is_seen(self):
        case = tool.Case("t: row", "row", tool.world(asset=1, books=[0, tool.LIMIT_HIGH, 0, 0], price=1))
        self.assertEqual(self.patched({}, case), "")
        self.assertNotEqual(self.patched({0x3BC3722: 0xD8}, case), "")

    def test_mode_gate_is_seen(self):
        case = self.check_case(mode=3, price=1, stored=tool.LIMIT_LOW, book=0)
        self.assertEqual(self.patched({}, case), "")
        self.assertIn("differs", self.patched({0x3708F1B: 0x04}, case))

    def test_tenth_constant_is_read_from_the_file(self):
        self.assertEqual(tool.to_float(self.image_word(0x20A880)), 0.1)

    def image_word(self, va):
        return int.from_bytes(self.image.blob[self.image.offset(va):self.image.offset(va) + 8], "little")

    def test_retain_keeps_order(self):
        rows = [(1, tool.LIMIT_HIGH), (2, 3), (3, 4)]
        case = tool.Case("t: retain", "retain", tool.world(lists=(rows, [], []), sizes={1: 1, 2: 1, 3: 1}))
        found = self.harness.run(case)
        self.assertEqual(found["lists"][0], [(2, 3), (3, 4)])
        self.assertEqual(len(found["errors"]), 2)

    def test_clear_replaces_the_mark_list(self):
        case = tool.Case("t: clear", "clear", tool.world(lists=([], [(1, 9)], [])))
        self.assertEqual(self.harness.run(case)["mark_head"], (0, 8))

    def test_host_uses_stored_prices_after_a_clear(self):
        case = self.host_case(cap=0, sizes={0: 1000}, lists=([], [(0, 5)], []))
        found = self.harness.run(case)
        self.assertEqual(found["lists"], [[], [], []])

    def test_stub_refuses_an_unknown_template(self):
        machine = self.harness.machine
        machine.regs[tool.RSI] = 0x1234
        with self.assertRaisesRegex(tool.Halt, "template"):
            self.harness.on_format(machine)


class Mutation(Shared):
    def test_patch_flips_one_bit(self):
        patch = tool.mutate_patch(self.image, tool.CHECK + 0x20, 1, "branch")
        self.assertEqual(len(patch), 1)

    def test_targets_cover_each_kind(self):
        rows = tool.decode_range(self.image, *self.image.exact_fde(tool.CHECK))
        kinds = {kind for _, _, kind in tool.mutation_targets(self.image, rows)}
        self.assertTrue({"branch", "immediate", "offset", "set", "cmov"} <= kinds)

    def test_every_reason_is_stated_in_the_file(self):
        rows = [line.split("\t") for line in (FOLDER / "mutations.tsv").read_text(encoding="ascii").splitlines()[1:]]
        self.assertGreater(len(rows), 300)
        for row in rows:
            if row[3] != "killed":
                self.assertTrue(row[5], row)
                self.assertFalse(row[5].startswith("no case"), row)

    def test_counts_match(self):
        doc = json.loads((FOLDER / "evidence.json").read_text(encoding="ascii"))
        rows = [line.split("\t") for line in (FOLDER / "mutations.tsv").read_text(encoding="ascii").splitlines()[1:]]
        self.assertEqual(doc["mutations"]["killed"], sum(1 for row in rows if row[3] == "killed"))


class Output(Shared):
    def test_render_is_stable(self):
        self.assertEqual(tool.render(self.evidence), tool.render(self.evidence))

    def test_files_match_without_the_mutants(self):
        doc = json.loads((FOLDER / "evidence.json").read_text(encoding="ascii"))
        fresh = json.loads(tool.render(self.evidence)["evidence.json"])
        for key in ("functions", "serde_fields", "host_bytes", "texts", "locations", "cases", "outcomes", "reference_claims"):
            self.assertEqual(doc[key], fresh[key], key)

    def test_write_outputs(self):
        with tempfile.TemporaryDirectory() as folder:
            tool.write_outputs(folder, {"a.txt": "x\n"})
            self.assertEqual((pathlib.Path(folder) / "a.txt").read_text(encoding="ascii"), "x\n")


if __name__ == "__main__":
    unittest.main()
