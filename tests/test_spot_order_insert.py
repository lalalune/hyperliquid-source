"""Tests of tools/spot_order_insert.py: real bytes in the evaluator against the specification, with negative controls."""

import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FOLDER = ROOT / "research" / "work-items" / "RE-006-spot-order-insert-94"
SPEC = importlib.util.spec_from_file_location("spot_order_insert", ROOT / "tools" / "spot_order_insert.py")
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)


CACHE = {}


def shared(cls):
    if not CACHE:
        CACHE["image"] = tool.load_image()
        CACHE["harness"] = tool.Harness(CACHE["image"])
        CACHE["doc"] = tool.analyse(CACHE["image"], full=False)
    cls.image, cls.harness, cls.doc = CACHE["image"], CACHE["harness"], CACHE["doc"]


def run(harness, world):
    case = tool.Case("test", "test", world)
    return tool.spec_run(case), harness.run(case)


class Base(unittest.TestCase):
    setUpClass = classmethod(shared)

    def same(self, world):
        expected, got = run(self.harness, world)
        self.assertEqual(tool.normal(expected, got), expected)
        return got

    def flip(self, va, at, kind, world):
        """The patched run must differ from the prediction."""
        machine = self.harness.machine
        machine.patches = tool.mutate_patch(self.image, va, at, kind)
        machine.cache.pop(va, None)
        try:
            return tool.compare_run(self.harness, tool.Case("control", "control", world))
        finally:
            machine.patches = {}
            machine.cache.pop(va, None)


class Identity(Base):
    def test_digest_is_checked(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "copy"
            path.write_bytes(self.image.blob[:4096])
            with self.assertRaisesRegex(tool.EvidenceError, "SHA-256 mismatch"):
                tool.load_image(path)

    def test_wrong_expected_digest(self):
        with self.assertRaisesRegex(tool.EvidenceError, "SHA-256 mismatch"):
            tool.load_image(tool.BINARY, "0" * 64)

    def test_function_extent(self):
        self.assertEqual(self.image.exact_fde(tool.INSERT), (0x26E81C0, 0x26EBDC0))
        self.assertEqual(self.doc["functions"][0]["size"], 15360)

    def test_address_inside_is_not_a_start(self):
        with self.assertRaisesRegex(tool.EvidenceError, "not an FDE start"):
            self.image.exact_fde(tool.INSERT + 1)

    def test_outside_every_mapping(self):
        with self.assertRaisesRegex(tool.EvidenceError, "outside file-backed"):
            self.image.offset(1 << 40)

    def test_nobits_never_maps(self):
        with self.assertRaisesRegex(tool.EvidenceError, "outside file-backed"):
            self.image.offset(self.image.named[".bss"]["address"])

    def test_no_mismatch(self):
        self.assertEqual(self.doc["mismatches"], 0)
        self.assertGreater(self.doc["cases"]["total"], 300)

    def test_require_raises_on_other_bytes(self):
        with self.assertRaisesRegex(tool.EvidenceError, "bytes at"):
            tool.require(self.image, 0x26E8768, b"\x00\x00", "control")


class StaticFacts(Base):
    def test_tif_table(self):
        self.assertEqual([row["arm"] for row in self.doc["tif_table"][:5]], ["0x26e86e1", "0x26e86c7", "0x26e8756", "0x26e86c7", "0x26e86c7"])

    def test_tif_table_ends_at_five(self):
        self.assertFalse(self.doc["tif_table"][5]["inside"])

    def test_band_words(self):
        self.assertEqual([row["value"] for row in self.doc["band"]], ["0.2", "-1.0"])

    def test_assert_text(self):
        self.assertEqual(self.doc["text"]["value"], "assertion failed: reduce_only")

    def test_statuses(self):
        words = {row["status"] for row in self.doc["status_word_sites"]}
        self.assertIn("0x8000000000000017", words)
        self.assertIn("0x8000000000000013", words)

    def test_dead_arm_flag_is_only_cleared(self):
        rows = {row["name"]: row["before_first_read"] for row in self.doc["dead_arm_words"]}
        self.assertEqual(rows["set flag"], ["0x26e8a3f"])

    def test_second_map_root_is_only_cleared(self):
        rows = {row["name"]: row["before_first_read"] for row in self.doc["dead_arm_words"]}
        self.assertEqual(rows["second user map root"], ["0x26e8a4f"])

    def test_locations_keep_no_root(self):
        for row in self.doc["locations"]:
            self.assertTrue(row["path"].startswith(("l1/", "library/")), row["path"])


class Gates(Base):
    def test_quote_set(self):
        got = self.same(tool.world(tokens={"5": 0}))
        self.assertEqual(got["result"]["status"], 0x8000000000000017)
        self.assertEqual(got["result"]["third"], 9)

    def test_quote_byte_must_be_zero(self):
        self.assertEqual(self.same(tool.world(tokens={"9": 1}))["result"]["status"], 0x8000000000000017)

    def test_post_only_crossing_at_equal_price(self):
        got = self.same(tool.world(tool.book(0, (1,), [100]), {"tif": 0}))
        self.assertEqual(got["result"]["status"], 0x8000000000000006)
        self.assertEqual(got["result"]["second"], 0x1111)

    def test_post_only_rests_below(self):
        self.assertEqual(self.same(tool.world(tool.book(0, (1,), [110]), {"tif": 0}))["book"]["rest"][1], 30)

    def test_taker_needs_a_cross(self):
        for tif in (1, 3, 4):
            self.assertEqual(self.same(tool.world([], {"tif": tif}))["result"]["status"], 0x8000000000000008)

    def test_reduce_flag_never_inserts(self):
        got = self.same(tool.world([], {"reduce": 1}))
        self.assertEqual(got["result"]["status"], 0x8000000000000005)
        self.assertEqual(got["log"], [["refresh", tool.TAKER, 1]])

    def test_missing_tag_panics(self):
        self.assertEqual(self.same(tool.world([], {"tag": 0}))["panic"], "reduce_only text")

    def test_price_limit_edge(self):
        self.assertIn("oid", self.same(tool.world([], {"px": 10 ** 15}))["result"])
        self.assertEqual(self.same(tool.world([], {"px": 10 ** 15 + 10}))["result"]["status"], tool.NONE_WORD)

    def test_class_one(self):
        self.assertEqual(self.same(tool.world([], cls=1))["result"]["status"], 0x8000000000000014)

    def test_control_quote_flip_is_seen(self):
        self.assertTrue(self.flip(0x26E84F5, 1, "branch", tool.world([])))

    def test_oid_saturates(self):
        self.assertEqual(self.same(tool.world([], next_oid=tool.MAX64))["book"]["next_oid"], tool.MAX64)


class Walk(Base):
    def buy(self, levels, **extra):
        return self.same(tool.world(levels, {"px": 200, **extra.pop("a", {})}, **extra))

    def test_price_time_order(self):
        got = self.buy([tool.chain(110, [3], 2), tool.chain(100, [3, 3])], a={"size": 7})
        self.assertEqual([row[0] for row in got["result"]["fills"]], [100, 100, 110])
        self.assertEqual(got["book"]["last_trade"], 110)

    def test_sell_walks_down(self):
        got = self.same(tool.world(tool.book(1, (2, 2)), {"side": 1, "px": 10}))
        self.assertEqual([row[0] for row in got["result"]["fills"]], [100, 90])

    def test_limit_is_inclusive(self):
        got = self.same(tool.world(tool.book(0, (4, 4, 4)), {"px": 110}))
        self.assertEqual([row[0] for row in got["result"]["fills"]], [100, 110])

    def test_same_user_skip_reason(self):
        got = self.buy([{"px": 100, "slots": [tool.slot(tool.TAKER, 4, 0x301)]}])
        self.assertIn(["skip", 0x301, tool.TAKER, 9], got["log"])
        self.assertEqual(got["result"]["users"], [[tool.TAKER, [0x301]]])

    def test_flagged_maker_reason(self):
        got = self.buy([{"px": 100, "slots": [tool.slot(tool.USERS[0], 4, 0x301, 1)]}])
        self.assertIn(["skip", 0x301, tool.USERS[0], 10], got["log"])
        self.assertEqual(got["book"]["sizes"][0], 4)

    def test_two_system_users_count_as_one(self):
        got = self.buy([{"px": 100, "slots": [tool.slot(tool.USERS[0], 4, 0x301)]}], system=[tool.TAKER, tool.USERS[0]])
        self.assertIn(["skip", 0x301, tool.USERS[0], 9], got["log"])

    def test_buyer_cap_floors(self):
        got = self.buy(tool.book(0, (4,)), balances={"9": [399, 0]})
        self.assertEqual(got["result"]["fills"][0][2], 3)

    def test_cap_stops_all_levels(self):
        got = self.buy(tool.book(0, (4, 4)), balances={"9": [399, 0]})
        self.assertEqual(len(got["result"]["fills"]), 1)
        self.assertEqual(got["book"]["sizes"][1], 4)

    def test_zero_cap_first(self):
        got = self.buy(tool.book(0, (4,)), balances={"9": [50, 0]})
        self.assertEqual(got["result"]["status"], 0x8000000000000012)
        self.assertEqual(got["result"]["third"], 0x8000000000000013)

    def test_hold_counts(self):
        self.assertEqual(self.buy(tool.book(0, (4,)), balances={"9": [400, 1]})["result"]["fills"][0][2], 3)

    def test_failed_convert_leaves_the_level(self):
        got = self.buy([tool.chain(100, [4, 4]), tool.chain(110, [4], 2)], convert={"0": [0, 1, 2]})
        self.assertEqual([row[0] for row in got["result"]["fills"]], [110])
        self.assertEqual(got["book"]["sizes"], [4, 4, 0, 7, 0])

    def test_notional_edge(self):
        size = (2 ** 63 - 2) // 3
        self.assertIn("oid", self.same(tool.world([tool.chain(3, [size])], {"px": 30, "size": size}, tick=1, balances={"9": [2 ** 64 - 1, 0]}))["result"])

    def test_notional_over(self):
        size = (2 ** 63 + 1) // 3
        self.assertEqual(self.same(tool.world([tool.chain(3, [size])], {"px": 30, "size": size}, tick=1, balances={"9": [2 ** 64 - 1, 0]}))["panic"], "notional")

    def test_bad_slot_panics(self):
        self.assertEqual(self.buy(tool.book(0, (4, 4)), broken_slot=0)["panic"], "slot")

    def test_settle_changes_last_trade(self):
        self.assertEqual(self.buy(tool.book(0, (4,)), settled={"0": [97, 4]})["book"]["last_trade"], 97)

    def test_control_limit_flip_is_seen(self):
        self.assertTrue(self.flip(0x26E8D43, 1, "branch", tool.world(tool.book(0, (4, 4, 4)), {"px": 110})))

    def test_control_order_of_users(self):
        self.assertTrue(self.flip(0x26E974C, 1, "branch", tool.world(tool.book(0, (4,)), {"px": 200})))


class Band(Base):
    BASE = {"rows": [[2, 3], [5, 0]], "tokens": {"5": 0, "0": 0}, "anchor": 100}

    def test_edge_stays(self):
        got = self.same(tool.world([tool.chain(100, [2]), tool.chain(120, [2], 1)], {"px": 200, "size": 4}, **self.BASE))
        self.assertEqual(len(got["result"]["fills"]), 2)

    def test_over_stops_after_fills(self):
        got = self.same(tool.world([tool.chain(100, [2]), tool.chain(121, [2], 1)], {"px": 200}, **self.BASE))
        self.assertEqual(len(got["result"]["fills"]), 1)
        self.assertIsNone(got["book"]["rest"][1])

    def test_first_level_over_stops(self):
        self.assertEqual(self.same(tool.world([tool.chain(121, [2])], {"px": 200}, **self.BASE))["result"]["status"], 0x8000000000000013)

    def test_nonzero_quote_has_no_band(self):
        got = self.same(tool.world([tool.chain(500, [2])], {"px": 600}, rows=[[2, 3], [5, 9]], tokens={"5": 0, "9": 0}))
        self.assertEqual(len(got["result"]["fills"]), 1)


class Rest(Base):
    def test_link_to_old_tail(self):
        got = self.same(tool.world([], rest_level=[0, 0]))
        self.assertEqual(got["book"]["links"], {"0": 30})
        self.assertEqual(got["book"]["rest"], [0, 30])

    def test_bid_key_is_negative(self):
        self.assertIn(["level", 0, -100], self.same(tool.world([]))["log"])

    def test_ask_key_is_positive(self):
        self.assertIn(["level", 1, 100], self.same(tool.world([], {"side": 1}))["log"])

    def test_vacant_tail(self):
        self.assertEqual(self.same(tool.world([], rest_level=[0, 1]))["panic"], "tail")

    def test_gate_refusal_alone(self):
        self.assertEqual(self.same(tool.world([], may_rest=False))["result"]["status"], 0x8000000000000013)

    def test_gate_refusal_after_fill_keeps_fills(self):
        self.assertEqual(len(self.same(tool.world(tool.book(0, (4,)), {"px": 200}, may_rest=False))["result"]["fills"]), 1)

    def test_status_row_after_fill(self):
        got = self.same(tool.world(tool.book(0, (10,)), {"px": 200}))
        self.assertEqual([row[0] for row in got["log"]][-2:], ["build_status", "row"])

    def test_no_row_for_word_nine(self):
        got = self.same(tool.world(tool.book(0, (10,)), {"px": 200, "kind": 9}))
        self.assertNotIn("row", [row[0] for row in got["log"]])

    def test_fresh_flag(self):
        self.assertTrue(self.same(tool.world([]))["result"]["fresh_rest"])
        self.assertFalse(self.same(tool.world([], {"oid_tag": 1}))["result"]["fresh_rest"])

    def test_given_oid_full_fill_row(self):
        got = self.same(tool.world(tool.book(0, (10,)), {"px": 200, "oid_tag": 1, "tif": 1}))
        self.assertEqual([row[1] for row in got["log"] if row[0] == "relations"].count(0x777), 2)


class Packet(Base):
    def test_files_match_the_tool_cases(self):
        lines = (FOLDER / "cases.tsv").read_text().splitlines()
        self.assertEqual(len(lines) - 1, self.doc["cases"]["total"])

    def test_outcomes_match(self):
        doc = json.loads((FOLDER / "evidence.json").read_text())
        self.assertEqual(doc["outcomes"], self.doc["outcomes"])
        self.assertEqual(doc["mismatches"], 0)

    def test_every_open_mutant_has_a_reason(self):
        for line in (FOLDER / "mutations.tsv").read_text().splitlines()[1:]:
            row = line.split("\t")
            self.assertTrue(row[3] == "killed" or row[5], line)

    def test_manifest(self):
        for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_corrupted_manifest_line_fails(self):
        line = (FOLDER / "MANIFEST.sha256").read_text().splitlines()[0]
        digest, name = line.split("  ")
        self.assertNotEqual(hashlib.sha256((FOLDER / name).read_bytes() + b"x").hexdigest(), digest)


if __name__ == "__main__":
    unittest.main()
