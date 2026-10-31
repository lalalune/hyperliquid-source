"""Tests for tools/fill_row_output.py: the node #94 fill rows, flush, sink and JSON keys, run from ELF bytes with stubbed edges."""

import hashlib
import json
import pathlib
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import fill_row_output as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-006-fill-row-output-94"


SHARED = {}


def load_shared(cls):
    if not SHARED:
        SHARED["image"] = tool.load_image()
        SHARED["harness"] = tool.Harness(SHARED["image"])
        SHARED["cases"] = tool.all_cases()
        SHARED["static"] = tool.analyse(SHARED["image"], full=False)
    cls.image = SHARED["image"]
    cls.harness = SHARED["harness"]
    cls.cases = SHARED["cases"]
    cls.by_label = {case.label: case for case in cls.cases}
    cls.static = SHARED["static"]


class Base(unittest.TestCase):
    setUpClass = classmethod(load_shared)

    def compare(self, label):
        return tool.compare_run(self.harness, self.by_label[label])

    def with_patch(self, patches):
        machine = self.harness.machine
        machine.patches = dict(patches)
        machine.cache = {}
        self.addCleanup(self.clear)

    def clear(self):
        self.harness.machine.patches = {}
        self.harness.machine.cache = {}

    def read_row(self, base, stride, index):
        return self.harness.machine.memory.bytes_at(base + index * stride, stride)

    def rows_of(self, label):
        found = self.harness.run(self.by_label[label])
        base, length = found["rows"]
        stride = tool.WIDTHS[tool.COPIES[self.by_label[label].copy].width].row
        return [self.read_row(base, stride, index) for index in range(length)]


class Identity(Base):
    def test_binary_digest(self):
        self.assertEqual(hashlib.sha256(bytes(self.image.blob)).hexdigest(), tool.SHA256)

    def test_wrong_digest_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_every_function_is_an_exact_fde(self):
        for row in self.static["functions"]:
            self.assertEqual(self.image.exact_fde(int(row["start"], 16))[1], int(row["end"], 16))

    def test_address_inside_a_function_refused(self):
        with self.assertRaises(tool.EvidenceError):
            self.image.exact_fde(0x26F4401)

    def test_address_out_of_range_refused(self):
        with self.assertRaises(tool.EvidenceError):
            self.image.offset(0x7FFFFFFFFFFF)


class Agreement(Base):
    def test_no_mismatch_in_any_case(self):
        self.assertEqual(self.static["first_mismatch"], "")
        self.assertEqual(self.static["mismatches"], 0)
        self.assertGreater(len(self.cases), 500)

    def test_every_outcome_class_is_reached(self):
        wanted = {"emit: 0 rows", "emit: 1 rows", "emit: 3 rows", "emit: 4 rows", "panic: oracle row", "sink: drop", "sink: fill", "sink: trade", "sink: none", "flush: panic coin", "flush: 3 rows", "fill writer: all keys", "trade writer: stopped"}
        self.assertLessEqual(wanted, set(self.static["outcomes"]))

    def test_all_writers_run(self):
        for row in self.static["functions"]:
            if "row writer" in row["role"]:
                self.assertGreater(row["instructions_stepped"], row["instructions"] * 3 // 4, row["role"])


class Rows(Base):
    def test_one_fill_gives_kinds_6_8_8(self):
        rows = self.rows_of("spot first: one fill")
        self.assertEqual([struct.unpack_from("<Q", row, 0)[0] for row in rows], [6, 8, 8])

    def test_flag_adds_a_leading_kind_5(self):
        rows = self.rows_of("perp first: one fill, flag")
        self.assertEqual([struct.unpack_from("<Q", row, 0)[0] for row in rows], [5, 6, 8, 8])

    def test_no_fill_with_flag_still_writes_kind_5(self):
        self.assertEqual(len(self.rows_of("spot second: no fills, flag")), 1)

    def test_side_byte_is_0_then_1(self):
        rows = self.rows_of("spot first: one fill")
        self.assertEqual((rows[1][0x23A], rows[2][0x23A]), (0, 1))

    def test_codes_split_by_side(self):
        rows = self.rows_of("spot first: codes 0xb0a0908")
        self.assertEqual(tuple(rows[1][0x238:0x23A]), (8, 9))
        self.assertEqual(tuple(rows[2][0x238:0x23A]), (10, 11))

    def test_flag_mask_covers_all_but_0_and_6(self):
        for low in range(11):
            first, _ = tool.flag_bytes(bytes(256), low)
            self.assertEqual(first, 0 if low in (0, 6) else 1)

    def test_both_clear_byte(self):
        self.assertEqual(tool.flag_bytes(bytes(256), 0)[1], 1)
        self.assertEqual(tool.flag_bytes(bytes(256), 0x30000)[1], 0)
        self.assertEqual(tool.flag_bytes(bytes(256), 3)[1], 0)
        self.assertEqual(tool.flag_bytes(bytes(256), 0x4400)[1], 1)

    def test_table_decides_when_low_code_is_outside_the_mask(self):
        table = self.static["copies"][0]["flag_table_bytes"]
        self.assertEqual(tool.flag_bytes(bytes(table) + bytes(245), 0x30000)[0], 1)
        self.assertEqual(tool.flag_bytes(bytes(table) + bytes(245), 0x60000)[0], 0)

    def test_three_clones_swap_coin_and_price_but_one(self):
        keep = [row["start"] for row in self.static["copies"] if row["keeps_output_order"]]
        self.assertEqual(keep, ["0x44714b0"])

    def test_spot_reference_word_falls_back_to_price(self):
        rows = self.rows_of("spot first: mark word zero")
        self.assertEqual(struct.unpack_from("<Q", rows[1], 0x230)[0], 0x77665544)

    def test_perp_reference_word_uses_the_oracle_row(self):
        rows = self.rows_of("perp first: mark word zero, large coin")
        self.assertEqual(struct.unpack_from("<Q", rows[1], 0x240)[0], 0x2345)

    def test_oracle_bound_panics_after_the_trade_row(self):
        found = self.harness.run(self.by_label["perp first: oracle row missing"])
        self.assertIn("bounds 4 4", found["panic"])
        self.assertEqual(found["rows"][1], 1)

    def test_word_two_stops_perp_loop(self):
        rows = self.rows_of("perp first: word two stops the loop")
        self.assertEqual([struct.unpack_from("<Q", row, 0)[0] for row in rows], [5, 6, 8, 8])

    def test_leg_helper_clears_unset_tag(self):
        data = tool.leg_bytes("spot", 0x33, first=7)
        self.assertEqual(tool.leg_fields("spot", data)[0], (0, bytes(8)))


class Controls(Base):
    def test_flipped_mask_is_seen(self):
        at = bytes(self.image.blob[self.image.offset(0x26F4400):self.image.offset(0x26F4400) + 2242]).index(b"\xb9\xbe\x07\x00\x00")
        self.with_patch({0x26F4400 + at + 1: 0xBF})
        self.assertNotEqual(self.compare("spot first: codes 0 and 0"), "")

    def test_wrong_row_stride_is_seen(self):
        self.with_patch({0x26F4400 + 0x8D: 0x60})
        self.assertNotEqual(self.compare("spot first: one fill, flag"), "")

    def test_plain_case_still_passes(self):
        self.assertEqual(self.compare("spot first: one fill"), "")

    def test_corrupt_table_refused(self):
        image = tool.load_image()
        image.blob = bytearray(image.blob)
        at = image.offset(0x3F09BC)
        image.blob[at + 1] ^= 1
        with self.assertRaisesRegex(tool.EvidenceError, "table is not the mask"):
            tool.copy_rows(image)

    def test_corrupt_chain_refused(self):
        image = tool.load_image()
        image.blob = bytearray(image.blob)
        image.blob[image.offset(tool.OVERRIDE_TAIL + 1)] ^= 1
        with self.assertRaisesRegex(tool.EvidenceError, "override chain"):
            tool.override_rows(image)

    def test_writer_key_change_is_seen(self):
        self.with_patch({tool.TRADE_WRITER + 0x48: 0x90})
        self.assertNotEqual(self.compare("trade writer: all keys"), "")


class Keys(Base):
    def test_trade_keys(self):
        names = [row["key"] for row in self.static["keys"]["trade"]]
        self.assertEqual(names, ["coin", "side", "time", "px", "sz", "hash", "trade_dir_override", "side_info"])

    def test_side_info_keys(self):
        self.assertEqual({row["key"]: row["offset"] for row in self.static["keys"]["side_info"]}["oid"], "0x18")

    def test_fill_keys_in_order(self):
        names = [row["key"] for row in self.static["keys"]["fill"]]
        self.assertEqual(names[:6], ["coin", "px", "sz", "side", "time", "startPosition"])
        self.assertEqual(names[-1], "priorityGas")
        self.assertEqual(len(names), 22)

    def test_absent_gates_drop_seven_keys(self):
        found = self.harness.run(self.by_label["fill writer: gated keys absent"])
        self.assertEqual(len(found["keys"]), 15)

    def test_override_names(self):
        rows = self.static["trade_dir_override"]
        self.assertEqual([row["name"] for row in rows["first_byte"]], ["Na", "LiquidatedCross", "LiquidatedIsolated", "Settlement", "AutoDeleveraging", "NetChildVaultPositions", "LiquidatedMarket", "SpotDustConversion", "BoleBackstopLiquidation", "BolePartialLiquidation", "OutcomeUserAction"])
        self.assertEqual([row["name"] for row in rows["second_byte_of_variant_10"]], ["SplitOutcome", "MergeOutcome", "NegateOutcome", "MergeQuestion"])


class Sink(Base):
    def test_fills_win_over_trades(self):
        self.assertEqual(self.harness.run(self.by_label["sink: head 0, both on"])["path"], "fill")

    def test_trade_only_from_the_row_of_the_fill_side(self):
        self.assertEqual(self.harness.run(self.by_label["sink: trade side 1 of fill side 1"])["path"], "trade")
        self.assertEqual(self.harness.run(self.by_label["sink: trade side 1 of fill side 0"])["path"], "none")

    def test_fill_takes_the_leg_of_its_side(self):
        self.assertEqual(self.harness.run(self.by_label["sink: fill side 1 of fill side 0"])["twap"], [0x1110, 0x1118])

    def test_kind_5_and_6_are_dropped(self):
        self.assertEqual(self.harness.run(self.by_label["sink: head 5 goes to the drop"])["path"], "drop")
        self.assertEqual(self.harness.run(self.by_label["sink: head 6 goes to the drop"])["path"], "drop")

    def test_start_position_scale(self):
        found = self.harness.run(self.by_label["sink: token decimals 8"])
        self.assertAlmostEqual(found["side_info"][1][0], 0x2222 / 1e8, 12)


class Flush(Base):
    def test_log_order(self):
        found = self.harness.run(self.by_label["flush: fill row side 1, class set"])
        self.assertEqual([row[0] for row in found["log"]], ["class", "effect", "apply", "lookup", "after"])

    def test_zero_price_skips_apply_only(self):
        found = self.harness.run(self.by_label["flush: fill row side 0, price zero"])
        self.assertEqual([row[0] for row in found["log"]], ["class", "lookup", "after"])

    def test_apply_sees_price_before_coin(self):
        found = self.harness.run(self.by_label["flush: fill row side 0"])
        self.assertEqual(found["log"][1][2:], [0x7654, 2])

    def test_stop_word(self):
        found = self.harness.run(self.by_label["flush: stop word"])
        self.assertEqual(len(found["rows"]), 1)

    def test_tree_value_or_zero(self):
        row = self.harness.run(self.by_label["flush: fill row, no entry below"])["rows"][0]
        self.assertEqual(struct.unpack_from("<QQ", row, 0x228), (1, 0))
        row = self.harness.run(self.by_label["flush: fill row, second level"])["rows"][0]
        self.assertEqual(struct.unpack_from("<QQ", row, 0x228), (1, 0xB0))


class Sites(Base):
    def test_site_count(self):
        self.assertEqual(len(tool.site_rows(self.image)), 38)

    def test_known_fixed_codes(self):
        rows = {row[1]: row for row in tool.site_rows(self.image)}
        self.assertEqual(rows[0x4CF0ADB][5], "Settlement, Settlement")
        self.assertEqual(rows[0x4CDBD18][5], "NetChildVaultPositions, NetChildVaultPositions")
        self.assertEqual(rows[0x4CFF54F][5], "LiquidatedMarket, LiquidatedMarket")
        self.assertEqual(rows[0x4D10665][4], "0x30003")


class Files(Base):
    def test_output_is_ascii_and_has_no_absolute_paths(self):
        files = tool.render(self.static)
        for name, text in files.items():
            text.encode("ascii")
            self.assertNotIn("code_Mainnet", text, name)

    def test_stored_evidence_matches_static_rows(self):
        stored = json.loads((FOLDER / "evidence.json").read_text())
        self.assertEqual(stored["copies"], json.loads(json.dumps(self.static["copies"])))
        self.assertEqual(stored["keys"], json.loads(json.dumps(self.static["keys"])))

    def test_no_file_has_a_pending_reason(self):
        self.assertNotIn("pending", (FOLDER / "mutations.tsv").read_text())

    def test_every_survivor_has_a_reason(self):
        rows = (FOLDER / "mutations.tsv").read_text().splitlines()[1:]
        for row in rows:
            cells = row.split("\t")
            if cells[3] != "killed":
                self.assertTrue(cells[5], row)

    def test_manifest_matches(self):
        for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)

    def test_write_outputs(self):
        with tempfile.TemporaryDirectory() as folder:
            tool.write_outputs(folder, {"x.txt": "a\n"})
            self.assertEqual((pathlib.Path(folder) / "x.txt").read_text(), "a\n")


if __name__ == "__main__":
    unittest.main()
