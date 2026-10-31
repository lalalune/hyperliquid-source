"""Tests for tools/reserve_accumulator_vote.py: real node #94 bytes with corruption controls."""

import copy
import hashlib
import importlib.util
import json
import math
import pathlib
import struct
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FOLDER = ROOT / "research" / "work-items" / "RE-004-reserve-accumulator-vote-94"
spec_ = importlib.util.spec_from_file_location("reserve_accumulator_vote", ROOT / "tools" / "reserve_accumulator_vote.py")
tool = importlib.util.module_from_spec(spec_)
sys.modules["reserve_accumulator_vote"] = tool
spec_.loader.exec_module(tool)

IMAGE = None
HARNESS = None
CASE = tool.Case
TOP = tool.TOP
OK = tool.OK
ARM_CAP_IMMEDIATE = 0x23563AB
ARM_LENGTH_D = 0x23597BA
ARM_LENGTH_M = 0x23597F3
EDGE = 184467440737095600


def setUpModule():
    global IMAGE, HARNESS
    IMAGE = tool.load_image()
    HARNESS = tool.Harness(IMAGE)


def vote(**fields):
    case = CASE("t", **fields)
    got = HARNESS.run(case)
    assert tool.same(case, got, tool.spec_for(case)), (fields, got)
    return got


def rows_of(got):
    return dict(got["rows"])


def row_word(row, offset):
    return struct.unpack_from("<Q", row, offset)[0]


def row_float(row, offset):
    return struct.unpack_from("<d", row, offset)[0]


def killed(patch, case):
    harness = tool.Harness(IMAGE, patch)
    harness.machine.step_limit = tool.MUTANT_STEP_LIMIT
    return tool.first_failure(harness, [case]) is not None


def corrupted(va, value):
    bad = copy.copy(IMAGE)
    data = bytearray(IMAGE.blob)
    data[IMAGE.offset(va)] = value
    bad.blob = bytes(data)
    bad.relative_map = None
    return bad


class ClosedForms(unittest.TestCase):
    def test_amount_below_the_cut_scales(self):
        self.assertEqual(tool.stored_amount(1), 100)
        self.assertEqual(tool.stored_amount(tool.SCALE_CUT), tool.SCALE_CUT * 100)

    def test_amount_past_the_cut_does_not_scale(self):
        self.assertEqual(tool.stored_amount(tool.SCALE_CUT + 1), (tool.SCALE_CUT + 1) // 100 * 100)
        self.assertEqual(tool.stored_amount(EDGE - 1), EDGE - 100)

    def test_amount_past_the_edge_has_no_row(self):
        self.assertIsNone(tool.stored_amount(EDGE))

    def test_ladder_covers_u64_without_gaps(self):
        rows = tool.ladder_rows()
        self.assertEqual(int(rows[0][0], 16), 0)
        self.assertEqual(int(rows[-1][1], 16), TOP)
        for one, two in zip(rows, rows[1:]):
            self.assertEqual(int(one[1], 16) + 1, int(two[0], 16))

    def test_window_floor(self):
        self.assertEqual(tool.window_of(3.0), 10.0)
        self.assertEqual(tool.window_of(10.0), 10.0)
        self.assertEqual(tool.window_of(11.0), 11.0)
        self.assertTrue(math.isnan(tool.window_of(math.nan)))

    def test_float_text(self):
        self.assertEqual(tool.rust_float(1e16), "1e16")
        self.assertEqual(tool.rust_float(1e-5), "0.00001")
        self.assertEqual(tool.rust_float(1.5e-6), "1.5e-6")
        self.assertEqual(tool.rust_float(math.nan), "null")
        self.assertEqual(tool.rust_float(30.0), "30.0")


class Vote(unittest.TestCase):
    def test_each_copy_builds_one_row_per_spot(self):
        for index in range(3):
            got = vote(copy=index, spots=(5, 2, 8), o=7000000, d_value=12.5, m_value=99.0)
            self.assertEqual(got["status"], OK)
            self.assertEqual(sorted(rows_of(got)), [2, 5, 8])

    def test_row_words(self):
        row = rows_of(vote(spots=(5,), o=7000000, d_value=12.5, m_value=99.0))[5]
        self.assertEqual(row_word(row, 0), 0)
        self.assertEqual(row_word(row, 8), 0)
        self.assertEqual(row_float(row, 0x10), 12.5)
        self.assertEqual(row_word(row, 0x18), 0)
        self.assertEqual(struct.unpack_from("<I", row, 0x20)[0], 0)
        self.assertEqual(row_word(row, 0x30), 5)
        self.assertEqual(row_word(row, 0x38), 700000000)
        self.assertEqual(row_float(row, 0x40), 99.0)

    def test_old_rows_are_all_replaced(self):
        got = vote(spots=(70,), old=(70, 71, 72))
        self.assertEqual(sorted(rows_of(got)), [70])
        self.assertNotEqual(rows_of(got)[70][:8], bytes([tool.OLD_MARK]) * 8)

    def test_two_level_old_map_is_freed(self):
        got = vote(old=tuple(range(30, 50)))
        self.assertEqual(got["leftover"], ())

    def test_native_unset_keeps_the_map(self):
        got = vote(native=0, old=(4, 7))
        self.assertEqual(got["status"], tool.TAG_TEXT)
        self.assertEqual(got["text"], b"native token is not set")
        self.assertEqual(sorted(rows_of(got)), [4, 7])

    def test_native_index_panics_before_the_map_changes(self):
        self.assertIsNotNone(vote(native_index=2, tokens=2)["panic"])

    def test_amount_gate_runs_after_the_clear(self):
        got = vote(o=tool.CAP, old=(4, 7))
        self.assertEqual((got["status"], got["word1"]), (tool.TAG_NUMBER, tool.CAP))
        self.assertEqual(got["rows"], ())

    def test_amount_gate_with_no_spots(self):
        self.assertEqual(vote(o=tool.CAP, spots=())["status"], tool.TAG_NUMBER)

    def test_text_gates_run_after_the_clear(self):
        for fields in (dict(d=b"1" * 101), dict(m=b"1" * 101)):
            got = vote(old=(4,), **fields)
            self.assertEqual(got["status"], tool.TAG_LENGTH)
            self.assertEqual(got["rows"], ())

    def test_text_length_limit_is_100(self):
        self.assertEqual(vote(d=b"1" * 100, m=b"1" * 100)["status"], OK)

    def test_texts_are_not_read_with_no_spots(self):
        got = vote(spots=(), d=b"1" * 101, bad=0)
        self.assertEqual((got["status"], got["parses"]), (OK, ()))

    def test_texts_are_parsed_once_per_spot(self):
        self.assertEqual(vote(spots=(1, 2, 3))["parses"], (0, 1, 0, 1, 0, 1))

    def test_bad_text_passes_the_status_object_through(self):
        got = vote(bad=1, old=(4,))
        self.assertEqual(got["status"], tool.TAG_BAD_TEXT)
        self.assertEqual(got["out"], tool.object_bytes(tool.TAG_BAD_TEXT))
        self.assertEqual(got["rows"], ())

    def test_amount_past_the_edge_is_ok_with_an_empty_map(self):
        got = vote(o=EDGE, old=(4,), spots=(4, 5))
        self.assertEqual((got["status"], got["rows"]), (OK, ()))

    def test_edge_less_one_keeps_a_row(self):
        self.assertEqual(row_word(rows_of(vote(o=EDGE - 1, spots=(4,)))[4], 0x38), EDGE - 100)

    def test_repeated_spot_gives_one_row(self):
        self.assertEqual(sorted(rows_of(vote(spots=(5, 5, 2)))), [2, 5])

    def test_window_floor_in_the_row(self):
        self.assertEqual(row_float(rows_of(vote(spots=(1,), d_value=3.0))[1], 0x10), 10.0)

    def test_third_copy_uses_the_shifted_map(self):
        got = vote(copy=2, old=(4,), spots=(9,))
        self.assertTrue(got["state_same"])
        self.assertEqual(sorted(rows_of(got)), [9])

    def test_real_parser_end_to_end(self):
        got = HARNESS.run(CASE("t", kind="end", copy=1, spots=(5,), text=b'{"o":7000000,"d":"12.5","m":"99"}'))
        self.assertEqual(got["status"], OK)
        row = dict(got["rows"])[5]
        self.assertEqual((row_float(row, 0x10), row_word(row, 0x38), row_float(row, 0x40)), (12.5, 700000000, 99.0))

    def test_real_parser_refuses_a_word(self):
        got = HARNESS.run(CASE("t", kind="end", copy=0, spots=(5,), text=b'{"o":1,"d":"x","m":"1"}'))
        self.assertNotEqual(got["status"], OK)


class Wire(unittest.TestCase):
    def read(self, text, fn=0):
        return HARNESS.run(CASE("t", kind="read_vote", fn=tool.VOTE_READ[fn], text=text))["result"]

    def test_keys_in_any_order(self):
        self.assertEqual(self.read(b'{"m":"3","d":"2","o":1}'), ("vote", 1, b"2", b"3"))

    def test_array_form(self):
        self.assertEqual(self.read(b'[1,"2","3"]', 1), ("vote", 1, b"2", b"3"))

    def test_long_key_names_are_ignored(self):
        result = self.read(b'{"order_ntl":5,"o":1,"d":"2","m":"3"}')
        self.assertEqual(result, ("vote", 1, b"2", b"3"))

    def test_missing_field(self):
        self.assertEqual(self.read(b'{"o":1,"d":"2"}')[2], b"missing field `m`")

    def test_duplicate_field(self):
        self.assertEqual(self.read(b'{"o":1,"o":2}')[2], b"duplicate field `o`")

    def test_negative_amount(self):
        self.assertEqual(self.read(b'{"o":-1}')[2], b"invalid value: integer `-1`, expected u64")

    def test_table_keys_are_the_fixed_texts(self):
        self.assertEqual(set(tool.WIRE), set(tool.WIRE_TEXTS))
        self.assertEqual(set(tool.ROWS_READ), set(tool.ROW_TEXTS))
        self.assertEqual(set(tool.PAIRS_READ), set(tool.PAIR_TEXTS))


class Codec(unittest.TestCase):
    ROW = tool.Row(num=1.5, denom=2.5, decay=30.0, samples=5, spot=9, amount=1000000, max_px=0.25)

    def test_field_ids(self):
        for text, number in ((b"spot", 0), (b"order_ntl", 1), (b"max_px", 2), (b"ema", 3), (b"o", 4), (b"emb", 4)):
            for fn in tool.FIELD_ID:
                self.assertEqual(HARNESS.run(CASE("t", kind="field", fn=fn, text=text)), dict(tag=9, id=number))

    def test_array_bytes_literal(self):
        want = bytes.fromhex("9409ce000f4240cb3fd000000000000095cb3ff8000000000000cb4004000000000000cb403e000000000000c005")
        for fn in tool.RMP_GENERAL + tool.RMP_DIRECT:
            self.assertEqual(HARNESS.run(CASE("t", kind="rmp", fn=fn, row=self.ROW, keyed=0))["result"], want)

    def test_map_form_names_each_field(self):
        got = HARNESS.run(CASE("t", kind="rmp", fn=tool.RMP_DIRECT[0], row=self.ROW, keyed=1))["result"]
        self.assertEqual(got[0], 0x84)
        for name in (b"spot", b"order_ntl", b"max_px", b"ema", b"num", b"denom", b"decay_duration", b"last_sample_time", b"n_samples"):
            self.assertIn(name, got)

    def test_json_text_literal(self):
        got = HARNESS.run(CASE("t", kind="json", fn=tool.JSON_ROW[0], row=self.ROW))["result"]
        self.assertIn(b'"order_ntl": 1000000', got)
        self.assertIn(b'"last_sample_time": null', got)

    def test_json_round_trip(self):
        rows = (self.ROW, tool.ROWS[7], tool.ROWS[9])
        for row in rows:
            text = HARNESS.run(CASE("t", kind="json", fn=tool.JSON_ROW[1], row=row))["result"]
            got = HARNESS.run(CASE("t", kind="read_row", fn=tool.ROW_READ[0], text=text))["result"]
            self.assertEqual(got, ("row", tool.mask_read(row.bytes())))

    def test_map_is_a_list_of_pairs(self):
        got = HARNESS.run(CASE("t", kind="map_json", rows=((9, self.ROW),)))["result"]
        self.assertTrue(got.startswith(b"[\n  [\n    9,\n    {"))

    def test_pairs_read_back(self):
        text = HARNESS.run(CASE("t", kind="map_json", rows=((9, self.ROW), (12, self.ROW))))["result"]
        got = HARNESS.run(CASE("t", kind="read_pairs", fn=tool.PAIR_READ[1], text=text))["result"]
        self.assertEqual([key for key, _ in got[1]], [9, 12])

    def test_clear_frees_every_node(self):
        old = tuple((key, bytes(tool.ROW_SIZE)) for key in range(1, 21))
        got = HARNESS.run(CASE("t", kind="clear", old=old))
        self.assertEqual((got["root"], got["count"], got["live"]), (0, 0, 0))


class Controls(unittest.TestCase):
    def test_wrong_digest_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_wrong_pin_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.pin_rows(corrupted(0x2356394, 0x90))

    def test_wrong_text_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.text_rows(corrupted(0x3E181B, 0x41))

    def test_wrong_constant_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.float_rows(corrupted(0x20A8AE, 0x41))

    def test_missing_serde_text_refused(self):
        bad = copy.copy(IMAGE)
        bad.blob = IMAGE.blob.replace(b"struct ReserveAccumulator with 4 elements", b"struct ReserveAccumulator with 5 elements")
        with self.assertRaises(tool.EvidenceError):
            tool.serde_rows(bad)

    def test_address_outside_the_file_refused(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.offset(0x10)

    def test_nobits_section_has_no_file_bytes(self):
        bss = IMAGE.named[".bss"]
        with self.assertRaises(tool.EvidenceError):
            IMAGE.offset(bss["address"] + 8)

    def test_not_an_fde_start_refused(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.exact_fde(tool.CLEAR + 1)

    def test_amount_bound_edit_is_seen(self):
        case = CASE("t", o=tool.CAP)
        self.assertTrue(killed({ARM_CAP_IMMEDIATE: 0xCD}, case))

    def test_length_bound_edits_are_seen(self):
        self.assertTrue(killed({ARM_LENGTH_D: 0x66}, CASE("t", d=b"1" * 101)))
        self.assertTrue(killed({ARM_LENGTH_M: 0x66}, CASE("t", m=b"1" * 101)))

    def test_native_flag_edit_is_seen(self):
        self.assertTrue(killed({0x2356357 + 1: 0x85}, CASE("t", native=0)))

    def test_unedited_image_passes_the_same_cases(self):
        harness = tool.Harness(IMAGE)
        self.assertIsNone(tool.first_failure(harness, [CASE("t", o=tool.CAP), CASE("t", d=b"1" * 101), CASE("t", native=0)]))

    def test_wrong_rule_is_seen(self):
        case = CASE("t", o=100)
        got = HARNESS.run(case)
        want = tool.spec_for(case)
        want["rows"] = ()
        self.assertFalse(tool.same(case, got, want))

    def test_wrong_wire_table_is_seen(self):
        case = CASE("t", kind="read_vote", fn=tool.VOTE_READ[0], text=b'[1,"2","3"]', want=dict(result=("vote", 2, b"2", b"3")))
        self.assertFalse(tool.same(case, HARNESS.run(case), tool.spec_for(case)))

    def test_vector_list_is_fixed(self):
        one = [(case.o, case.spots) for case in tool.vector_cases(30)]
        two = [(case.o, case.spots) for case in tool.vector_cases(30)]
        self.assertEqual(one, two)


class Packet(unittest.TestCase):
    def test_folder_holds_exactly_the_generated_set(self):
        names = {path.name for path in FOLDER.iterdir()}
        self.assertEqual(names, {"README.md", "MANIFEST.sha256", "evidence.json", "function-rows.tsv", "arm-rows.tsv", "amount-ladder.tsv", "pins.tsv", "texts.tsv", "serde.tsv", "slots.tsv", "constants.tsv", "reference.tsv", "wire.tsv", "outcomes.tsv"})

    def test_manifest_matches(self):
        for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_small_evidence_is_regenerated_exactly(self):
        result = tool.analyse(IMAGE, mutate=False, vectors=800)
        files = tool.render(result)
        for name, text in files.items():
            if name in ("evidence.json", "mutations.tsv"):
                continue
            self.assertEqual((FOLDER / name).read_text(encoding="ascii"), text, name)

    def test_evidence_counts(self):
        data = json.loads((FOLDER / "evidence.json").read_text())
        self.assertEqual(data["sha256"], tool.SHA256)
        self.assertEqual(data["named_cases"], len(tool.base_cases()))

    def test_no_external_program(self):
        text = (ROOT / "tools" / "reserve_accumulator_vote.py").read_text()
        self.assertNotIn("subprocess", text)
        self.assertNotIn("os.system", text)


if __name__ == "__main__":
    unittest.main()
