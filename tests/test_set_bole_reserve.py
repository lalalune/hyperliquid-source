"""Tests for tools/set_bole_reserve.py: real node #94 bytes with corruption controls."""

import copy
import hashlib
import importlib.util
import json
import pathlib
import struct
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FOLDER = ROOT / "research" / "work-items" / "RE-004-set-bole-reserve-94"
spec_ = importlib.util.spec_from_file_location("set_bole_reserve", ROOT / "tools" / "set_bole_reserve.py")
tool = importlib.util.module_from_spec(spec_)
sys.modules["set_bole_reserve"] = tool
spec_.loader.exec_module(tool)

IMAGE = None
HARNESS = None
RESULT = None
FILES = None
OK = tool.OK
CAP = tool.CAP
TOP = tool.MASK[8]
CHECK_CAP_JUMP = 0x3740599
CHECK_USER_JUMP = 0x3740577
CHECK_TOKEN_JUMP = 0x3740415
CHECK_BRANCH = 0x3740401
APPLY_NEW_LTV = 0x3741aa1
APPLY_MIN_ONE = 0x3741cf9
APPLY_STATUS = 0x3741de7
APPLY_FALLBACK = 0x3741fdb
GATE_INDEX_SHIFT = 0x3734e2a
GATE_ROUND_TEST = 0x3734f04
GATE_ROOM_COMPARE = 0x37350a4


def setUpModule():
    global IMAGE, HARNESS, RESULT, FILES
    IMAGE = tool.load_image()
    HARNESS = tool.Harness(IMAGE)
    RESULT = tool.analyse(IMAGE, mutate=False, vectors=200)
    FILES = tool.render(RESULT)


def reserve(**fields):
    fields.setdefault("rows", ((2, tool.base_row()),))
    case = tool.Case("t", **fields)
    got = HARNESS.run(case)
    assert tool.same(case, got, tool.spec_for(case)), (fields, got["status"], got["warned"])
    return got


def word(number, value=0, **fields):
    case = tool.Case("t", kind="word", word=number, value=value, **fields)
    got = HARNESS.run(case)
    assert tool.same(case, got, tool.spec_for(case)), (number, value, got)
    return got


def gate(**fields):
    fields.setdefault("rec", tool.Row(**tool.SIDE_ROW))
    fields.setdefault("token", 3)
    case = tool.Case("t", kind="gate", **fields)
    got = HARNESS.run(case)
    assert tool.same(case, got, tool.spec_for(case)), (fields, got)
    return got


def killed(patch, case):
    harness = tool.Harness(IMAGE, patch)
    harness.machine.step_limit = tool.MUTANT_STEP_LIMIT
    return tool.first_failure(harness, [case]) is not None


def row_words(got):
    return {key: struct.unpack("<21Q", value[:0xA8]) for key, value in got["rows"]}


class WordTable(unittest.TestCase):
    def test_selector_entry_holds_the_arm_in_each_copy(self):
        self.assertEqual(tool.COPIES[0].arm(IMAGE), 0x23593DB)
        self.assertEqual(tool.sub_table(IMAGE, tool.COPIES[0]), 0x3DD340)

    def test_three_copies_have_three_tables(self):
        tables = {tool.sub_table(IMAGE, copy_) for copy_ in tool.COPIES}
        self.assertEqual(len(tables), 3)

    def test_table_rows_cover_sixteen_arms_per_copy(self):
        rows = tool.word_rows(IMAGE)
        self.assertEqual(len(rows), 48)
        self.assertEqual({row[3] for row in rows if row[2] == 1}, {"0,1"})

    def test_reserve_arm_entry(self):
        self.assertEqual(next(row[4] for row in tool.word_rows(IMAGE) if row[0] == "a" and row[2] == 1), "0x235c3ca")

    def test_serde_texts_are_in_the_image(self):
        self.assertEqual(len(tool.serde_rows(IMAGE)), len(tool.SERDE))

    def test_slot_targets(self):
        slots = {row[2]: row[1] for row in tool.slot_rows(IMAGE)}
        self.assertEqual(slots["reserve_apply"], "0x37417b0")
        self.assertEqual(slots["reserve_side_gate"], "0x3734e00")

    def test_a_missing_text_stops_the_tool(self):
        bad = copy.copy(IMAGE)
        bad.blob = bytes(IMAGE.blob).replace(tool.SERDE[0], b"x" * len(tool.SERDE[0]))
        with self.assertRaises(tool.EvidenceError):
            tool.serde_rows(bad)


class SimpleWords(unittest.TestCase):
    def test_flags_take_the_low_bit(self):
        for number, offset in tool.FLAGS.items():
            self.assertEqual(word(number, 3)["status"], OK)
            self.assertEqual(word(number, 2)["status"], OK)

    def test_flag_byte_is_the_named_one(self):
        got = word(2, 1)
        self.assertEqual(got["changes"][0][0], 0x5B0)
        self.assertEqual(struct.pack("<Q", got["changes"][0][1])[3], 1)

    def test_caps_stop_at_the_bound(self):
        for number, offset in tool.CAPS.items():
            self.assertEqual(word(number, CAP - 1)["changes"], ((offset, CAP - 1),))
            refused = word(number, CAP)
            self.assertEqual(refused["status"], tool.TAG_NUMBER)
            self.assertEqual(refused["word1"], CAP)
            self.assertEqual(refused["changes"], ())

    def test_word_8_refused_on_the_mainnet_byte(self):
        for index in range(3):
            self.assertEqual(word(8, chain=3, copy=index)["status"], tool.TAG_TESTNET)

    def test_rate_limit_writes_before_a_refusal_stay(self):
        values = [1, 21, 1, 22, 1, CAP, 1, 24, 25, 26, 27]
        case = tool.Case("t", kind="word", word=14, values=tuple(values))
        got = HARNESS.run(case)
        self.assertEqual(got["status"], tool.TAG_NUMBER)
        self.assertEqual(got["word1"], CAP)
        self.assertEqual(got["changes"], ((0x4F0, 21), (0x4F8, 25), (0x500, 22)))

    def test_rate_limit_absent_writes_nothing(self):
        case = tool.Case("t", kind="word", word=14, values=(0,) * 11)
        self.assertEqual(HARNESS.run(case)["changes"], ())


class ReserveArm(unittest.TestCase):
    def test_no_field_keeps_the_row(self):
        got = reserve()
        self.assertEqual(got["status"], OK)

    def test_token_gate_comes_first(self):
        got = reserve(token=8, l=b"9", bad_ltv=True)
        self.assertEqual((got["status"], got["word1"]), (tool.TAG_TOKEN, 8))

    def test_text_length_limit(self):
        self.assertEqual(reserve(l=b"0" * 100, l_value=5)["status"], OK)
        self.assertEqual(reserve(l=b"0" * 101)["status"], tool.TAG_LENGTH)

    def test_borrow_cap_refusal_payload_is_one(self):
        got = reserve(b=CAP)
        self.assertEqual((got["status"], got["word1"]), (tool.TAG_NUMBER, 1))

    def test_refusal_order(self):
        self.assertEqual(reserve(s=CAP, min_text=b"x", bad_min=True)["events"], ())
        self.assertEqual(reserve(y=tool.CURVE, bad_curve=True, s=CAP)["status"], tool.TAG_BAD_CURVE)

    def test_events_on_full_patch(self):
        got = reserve(l=b"7", l_value=5, y=tool.CURVE, min_text=b"0", min_value=0, max_text=b"9", max_value=2)
        self.assertEqual(got["events"], ("text", "ltv", "curve", "price", "price", "seed"))

    def test_refused_check_is_a_nested_ten(self):
        got = reserve(b=10, s=9)
        self.assertEqual((got["status"], got["nested"]), (tool.TAG_NESTED, 0xA))

    def test_patch_writes_named_words(self):
        got = reserve(s=2000, us=500)
        words = row_words(got)[2]
        self.assertEqual((words[13], words[14]), (2000, 500))

    def test_clear_ltv_keeps_the_old_word(self):
        got = reserve(token=0, l=b"0", rows=((0, tool.base_row()),))
        words = row_words(got)[0]
        self.assertEqual((words[0], words[1]), (0, tool.BASE_ROW["ltv"]))


class NewRow(unittest.TestCase):
    FULL = dict(b=0, s=100, ub=0, us=50, y=tool.CURVE, l=b"7", l_value=5, min_text=b"0", min_value=0, max_text=b"9", max_value=321, rows=())

    def test_new_row_words(self):
        got = reserve(**self.FULL)
        words = row_words(got)[2]
        self.assertEqual((words[0], words[1], words[2]), (1, 5, 0x2525))
        self.assertEqual((words[11], words[15]), (tool.ONE, tool.ONE))
        self.assertEqual((words[3], words[4], words[5], words[8], words[12]), (0, 0, 0, 0, 0))
        self.assertEqual(words[20], 0x6161616161616161)

    def test_one_field_missing_refuses(self):
        for name in ("b", "s", "ub", "us", "y", "l", "min_text", "max_text"):
            self.assertEqual(reserve(**dict(self.FULL, **{name: None}))["status"], tool.TAG_NESTED, name)

    def test_ltv_with_a_min_price_refuses(self):
        self.assertEqual(reserve(**dict(self.FULL, min_value=4))["status"], tool.TAG_NESTED)

    def test_full_leaf_splits(self):
        rows = tuple((key, tool.base_row(seed=key)) for key in range(10, 21))
        got = reserve(**dict(self.FULL, token=25, tokens=30, rows=rows))
        self.assertEqual([key for key, _ in got["rows"]], list(range(10, 21)) + [25])

    def test_new_row_without_ltv_keeps_the_tag_word(self):
        fields = dict(self.FULL, token=0, l=b"0", l_value=None, min_value=0, max_value=0, max_text=b"0", b=1, ub=1)
        words = row_words(reserve(**fields))[0]
        self.assertEqual((words[0], words[1]), (0, 1))


class Check(unittest.TestCase):
    def test_full_table_rows(self):
        self.assertEqual(len(RESULT["validity"]), 128)

    def test_valid_shapes(self):
        valid = [row[:7] for row in RESULT["validity"] if row[7] == "valid"]
        self.assertTrue(all((row[1] == 0 and row[2] and not row[3] and not row[4] and not row[5] and row[6]) or (row[0] and not row[2]) or (row[1] and not row[2] and row[5] and not row[6]) for row in valid))
        self.assertEqual(len(valid), 38)

    def test_warning_texts(self):
        texts = [row[1] for row in RESULT["texts"]]
        self.assertTrue(texts[0].startswith("invalid config"))
        self.assertTrue(texts[1].startswith("borrow_cap > supply_cap"))
        self.assertTrue(texts[2].startswith("user_borrow_cap > user_supply_cap"))

    def test_cap_equal_passes_and_past_warns(self):
        row = tool.base_row(ltv_tag=0, ltv=0, min_px=5, max_px=0)
        self.assertEqual(reserve(quote=(2,), b=9, s=9, rows=((2, row),))["warned"], ())
        self.assertEqual(reserve(quote=(2,), b=10, s=9, rows=((2, row),))["warned"], (("cap", 2, 10, 9),))


class SideGate(unittest.TestCase):
    def test_both_absent_passes(self):
        self.assertEqual(gate()["status"], tool.STATUS_OK)

    def test_keep_flag_turns_the_compare(self):
        rows = dict(old=((3, 7, 7),), new=((3, 8, 8),))
        self.assertEqual(gate(keep=0, **rows)["status"], tool.STATUS_OK)
        self.assertEqual(gate(keep=1, **rows)["status"], tool.STATUS_SHORT)

    def test_side_one_rounds_up(self):
        rec = tool.Row(**dict(tool.SIDE_ROW, borrow_index=tool.ONE // 3, supply_index=tool.ONE // 3))
        self.assertEqual(gate(side=1, new=((3, 1, 0),), rec=rec, keep=1)["status"], tool.STATUS_SHORT)
        self.assertEqual(gate(side=0, new=((3, 0, 1),), rec=rec, keep=1)["status"], tool.STATUS_OK)

    def test_room_edge(self):
        room = tool.spec_room(tool.Row(**tool.SIDE_ROW))[1]
        self.assertEqual(gate(amount=room)["status"], tool.STATUS_OK)
        self.assertEqual(gate(amount=room + 1)["status"], tool.STATUS_SHORT)

    def test_overflow_status(self):
        rec = tool.Row(**dict(tool.SIDE_ROW, supply_index=2 * tool.ONE))
        self.assertEqual(gate(old=((3, TOP, TOP),), rec=rec)["status"], tool.STATUS_OVERFLOW)

    def test_saturation_recorder_runs(self):
        rec = tool.Row(**dict(tool.SIDE_ROW, balance=TOP, borrowed=1, held=0, paid=0, supplied=0))
        self.assertEqual(gate(rec=rec)["saturated"], 1)


class Controls(unittest.TestCase):
    def test_hash_is_checked(self):
        path = ROOT / "work" / "does-not-exist"
        with self.assertRaises((tool.EvidenceError, OSError)):
            tool.load_image(path)
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(tool.BINARY, "0" * 64)

    def test_user_cap_jump(self):
        case = tool.Case("t", quote=(2,), ub=10, us=9, rows=((2, tool.base_row(ltv_tag=0, ltv=0, min_px=5, max_px=0)),))
        self.assertTrue(killed({CHECK_USER_JUMP: IMAGE.blob[IMAGE.offset(CHECK_USER_JUMP)] ^ 1}, case))

    def test_borrow_cap_jump(self):
        case = tool.Case("t", quote=(2,), b=10, s=9, rows=((2, tool.base_row(ltv_tag=0, ltv=0, min_px=5, max_px=0)),))
        self.assertTrue(killed({CHECK_CAP_JUMP: IMAGE.blob[IMAGE.offset(CHECK_CAP_JUMP)] ^ 1}, case))

    def test_token_zero_rule(self):
        case = tool.Case("t", token=0, rows=((0, tool.base_row(ltv_tag=0, ltv=0)),))
        self.assertTrue(killed({CHECK_TOKEN_JUMP: IMAGE.blob[IMAGE.offset(CHECK_TOKEN_JUMP)] ^ 1}, case))

    def test_success_status_byte(self):
        case = tool.Case("t", rows=((2, tool.base_row()),))
        self.assertTrue(killed({APPLY_STATUS: 0x12}, case))

    def test_gate_index_field(self):
        case = tool.Case("t", kind="gate", token=3, rec=tool.Row(**tool.SIDE_ROW), old=((3, 7, 7),), new=((3, 7, 8),), side=0, keep=1)
        self.assertTrue(killed({GATE_INDEX_SHIFT + 2: 4}, case))

    def test_unmodelled_spec_change_is_seen(self):
        case = tool.Case("t", kind="gate", token=3, rec=tool.Row(**tool.SIDE_ROW), amount=1)
        want = dict(tool.spec_for(case), status=tool.STATUS_SHORT)
        self.assertFalse(tool.same(case, HARNESS.run(case), want))


class Packet(unittest.TestCase):
    def test_folder_is_the_generated_set(self):
        names = sorted(path.name for path in FOLDER.iterdir())
        self.assertEqual(names, sorted(set(FILES) | {"README.md", "MANIFEST.sha256", "mutations.tsv"}))

    def test_generated_files_match(self):
        for name, text in FILES.items():
            if name in ("evidence.json", "outcomes.tsv"):
                continue
            self.assertEqual((FOLDER / name).read_text(encoding="ascii"), text, name)

    def test_outcomes_keep_every_named_case(self):
        self.assertEqual(len((FOLDER / "outcomes.tsv").read_text(encoding="ascii").splitlines()) - 1, len(RESULT["cases"]))

    def test_manifest(self):
        for line in (FOLDER / "MANIFEST.sha256").read_text(encoding="ascii").splitlines():
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_mutation_count_matches_summary(self):
        summary = json.loads((FOLDER / "evidence.json").read_text(encoding="ascii"))["mutations"]
        lines = (FOLDER / "mutations.tsv").read_text(encoding="ascii").splitlines()[1:]
        self.assertEqual(summary["total"], len(lines))
        self.assertEqual(summary["survived"], sum(1 for line in lines if line.split("\t")[2] == "survived"))

    def test_every_survivor_is_classified(self):
        lines = (FOLDER / "mutations.tsv").read_text(encoding="ascii").splitlines()[1:]
        self.assertFalse([line for line in lines if line.split("\t")[2] == "survived" and line.split("\t")[3] == tool.UNCLASSIFIED])


if __name__ == "__main__":
    unittest.main()
