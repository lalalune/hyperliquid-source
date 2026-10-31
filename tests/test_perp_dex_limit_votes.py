"""Tests for tools/perp_dex_limit_votes.py: real node #94 bytes with corruption controls."""

import copy
import hashlib
import importlib.util
import json
import pathlib
import struct
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FOLDER = ROOT / "research" / "work-items" / "RE-004-perp-dex-limit-votes-94"
spec_ = importlib.util.spec_from_file_location("perp_dex_limit_votes", ROOT / "tools" / "perp_dex_limit_votes.py")
tool = importlib.util.module_from_spec(spec_)
sys.modules["perp_dex_limit_votes"] = tool
spec_.loader.exec_module(tool)

IMAGE = None
HARNESS = None
CAP = tool.CAP
MILLION = tool.ONE_MILLION
FLOOR = tool.FLOOR_TRANSFER
MAIN = tool.TAG_MAIN


def setUpModule():
    global IMAGE, HARNESS
    IMAGE = tool.load_image()
    tool.RealCode.ALL = tool.collect_real(IMAGE)
    HARNESS = tool.Harness(IMAGE)


def run(**fields):
    case = tool.Case("t", **fields)
    before, got = HARNESS.run(case)
    want = tool.spec_run(case, before)
    assert tool.same(case, got, want), tool.diff_text(case, got, want)
    return got


def word(got):
    return struct.unpack_from("<H", got[1])[0]


def payload(got):
    return struct.unpack_from("<Q", got[1], 8)[0]


def row(got, index, field):
    return struct.unpack_from("<Q", got[2], tool.ROWS - tool.HEAP_BASE + index * tool.ROW_SIZE + tool.LIMITS_AT + field)[0]


def default(got, offset, chosen=0):
    return struct.unpack_from("<Q", got[2], tool.S - tool.HEAP_BASE + tool.COPIES[chosen].defaults + offset)[0]


def corrupted(va, value):
    bad = copy.copy(IMAGE)
    data = bytearray(IMAGE.blob)
    data[IMAGE.offset(va)] = value
    bad.blob = bytes(data)
    bad.relative_map = None
    return bad


def mutated(patch, case):
    harness = tool.Harness(IMAGE, patch)
    return tool.first_failure(harness, [case]) is not None


class Gates(unittest.TestCase):
    def test_total_cap_floor_is_one_million(self):
        for index in range(3):
            self.assertEqual(word(run(copy=index, word=tool.WORD_TOTAL, v=MILLION - 1)), tool.TAG_NUMBER)
            self.assertEqual(word(run(copy=index, word=tool.WORD_TOTAL, v=MILLION)), tool.OK)

    def test_numbers_at_the_cap_refuse_with_the_value(self):
        for chosen in (tool.WORD_TOTAL, tool.WORD_SZ, tool.WORD_USERS):
            got = run(word=chosen, v=CAP)
            self.assertEqual((word(got), payload(got)), (tool.TAG_NUMBER, CAP))
            self.assertEqual(word(run(word=chosen, v=CAP - 1)), tool.OK)

    def test_sz_and_user_caps_have_no_floor(self):
        self.assertEqual(word(run(word=tool.WORD_SZ, v=0, dex=b"ab")), tool.OK)
        self.assertEqual(word(run(word=tool.WORD_USERS, v=0, dex=b"ab")), tool.OK)

    def test_transfer_rule_off_chain_two(self):
        pass_pair = dict(word=tool.WORD_TRANSFER, chain=3, v=FLOOR, w=10 * FLOOR)
        self.assertEqual(word(run(**pass_pair)), tool.OK)
        self.assertEqual(word(run(word=tool.WORD_TRANSFER, chain=3, v=FLOOR - 1, w=10 * FLOOR)), tool.TAG_NUMBER)
        self.assertEqual(word(run(word=tool.WORD_TRANSFER, chain=3, v=FLOOR, w=10 * FLOOR - 1)), tool.TAG_NUMBER)
        self.assertEqual(word(run(word=tool.WORD_TRANSFER, chain=3, v=3 * FLOOR, w=15 * FLOOR)), tool.OK)
        self.assertEqual(word(run(word=tool.WORD_TRANSFER, chain=3, v=3 * FLOOR, w=15 * FLOOR - 1)), tool.TAG_NUMBER)

    def test_transfer_rule_on_chain_two(self):
        self.assertEqual(word(run(word=tool.WORD_TRANSFER, chain=2, v=0, w=0)), tool.OK)
        self.assertEqual(word(run(word=tool.WORD_TRANSFER, chain=2, v=7, w=14)), tool.OK)
        self.assertEqual(word(run(word=tool.WORD_TRANSFER, chain=2, v=7, w=13)), tool.TAG_NUMBER)

    def test_transfer_second_number_cap_reports_the_second(self):
        got = run(word=tool.WORD_TRANSFER, v=FLOOR, w=CAP)
        self.assertEqual((word(got), payload(got)), (tool.TAG_NUMBER, CAP))


class Writers(unittest.TestCase):
    def test_no_name_sets_default_and_raises_rows(self):
        for index, chosen in enumerate(tool.COPIES):
            got = run(copy=index, word=tool.WORD_TOTAL, v=0x5150000 - 8, tags=(MAIN, 0, 1), dex=None)
            self.assertEqual(default(got, 8, index), 0x5150000 - 8)
            self.assertEqual(row(got, 0, 8), tool.row_word(0, 8))
            self.assertEqual(row(got, 1, 8), 0x5150000 - 8)
            self.assertEqual(row(got, 2, 8), tool.row_word(2, 8))

    def test_no_name_never_lowers_a_row(self):
        got = run(word=tool.WORD_SZ, v=0, tags=(0, 1), dex=None)
        self.assertEqual(row(got, 1, 0x10), tool.row_word(1, 0x10))
        self.assertEqual(default(got, 0x10), 0)

    def test_named_can_lower_and_leaves_the_default(self):
        got = run(word=tool.WORD_SZ, v=5, dex=b"abc", hit=1, tags=(MAIN, 0))
        self.assertEqual(row(got, 1, 0x10), 5)
        self.assertEqual(default(got, 0x10), tool.default_word(0x10))

    def test_transfer_writes_two_words(self):
        got = run(word=tool.WORD_TRANSFER, v=FLOOR, w=10 * FLOOR, dex=b"abc", hit=1, tags=(MAIN, 0))
        self.assertEqual((row(got, 1, 0x18), row(got, 1, 0x20)), (FLOOR, 10 * FLOOR))

    def test_named_main_is_refused(self):
        got = run(word=tool.WORD_TOTAL, dex=b"abc", hit=0, tags=(MAIN, 0))
        self.assertEqual(word(got), tool.TAG_DEX)
        self.assertEqual(row(got, 0, 8), tool.row_word(0, 8))

    def test_lookup_error_comes_through_whole(self):
        got = run(word=tool.WORD_TOTAL, dex=b"abc", fail=True)
        self.assertEqual(got[1], tool.Harness.object_bytes(None, tool.TAG_LOOKUP))

    def test_name_length_edge(self):
        self.assertEqual(word(run(word=tool.WORD_TOTAL, dex=b"x" * 100)), tool.OK)
        got = run(word=tool.WORD_TOTAL, dex=b"x" * 101)
        self.assertEqual((word(got), payload(got)), (tool.TAG_LENGTH, 101))

    def test_copy_c_uses_the_shifted_layout(self):
        got = run(copy=2, word=tool.WORD_USERS, v=9, tags=(0,), dex=None)
        self.assertEqual(default(got, 0x28, 2), 9)
        self.assertEqual(tool.COPIES[2].defaults + 0x28, 0x43B0)


class Override(unittest.TestCase):
    def test_set_below_a_million_is_a_silent_no_op(self):
        got = run(word=tool.WORD_OVERRIDE, dex=b"BTC", v=MILLION - 1, tree=((3, 5),))
        self.assertEqual((word(got), got[3]), (tool.OK, ((3, 5),)))

    def test_set_and_replace(self):
        self.assertEqual(run(word=tool.WORD_OVERRIDE, dex=b"BTC", v=MILLION, tree=((3, 5),))[3], ((3, 5), (7, MILLION)))
        self.assertEqual(run(word=tool.WORD_OVERRIDE, dex=b"BTC", v=MILLION, asset=3, tree=((3, 5),))[3], ((3, MILLION),))

    def test_cap_is_checked_only_on_a_main_row(self):
        got = run(word=tool.WORD_OVERRIDE, dex=b"BTC", v=CAP)
        self.assertEqual((word(got), payload(got)), (tool.TAG_NUMBER, CAP))
        self.assertEqual(word(run(word=tool.WORD_OVERRIDE, dex=b"BTC", v=CAP, tags=(1, 0))), tool.OK)

    def test_none_clears(self):
        self.assertEqual(run(word=tool.WORD_OVERRIDE, dex=b"BTC", some=0, asset=3, tree=((3, 5), (9, 1)))[3], ((9, 1),))

    def test_none_on_a_missing_key_keeps_the_map(self):
        self.assertEqual(run(word=tool.WORD_OVERRIDE, dex=b"BTC", some=0, tree=((3, 5),))[3], ((3, 5),))

    def test_rebalance_on_clear(self):
        items = tuple((slot * 2 + 1, slot) for slot in range(12))
        got = run(word=tool.WORD_OVERRIDE, dex=b"BTC", some=0, asset=1, tree=items)
        self.assertEqual(got[3], items[1:])

    def test_split_on_insert(self):
        items = tuple((slot * 2 + 1, slot) for slot in range(11))
        got = run(word=tool.WORD_OVERRIDE, dex=b"BTC", v=MILLION, asset=4, tree=items)
        self.assertEqual(len(got[3]), 12)


class Bytes(unittest.TestCase):
    def test_serde_keys(self):
        rows = tool.key_rows(IMAGE)
        self.assertEqual({row_[6]: row_[5] for row_ in rows if row_[0] == "limits"}["total_oi_cap2"], "0x8")
        self.assertEqual({row_[6]: row_[5] for row_ in rows if row_[0] == "limits"}["max_n_users_with_positions"], "0x28")
        self.assertEqual({row_[6]: row_[5] for row_ in rows if row_[0] == "MainOrHip3"}["override_max_oi_per_second"], "0x28")

    def test_corrupt_key_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.key_rows(corrupted(0x3DFA9A, 0x58))

    def test_corrupt_field_row_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.key_rows(corrupted(0x233B040, 0x18))

    def test_serde_texts(self):
        self.assertEqual([row_[1] for row_ in tool.serde_rows(IMAGE)], [item.decode() for item in tool.SERDE])

    def test_corrupt_serde_text_is_refused(self):
        bad = copy.copy(IMAGE)
        bad.blob = bytes(IMAGE.blob).replace(tool.SERDE[0], b"X" * len(tool.SERDE[0]))
        with self.assertRaises(tool.EvidenceError):
            tool.serde_rows(bad)

    def test_tag_texts(self):
        self.assertEqual(dict(tool.text_rows(IMAGE)), {"%#x" % key: value for key, value in tool.TAG_TEXTS.items()})

    def test_wrong_tag_text_is_refused(self):
        saved = dict(tool.TAG_TEXTS)
        tool.TAG_TEXTS[tool.TAG_DEX] = "other"
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.text_rows(IMAGE)
        finally:
            tool.TAG_TEXTS.clear()
            tool.TAG_TEXTS.update(saved)

    def test_arm_table_lands_on_the_writers(self):
        rows = {(row_[0], row_[1]): int(row_[2], 16) for row_ in tool.arm_rows(IMAGE)}
        self.assertEqual(rows["a", tool.WORD_TRANSFER], 0x2358493)
        self.assertEqual(rows["b", tool.WORD_OVERRIDE], 0x4CAB1C1)
        self.assertEqual(rows["c", tool.WORD_USERS], 0x4CB3DA3)

    def test_writer_list_is_twelve_distinct_fdes(self):
        self.assertEqual(len(set(tool.WRITERS)), 12)
        for target in tool.WRITERS:
            self.assertEqual(IMAGE.exact_fde(target)[0], target)

    def test_address_outside_an_fde_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.exact_fde(tool.WRITERS[0] + 1)

    def test_bad_digest_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)


class Controls(unittest.TestCase):
    def test_unedited_case_passes_the_same_check(self):
        self.assertFalse(mutated({}, tool.Case("c", word=tool.WORD_TOTAL, dex=None)))

    def test_floor_edit_is_seen(self):
        self.assertTrue(mutated({0x2356C9C: 0x41}, tool.Case("c", word=tool.WORD_TOTAL, v=MILLION, dex=None)))

    def test_max_to_set_edit_is_seen(self):
        self.assertTrue(mutated({0x235F27C: 0x47}, tool.Case("c", word=tool.WORD_TOTAL, v=MILLION, tags=(0, 0), dex=None)))

    def test_main_row_skip_edit_is_seen(self):
        self.assertTrue(mutated({0x235EF98: 0x75}, tool.Case("c", word=tool.WORD_TRANSFER, v=FLOOR, w=10 * FLOOR, tags=(MAIN, 0), dex=None)))

    def test_ratio_edit_is_seen(self):
        self.assertTrue(mutated({0x23584E5: 0x03}, tool.Case("c", word=tool.WORD_TRANSFER, v=3 * FLOOR, w=15 * FLOOR, dex=None)))

    def test_chain_edit_is_seen(self):
        self.assertTrue(mutated({0x23584CB: 0x03}, tool.Case("c", word=tool.WORD_TRANSFER, chain=3, v=FLOOR - 1, w=10 * FLOOR, dex=None)))

    def test_a_bad_parent_link_is_refused(self):
        harness = tool.Harness(IMAGE)
        harness.fresh(tool.Case("c", word=tool.WORD_OVERRIDE, dex=b"x", tree=((3, 5),)))
        root = tool.ROWS + tool.OVERRIDE_AT
        at = harness.machine.memory.read(root, 8)
        harness.machine.memory.write(at, 8, 1)
        with self.assertRaises(tool.Halt):
            harness.walk(at, 0)

    def test_unreleased_name_fails_the_check(self):
        case = tool.Case("c", word=tool.WORD_TOTAL, dex=b"abc")
        before, got = tool.Harness(IMAGE).run(case)
        want = tool.spec_run(case, before)
        self.assertFalse(tool.same(case, got[:5] + ({tool.NAME: 3},), want))


class Evidence(unittest.TestCase):
    def test_summary_matches_the_run(self):
        data = json.loads((FOLDER / "evidence.json").read_text())
        self.assertEqual(data["sha256"], tool.SHA256)
        self.assertEqual(data["named_cases"], len(tool.base_cases()))
        mutants = data["mutations"]
        self.assertEqual(mutants["killed"] + mutants["survived"], mutants["total"])

    def test_every_survivor_has_a_reason(self):
        lines = (FOLDER / "mutations.tsv").read_text().splitlines()[1:]
        survivors = [line.split("\t") for line in lines if line.split("\t")[2] == "survived"]
        self.assertTrue(survivors)
        self.assertFalse([row_ for row_ in survivors if row_[3] == "UNEXPLAINED"])

    def test_function_rows_hold_the_real_bytes(self):
        lines = (FOLDER / "function-rows.tsv").read_text().splitlines()[1:]
        for line in lines[:300]:
            _, addr, size, data, _ = line.split("\t")
            at = IMAGE.offset(int(addr, 16))
            self.assertEqual(bytes(IMAGE.blob[at:at + int(size)]).hex(), data)

    def test_arm_rows_hold_the_real_bytes(self):
        for line in (FOLDER / "arm-rows.tsv").read_text().splitlines()[1:]:
            _, addr, size, data, _ = line.split("\t")
            at = IMAGE.offset(int(addr, 16))
            self.assertEqual(bytes(IMAGE.blob[at:at + int(size)]).hex(), data)

    def test_manifest(self):
        for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_folder_holds_only_the_generated_set(self):
        names = {path.name for path in FOLDER.iterdir()}
        self.assertEqual(names, {"README.md", "MANIFEST.sha256", "evidence.json", "function-rows.tsv", "arm-rows.tsv", "writers.tsv", "arms.tsv", "keys.tsv", "texts.tsv", "serde.tsv", "outcomes.tsv", "mutations.tsv"})

    def test_no_external_tool_is_called(self):
        text_ = (ROOT / "tools" / "perp_dex_limit_votes.py").read_text()
        self.assertNotIn("subprocess", text_)


if __name__ == "__main__":
    unittest.main()
