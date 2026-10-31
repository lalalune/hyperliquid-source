"""Tests for tools/gov_vote_weight.py: real node #94 bytes with corruption controls."""

import copy
import hashlib
import importlib.util
import json
import pathlib
import struct
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FOLDER = ROOT / "research" / "work-items" / "RE-004-gov-vote-weight-94"
spec_ = importlib.util.spec_from_file_location("gov_vote_weight", ROOT / "tools" / "gov_vote_weight.py")
tool = importlib.util.module_from_spec(spec_)
sys.modules["gov_vote_weight"] = tool
spec_.loader.exec_module(tool)

IMAGE = None
HARNESS = None
RESULT = None
TOP = 0xFFFFFFFFFFFFFFFF
LOCKED = (20000, 100, 6)
NOW = (20000, 100, 5)


def setUpModule():
    global IMAGE, HARNESS, RESULT
    IMAGE = tool.load_image()
    HARNESS = tool.Harness(IMAGE)
    RESULT = tool.analyse(IMAGE, mutate=False, vectors=100)


def run(kind=tool.VOTE, **fields):
    case = tool.Case("t", kind, **fields)
    got = HARNESS.run(case)
    assert got == tool.spec_run(case, HARNESS.before, HARNESS.where), case.__dict__
    return got


def status(got):
    return struct.unpack_from("<H", got[2], tool.OUT - tool.HEAP_BASE)[0]


def event(got, name):
    return next(row for row in got[1] if row[0] == name)


def names(got):
    return [row[0] for row in got[1]]


def weight(**fields):
    return event(run(**fields), "upsert")[3]


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


class Identity(unittest.TestCase):
    def test_digest_is_the_target(self):
        self.assertEqual(hashlib.sha256(IMAGE.blob).hexdigest(), tool.SHA256)

    def test_wrong_digest_fails(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_nobits_section_does_not_resolve(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.offset(IMAGE.named[".bss"]["address"])

    def test_function_extents_are_exact(self):
        for target, size in ((tool.VOTE, 926), (tool.RAISE, 898), (tool.PROPOSE, 1860), (tool.DRAIN, 1424)):
            start, end = IMAGE.exact_fde(target)
            self.assertEqual((start, end - start), (target, size))

    def test_address_inside_a_function_is_not_a_start(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.exact_fde(tool.VOTE + 1)


class VoteWeight(unittest.TestCase):
    def test_open_stake_is_stored_as_is(self):
        self.assertEqual(weight(s=5000), 5000)

    def test_running_lock_multiplies_by_four(self):
        self.assertEqual(weight(s=5000, lock=LOCKED), 20000)

    def test_last_value_that_fits(self):
        self.assertEqual(weight(s=(1 << 62) - 1, lock=LOCKED), TOP - 3)

    def test_two_to_sixty_two_keeps_the_plain_value(self):
        self.assertEqual(weight(s=1 << 62, lock=LOCKED), 1 << 62)
        self.assertEqual(weight(s=TOP, lock=LOCKED), TOP)

    def test_lock_equal_to_now_is_over_and_cleared(self):
        got = run(s=5000, lock=NOW)
        self.assertEqual(event(got, "upsert")[3], 5000)
        word = struct.unpack_from("<i", got[2], HARNESS.where["user"] + 8 - tool.HEAP_BASE)[0]
        self.assertEqual(word, 0)

    def test_running_lock_is_not_touched(self):
        got = run(s=5000, lock=LOCKED)
        word = struct.unpack_from("<i", got[2], HARNESS.where["user"] + 8 - tool.HEAP_BASE)[0]
        self.assertEqual(word, LOCKED[0])

    def test_date_word_zero_means_no_lock(self):
        self.assertEqual(weight(s=5000, lock=(0, 0xFFFFFFFF, 7)), 5000)

    def test_missing_user_row_is_plain(self):
        self.assertEqual(weight(s=5000, u_present=False), 5000)
        self.assertEqual(weight(s=5000, u_shape="none"), 5000)

    def test_choice_is_the_low_byte(self):
        self.assertEqual(event(run(choice=0xABCDEF02), "upsert")[4], 2)

    def test_upsert_goes_to_the_row_votes(self):
        got = run()
        self.assertEqual(event(got, "upsert")[1], HARNESS.where["proposal"] + 0x30)

    def test_pieces_cover_every_stake(self):
        rows = {row[0]: row for row in RESULT["pieces"]}
        self.assertEqual((rows["locked_times_four"][1], rows["locked_times_four"][2]), (1, (1 << 62) - 1))
        self.assertEqual((rows["locked_kept"][1], rows["locked_kept"][2]), (1 << 62, TOP))
        self.assertEqual(rows["refused"][3], "0x107")


class VoteOrder(unittest.TestCase):
    def test_missing_proposal(self):
        self.assertEqual(status(run(p_shape="none")), tool.TAG_MISSING)
        self.assertEqual(status(run(p_present=False)), tool.TAG_MISSING)

    def test_end_is_inclusive(self):
        self.assertEqual(status(run(end=NOW)), tool.TAG_OK)
        self.assertEqual(status(run(end=(20000, 100, 4))), tool.TAG_ENDED)

    def test_ended_comes_before_already_voted(self):
        self.assertEqual(status(run(voted=True, end=(19999, 0, 0))), tool.TAG_ENDED)

    def test_voted_comes_before_the_stake_read(self):
        got = run(voted=True, s=0)
        self.assertEqual(status(got), tool.TAG_VOTED)
        self.assertEqual(names(got), [])

    def test_zero_stake_writes_nothing(self):
        got = run(s=0, rows=((1, 1, 1),))
        self.assertEqual(status(got), tool.TAG_VOTE_STAKE)
        self.assertEqual(got[2], HARNESS.before[:tool.OUT - tool.HEAP_BASE] + struct.pack("<H", tool.TAG_VOTE_STAKE) + HARNESS.before[tool.OUT - tool.HEAP_BASE + 2:])


class LockupRaise(unittest.TestCase):
    def row(self, got, index):
        addr = HARNESS.where["rows"][index][0]
        return struct.unpack_from("<iII", got[2], addr + 8 - tool.HEAP_BASE)

    def test_lower_row_rises_to_the_end(self):
        got = run(rows=((1, 2, 3),), end=(20001, 7, 8))
        self.assertEqual(self.row(got, 0), (20001, 7, 8))

    def test_higher_row_stays(self):
        got = run(rows=((30000, 2, 3),), end=(20001, 7, 8))
        self.assertEqual(self.row(got, 0), (30000, 2, 3))

    def test_every_row_of_a_tall_tree(self):
        got = run(rows=tool.FIFTEEN, r_shape="tall", end=(20001, 100, 5))
        for index, stamp in enumerate(tool.FIFTEEN):
            self.assertEqual(self.row(got, index), max(stamp, (20001, 100, 5)))

    def test_other_users_keep_their_rows(self):
        lone = tool.pack_time((1, 1, 1))
        got = run(rows=((1, 2, 3),))
        self.assertEqual(got[2].count(lone), HARNESS.before.count(lone))

    def test_raise_control_sees_a_flipped_compare(self):
        self.assertTrue(mutated({0x3C0F687: IMAGE.blob[IMAGE.offset(0x3C0F687)] ^ 1}, tool.Case("c", tool.VOTE, rows=((30000, 2, 3),))))


class ProposeGates(unittest.TestCase):
    def ok(self, **fields):
        return run(tool.PROPOSE, **dict(dict(p_present=False, s=tool.MIN_STAKE), **fields))

    def test_title_bounds(self):
        self.assertEqual(status(run(tool.PROPOSE, title=0)), tool.TAG_TITLE)
        self.assertEqual(status(self.ok(title=1)), tool.TAG_OK)
        self.assertEqual(status(self.ok(title=50)), tool.TAG_OK)
        self.assertEqual(status(run(tool.PROPOSE, title=51)), tool.TAG_TITLE)

    def test_description_bounds(self):
        self.assertEqual(status(run(tool.PROPOSE, description=0)), tool.TAG_DESCRIPTION)
        self.assertEqual(status(self.ok(description=1000)), tool.TAG_OK)
        self.assertEqual(status(run(tool.PROPOSE, description=1001)), tool.TAG_DESCRIPTION)

    def test_stake_bound(self):
        self.assertEqual(status(run(tool.PROPOSE, s=tool.MIN_STAKE - 1)), tool.TAG_STAKE)
        self.assertEqual(status(self.ok()), tool.TAG_OK)

    def test_third_row_is_admitted_and_fourth_refused(self):
        self.assertEqual(status(self.ok(others=(1, 1))), tool.TAG_OK)
        self.assertEqual(status(self.ok(others=(1, 1, 1))), tool.TAG_LIMIT)

    def test_rows_of_others_do_not_count(self):
        self.assertEqual(status(self.ok(others=(0, 0, 0, 0, 0))), tool.TAG_OK)

    def test_refusal_frees_both_strings(self):
        got = run(tool.PROPOSE, title=51)
        self.assertEqual(got[1], (("free", tool.DESC_PTR, 20), ("free", tool.TITLE_PTR, 5)))

    def test_stored_record_fields(self):
        got = self.ok(base=2000, long=1, end=(30000, 1, 2), title=7)
        data = event(got, "insert")[3]
        self.assertEqual(struct.unpack_from("<Q", data, 0x48)[0], 200)
        self.assertEqual(struct.unpack_from("<3Q", data, 0x30), (0, 0, 0))
        self.assertEqual(data[0x5C:0x70], tool.WHO)
        self.assertEqual(data[0x70], 1)
        self.assertEqual(struct.unpack_from("<iII", data, 0x50), (30000, 1, 2))


class Seconds(unittest.TestCase):
    def seconds(self, mode, long):
        bits = event(run(tool.PROPOSE, p_present=False, s=tool.MIN_STAKE, mode=mode, long=long), "time")[2]
        return struct.unpack("<d", struct.pack("<Q", bits))[0]

    def test_four_values(self):
        self.assertEqual(self.seconds(3, 0), 86400.0)
        self.assertEqual(self.seconds(3, 1), 518400.0)
        self.assertEqual(self.seconds(1, 0), 120.0)
        self.assertEqual(self.seconds(2, 1), 300.0)

    def test_all_mode_bytes_grouped(self):
        self.assertEqual([row[2] for row in RESULT["seconds"]], [2, 254, 2, 254])

    def test_constants_read_from_bytes(self):
        rows = {row[0]: row[2] for row in RESULT["constants"]}
        self.assertEqual((rows["short_rate"], rows["long_rate"]), (0.05, 0.1))
        self.assertEqual(rows["proposal_limit_shown"], 3)

    def test_corrupt_constant_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.constant_rows(corrupted(tool.RATES, IMAGE.blob[IMAGE.offset(tool.RATES)] ^ 1))


class Quorum(unittest.TestCase):
    def stored(self, base, long):
        return tool.stored_quorum(HARNESS, base, long)

    def test_small_values_are_the_integer_floor(self):
        for base in (0, 1, 19, 20, 59, 60, 61, 1000, 999999):
            self.assertEqual(self.stored(base, 0), base // 20)
            self.assertEqual(self.stored(base, 1), base // 10)

    def test_first_bases(self):
        self.assertEqual(tool.first_above(0.05, 20), 6755399441055759)
        self.assertEqual(tool.first_above(0.1, 10), 6755399441055749)

    def test_first_base_is_one_above_and_its_neighbour_is_not(self):
        for long, rate, parts in ((0, 0.05, 20), (1, 0.1, 10)):
            first = tool.first_above(rate, parts)
            self.assertEqual(self.stored(first, long), first // parts + 1)
            self.assertEqual(self.stored(first - parts, long), (first - parts) // parts)

    def test_top_of_the_domain(self):
        self.assertEqual(self.stored(TOP, 1), 1844674407370955264)
        self.assertEqual(self.stored(TOP, 0), 922337203685477632)

    def test_rate_at_or_below_the_fraction_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.first_above(0.25, 4)

    def test_quorum_is_not_a_function_of_the_proposer(self):
        one = event(run(tool.PROPOSE, p_present=False, s=tool.MIN_STAKE, base=4000), "insert")[3]
        two = event(run(tool.PROPOSE, p_present=False, s=tool.MIN_STAKE * 9, base=4000), "insert")[3]
        self.assertEqual(one, two)


class Drain(unittest.TestCase):
    def removed(self, **fields):
        got = run(tool.DRAIN, now=NOW, **fields)
        return [row[1] for row in got[1] if row[0] == "remove"]

    def test_end_equal_to_now_goes(self):
        self.assertEqual(len(self.removed(ends=(NOW,))), 1)

    def test_later_end_stays(self):
        self.assertEqual(self.removed(ends=((20000, 100, 6),)), [])

    def test_vote_and_drain_share_the_equal_instant(self):
        self.assertEqual(status(run(end=NOW)), tool.TAG_OK)
        self.assertEqual(len(self.removed(ends=(NOW,))), 1)

    def test_key_order(self):
        keys = self.removed(ends=((19000, 0, 0),) * 9)
        self.assertEqual(keys, sorted(keys))
        self.assertEqual(len(keys), 9)

    def test_output_counts_rows(self):
        got = run(tool.DRAIN, now=NOW, ends=((19000, 0, 0), (21000, 0, 0), (19000, 0, 0)))
        self.assertEqual(struct.unpack_from("<Q", got[2], tool.OUT + 0x10 - tool.HEAP_BASE)[0], 2)

    def test_tall_tree(self):
        self.assertEqual(len(self.removed(p_shape="tall", ends=((19000, 0, 0),) * 15)), 15)


class Names(unittest.TestCase):
    def test_keys_and_offsets(self):
        rows = {row[2]: row[3] for row in RESULT["names"]}
        self.assertEqual(rows["quorum"], "0x48")
        self.assertEqual(rows["votes"], "0x30")
        self.assertEqual(rows["end"], "0x50")
        self.assertEqual(rows["proposer"], "0x5c")
        self.assertEqual(rows["proposals"], "0x198")

    def test_status_text(self):
        rows = {row[0]: row[2] for row in RESULT["statuses"]}
        self.assertIn("between 1 and 50", rows["0x100"])
        self.assertIn("between 1 and 1000", rows["0x101"])
        self.assertIn("lockup period after delegating or voting", rows["0xff"])
        self.assertIn("Limit is", rows["0x104"])

    def test_corrupt_key_is_refused(self):
        bad = corrupted(0x58B08B, 0x51)
        with self.assertRaises(tool.EvidenceError):
            tool.name_rows(bad)

    def test_corrupt_slot_is_refused(self):
        bad = corrupted(0x398D520, 0x90)
        self.assertEqual(tool.direct_to(bad, tool.UPSERT).count(0x398D520), 0)

    def test_status_arm_shape_is_checked(self):
        arm = tool.STATUS_TABLE + struct.unpack_from("<i", IMAGE.blob, IMAGE.offset(tool.STATUS_TABLE) + 4 * tool.TAG_STAKE)[0]
        at = bytes(IMAGE.blob[IMAGE.offset(arm):IMAGE.offset(arm) + 64]).find(b"\x48\x8d\x35")
        bad = corrupted(arm + at + 7, 0x90)
        with self.assertRaises(tool.EvidenceError):
            tool.status_rows(bad)


class Controls(unittest.TestCase):
    def test_shift_two_edit_is_seen(self):
        self.assertTrue(mutated({0x398D4FC: 0x03}, tool.Case("c", tool.VOTE, lock=LOCKED)))

    def test_side_bound_edit_is_seen(self):
        self.assertTrue(mutated({0x398D4F6: 0x3F}, tool.Case("c", tool.VOTE, lock=LOCKED, s=1 << 62)))

    def test_stake_bound_edit_is_seen(self):
        self.assertTrue(mutated({0x398D635: 0x9B}, tool.Case("c", tool.PROPOSE, s=tool.MIN_STAKE, p_present=False)))

    def test_rate_table_edit_is_seen(self):
        harness = tool.Harness(corrupted(tool.RATES + 6, 0xB9))
        self.assertIsNotNone(tool.first_failure(harness, [tool.Case("c", tool.PROPOSE, p_present=False, s=tool.MIN_STAKE, base=4000)]))

    def test_unedited_case_passes_the_same_check(self):
        self.assertIsNone(tool.first_failure(tool.Harness(IMAGE), [tool.Case("c", tool.VOTE, lock=LOCKED)]))

    def test_stub_refuses_a_wrong_compare_length(self):
        harness = tool.Harness(IMAGE, {0x398D1A0 + 0x7A: 0x15})
        self.assertIsNotNone(tool.first_failure(harness, [tool.Case("c", tool.VOTE)]))


class Evidence(unittest.TestCase):
    def test_summary_matches_the_run(self):
        data = json.loads((FOLDER / "evidence.json").read_text())
        self.assertEqual(data["sha256"], tool.SHA256)
        self.assertEqual(data["named_cases"], len(tool.named_cases()))
        mutants = data["mutations"]
        self.assertEqual(mutants["killed"] + mutants["survived"], mutants["total"])

    def test_every_survivor_has_a_reason(self):
        lines = (FOLDER / "mutations.tsv").read_text().splitlines()[1:]
        survivors = [line.split("\t") for line in lines if line.split("\t")[2] == "survived"]
        self.assertTrue(survivors)
        self.assertFalse([row for row in survivors if row[3] == "UNEXPLAINED"])

    def test_function_rows_hold_the_real_bytes(self):
        lines = (FOLDER / "function-rows.tsv").read_text().splitlines()[1:]
        for line in lines[:200]:
            _, addr, size, data, _ = line.split("\t")
            at = IMAGE.offset(int(addr, 16))
            self.assertEqual(bytes(IMAGE.blob[at:at + int(size)]).hex(), data)

    def test_manifest(self):
        for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_no_external_tool_is_called(self):
        text = (ROOT / "tools" / "gov_vote_weight.py").read_text()
        self.assertNotIn("subprocess", text)


if __name__ == "__main__":
    unittest.main()
