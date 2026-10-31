"""Tests for tools/staking_withdrawal_drain.py: real node #94 bytes with corruption controls."""

import hashlib
import importlib.util
import json
import pathlib
import sys
import unittest
import unittest.mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
FOLDER = ROOT / "research" / "work-items" / "staking-withdrawal-drain-94"
spec_ = importlib.util.spec_from_file_location("staking_withdrawal_drain", ROOT / "tools" / "staking_withdrawal_drain.py")
tool = importlib.util.module_from_spec(spec_)
sys.modules["staking_withdrawal_drain"] = tool
spec_.loader.exec_module(tool)

IMAGE = None
HARNESS = None
RESULT = None
NOW = tool.NOW


def setUpModule():
    global IMAGE, HARNESS, RESULT
    IMAGE = tool.load_image()
    HARNESS = tool.Harness(IMAGE)
    RESULT = tool.analyse(IMAGE, mutate=False, vectors=60)


def run(**fields):
    case = tool.Case("t", **fields)
    got = HARNESS.run(case)
    assert got == tool.spec_run(case), case.__dict__
    return got


def one(amount=100, pending=100, count=1, balance=100, key=None, **fields):
    base = dict(queue=(((key or tool.key_at(-1)), ((amount, 1),), 0),), totals=((1, pending, count),), users=((1, balance),))
    base.update(fields)
    return run(**base)


def events(got, kind):
    return [event for event in got[2] if event[0] == kind]


def changed(patch, **fields):
    harness = tool.Harness(IMAGE, patch)
    return tool.first_failure(harness, [tool.Case("t", **fields)]) is not None


class Identity(unittest.TestCase):
    def test_digest_is_the_target(self):
        self.assertEqual(hashlib.sha256(IMAGE.blob).hexdigest(), tool.SHA256)

    def test_wrong_digest_fails(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_address_outside_every_fde_fails(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.fde(0x10)

    def test_exact_bounds(self):
        self.assertEqual(IMAGE.exact_fde(tool.DRAIN), (0x26FDAF0, 0x26FDAF0 + 1067))
        self.assertEqual(IMAGE.exact_fde(tool.FILTER), (0x33082C0, 0x33082C0 + 468))

    def test_inside_address_is_not_an_entry(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.exact_fde(tool.DRAIN + 1)


class Gate(unittest.TestCase):
    def test_tag_other_than_one_does_nothing(self):
        for tag in (0, 2, 0x100000000):
            got = one(tag=tag)
            self.assertEqual(got[2], ())
            self.assertEqual(len(got[4][0]), 1)

    def test_high_word_of_tag_is_not_read(self):
        self.assertEqual(len(events(one(tag=0x100000001), "credit")), 1)

    def test_empty_queue_only_reads_name_and_handle(self):
        got = run()
        self.assertEqual([event[0] for event in got[2]], ["name", "handle"])


class TimeSplit(unittest.TestCase):
    def due(self, key, **fields):
        return len(events(one(key=key, **fields), "credit"))

    def test_key_equal_to_now_waits(self):
        self.assertEqual(self.due(NOW), 0)

    def test_one_nano_below_goes(self):
        self.assertEqual(self.due((NOW[0], NOW[1], NOW[2] - 1)), 1)

    def test_second_word_outranks_nanos(self):
        self.assertEqual(self.due((NOW[0], NOW[1] - 1, 0xFFFFFFFF)), 1)
        self.assertEqual(self.due((NOW[0], NOW[1] + 1, 0)), 0)

    def test_date_word_is_signed(self):
        self.assertEqual(self.due((0x80000000, 0, 0)), 1)
        self.assertEqual(self.due((0xC0000000, 0, 0)), 1)
        self.assertEqual(self.due((0x7FFFFFFF, 0, 0)), 0)

    def test_order_is_key_order_not_row_order(self):
        got = run(queue=(tool.row_at(-1, ((2, 1),)), tool.row_at(-5, ((1, 1),)), tool.row_at(-3, ((3, 1),))), totals=((1, 6, 3),), users=((1, 6),))
        self.assertEqual([event[3] for event in events(got, "credit")], [1, 3, 2])

    def test_every_cut_of_a_two_level_tree(self):
        for cut in (1, 12, 13, 24, 25, 35):
            got = run(**tool.many(36, cut))
            self.assertEqual(len(events(got, "credit")), cut)
            self.assertEqual(len(got[4][0]), 36 - cut)

    def test_three_level_tree(self):
        got = run(**tool.many(144, 40, lambda at: at % 5 + 1))
        self.assertEqual(len(got[4][0]), 104)

    def test_second_block_sees_the_kept_tree(self):
        got = run(now=tool.key_at(0), again=tool.key_at(5), queue=(tool.row_at(-1, ((7, 1),)), tool.row_at(3, ((8, 1),)), tool.row_at(9, ((9, 1),))), totals=((1, 24, 3),), users=((1, 24),))
        self.assertEqual([event[3] for event in events(got, "credit")], [7, 8])
        self.assertEqual(got[4][1], ((1, 9, 1),))


class Totals(unittest.TestCase):
    def test_amount_and_one_count_leave(self):
        self.assertEqual(one(pending=250, count=2)[4][1], ((1, 150, 1),))

    def test_last_count_removes_the_row_with_pending_left(self):
        self.assertEqual(one(pending=250, count=1)[4][1], ())

    def test_short_pending_saturates_with_one_recorder_hit(self):
        got = one(pending=40, count=2)
        self.assertEqual(got[3], ("sub",))
        self.assertEqual(got[4][1], ((1, 0, 1),))

    def test_absent_row_is_inserted_and_removed(self):
        got = one(totals=())
        self.assertEqual(got[3], ("sub",))
        self.assertEqual(got[4][1], ())

    def test_zero_amount_gives_no_recorder_hit(self):
        self.assertEqual(one(amount=0, pending=0, totals=())[3], ())

    def test_count_zero_stays_zero_and_removes(self):
        self.assertEqual(one(pending=500, count=0)[4][1], ())


class Filter(unittest.TestCase):
    def test_exact_balance_is_paid(self):
        got = one(balance=100)
        self.assertEqual(got[4][2], ((1, 0),))
        self.assertEqual(len(events(got, "credit")), 1)

    def test_short_balance_pays_nothing_but_pending_falls(self):
        got = one(balance=99, pending=250, count=2)
        self.assertEqual(got[4][2], ((1, 99),))
        self.assertEqual(got[4][1], ((1, 150, 1),))
        self.assertEqual(events(got, "credit"), [])
        self.assertEqual(events(got, "sink"), [])

    def test_absent_user_pays_nothing_and_leaves_no_row(self):
        got = one(users=())
        self.assertEqual(got[4][2], ())
        self.assertEqual(events(got, "credit"), [])

    def test_balance_falls_between_rows(self):
        got = run(queue=(tool.row_at(-2, ((70, 1),)), tool.row_at(-1, ((50, 1),))), totals=((1, 120, 2),), users=((1, 100),))
        self.assertEqual([event[3] for event in events(got, "credit")], [70])
        self.assertEqual(got[4][2], ((1, 30),))

    def test_dropped_big_row_lets_a_later_small_row_pay(self):
        got = run(queue=(tool.row_at(-2, ((150, 1),)), tool.row_at(-1, ((50, 1),))), totals=((1, 200, 2),), users=((1, 100),))
        self.assertEqual([event[3] for event in events(got, "credit")], [50])


class Ledger(unittest.TestCase):
    def test_credit_then_sink_per_row(self):
        got = run(queue=(tool.row_at(-1, ((7, 1), (8, 2))),), totals=((1, 7, 1), (2, 8, 1)), users=((1, 7), (2, 8)))
        self.assertEqual([event[0] for event in got[2]], ["name", "handle", "credit", "sink", "credit", "sink"])

    def test_amount_over_power_of_ten(self):
        got = one(amount=123456789, pending=123456789, balance=123456789, decimals=8)
        self.assertEqual(events(got, "sink")[0][3], tool.to_bits(1.23456789))

    def test_float_rounds_above_53_bits(self):
        amount = (1 << 53) + 1
        got = one(amount=amount, pending=amount, balance=amount, decimals=0)
        self.assertEqual(events(got, "sink")[0][3], tool.to_bits(float(1 << 53)))

    def test_token_past_table_panics_after_the_credit(self):
        got = one(token=200)
        self.assertEqual(got[:2], ("panic", "unwrap"))
        self.assertEqual(len(events(got, "credit")), 1)

    def test_token_past_table_without_a_kept_row_does_not_panic(self):
        self.assertEqual(one(token=200, users=())[0], "done")

    def test_sink_time_is_the_block_time(self):
        self.assertEqual(events(one(), "sink")[0][4], NOW)

    def test_allocation_failures_end_the_run(self):
        self.assertEqual(one(fail=0x14)[:2], ("panic", "alloc"))
        self.assertEqual(one(fail=4)[:2], ("panic", "alloc"))


class Copies(unittest.TestCase):
    def test_second_copy_has_equal_rows(self):
        self.assertEqual(RESULT["copies"][0][3:5], (223, 223))

    def test_third_copy_adds_one_event(self):
        got = one(copy=2, extra_byte=9)
        self.assertEqual(events(got, "extra"), [("extra", 100, 150, 1, 9)])
        self.assertEqual(events(one(copy=1), "extra"), [])

    def test_third_copy_shifts_the_fields(self):
        self.assertEqual((tool.COPIES[2].queue - tool.COPIES[0].queue, tool.COPIES[2].users - tool.COPIES[0].users), (0xA80, 0xA80))

    def test_only_the_third_copy_differs_in_calls(self):
        self.assertEqual(RESULT["copies"][0][5], "none")
        self.assertIn("0x5776ad0", RESULT["copies"][1][5])

    def test_three_steps_have_one_call_each(self):
        self.assertEqual([tool.direct_to(IMAGE, row[0]) for row in tool.STEP_HOSTS], [[row[1]] for row in tool.STEP_HOSTS])


class KindByte(unittest.TestCase):
    def test_drain_sites_store_zero_and_deposit_sites_one(self):
        rows = {row[1]: row[2] for row in RESULT["kinds"]}
        self.assertEqual(rows, {"0x26fdaf0": 0, "0x4ce6090": 0, "0x4ce5be0": 0, "0x2734840": 1, "0x4d40eb0": 1, "0x4d44e60": 1})


class Controls(unittest.TestCase):
    def fields(self):
        return dict(queue=(tool.row_at(-2, ((70, 1),)), tool.row_at(-1, ((50, 2),)), tool.row_at(1, ((5, 1),))), totals=((1, 75, 2), (2, 50, 1)), users=((1, 80), (2, 50)))

    def test_clean_image_matches(self):
        self.assertFalse(changed({}, **self.fields()))

    def test_gate_immediate(self):
        self.assertTrue(changed({0x26FDB07: 0}, **self.fields()))

    def test_queue_offset(self):
        self.assertTrue(changed({0x26FDB70: 0x10}, **self.fields()))

    def test_user_offset(self):
        self.assertTrue(changed({0x26FDBA1: 0xF8}, **self.fields()))

    def test_filter_subtract_edge(self):
        self.assertTrue(changed({0x3308439: 0x83}, **self.fields()))

    def test_count_rule_condition(self):
        self.assertTrue(changed({0x3BABF05: 0x73}, **self.fields()))

    def test_time_split_condition(self):
        self.assertTrue(changed({0x2FB2E32: 0x73}, queue=(tool.row_at(0, ((1, 1),)),), now=NOW))

    def test_rule_list_catches_a_wrong_rule(self):
        case = tool.Case("t", **self.fields())
        got = HARNESS.run(case)
        with unittest.mock.patch.object(tool, "time_order", lambda key: (key[0], key[1], -key[2])):
            self.assertNotEqual(got, tool.spec_run(case))

    def test_corrupt_user_tail_halts(self):
        case = tool.Case("t", **self.fields())
        HARNESS.fresh(case)
        HARNESS.word(tool.EX + tool.COPIES[0].users + 0x18, 0)
        root = HARNESS.read(tool.EX + tool.COPIES[0].users)
        HARNESS.word(root + tool.USER_MAP.val_at + 8, 0)
        with self.assertRaises(tool.Halt):
            HARNESS.state()

    def test_address_bytes_are_checked(self):
        with self.assertRaises(tool.Halt):
            tool.address_index(bytes(20))

    def test_unknown_case_field_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.Case("t", nothing=1)

    def test_bent_immediate_is_refused(self):
        bent = (("gate_tag", 0x26FDB01, "83bf8000000002", "bent"),)
        with unittest.mock.patch.object(tool, "IMMEDIATES", bent):
            with self.assertRaises(tool.EvidenceError):
                tool.constant_rows(IMAGE)

    def test_bent_field_is_refused(self):
        bent = (("user_states", 0x3DF9E4, 11, 0x200, 0x238D653, "lea"),)
        with unittest.mock.patch.object(tool, "FIELDS", bent):
            with self.assertRaises(tool.EvidenceError):
                tool.field_rows(IMAGE)

    def test_bent_step_site_is_refused(self):
        with unittest.mock.patch.object(tool, "STEP_HOSTS", ((tool.DRAIN, 0x222A12F, 0x22297C0),)):
            with self.assertRaises(tool.EvidenceError):
                tool.caller_rows(IMAGE)

    def test_bent_slot_is_refused(self):
        with unittest.mock.patch.object(tool, "SLOT_NAME", tool.SLOT_HANDLE):
            with self.assertRaises(tool.EvidenceError):
                tool.caller_rows(IMAGE)


class Evidence(unittest.TestCase):
    def test_outcomes_cover_every_case(self):
        names = [line.split("\t")[0] for line in (FOLDER / "outcomes.tsv").read_text().splitlines()[1:]]
        self.assertEqual(names, [case.name for case in tool.named_cases()])

    def test_regenerated_tables_match_files(self):
        fresh = tool.render(RESULT)
        for name in ("function-rows.tsv", "callers.tsv", "constants.tsv", "field-names.tsv", "kind-sites.tsv", "copy-compare.tsv", "outcomes.tsv"):
            self.assertEqual((FOLDER / name).read_text(), fresh[name], name)

    def test_manifest_covers_every_file(self):
        rows = dict(reversed(line.split("  ")) for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines())
        names = sorted(path.name for path in FOLDER.iterdir() if path.name != "MANIFEST.sha256")
        self.assertEqual(sorted(rows), names)
        for name, digest in rows.items():
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)

    def test_mutation_counts_agree(self):
        data = json.loads((FOLDER / "evidence.json").read_text())
        lines = (FOLDER / "mutations.tsv").read_text().splitlines()[1:]
        self.assertEqual(data["mutations"]["total"], len(lines))
        self.assertEqual(data["mutations"]["survived"], sum(1 for line in lines if line.split("\t")[2] == "survived"))

    def test_no_absolute_paths_in_output(self):
        for path in FOLDER.iterdir():
            text = path.read_bytes()
            for word in (b"\x2ftmp", b"\x2fhome", b"\x2fsrv", b"\x2fmnt"):
                self.assertNotIn(word, text, path.name)


if __name__ == "__main__":
    unittest.main()
