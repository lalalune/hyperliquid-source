"""Tests for tools/cwithdraw_queue.py: real node #94 bytes with corruption controls."""

import copy
import hashlib
import importlib.util
import json
import pathlib
import struct
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FOLDER = ROOT / "research" / "work-items" / "RE-004-cwithdraw-queue-94"
spec_ = importlib.util.spec_from_file_location("cwithdraw_queue", ROOT / "tools" / "cwithdraw_queue.py")
tool = importlib.util.module_from_spec(spec_)
sys.modules["cwithdraw_queue"] = tool
spec_.loader.exec_module(tool)

IMAGE = None
HARNESS = None
RESULT = None
TOP = 0xFFFFFFFFFFFFFFFF


def setUpModule():
    global IMAGE, HARNESS, RESULT
    IMAGE = tool.load_image()
    HARNESS = tool.Harness(IMAGE)
    RESULT = tool.analyse(IMAGE)


def run(kind=tool.GATE, **fields):
    case = tool.Case("t", kind, **fields)
    got = HARNESS.run(case)
    assert got == tool.spec_run(case, HARNESS.before, HARNESS.where), case.__dict__
    return got


def status(got):
    return struct.unpack_from("<H", got[2], tool.OUT - tool.HEAP_BASE)[0]


def names(got):
    return [event[0] for event in got[1]]


def word(got, addr, size=8):
    return int.from_bytes(got[2][addr - tool.HEAP_BASE:addr - tool.HEAP_BASE + size], "little")


def corrupted(va, value):
    bad = copy.copy(IMAGE)
    data = bytearray(IMAGE.blob)
    data[IMAGE.offset(va)] = value
    bad.blob = bytes(data)
    bad.relative_map = None
    return bad


class Identity(unittest.TestCase):
    def test_digest_is_the_target(self):
        self.assertEqual(hashlib.sha256(IMAGE.blob).hexdigest(), tool.SHA256)

    def test_wrong_digest_fails(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_nobits_section_does_not_resolve(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.offset(IMAGE.named[".bss"]["address"])

    def test_fdes_are_exact(self):
        self.assertEqual(IMAGE.exact_fde(tool.GATE), (0x3993110, 0x39935C8))
        self.assertEqual(IMAGE.exact_fde(tool.QUEUE), (0x3C13000, 0x3C133FC))
        self.assertEqual(IMAGE.exact_fde(tool.TOTAL), (0x3C0F050, 0x3C0F34B))
        self.assertEqual(IMAGE.exact_fde(tool.ENTRY), (0x33BAC00, 0x33BAD4E))

    def test_mid_function_address_is_no_start(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.exact_fde(tool.GATE + 1)

    def test_tool_runs_no_other_program(self):
        text = (ROOT / "tools" / "cwithdraw_queue.py").read_text()
        self.assertNotIn("import subprocess", text)


class Lock(unittest.TestCase):
    def test_live_lock_refuses(self):
        self.assertEqual(status(run(lock=(20001, 0, 0))), tool.TAG_LOCKED)
        self.assertEqual(status(run(now=(20000, 100, 5), lock=(20000, 100, 6))), tool.TAG_LOCKED)

    def test_equal_time_passes(self):
        self.assertEqual(status(run(now=(20000, 100, 5), lock=(20000, 100, 5))), tool.TAG_OK)

    def test_date_is_signed_and_clock_words_unsigned(self):
        self.assertEqual(status(run(now=(-5, 1, 1), lock=(3, 0, 0))), tool.TAG_LOCKED)
        self.assertEqual(status(run(now=(3, 1, 1), lock=(-5, 0, 0))), tool.TAG_OK)
        self.assertEqual(status(run(now=(5, 0x80000000, 0), lock=(5, 0x80000001, 0))), tool.TAG_LOCKED)

    def test_zero_date_means_no_lock(self):
        self.assertEqual(status(run(now=(-5, 0, 0), lock=(0, 900, 9))), tool.TAG_OK)

    def test_lock_comes_before_the_amount_tests(self):
        self.assertEqual(status(run(lock=(20001, 0, 0), x=TOP, y=TOP)), tool.TAG_LOCKED)

    def test_ended_lock_is_cleared_even_when_the_amount_fails(self):
        case = tool.Case("t", tool.GATE, lock=(19000, 3, 4), x=9001)
        got = HARNESS.run(case)
        self.assertEqual(status(got), tool.TAG_FUNDS)
        at = HARNESS.where["user"] + 8
        self.assertEqual(word(got, at, 4), 0)
        self.assertEqual(word(got, at + 4, 8), 3 | 4 << 32)


class Amounts(unittest.TestCase):
    def test_undelegated_is_the_limit_with_no_stake(self):
        self.assertEqual(status(run(x=9000)), tool.TAG_OK)
        self.assertEqual(status(run(x=9001)), tool.TAG_FUNDS)

    def test_stake_widens_the_first_test_only(self):
        self.assertEqual(status(run(delegated=(5000,), x=2000, y=12000)), tool.TAG_OK)
        self.assertEqual(status(run(delegated=(5000,), x=2000, y=12001)), tool.TAG_FUNDS)
        self.assertEqual(status(run(delegated=(5000,), x=9001)), tool.TAG_FUNDS)

    def test_stake_row_with_no_user_state_cannot_pay(self):
        self.assertEqual(status(run(v0=None, delegated=(5000,), x=1)), tool.TAG_FUNDS)

    def test_pending_counts_against_both_tests(self):
        self.assertEqual(status(run(total=(1000, 1), x=8000)), tool.TAG_OK)
        self.assertEqual(status(run(total=(1000, 1), x=8001)), tool.TAG_FUNDS)

    def test_pending_above_total_clamps_to_zero(self):
        self.assertEqual(status(run(total=(9500, 1), x=1)), tool.TAG_FUNDS)

    def test_amount_and_extra_wrap(self):
        self.assertEqual(status(run(x=TOP, y=1, v0=TOP)), tool.TAG_FUNDS)

    def test_wrapped_stake_sum_counts_as_zero(self):
        self.assertEqual(status(run(delegated=(TOP, 2), x=9000)), tool.TAG_OK)
        self.assertEqual(status(run(delegated=(TOP, 2), x=9000, y=1)), tool.TAG_FUNDS)

    def test_wrapped_grand_total_leaves_no_room(self):
        self.assertEqual(status(run(delegated=(TOP,), v0=1, x=1)), tool.TAG_FUNDS)
        self.assertEqual(status(run(delegated=(TOP,), v0=1, x=0, total=(7, 1))), tool.TAG_FUNDS)

    def test_zero_amount_is_filed(self):
        self.assertEqual(status(run(x=0)), tool.TAG_OK)

    def test_stake_tree_of_height_two(self):
        self.assertEqual(status(run(delegated=tuple(range(1, 16)), d_tall=True, x=1000, y=8120)), tool.TAG_OK)
        self.assertEqual(status(run(delegated=tuple(range(1, 16)), d_tall=True, x=1000, y=8121)), tool.TAG_FUNDS)


class Queue(unittest.TestCase):
    def test_five_rows_then_refused(self):
        self.assertEqual(status(run(total=(1, 4), x=1)), tool.TAG_OK)
        self.assertEqual(status(run(total=(1, 5), x=1)), tool.TAG_MANY)

    def test_row_count_comes_before_funds(self):
        self.assertEqual(status(run(tool.QUEUE, total=(TOP, 5), x=1, v0=0)), tool.TAG_MANY)

    def test_direct_wrap_refuses(self):
        self.assertEqual(status(run(tool.QUEUE, total=(2, 1), x=TOP, v0=TOP)), tool.TAG_FUNDS)

    def test_total_and_count_rise(self):
        case = tool.Case("t", tool.GATE, total=(1000, 2), x=500)
        got = HARNESS.run(case)
        at = HARNESS.where["total"]
        self.assertEqual((word(got, at), word(got, at + 8)), (1500, 3))

    def test_first_row_for_a_user_starts_a_new_entry(self):
        got = run()
        self.assertEqual(names(got)[0], "total_insert")
        self.assertEqual((word(got, tool.NEW_TOTAL), word(got, tool.NEW_TOTAL + 8)), (1000, 1))

    def test_first_row_in_an_empty_map_builds_the_root(self):
        got = run(t_shape="none")
        self.assertEqual(word(got, tool.STATE + tool.S_TOTALS), tool.ROOT_NODE)
        self.assertEqual(word(got, tool.ROOT_NODE + 0x196, 2), 1)
        self.assertEqual((word(got, tool.ROOT_NODE), word(got, tool.ROOT_NODE + 8)), (1000, 1))

    def test_alloc_failure_panics(self):
        self.assertEqual(run(t_shape="none", alloc_fail=True)[:2], ("panic", "alloc"))

    def test_seconds_by_low_byte(self):
        for mode, seconds in ((0, 604800.0), (1, 300.0), (2, 300.0), (3, 604800.0), (0x102, 300.0), (0xFF, 604800.0)):
            event = next(event for event in run(mode=mode)[1] if event[0] == "time")
            self.assertEqual(struct.unpack("<d", event[2])[0], seconds)

    def test_row_holds_amount_then_user(self):
        got = run(rows=(1, 4), x=777)
        block = HARNESS.where["row_block"]
        self.assertEqual(word(got, block + 0x20), 777)
        at = block + 0x28 - tool.HEAP_BASE
        self.assertEqual(got[2][at:at + 20], tool.WHO)
        self.assertEqual(word(got, HARNESS.where["vec"] + 0x10), 2)

    def test_full_row_list_grows_first(self):
        got = run(rows=(4, 4), x=777)
        self.assertIn("grow", names(got))
        self.assertEqual(word(got, tool.NEW_ROWS + 0x80), 777)

    def test_same_unlock_time_shares_one_list(self):
        self.assertNotIn("queue_insert", names(run(rows=(2, 4))))
        self.assertIn("queue_insert", names(run()))

    def test_add_failure_row_is_not_reached(self):
        self.assertEqual(RESULT["unreached"][tool.QUEUE], [0x3C133F6, 0x3C133FA])


class Evidence(unittest.TestCase):
    def test_seconds_table(self):
        self.assertEqual([row[2] for row in RESULT["constants"]], [604800.0, 300.0])

    def test_field_keys(self):
        self.assertEqual([row[3] for row in RESULT["names"]], ["delegations", "user_states", "pending_withdrawals", "queue", "user_to_total_withdrawal", "delegated", "undelegated", "totalPendingWithdrawal", "nPendingWithdrawals"])

    def test_status_text(self):
        self.assertEqual({row[0]: row[2] for row in RESULT["statuses"]}["0x12e"], "Too many concurrent CStaking withdrawals")

    def test_mode_groups(self):
        self.assertEqual([row[:2] for row in RESULT["modes"]], [(300.0, 2), (604800.0, 254)])

    def test_gate_sites(self):
        self.assertEqual(RESULT["sites"], [("0x2758a41", "0x8f8", "0x8f2"), ("0x4d81ca2", "0x8f8", "0x8f2"), ("0x4d82051", "0x1378", "0x1372")])

    def test_bent_seconds_table_fails(self):
        with self.assertRaises(tool.EvidenceError):
            tool.constant_rows(corrupted(tool.SECONDS_TABLE + 6, 0x40))

    def test_bent_field_key_fails(self):
        with self.assertRaises(tool.EvidenceError):
            tool.name_rows(corrupted(0x3E052B, 0x41))

    def test_bent_summary_key_fails(self):
        with self.assertRaises(tool.EvidenceError):
            tool.name_rows(corrupted(0x42134A, 0x41))

    def test_bent_state_load_fails(self):
        with self.assertRaises(tool.EvidenceError):
            tool.site_rows(corrupted(0x27589EB + 3, 0))

    def test_bent_queue_call_fails(self):
        with self.assertRaises(tool.EvidenceError):
            tool.site_rows(corrupted(0x39935A2 + 1, 0))

    def test_edited_condition_is_seen(self):
        harness = tool.Harness(IMAGE, {0x3C1312D + 1: IMAGE.blob[IMAGE.offset(0x3C1312D + 1)] ^ 1})
        self.assertIsNotNone(tool.first_failure(harness, tool.named_cases()))

    def test_edited_seconds_index_is_seen(self):
        harness = tool.Harness(IMAGE, {0x3C131C9 + 2: 3})
        self.assertIsNotNone(tool.first_failure(harness, tool.named_cases()))

    def test_unedited_image_passes_with_the_mutant_limit(self):
        harness = tool.Harness(IMAGE)
        harness.machine.step_limit = tool.MUTANT_STEP_LIMIT
        self.assertIsNone(tool.first_failure(harness, tool.named_cases()))

    def test_every_survivor_has_a_reason(self):
        rows = RESULT["mutations"]
        survivors = [(row[0], row[1]) for row in rows if row[2] == "survived"]
        self.assertEqual(set(survivors), set(tool.EXPECTED_SURVIVORS))
        self.assertGreater(len(rows), 250)

    def test_packet_files_match_the_tool(self):
        files = tool.render(RESULT)
        for name, text in files.items():
            self.assertEqual((FOLDER / name).read_text(encoding="ascii"), text, name)

    def test_manifest(self):
        lines = (FOLDER / "MANIFEST.sha256").read_text().splitlines()
        listed = {line.split("  ")[1]: line.split("  ")[0] for line in lines}
        self.assertEqual(sorted(listed), sorted(p.name for p in FOLDER.iterdir() if p.name != "MANIFEST.sha256"))
        for name, digest in listed.items():
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_summary_counts(self):
        summary = json.loads((FOLDER / "evidence.json").read_text())
        self.assertEqual(summary["sha256"], tool.SHA256)
        self.assertEqual(summary["functions"]["gate"]["unreached_rows"], [])
        self.assertEqual(summary["mutations"]["survived"], len(tool.EXPECTED_SURVIVORS))


if __name__ == "__main__":
    unittest.main()
