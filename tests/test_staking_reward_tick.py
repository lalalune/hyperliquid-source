"""Tests for tools/staking_reward_tick.py: real node #94 bytes with corruption controls."""

import hashlib
import importlib.util
import json
import math
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FOLDER = ROOT / "research" / "work-items" / "staking-reward-tick-94"
spec_ = importlib.util.spec_from_file_location("staking_reward_tick", ROOT / "tools" / "staking_reward_tick.py")
tool = importlib.util.module_from_spec(spec_)
sys.modules["staking_reward_tick"] = tool
spec_.loader.exec_module(tool)

IMAGE = None
HARNESS = None
RESULT = None
H = 3600000
BIG = 1 << 40
ONLY_STAGE = dict(dist=(H, BIG), decay=(H, BIG))
ONLY_DIST = dict(stage=(H, BIG), decay=(H, BIG))
ONLY_DECAY = dict(stage=(H, BIG), dist=(H, BIG))
IDLE = dict(stage=(H, BIG), dist=(H, BIG), decay=(H, BIG))
THREE = ((1, 400, 410), (2, 200, 200), (3, 100, 90))
LATER = tool.Case.FIELDS["now"][0] + (2 << 4)


def setUpModule():
    global IMAGE, HARNESS, RESULT
    IMAGE = tool.load_image()
    HARNESS = tool.Harness(IMAGE)
    RESULT = tool.analyse(IMAGE, mutate=False, vectors=60)


def run(**fields):
    case = tool.Case("t", **fields)
    got = HARNESS.run(case)
    assert got == tool.spec_run(case, HARNESS.frozen_digest), case.__dict__
    return got


def stage(got):
    return got[1]


def sink(got):
    return got[2]


def state(got):
    return got[5]


def users(got):
    return {row[0]: row[1:] for row in state(got)[3]}


def changed(patch, **fields):
    harness = tool.Harness(IMAGE, patch)
    return tool.first_failure(harness, [tool.Case("t", **fields)]) is not None


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
        sizes = ((tool.HOST, 1543), (tool.STAGE, 2454), (tool.TOTAL, 560), (tool.CLOSURE, 2301), (tool.DIST, 6899), (tool.DECAY, 1265), (tool.DECAY_CORE, 784), (tool.SNAP, 223), (tool.JAIL_SNAP, 498), (tool.EPOCH_KEY, 246), (tool.STAKES_AT, 241))
        for target, size in sizes:
            start, end = IMAGE.exact_fde(target)
            self.assertEqual((start, end - start), (target, size))

    def test_address_inside_a_function_is_not_a_start(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.exact_fde(tool.HOST + 1)

    def test_host_has_three_call_sites_through_one_slot(self):
        self.assertEqual(IMAGE.relative()[tool.SLOT_HOST], tool.HOST)
        self.assertEqual(sorted(tool.slot_sites(IMAGE, tool.SLOT_HOST)), [0x220A5EE, 0x446E882, 0x446F202])

    def test_field_names_bind_offsets(self):
        table = {row[0]: row[2] for row in RESULT["fields"]}
        self.assertEqual(table["validator_to_staged_rewards"], "0x1e0")
        self.assertEqual(table["stage_reward_bucket_guard"], "0x100")
        self.assertEqual(table["distribute_reward_bucket_guard"], "0x110")
        self.assertEqual(table["native_token_reserve"], "0x60")

    def test_labels_are_in_rodata(self):
        texts = [row[3] for row in RESULT["constants"] if row[0] == "label_text"]
        self.assertEqual(texts, ["c_staking_stage_reward", "c_staking_distribute_staged_rewards", "jail vote tracker", "decay_staking"])

    def test_wrong_constant_fails(self):
        saved = tool.CONSTANTS
        tool.CONSTANTS = (("x", 0x20AB88, b"\x00" * 8, ""),)
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.constant_rows(IMAGE)
        finally:
            tool.CONSTANTS = saved

    def test_wrong_field_offset_fails(self):
        saved = tool.FIELDS
        tool.FIELDS = (("stakes", 0x3E04DF, 6, 0x18, 0x3C12174, "mov"),)
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.field_rows(IMAGE)
        finally:
            tool.FIELDS = saved


class Buckets(unittest.TestCase):
    def bucket(self):
        return tool.Spec(tool.Case("b")).millis() // H

    def test_equal_bucket_does_not_fire(self):
        got = run(stage=(H, self.bucket()), dist=(H, BIG), decay=(H, BIG))
        self.assertIsNone(stage(got))
        self.assertEqual(state(got)[0][0], self.bucket())

    def test_next_bucket_fires_and_stores(self):
        got = run(stage=(H, self.bucket() - 1), dist=(H, BIG), decay=(H, BIG))
        self.assertIsNotNone(stage(got))
        self.assertEqual(state(got)[0][0], self.bucket())

    def test_old_last_is_kept_when_higher(self):
        self.assertEqual(state(run(**IDLE))[0], (BIG, BIG, BIG))

    def test_negative_time_clamps_to_bucket_zero(self):
        got = run(now=(tool.date_word(-1, 200), 5, 0), **{k: (H, 0) for k in ("stage", "dist", "decay")})
        self.assertIsNone(stage(got))
        self.assertEqual(state(got)[0], (0, 0, 0))


class Rate(unittest.TestCase):
    def amount(self, weight, supply, stake, width=H):
        got = run(hist=((9000, ((1, stake, weight),)),), b=supply, stage=(width, 0), reserve=(1, 1 << 62), **{k: v for k, v in ONLY_STAGE.items()})
        return stage(got)[0][1]

    def expected(self, fraction, stake, seconds_value=3600.0):
        q = 0.015 / max(math.sqrt(fraction), 0.015)
        return int(stake * ((q * q * -0.5 + q) / (31557600.0 / seconds_value)))

    def test_all_supply_staked(self):
        self.assertEqual(self.amount(1000, 1000, 10 ** 15), self.expected(1.0, 10 ** 15))

    def test_four_tenths_staked(self):
        self.assertEqual(self.amount(400, 1000, 10 ** 15), self.expected(0.4, 10 ** 15))

    def test_q_is_one_at_the_floor(self):
        got = self.amount(1, 10 ** 12, 10 ** 15)
        self.assertEqual(got, int(10 ** 15 * (0.5 / (31557600.0 / 3600.0))))

    def test_weight_is_word_one_and_stake_is_word_zero(self):
        self.assertNotEqual(self.amount(400, 1000, 10 ** 15), self.amount(10 ** 15, 1000, 400))

    def test_period_scales_rate(self):
        self.assertEqual(self.amount(400, 1000, 10 ** 15, 86400000), self.expected(0.4, 10 ** 15, 86400.0))

    def test_a_zero_pays_zero_rows(self):
        self.assertEqual(stage(run(a=0, reserve=(1, 9), **ONLY_STAGE)), ((1, 0), (2, 0), (3, 0)))

    def test_b_zero_pays_zero_rows(self):
        self.assertEqual(stage(run(b=0, **ONLY_STAGE)), ((1, 0), (2, 0), (3, 0)))

    def test_weight_sum_overflow_pays_zero(self):
        got = run(hist=((9000, ((1, 1000, tool.TOP), (2, 2000, 5))),), profiles=((1, 11, 0), (2, 12, 0)), **ONLY_STAGE)
        self.assertEqual(stage(got), ((1, 0), (2, 0)))

    def test_rate_above_fraction_top_pays_zero(self):
        got = run(stage=(64000000000, 0), hist=((9000, ((1, 10 ** 6, 1),)),), profiles=((1, 11, 0),), b=1 << 62, **ONLY_STAGE)
        self.assertEqual(stage(got), ((1, 0),))

    def test_zero_duration_trips_the_assert(self):
        self.assertEqual(run(direct=True, stage=(0, 0)), ("panic", "assert_duration"))

    def test_rate_table_row(self):
        row = next(r for r in RESULT["rates"] if r[0] == "0.4" and r[1] == 1)
        self.assertAlmostEqual(float(row[5]), (0.015 / math.sqrt(0.4)) - 0.5 * (0.015 / math.sqrt(0.4)) ** 2, places=12)


class StageRows(unittest.TestCase):
    def test_paid_rows_debit_reserve_and_stage(self):
        got = run(hist=((9000, ((1, 10 ** 12, 500), (2, 10 ** 12, 500))),), profiles=((1, 11, 0), (2, 12, 0)), b=1000, **ONLY_STAGE)
        paid = stage(got)
        self.assertEqual(paid[0][1], paid[1][1])
        self.assertEqual(state(got)[1], (1, 500000000000 - 2 * paid[0][1]))
        self.assertEqual(state(got)[2], paid)

    def test_no_profile_is_none(self):
        self.assertEqual(stage(run(profiles=((2, 12, 1000), (3, 13, 0)), **ONLY_STAGE))[0], (1, None))

    def test_signer_out_of_power_is_none(self):
        self.assertEqual(stage(run(power=(11, 13), **ONLY_STAGE))[1], (2, None))

    def test_jailed_signer_is_none_and_keys_by_signer(self):
        self.assertEqual(stage(run(jailed=(12,), **ONLY_STAGE))[1], (2, None))
        self.assertNotEqual(stage(run(jailed=(2,), **ONLY_STAGE))[1], (2, None))

    def test_short_reserve_reports_full_amount_but_stages_rest(self):
        got = run(reserve=(1, 3), hist=((9000, ((1, 10 ** 15, 1000),)),), profiles=((1, 11, 0),), b=1000, **ONLY_STAGE)
        self.assertGreater(stage(got)[0][1], 3)
        self.assertEqual(state(got)[1], (1, 0))
        self.assertEqual(state(got)[2], ((1, 3),))
        self.assertEqual(got[4], ("sub",))

    def test_reserve_none_stages_nothing(self):
        got = run(reserve=(0, 77), **ONLY_STAGE)
        self.assertGreater(stage(got)[0][1], 0)
        self.assertEqual(state(got)[2], ())
        self.assertEqual(state(got)[1], (0, 77))

    def test_no_history_row_gives_none(self):
        self.assertIsNone(stage(run(hist=(), interval=BIG, **ONLY_STAGE)))

    def test_window_two_hundred_back(self):
        self.assertIsNotNone(stage(run(hist=((8800, THREE),), cur=9000, low=100, interval=BIG, **ONLY_STAGE)))
        self.assertIsNone(stage(run(hist=((8799, THREE),), cur=9000, low=100, interval=BIG, **ONLY_STAGE)))

    def test_first_2000_keys_use_low(self):
        self.assertIsNotNone(stage(run(hist=((1200, THREE),), cur=3000, low=1001, interval=BIG, **ONLY_STAGE)))
        self.assertIsNone(stage(run(hist=((1200, THREE),), cur=3001, low=1001, interval=BIG, **ONLY_STAGE)))


class Distribute(unittest.TestCase):
    def test_commission_then_members(self):
        got = run(delegators=((1, ((21, 700, 900, 9000), (22, 300, 100, 8000))),), staged=((1, 100000),), **ONLY_DIST)
        self.assertEqual(sink(got), ((5000, 1, 1, 0), (71250, 21, 1, 1), (23750, 22, 1, 1)))
        self.assertEqual(users(got)[1][0], 5000)
        self.assertEqual(state(got)[2], ())

    def test_epoch_word_selects_current_or_previous(self):
        got = run(delegators=((1, ((21, 700, 900, 8999), (22, 300, 100, 9000))),), staged=((1, 100000),), **ONLY_DIST)
        self.assertEqual(sink(got), ((5000, 1, 1, 0), (83125, 21, 1, 1), (11875, 22, 1, 1)))

    def test_no_members_keeps_the_share_in_reserve(self):
        got = run(staged=((1, 100000),), **ONLY_DIST)
        self.assertEqual(sink(got), ((5000, 1, 1, 0),))
        self.assertEqual(state(got)[1], (1, 500000000000 + 95000))

    def test_no_profile_keeps_all_in_reserve(self):
        got = run(profiles=(), staged=((1, 100000),), **ONLY_DIST)
        self.assertEqual(sink(got), ())
        self.assertEqual(state(got)[1], (1, 500000000000 + 100000))

    def test_commission_above_edge_pays_none(self):
        got = run(profiles=((1, 11, 10101),), staged=((1, 100000),), **ONLY_DIST)
        self.assertEqual(sink(got), ())
        self.assertEqual(users(got)[1][0], 0)

    def test_commission_101_percent_is_capped_by_amount(self):
        got = run(profiles=((1, 11, 10100),), staged=((1, 100000),), **ONLY_DIST)
        self.assertEqual(got[4], ("sub",))
        self.assertEqual(users(got)[1][0], 100000)
        self.assertEqual(sink(got), ((101000, 1, 1, 0),))

    def test_dust_returns_to_reserve(self):
        got = run(delegators=((1, ((21, 1, 1, 0), (22, 1, 1, 0), (23, 1, 1, 0))),), staged=((1, 10),), profiles=((1, 11, 0),), **ONLY_DIST)
        self.assertEqual([row[0] for row in sink(got)], [3, 3, 3])
        self.assertEqual(state(got)[1], (1, 500000000000 + 1))

    def test_member_sum_overflow_keeps_share(self):
        got = run(delegators=((1, ((21, 0, tool.TOP, 9000), (22, 0, 5, 9000))),), staged=((1, 100000),), **ONLY_DIST)
        self.assertEqual(sink(got), ((5000, 1, 1, 0),))
        self.assertEqual(state(got)[1][1], 500000000000 + 95000)

    def test_no_history_row_drops_staged_silently(self):
        got = run(hist=(), staged=((1, 50),), interval=BIG, **ONLY_DIST)
        self.assertIsNone(sink(got))
        self.assertEqual(state(got)[2], ())
        self.assertEqual(state(got)[1], (1, 500000000000))

    def test_reserve_none_leaves_staged(self):
        got = run(staged=((1, 9),), reserve=(0, 4), **ONLY_DIST)
        self.assertIsNone(sink(got))
        self.assertEqual(state(got)[2], ((1, 9),))

    def test_reserve_overflow_reports_status_and_keeps_value(self):
        got = run(profiles=(), staged=((1, 9),), reserve=(1, tool.TOP), **ONLY_DIST)
        self.assertEqual(got[3], (0xBE,))
        self.assertEqual(state(got)[1], (1, tool.TOP))


class Bonus(unittest.TestCase):
    locks = dict(delegators=((1, ((21, 500, 500, 0), (22, 500, 500, 0))),), profiles=((1, 11, 0),), staged=((1, 100000),), **ONLY_DIST)

    def test_running_lock_pays_half_more_from_reserve(self):
        got = run(users=((21, 1, LATER, 5, 6),), **self.locks)
        self.assertEqual(sink(got), ((75000, 21, 1, 1), (50000, 22, 1, 1)))
        self.assertEqual(users(got)[21], (75001, LATER, 5, 6))
        self.assertEqual(state(got)[1], (1, 500000000000 - 25000))

    def test_expired_lock_is_cleared(self):
        now = tool.Case.FIELDS["now"]
        got = run(users=((21, 1, now[0], now[1], now[2]),), **self.locks)
        self.assertEqual(sink(got)[0], (50000, 21, 1, 1))
        self.assertEqual(users(got)[21], (50001, 0, 0, 0))

    def test_one_nano_before_lock_end_still_pays(self):
        now = tool.Case.FIELDS["now"]
        got = run(users=((21, 1, now[0], now[1], now[2] + 1),), **self.locks)
        self.assertEqual(sink(got)[0][0], 75000)

    def test_short_reserve_row_still_says_one_and_a_half(self):
        got = run(users=((21, 1, LATER, 0, 0),), reserve=(1, 3), **self.locks)
        self.assertEqual(sink(got)[0][0], 75000)
        self.assertEqual(users(got)[21][0], 50004)
        self.assertEqual(state(got)[1], (1, 0))


class Snapshots(unittest.TestCase):
    def test_due_exactly_at_interval(self):
        got = run(round=19000, interval=10000, **IDLE)
        self.assertEqual([row[0] for row in state(got)[5]], [9000, 19000])

    def test_not_due_one_before(self):
        got = run(round=18999, interval=10000, **IDLE)
        self.assertEqual([row[0] for row in state(got)[5]], [9000])

    def test_cap_drops_oldest(self):
        got = run(round=200000, cap=1, jail_cap=1, **IDLE)
        self.assertEqual([row[0] for row in state(got)[5]], [200000])
        self.assertEqual([row[0] for row in state(got)[6]], [200000])

    def test_stored_row_is_live_stakes(self):
        got = run(round=200000, stakes=((5, 8, 9),), **IDLE)
        self.assertEqual(state(got)[5][-1], (200000, ((5, 8, 9),)))

    def test_jail_row_is_live_set(self):
        got = run(round=200000, jailed=(4, 9), **IDLE)
        self.assertEqual(state(got)[6][-1], (200000, (4, 9)))

    def test_snapshot_comes_before_decay_in_one_tick(self):
        got = run(round=200000, stakes=((5, 100, 200),), **ONLY_DECAY)
        self.assertEqual(state(got)[5][-1], (200000, ((5, 100, 200),)))
        self.assertEqual(state(got)[4], ((5, 199, 200),))


class Decay(unittest.TestCase):
    def test_rise_closes_ninety_nine_percent(self):
        self.assertEqual(state(run(stakes=((1, 100, 200),), **ONLY_DECAY))[4], ((1, 199, 200),))

    def test_fall_is_immediate(self):
        self.assertEqual(state(run(stakes=((1, 200, 100),), **ONLY_DECAY))[4], ((1, 100, 100),))

    def test_gap_of_one_stays(self):
        self.assertEqual(state(run(stakes=((1, 100, 101),), **ONLY_DECAY))[4], ((1, 100, 101),))

    def test_idle_bucket_keeps_row(self):
        self.assertEqual(state(run(stakes=((1, 100, 200),), **IDLE))[4], ((1, 100, 200),))


class Tamper(unittest.TestCase):
    def test_stage_gate_flip(self):
        self.assertTrue(changed({0x3996876: 0x96}, **ONLY_STAGE))

    def test_bonus_shift_direction(self):
        self.assertTrue(changed({0x3371949 + 2: 0xE0}, users=((21, 1, LATER, 5, 6),), **Bonus.locks))

    def test_commission_scale_read(self):
        self.assertTrue(changed({0x3370cc8 + 4: 0x20}, staged=((1, 100000),), **ONLY_DIST))

    def test_decay_store_target(self):
        self.assertTrue(changed({0x3C12230: 0x90, 0x3C12231: 0x90, 0x3C12232: 0x90}, stakes=((1, 100, 200), (2, 7, 9)), **ONLY_DECAY))

    def test_reserve_add_skipped(self):
        self.assertTrue(changed({0x3371d5d: 0x90, 0x3371d5e: 0x90, 0x3371d5f: 0x90, 0x3371d60: 0x90}, profiles=(), staged=((1, 9),), **ONLY_DIST))


class Files(unittest.TestCase):
    def test_vectors_ran(self):
        self.assertEqual(RESULT["vector_count"], 60)

    def test_generated_files_match_the_folder(self):
        fresh = tool.render(RESULT)
        for name in ("function-rows.tsv", "callers.tsv", "constants.tsv", "field-names.tsv", "rate-table.tsv", "outcomes.tsv"):
            self.assertEqual((FOLDER / name).read_text(), fresh[name], name)

    def test_manifest_covers_every_file(self):
        rows = dict(reversed(line.split("  ")) for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines())
        names = sorted(path.name for path in FOLDER.iterdir() if path.name != "MANIFEST.sha256")
        self.assertEqual(sorted(rows), names)
        for name in names:
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), rows[name], name)

    def test_summary_counts(self):
        data = json.loads((FOLDER / "evidence.json").read_text())
        self.assertEqual(data["sha256"], tool.SHA256)
        self.assertEqual(data["named_cases"], len(tool.named_cases()))
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
