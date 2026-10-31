"""Tests for tools/validator_l1_vote.py: real node #94 bytes with corruption controls."""

import copy
import hashlib
import importlib.util
import json
import pathlib
import struct
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FOLDER = ROOT / "research" / "work-items" / "staking-validator-l1-vote-94"
spec_ = importlib.util.spec_from_file_location("validator_l1_vote", ROOT / "tools" / "validator_l1_vote.py")
tool = importlib.util.module_from_spec(spec_)
sys.modules["validator_l1_vote"] = tool
spec_.loader.exec_module(tool)

IMAGE = None
HARNESS = None
RESULT = None
Op, Pay, seed = tool.Op, tool.Pay, tool.seed
ONE = Pay(4, number=1, flag=1)
INNER = Pay(6, inner=(1 << 63) + 2)


def setUpModule():
    global IMAGE, HARNESS, RESULT
    IMAGE = tool.load_image()
    HARNESS = tool.Harness(IMAGE)
    RESULT = tool.analyse(IMAGE, mutate=False, vectors=60)


def run(**fields):
    case = tool.Case("t", fields.pop("kind", "vote"), **fields)
    got = HARNESS.run(case)
    assert got == tool.spec_run(case, HARNESS.frozen_digest), case.__dict__
    return got


def results(got):
    return list(got[1])


def names(got):
    return [row[0] for row in got[2]]


def rows(got):
    return got[3][0]


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
        sizes = ((tool.HANDLER, 1127), (tool.HOST, 1638), (tool.BODY, 3375), (tool.COUNT, 698), (tool.KEY_CMP, 596), (tool.TRACK, 2400), (tool.QUORUM, 545), (tool.STAKE_TEST, 1983), (tool.ROW_ENTRY, 787), (tool.STREAM_WRAP, 213), (tool.STREAM, 844), (tool.UPSERT, 654))
        for target, size in sizes:
            start, end = IMAGE.exact_fde(target)
            self.assertEqual((start, end - start), (target, size))

    def test_address_inside_a_function_is_not_a_start(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.exact_fde(tool.BODY + 1)

    def test_slots_resolve_from_relocations(self):
        relative = IMAGE.relative()
        self.assertEqual(relative[tool.SLOT_BODY], tool.BODY)
        self.assertEqual(relative[tool.SLOT_STAKES], 0x336D5B0)
        self.assertEqual(relative[tool.SLOT_RATIO], tool.RATIO)

    def test_status_text(self):
        table = {row[0]: row[2] for row in RESULT["statuses"]}
        self.assertEqual(table["0x36"], "Too many pending votes")
        self.assertEqual(table["0x91"], "Unknown validator")
        self.assertEqual(table["0x94"], "Invalid validator")
        self.assertEqual(table["0x140"], "Invalid input")

    def test_quorum_table_bytes(self):
        pair = struct.unpack_from("<dd", IMAGE.blob, IMAGE.offset(0x209510))
        self.assertEqual(pair, (2.0 / 3.0, 0.2))


class Corruption(unittest.TestCase):
    def corrupt(self, va):
        image = copy.copy(IMAGE)
        image.blob = bytearray(IMAGE.blob)
        image.blob[IMAGE.offset(va)] ^= 1
        return image

    def test_constant_row(self):
        with self.assertRaises(tool.EvidenceError):
            tool.constant_rows(self.corrupt(0x39494F6))

    def test_quorum_table(self):
        with self.assertRaises(tool.EvidenceError):
            tool.constant_rows(self.corrupt(0x209510))

    def test_rate_bound(self):
        with self.assertRaises(tool.EvidenceError):
            tool.constant_rows(self.corrupt(0x20A736))

    def test_field_key_text(self):
        with self.assertRaises(tool.EvidenceError):
            tool.field_rows(self.corrupt(0x5A5F96))

    def test_field_proof(self):
        with self.assertRaises(tool.EvidenceError):
            tool.field_rows(self.corrupt(0x394833F))

    def test_apply_call_row(self):
        with self.assertRaises(tool.EvidenceError):
            tool.first_call(self.corrupt(0x2387555), 1)


class Gate(unittest.TestCase):
    def test_stranger_refused(self):
        self.assertEqual(results(run(ops=(Op(9, ONE),))), [("err", 0x94, False)])

    def test_allow_all_lets_a_stranger_vote(self):
        got = run(allow_all=True, profiles=((9, 25),), active=((25, 1),), stakes=((9, 10),), ops=(Op(9, ONE),))
        self.assertEqual(results(got), [("ok", 1)])

    def test_inactive_refuses_both_ways(self):
        for allow in (False, True):
            self.assertEqual(results(run(enabled=False, allow_all=allow, ops=(Op(1, ONE),))), [("err", 0x94, False)])

    def test_new_row_needs_a_profile(self):
        self.assertEqual(results(run(profiles=(), ops=(Op(1, ONE),))), [("err", 0x91, False)])

    def test_new_row_needs_an_active_signer(self):
        self.assertEqual(results(run(active=((18, 1),), ops=(Op(1, ONE),))), [("err", 0x94, False)])

    def test_row_hit_reads_the_snapshot_not_the_active_set(self):
        got = run(rows=(seed(ONE),), active=(), profiles=(), ops=(Op(1, ONE),))
        self.assertEqual(results(got), [("ok", 0)])
        self.assertNotIn("active", names(got))

    def test_row_hit_outside_snapshot_keeps_the_payload_undropped(self):
        got = run(rows=(seed(ONE, stakes=((2, 100),)),), ops=(Op(1, ONE),))
        self.assertEqual(results(got), [("err", 0x94, False)])
        self.assertNotIn("drop_payload", names(got))
        self.assertIn("drop_key", names(got))


class Cap(unittest.TestCase):
    FILLED = tuple(seed(Pay(4, number=index + 1), stakes=((1, 1), (2, 1)), voters=(1,), fin=0x100) for index in range(49))

    def test_49_passes_and_50_refuses(self):
        got = run(rows=self.FILLED, stakes=((1, 1), (2, 1)), ops=(Op(1, Pay(4, number=500)), Op(1, Pay(4, number=501))))
        self.assertEqual(results(got), [("ok", 0), ("err", 0x36, False)])

    def test_cap_is_per_voter(self):
        rows_ = self.FILLED + (seed(Pay(4, number=900), voters=(1,), fin=0x100),)
        self.assertEqual(results(run(rows=rows_, ops=(Op(2, Pay(4, number=500)),))), [("ok", 0)])

    def test_finished_rows_count(self):
        rows_ = tuple(seed(Pay(4, number=index + 1), voters=(1,), fin=1, done=1) for index in range(50))
        self.assertEqual(results(run(rows=rows_, ops=(Op(1, Pay(4, number=500)),))), [("err", 0x36, False)])

    def test_mutated_cap_is_seen(self):
        case = tool.Case("t", "vote", rows=self.FILLED, stakes=((1, 1), (2, 1)), ops=(Op(1, Pay(4, number=500)), Op(1, Pay(4, number=501))))
        self.assertTrue(mutated({0x39494F9: 0x30}, case))


class Quorum(unittest.TestCase):
    def test_strict_two_thirds(self):
        self.assertEqual(results(run(stakes=((1, 200), (2, 100)), ops=(Op(1, ONE),))), [("ok", 0)])
        self.assertEqual(results(run(stakes=((1, 201), (2, 99)), ops=(Op(1, ONE),))), [("ok", 1)])

    def test_nested_action_needs_one_fifth(self):
        self.assertEqual(results(run(stakes=((1, 60), (2, 240)), ops=(Op(1, INNER),))), [("ok", 0)])
        self.assertEqual(results(run(stakes=((1, 61), (2, 239)), ops=(Op(1, INNER),))), [("ok", 1)])

    def test_row_keeps_the_ratio_bits(self):
        got = run(ops=(Op(1, INNER), Op(1, ONE)))
        ratios = {row[0][0]: row[6] for row in rows(got)}
        self.assertEqual(ratios[6], tool.to_bits(0.2))
        self.assertEqual(ratios[4], tool.to_bits(2.0 / 3.0))

    def test_snapshot_does_not_move(self):
        got = run(ops=(Op(1, ONE), Op(2, ONE, stakes=((2, 900), (3, 1))), Op(3, ONE)))
        self.assertEqual(results(got)[-1], ("ok", 1))
        self.assertEqual(rows(got)[0][5], ((1, 100), (2, 100), (3, 100)))

    def test_expire_is_block_time_plus_seven_days_and_stays(self):
        got = run(ops=(Op(1, ONE), Op(2, ONE, now=tool.later(tool.T0, 500))))
        self.assertEqual(rows(got)[0][7], (tool.date_at(tool.day_number(tool.T0[0]) + 7), 3600, 9))

    def test_past_expire_changes_nothing(self):
        old = (tool.BASE_DATE - 16, 0, 0)
        got = run(rows=(seed(ONE, expire=old),), ops=(Op(1, ONE),))
        self.assertEqual(results(got), [("ok", 0)])
        self.assertEqual(rows(got)[0][7], old)

    def test_hc_ratio_blocks_stake(self):
        self.assertEqual(results(run(hvs=(1, 2, 3, 4), hc=(0.5, 0.0), stakes=((1, 100),), ops=(Op(1, ONE),))), [("ok", 0)])

    def test_finished_row_never_applies_twice(self):
        got = run(stakes=((1, 100), (2, 1)), ops=(Op(1, ONE), Op(2, ONE), Op(1, ONE)))
        self.assertEqual(results(got), [("ok", 1), ("ok", 0), ("ok", 0)])
        self.assertEqual(names(got).count("apply"), 1)

    def test_apply_refusal_is_final(self):
        got = run(stakes=((1, 100), (2, 1)), ops=(Op(1, ONE, apply=0xEA), Op(2, ONE), Op(1, ONE)))
        self.assertEqual(results(got), [("err", 0xEA, True), ("ok", 0), ("ok", 0)])
        self.assertEqual(rows(got)[0][8], 1)

    def test_hvs_voter_opens_a_row_but_cannot_join_one(self):
        got = run(allowed=(1, 2, 3), hvs=(1, 2), stakes=((3, 100),), ops=(Op(1, ONE), Op(2, ONE), Op(3, ONE)))
        self.assertEqual(results(got)[1], ("err", 0x94, False))

    def test_stake_sum_overflow_panics(self):
        got = run(stakes=((1, 1 << 63), (2, 1 << 63)), ops=(Op(1, ONE),))
        self.assertEqual(got[:2], ("panic", "add_overflow"))

    def test_mutated_ratio_store_is_seen(self):
        case = tool.Case("t", "vote", stakes=((1, 61), (2, 239)), ops=(Op(1, INNER),))
        self.assertTrue(mutated({0x3949535 + 2: IMAGE.blob[IMAGE.offset(0x3949535 + 2)] ^ 1}, case))


class Handler(unittest.TestCase):
    def test_text_limits(self):
        for k in (0, 3, 5):
            self.assertEqual(results(run(ops=(Op(1, Pay(k, b"x" * 101)),))), [("err", 0x143, False)])
            self.assertEqual(results(run(ops=(Op(1, Pay(k, b"x" * 21)),))), [("err", 0x140, False)])
            self.assertEqual(results(run(ops=(Op(1, Pay(k, b"x" * 20)),))), [("ok", 0)])

    def test_token_status_passes_through(self):
        self.assertEqual(results(run(ops=(Op(1, Pay(2, b"BAD"), token=0xEB),))), [("err", 0xEB, True)])

    def test_inner_mask(self):
        got = results(run(ops=tuple(Op(1, Pay(6, inner=(1 << 63) + tag)) for tag in range(10))))
        self.assertEqual([tag for tag, item in enumerate(got) if item[0] == "err"], [0, 1, 7])

    def test_key_flag_splits_rows(self):
        got = run(ops=(Op(1, Pay(3, b"dex", flag=1)), Op(1, Pay(3, b"dex", flag=0))))
        self.assertEqual(len(rows(got)), 2)

    def test_same_text_other_variant_is_another_row(self):
        got = run(ops=(Op(1, Pay(3, b"dex")), Op(1, Pay(5, b"dex")), Op(1, Pay(0, b"dex"))))
        self.assertEqual([row[0][0] for row in rows(got)], [0, 3, 5])


class Stream(unittest.TestCase):
    def rate(self, *ops, **fields):
        return run(kind="stream", ops=ops, **fields)

    def st(self, caller=1, text=b"0.05", **fields):
        return Op(caller, kind="stream", text=text, **fields)

    def test_bounds(self):
        for number, want in ((0.0, "ok"), (-0.0, "ok"), (1.0, "ok"), (5e-324, "ok"), (1.0000000000000002, "err"), (-5e-324, "err"), (-1.7976931348623157e308, "err"), (float("inf"), "err"), (float("nan"), "err")):
            self.assertEqual(results(self.rate(self.st(number=number)))[0][0], want, number)

    def test_order_validator_then_length(self):
        self.assertEqual(results(self.rate(self.st(9, b"1" * 101))), [("err", 0x91, False)])
        self.assertEqual(results(self.rate(self.st(1, b"1" * 101))), [("err", 0x143, False)])

    def test_row_is_replaced(self):
        got = self.rate(self.st(number=0.1), self.st(number=0.2, now=(tool.BASE_DATE + 16, 7, 77)))
        self.assertEqual(got[3][1], ((1, (tool.to_bits(0.2), (tool.BASE_DATE + 16, 7, 77))),))

    def test_refused_rate_keeps_the_old_row(self):
        got = self.rate(self.st(number=0.1), self.st(number=1.5))
        self.assertEqual(got[3][1][0][1][0], tool.to_bits(0.1))


class Evidence(unittest.TestCase):
    def test_outcomes_match_the_rule_list(self):
        self.assertEqual(len(RESULT["cases"]), len(RESULT["outcomes"]))
        self.assertGreater(len(RESULT["cases"]), 170)

    def test_committed_files_match_a_fresh_table(self):
        files = tool.render(RESULT)
        for name in ("function-rows.tsv", "callers.tsv", "copies.tsv", "constants.tsv", "field-names.tsv", "status-text.tsv", "variants.tsv", "outcomes.tsv"):
            self.assertEqual((FOLDER / name).read_text(encoding="ascii"), files[name], name)

    def test_manifest(self):
        for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)

    def test_summary_counts(self):
        summary = json.loads((FOLDER / "evidence.json").read_text())
        self.assertEqual(summary["sha256"], tool.SHA256)
        rows_ = (FOLDER / "mutations.tsv").read_text().splitlines()[1:]
        self.assertEqual(summary["mutations"]["total"], len(rows_))
        self.assertEqual(summary["mutations"]["survived"], sum(1 for row in rows_ if "\tsurvived\t" in row))

    def test_copies_share_their_shape(self):
        shifts = {row[1]: row[4] for row in RESULT["copies"]}
        self.assertEqual(shifts, {"0x4cf1650": "0xa80", "0x4cf1cc0": "0x0", "0x4cf2330": "0x0", "0x4cf2680": "0xa80"})


if __name__ == "__main__":
    unittest.main()
