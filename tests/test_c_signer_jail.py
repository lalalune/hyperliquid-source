"""Tests for tools/c_signer_jail.py: real node #94 bytes with corruption controls."""

import copy
import hashlib
import importlib.util
import json
import pathlib
import struct
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FOLDER = ROOT / "research" / "work-items" / "staking-c-signer-jail-94"
spec_ = importlib.util.spec_from_file_location("c_signer_jail", ROOT / "tools" / "c_signer_jail.py")
tool = importlib.util.module_from_spec(spec_)
sys.modules["c_signer_jail"] = tool
spec_.loader.exec_module(tool)

IMAGE = None
HARNESS = None
RESULT = None
T0 = tool.T0
A, B, C = tool.later(T0, 100), tool.later(T0, 200), tool.later(T0, 300)
UNJAIL, JAIL_SELF, VOTE = 0, 1, 2


def setUpModule():
    global IMAGE, HARNESS, RESULT
    IMAGE = tool.load_image()
    HARNESS = tool.Harness(IMAGE)
    RESULT = tool.analyse(IMAGE, mutate=False, vectors=96)


def run(kind=tool.BODY, **fields):
    case = tool.Case("t", kind, **fields)
    got = HARNESS.run(case)
    assert got == tool.spec_run(case, HARNESS.where), case.__dict__
    return got


def status(got):
    return got[1][0]


def names(got):
    return [row[0] for row in got[2]]


def until_rows(got):
    return {key[0] - 0x20: value for key, value in got[3][0]}


def last_rows(got):
    return {key[0] - 0x20: value for key, value in got[3][1]}


def trackers(got):
    return {row[0][0] - 0x20: row for row in got[3][2]}


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
        sizes = ((tool.BODY, 5223), (tool.GATE, 1715), (tool.JAIL, 1673), (tool.VOTED, 302), (tool.QUORUM, 1863), (tool.COLLECT, 1125), (tool.SORT, 401), (tool.UPSERT, 647))
        for target, size in sizes:
            start, end = IMAGE.exact_fde(target)
            self.assertEqual((start, end - start), (target, size))

    def test_address_inside_a_function_is_not_a_start(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.exact_fde(tool.BODY + 1)

    def test_slots_resolve_from_relocations(self):
        relative = IMAGE.relative()
        self.assertEqual(relative[tool.SLOT_BODY], tool.BODY)
        self.assertEqual(relative[tool.SLOT_GATE], tool.GATE)
        self.assertEqual(relative[tool.SLOT_QUORUM], tool.QUORUM)


class UnjailSelf(unittest.TestCase):
    def test_not_jailed_is_a_plain_ok(self):
        got = run(tag=UNJAIL)
        self.assertEqual(status(got), 0x186)
        self.assertEqual(names(got), [])

    def test_jailed_signer_leaves_the_set_and_stamps_the_time(self):
        got = run(tag=UNJAIL, jailed=(1,))
        self.assertEqual(status(got), 0x186)
        self.assertIn(("jailed_remove", 1), got[2])
        self.assertEqual(last_rows(got)[1], T0)

    def test_list_member_skips_both_time_gates(self):
        got = run(tag=UNJAIL, jailed=(1,), protected=(1,), jail_until=((1, A),), last=((1, T0),))
        self.assertEqual(status(got), 0x186)
        self.assertEqual(last_rows(got)[1], T0)
        self.assertIn(("jailed_remove", 1), got[2])

    def test_jail_until_blocks_and_carries_the_time(self):
        got = run(tag=UNJAIL, jailed=(1,), jail_until=((1, A),))
        self.assertEqual(got[1], (0x9C, A))
        self.assertNotIn("jailed_remove", names(got))

    def test_jail_until_equal_to_now_passes(self):
        self.assertEqual(status(run(tag=UNJAIL, jailed=(1,), jail_until=((1, T0),))), 0x186)

    def test_jail_until_keeps_the_row(self):
        got = run(tag=UNJAIL, jailed=(1,), jail_until=((1, tool.later(T0, -5)),))
        self.assertEqual(until_rows(got)[1], tool.later(T0, -5))

    def test_second_manual_unjail_inside_300_seconds_fails(self):
        got = run(tag=UNJAIL, jailed=(1,), last=((1, tool.later(T0, -299)),))
        self.assertEqual(got[1], (0x9B, None))

    def test_exactly_300_seconds_passes(self):
        self.assertEqual(status(run(tag=UNJAIL, jailed=(1,), last=((1, tool.later(T0, -300)),))), 0x186)

    def test_the_gap_crosses_midnight(self):
        moment = (tool.BASE_DATE + 16, 100, 0)
        self.assertEqual(status(run(tag=UNJAIL, jailed=(1,), now=moment, last=((1, (tool.BASE_DATE, 86300, 0)),))), 0x9B)

    def test_panics_when_the_date_add_fails(self):
        self.assertEqual(run(tag=UNJAIL, jailed=(1,), date_fail=True)[:2], ("panic", "date_overflow"))

    def test_chain_zero_panics(self):
        self.assertEqual(run(tag=UNJAIL, jailed=(1,), mode=0)[:2], ("panic", "invalid_chain"))


class JailSelf(unittest.TestCase):
    def test_new_row_holds_the_unix_epoch(self):
        got = run(tag=JAIL_SELF)
        self.assertEqual(status(got), 0x186)
        self.assertEqual(until_rows(got)[1], (tool.EPOCH_DATE, 0, 0))
        self.assertIn(("jailed_insert", 1), got[2])

    def test_existing_row_keeps_its_time(self):
        self.assertEqual(until_rows(run(tag=JAIL_SELF, jail_until=((1, A),)))[1], A)

    def test_main_list_member_is_refused_while_a_peer_is_jailed(self):
        got = run(tag=JAIL_SELF, main=(1, 2), jailed=(2,))
        self.assertEqual(status(got), 0x186)
        self.assertNotIn("jailed_insert", names(got))

    def test_main_list_member_jails_when_no_peer_is_jailed(self):
        self.assertIn("jailed_insert", names(run(tag=JAIL_SELF, main=(1, 2), jailed=(3,))))


class JailHelper(unittest.TestCase):
    def test_time_only_moves_forward(self):
        self.assertEqual(until_rows(run(tool.JAIL, until=A, jail_until=((5, B),)))[5], B)
        self.assertEqual(until_rows(run(tool.JAIL, until=C, jail_until=((5, B),)))[5], C)

    def test_chain_three_reads_its_own_static(self):
        got = run(tool.JAIL, main=(5, 6), jailed=(6,), protected=())
        self.assertEqual(got[2][0], ("protected", 1, 9))

    def test_other_chains_read_the_shared_getter(self):
        got = run(tool.JAIL, mode=1, protected=(5, 6), jailed=(6,))
        self.assertEqual(got[2][0], ("static", 1))
        self.assertNotIn("jailed_insert", names(got))

    def test_chain_three_ignores_the_getter_list(self):
        self.assertIn("jailed_insert", names(run(tool.JAIL, protected=(5, 6), jailed=(6,))))


class VoteJail(unittest.TestCase):
    def test_first_vote_builds_the_tracker(self):
        got = run()
        self.assertEqual(status(got), 0x186)
        self.assertEqual(trackers(got)[5][1], 0x100)
        self.assertEqual(len(trackers(got)[5][2]), 1)

    def test_no_current_stakes_means_no_vote(self):
        got = run(cur=False)
        self.assertEqual(status(got), 0x186)
        self.assertEqual(names(got), [])

    def test_non_validator_vote_is_dropped_silently(self):
        got = run(signer=9)
        self.assertEqual(status(got), 0x186)
        self.assertEqual(trackers(got), {})

    def test_list_member_cannot_be_voted(self):
        self.assertEqual(trackers(run(protected=(5,))), {})

    def test_vote_replaces_the_same_voter(self):
        got = run(until=C, jvt=((5, 0x100, ((1, A), (2, B))),))
        self.assertEqual(trackers(got)[5][2][0][1], C)

    def test_two_thirds_exactly_does_not_fire(self):
        got = run(signer=2, jvt=((5, 0x100, ((1, A),)),))
        self.assertIn(5, trackers(got))
        self.assertNotIn("jailed_insert", names(got))

    def test_quorum_removes_the_tracker_and_jails_at_the_median(self):
        got = run(signer=3, until=C, jvt=((5, 0x100, ((1, A), (2, B))),))
        self.assertEqual(trackers(got), {})
        self.assertEqual(until_rows(got)[5], B)
        self.assertIn(("jvt_remove", 5), got[2])

    def test_median_is_stake_weighted(self):
        got = run(signer=3, until=C, validators=((1, 100), (2, 150), (3, 700)), jvt=((5, 0x100, ((1, A), (2, B))),))
        self.assertEqual(until_rows(got)[5], C)

    def test_half_of_the_stake_stops_the_walk(self):
        rows = ((1, 100), (2, 100), (3, 200), (4, 1))
        got = run(signer=3, until=C, validators=rows, jvt=((5, 0x100, ((1, A), (2, B))),))
        self.assertEqual(until_rows(got)[5], B)

    def test_vote_of_a_former_validator_is_not_counted(self):
        got = run(signer=3, validators=((2, 100), (3, 300)), jvt=((5, 0x100, ((1, A), (2, B))),))
        self.assertEqual(until_rows(got)[5], tool.later(T0, 7200))

    def test_fired_flag_stops_the_recount(self):
        got = run(signer=3, jvt=((5, 0x101, ((1, A), (2, B))),))
        self.assertNotIn("voter_set", names(got))
        self.assertEqual(len(trackers(got)[5][2]), 3)

    def test_already_past_quorum_never_fires(self):
        got = run(signer=3, validators=((1, 200), (2, 200), (3, 100)), jvt=((5, 0x100, ((1, A), (2, B))),))
        self.assertIn(5, trackers(got))

    def test_the_first_keys_scan_is_dead(self):
        got = run(fake_len=101, jvt=((5, 0x100, ((1, A),)),))
        self.assertIn(("first_keys", 101, 100), got[2])
        self.assertIn(("free", 800), got[2])
        self.assertIn(5, trackers(got))

    def test_jvt_of_100_rows_skips_the_scan(self):
        self.assertNotIn("first_keys", names(run(fake_len=100, jvt=((5, 0x100, ((1, A),)),))))

    def test_sort_helper_handles_five_rows(self):
        self.assertIn(("grow", 4), HARNESS.run(named("vote_big_5"))[2])

    def test_twenty_one_rows_use_the_second_sort(self):
        self.assertIn(("drift_sort", 21), HARNESS.run(named("vote_big_21"))[2])
        self.assertNotIn("drift_sort", names(HARNESS.run(named("vote_big_20"))))


def named(name):
    return next(case for _, group in tool.GROUPS for case in group if case.name == name)


class Gate(unittest.TestCase):
    def test_allow_all_uses_round_stakes(self):
        self.assertEqual(run(tool.GATE, allow=1)[1], 1)
        self.assertEqual(run(tool.GATE, allow=1, signer=9)[1], 0)

    def test_list_mode_compares_the_profile_signer(self):
        self.assertEqual(run(tool.GATE, signer=1, allowed=(3,), profiles=((3, 1),))[1], 1)

    def test_list_mode_does_not_compare_the_validator_key(self):
        self.assertEqual(run(tool.GATE, signer=2, allowed=(2,), profiles=((2, 8),))[1], 0)

    def test_empty_list_refuses(self):
        self.assertEqual(run(tool.GATE)[1], 0)

    def test_row_without_a_profile_is_skipped(self):
        self.assertEqual(run(tool.GATE, signer=1, allowed=(2, 3), profiles=((3, 1),))[1], 1)


class Quorum(unittest.TestCase):
    def test_strict_two_thirds(self):
        self.assertEqual(run(tool.QUORUM, voters=(1, 2))[1], 0)
        self.assertEqual(run(tool.QUORUM, voters=(1, 2, 3))[1], 1)

    def test_top_bit_total_is_false(self):
        self.assertEqual(run(tool.QUORUM, validators=((1, 1 << 63), (2, 8)), voters=(1, 2))[1], 0)

    def test_triple_overflow_is_false(self):
        self.assertEqual(run(tool.QUORUM, validators=((1, (1 << 63) - 8), (2, 1 << 62)), voters=(1,))[1], 0)

    def test_total_overflow_panics(self):
        self.assertEqual(run(tool.QUORUM, validators=((1, 1 << 63), (2, 1 << 63)), voters=(1,))[:2], ("panic", "add_overflow"))


class Constants(unittest.TestCase):
    def test_display_and_code_agree_on_300(self):
        rows = {row[0]: row for row in RESULT["constants"]}
        self.assertEqual(rows["display_gap_f64"][2], "300.0")
        self.assertEqual(struct.unpack("<I", bytes.fromhex(rows["unjail_gap_seconds"][2])[1:])[0], 300)

    def test_status_rows(self):
        rows = {row[0]: row[2] for row in RESULT["statuses"]}
        self.assertEqual(rows["0x95"], "Signer invalid or inactive for current epoch")
        self.assertEqual(rows["0x91"], "Unknown validator")

    def test_field_rows(self):
        rows = {row[0]: row[2] for row in RESULT["fields"]}
        self.assertEqual(rows["jail_until"], "0x1b0")
        self.assertEqual(rows["signer_to_last_manual_unjail_time"], "0x1c8")

    def test_chain_list_table(self):
        self.assertEqual([row[2] for row in RESULT["statics"]], ["panic", "cell", "cell", "cell"])

    def test_corrupted_constant_fails(self):
        bad = copy.copy(IMAGE)
        data = bytearray(IMAGE.blob)
        data[IMAGE.offset(0x3994A0C)] ^= 1
        bad.blob = bytes(data)
        with self.assertRaises(tool.EvidenceError):
            tool.constant_rows(bad)

    def test_corrupted_field_proof_fails(self):
        bad = copy.copy(IMAGE)
        data = bytearray(IMAGE.blob)
        data[IMAGE.offset(0x3990B5D)] ^= 1
        bad.blob = bytes(data)
        with self.assertRaises(tool.EvidenceError):
            tool.field_rows(bad)


class Mutants(unittest.TestCase):
    def test_gap_is_needed(self):
        case = tool.Case("t", tool.BODY, tag=UNJAIL, jailed=(1,), last=((1, tool.later(T0, -300)),))
        self.assertFalse(mutated({}, case))
        self.assertTrue(mutated({0x3994A0C: 0x2D}, case))

    def test_scan_bound_is_needed(self):
        self.assertTrue(mutated({0x3994138: 0x64}, tool.Case("t", tool.BODY, fake_len=100, jvt=((5, 0x100, ((1, A),)),))))

    def test_median_double_is_needed(self):
        self.assertTrue(mutated({0x39944A8: 0x37}, tool.Case("t", tool.BODY, signer=3, until=C, validators=((1, 100), (2, 150), (3, 700)), jvt=((5, 0x100, ((1, A), (2, B))),))))

    def test_evaluator_fails_on_an_unmodelled_call(self):
        harness = tool.Harness(IMAGE)
        del harness.machine.calls[tool.NEXT_VOTE]
        with self.assertRaises(tool.Halt):
            harness.run(tool.Case("t", tool.BODY, signer=3, jvt=((5, 0x100, ((1, A), (2, B))),)))

    def test_spec_notices_a_changed_time(self):
        case = tool.Case("t", tool.BODY, tag=UNJAIL, jailed=(1,))
        got = HARNESS.run(case)
        want = tool.spec_run(case, HARNESS.where)
        self.assertEqual(got, want)
        self.assertNotEqual(got[3], (want[3][0], ((want[3][1][0][0], A),), want[3][2], want[3][3]))


class Evidence(unittest.TestCase):
    def test_generated_files_match(self):
        files = tool.render(RESULT)
        for name, text in files.items():
            if name == "evidence.json":
                continue
            self.assertEqual((FOLDER / name).read_text(), text, name)

    def test_summary(self):
        data = json.loads((FOLDER / "evidence.json").read_text())
        self.assertEqual(data["sha256"], tool.SHA256)
        self.assertEqual(data["named_cases"], len(tool.named_cases()))
        self.assertEqual(data["functions"]["c_signer_body"]["bytes"], 5223)

    def test_mutation_table_is_explained(self):
        rows = [line.split("\t") for line in (FOLDER / "mutations.tsv").read_text().splitlines()[1:]]
        self.assertTrue(rows)
        for row in rows:
            if row[2] == "survived":
                self.assertTrue(row[3])

    def test_manifest(self):
        for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)


if __name__ == "__main__":
    unittest.main()
