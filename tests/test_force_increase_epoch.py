"""Tests for tools/force_increase_epoch.py: real node #94 bytes with corruption controls."""

import copy
import hashlib
import importlib.util
import json
import pathlib
import struct
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FOLDER = ROOT / "research" / "work-items" / "staking-force-increase-epoch-94"
spec_ = importlib.util.spec_from_file_location("force_increase_epoch", ROOT / "tools" / "force_increase_epoch.py")
tool = importlib.util.module_from_spec(spec_)
sys.modules["force_increase_epoch"] = tool
spec_.loader.exec_module(tool)

IMAGE = None
HARNESS = None
RESULT = None
TOP = 0xFFFFFFFFFFFFFFFF
LATE = tool.LATE
FULL = tool.FULL
HEAVY = dict(validators=(1, 2, 3), stakes=((1, 100), (2, 100), (3, 100)))


def setUpModule():
    global IMAGE, HARNESS, RESULT
    IMAGE = tool.load_image()
    HARNESS = tool.Harness(IMAGE)
    RESULT = tool.analyse(IMAGE, mutate=False, vectors=90)


def run(kind=tool.FORCE, **fields):
    case = tool.Case("t", kind, **fields)
    got = HARNESS.run(case)
    assert got == tool.spec_run(case, HARNESS.before, HARNESS.where), case.__dict__
    return got


def status(got):
    return struct.unpack_from("<H", got[2], tool.OUT - tool.HEAP_BASE)[0]


def calls(got):
    return got[2] if got[0] == "value" else got[1]


def names(got):
    return [row[0] for row in calls(got)]


def event(got, name):
    return next(row for row in calls(got) if row[0] == name)


def state(got, field):
    return struct.unpack_from("<Q", got[-1], tool.STATE + field - tool.HEAP_BASE)[0]


def roll(**fields):
    return run(tool.ROLL, **fields)


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
        for target, size in ((tool.FORCE, 3378), (tool.ROLL, 1786), (tool.QUORUM, 2506), (tool.LOOKUP, 422), (tool.LAST, 344), (tool.TRACK, 358), (tool.ENCODE_TUPLE, 357)):
            start, end = IMAGE.exact_fde(target)
            self.assertEqual((start, end - start), (target, size))

    def test_address_inside_a_function_is_not_a_start(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.exact_fde(tool.FORCE + 1)


class GateOrder(unittest.TestCase):
    def test_plain_force_moves_active_and_next(self):
        got = run()
        self.assertEqual(status(got), 0x186)
        self.assertEqual((state(got, tool.S_ACTIVE), state(got, tool.S_CUR)), (7, 8))

    def test_signature_count_comes_before_the_number_cap(self):
        got = run(n_word=10001, epoch=TOP)
        self.assertEqual(status(got), 0x143)
        self.assertEqual(struct.unpack_from("<Q", got[2], tool.OUT + 0x18 - tool.HEAP_BASE)[0], 10001)

    def test_count_limit_is_ten_thousand_signatures_not_an_epoch(self):
        self.assertEqual(status(run(n_word=10000)), 0x186)
        self.assertEqual(status(run(epoch=10001, n_word=3)), 0x186)

    def test_number_cap_comes_before_the_cur_epoch_gate(self):
        got = run(epoch=tool.NUMBER_CAP)
        self.assertEqual(status(got), 0x13F)
        self.assertEqual(struct.unpack_from("<Q", got[2], tool.OUT + 8 - tool.HEAP_BASE)[0], tool.NUMBER_CAP)
        self.assertEqual(status(run(epoch=tool.NUMBER_CAP - 1)), 0x186)

    def test_cur_epoch_gate_refuses_before_any_signature(self):
        got = run(epoch=6)
        self.assertEqual(status(got), 0x98)
        self.assertNotIn("abi", names(got))

    def test_equal_to_cur_epoch_is_admitted(self):
        self.assertEqual(status(run(epoch=7)), 0x186)

    def test_signatures_are_checked_before_the_quorum(self):
        got = run(signatures=((1, "wrong_last"),), validators=(1, 2, 3), stakes=((1, 1), (2, 100), (3, 100)))
        self.assertEqual(status(got), 0x11F)
        self.assertNotIn("stakes", names(got))

    def test_quorum_is_checked_before_the_epoch_moves(self):
        got = run(signatures=FULL[:2], **HEAVY)
        self.assertEqual(status(got), 0x99)
        self.assertNotIn("insert", names(got))
        self.assertEqual(state(got, tool.S_ACTIVE), 5)


class MissingActive(unittest.TestCase):
    def test_no_signature_is_read(self):
        got = run(active=4)
        self.assertEqual(status(got), 0x186)
        self.assertNotIn("abi", names(got))

    def test_the_action_epoch_is_not_used(self):
        got = run(active=4, epoch=99)
        self.assertEqual(event(got, "insert")[1], 7)
        self.assertEqual(state(got, tool.S_CUR), 8)
        self.assertEqual(state(got, tool.S_ACTIVE), 4)

    def test_count_and_cap_are_not_read(self):
        self.assertEqual(status(run(active=4, n_word=20000, epoch=TOP)), 0x186)

    def test_refused_roll_gives_force_failed(self):
        self.assertEqual(status(run(active=4, added=(tool.BASE_DATE, 3600, 9))), 0x98)


class SignedTuple(unittest.TestCase):
    def test_string_and_two_words(self):
        self.assertEqual(event(run(nonce=9, epoch=8), "abi")[1:], (b"forceIncreaseEpoch", 8, 9))

    def test_source_byte(self):
        for chain, byte in ((3, 0x61), (0, 0x62), (1, 0x62), (2, 0x62), (4, 0x62), (0xFF, 0x62)):
            self.assertEqual(event(run(chain=chain), "agent")[1], byte)

    def test_only_the_low_byte_of_the_chain_word_is_read(self):
        self.assertEqual(event(run(chain=3, extra_high=0xABCDEF), "agent")[1], 0x61)
        self.assertEqual(event(run(chain=2, extra_high=3), "agent")[1], 0x62)

    def test_hash_chain_runs_once_per_signature(self):
        got = run(signatures=FULL)
        self.assertEqual(names(got).count("abi"), 3)
        self.assertEqual(names(got).count("absorb"), 3)
        self.assertEqual(names(got).count("recover"), 3)

    def test_recover_failure(self):
        got = run(signatures=((1, "fail"),))
        self.assertEqual(status(got), 0x7A)
        self.assertEqual(struct.unpack_from("<Q", got[2], tool.OUT + 8 - tool.HEAP_BASE)[0], 0x888)

    def test_digest_failure_gives_the_same_status(self):
        got = run(digest_fail=1)
        self.assertEqual(status(got), 0x7A)
        self.assertEqual(names(got).count("recover"), 1)

    def test_recover_runs_before_the_key_lookup(self):
        self.assertEqual(status(run(signatures=((9, "fail"),))), 0x7A)
        self.assertEqual(status(run(signatures=((9, "ok"),))), 0x94)

    def test_all_twenty_bytes_are_compared(self):
        for verdict in ("wrong_first", "wrong_word", "wrong_last"):
            self.assertEqual(status(run(signatures=((1, verdict),))), 0x11F)

    def test_signer_field_is_the_cold_user_not_the_hot_user(self):
        self.assertTrue(mutated({0x3368C27: 0xD8}, tool.Case("t", tool.FORCE)))
        got = run(signatures=((1, "ok"),), validators=(1,), stakes=((1, 5),))
        row = HARNESS.where["epoch_rows"][5]
        root = struct.unpack_from("<Q", got[2], row - tool.HEAP_BASE)[0]
        self.assertEqual(bytes(got[2][root + 0x2C - tool.HEAP_BASE:root + 0x40 - tool.HEAP_BASE]), tool.signer_of(1))
        self.assertEqual(bytes(got[2][root + 0x18 - tool.HEAP_BASE:root + 0x2C - tool.HEAP_BASE]), tool.user_of(1))


class Quorum(unittest.TestCase):
    def quorum(self, stakes, chosen):
        members = tuple(index for index, _ in stakes)
        return run(tool.QUORUM, target=5, validators=members, stakes=stakes, set_keys=chosen)[1]

    def test_exact_two_thirds_is_refused(self):
        self.assertEqual(self.quorum(((1, 2), (2, 2), (3, 2)), (1, 2)), 0)

    def test_one_above_passes(self):
        self.assertEqual(self.quorum(((1, 101), (2, 100), (3, 100)), (1, 2)), 1)

    def test_compare_is_wider_than_64_bits(self):
        self.assertEqual(self.quorum(((1, 0xAAAAAAAAAAAAAAAB), (2, 0x5555555555555554)), (1,)), 1)
        self.assertEqual(self.quorum(((1, 0xAAAAAAAAAAAAAAAA), (2, 0x5555555555555555)), (1,)), 0)

    def test_total_overflow_panics(self):
        self.assertEqual(run(tool.QUORUM, target=5, validators=(1, 2), stakes=((1, TOP), (2, 1)), set_keys=(1,))[:2], ("panic", "add_overflow"))

    def test_keys_outside_the_stake_map_count_zero(self):
        self.assertEqual(self.quorum(((1, 100), (2, 1)), (2, 9)), 0)

    def test_absent_epoch_is_false_with_a_dropped_status(self):
        got = run(tool.QUORUM, target=4)
        self.assertEqual(got[1], 0)
        self.assertEqual(got[2], (("drop_status", 0x97),))

    def test_empty_set_and_all_zero_stake(self):
        self.assertEqual(self.quorum(((1, 100),), ()), 0)
        self.assertEqual(self.quorum(((1, 0), (2, 0)), (1, 2)), 0)


class Advance(unittest.TestCase):
    def test_below_cur_is_refused(self):
        self.assertEqual(roll(now=LATE, target=6)[1], 0)

    def test_same_bucket_is_refused(self):
        self.assertEqual(roll(start=(tool.BASE_DATE, 86399, 0), now=(tool.BASE_DATE, 86399, 7))[1], 0)

    def test_next_bucket_moves(self):
        got = roll(start=(tool.BASE_DATE, 86399, 0), now=(tool.BASE_DATE, 86400, 0))
        self.assertEqual(got[1], 1)
        self.assertEqual(state(got, tool.S_CUR), 8)

    def test_stored_snapshot_keeps_the_old_start_time(self):
        got = roll(now=LATE)
        row = event(got, "insert")
        self.assertEqual(row[1], 7)
        self.assertEqual(row[2][24:], tool.pack_time((tool.BASE_DATE, 3600, 9)))

    def test_start_time_takes_all_twelve_bytes_of_now(self):
        got = roll(now=(tool.BASE_DATE + 16, 7, 0xABCD))
        at = tool.STATE + tool.S_START - tool.HEAP_BASE
        self.assertEqual(bytes(got[-1][at:at + 12]), tool.pack_time((tool.BASE_DATE + 16, 7, 0xABCD)))

    def test_cur_epoch_saturates(self):
        self.assertEqual(state(roll(now=LATE, target=TOP), tool.S_CUR), TOP)

    def test_flag_needs_active_zero(self):
        self.assertEqual(roll(active=0, force=1)[1], 1)
        self.assertEqual(roll(active=2, force=1)[1], 0)

    def test_flag_by_three_validators(self):
        self.assertEqual(roll(active=0, v_len=3)[1], 1)
        self.assertEqual(roll(active=0, v_len=4)[1], 0)
        self.assertEqual(roll(active=0, v_len=2)[1], 0)

    def test_flag_copies_the_old_cur_epoch_into_active(self):
        self.assertEqual(state(roll(active=0, force=1, target=9), tool.S_ACTIVE), 7)

    def test_only_the_low_force_byte_is_read(self):
        self.assertEqual(roll(active=0, force=0, extra_high=0x123456)[1], 0)

    def test_null_root_with_a_length_panics(self):
        self.assertEqual(roll(v_root=False, now=LATE)[:2], ("panic", "unwrap"))

    def test_empty_current_set_stores_an_empty_row(self):
        got = roll(v_len=0, v_root=False, now=LATE)
        self.assertEqual(event(got, "insert")[2][:24], bytes(24))
        self.assertNotIn("clone", names(got))

    def test_before_1970_clamps_to_zero(self):
        self.assertEqual(roll(start=(tool.date_of(1969, 100), 0, 0), now=(tool.date_of(1969, 200), 0, 0))[1], 0)


class Prune(unittest.TestCase):
    def test_limit(self):
        self.assertNotIn("pop", names(roll(now=LATE, len_word=999)))
        self.assertIn("pop", names(roll(now=LATE, len_word=1000)))

    def test_keys_at_or_above_active_stay(self):
        self.assertNotIn("pop", names(roll(now=LATE, len_word=1000, epochs=((5, 19000), (6, 19000)))))

    def test_stops_at_active_with_length_still_above_limit(self):
        got = roll(now=LATE, len_word=1010, epochs=((1, 19000), (2, 19000), (5, 19000), (6, 19000)))
        self.assertEqual(names(got).count("pop"), 2)
        self.assertEqual(state(got, tool.S_EPOCHS + 0x10), 1009)

    def test_new_active_bounds_the_prune(self):
        got = roll(now=LATE, active=0, force=1, len_word=1010, cur=2, epochs=((1, 19000), (2, 19000), (5, 19000)))
        self.assertEqual(names(got).count("pop"), 1)

    def test_force_prunes_against_the_old_active(self):
        got = run(len_word=1000, epochs=((2, 19000), (5, 19000), (6, 19000)), epoch=9)
        self.assertEqual(names(got).count("pop"), 1)
        self.assertEqual(state(got, tool.S_ACTIVE), 9)

    def test_date_zero_row_is_not_dropped(self):
        got = roll(now=LATE, len_word=1000, epochs=((2, 0), (5, 19000)))
        self.assertIn("pop", names(got))
        self.assertNotIn("drop_map", names(got))

    def test_root_shrink(self):
        got = roll(now=LATE, len_word=1000, active=9, e_shape="deep", epochs=tool.SIXTEEN_EPOCHS[:13], shrink=(True,))
        self.assertEqual(state(got, tool.S_EPOCHS + 8), 0)


class Lookup(unittest.TestCase):
    def test_returns_the_hot_user(self):
        got = run(tool.LOOKUP, target=5, lookup=3)
        self.assertEqual(status(got), 0x186)
        self.assertEqual(bytes(got[2][tool.OUT + 2 - tool.HEAP_BASE:tool.OUT + 22 - tool.HEAP_BASE]), tool.user_of(3))

    def test_refusals(self):
        self.assertEqual(status(run(tool.LOOKUP, target=4)), 0x97)
        self.assertEqual(status(run(tool.LOOKUP, target=5, lookup=9)), 0x94)
        self.assertEqual(status(run(tool.LOOKUP, target=5, v_null=True)), 0x94)


class LastKey(unittest.TestCase):
    def test_last_key(self):
        self.assertEqual(run(tool.LAST)[1], (1, 6))
        self.assertEqual(run(tool.LAST, e_shape="tall", epochs=tool.SIXTEEN_EPOCHS)[1], (1, 15))

    def test_empty(self):
        self.assertEqual(run(tool.LAST, epochs=(), l_null=True)[1][0], 0)
        self.assertEqual(run(tool.LAST, len_word=0, l_zero=True)[1][0], 0)


class Tracker(unittest.TestCase):
    def test_existing_row_refuses(self):
        self.assertEqual(status(run(tool.TRACK, target=5, tracked=(1, 5, 9))), 0x9A)

    def test_new_row_is_empty_and_flagged(self):
        got = run(tool.TRACK, target=4, tracked=(1, 5, 9))
        self.assertEqual(status(got), 0x186)
        row = event(got, "vacant")
        self.assertEqual((row[2], row[4]), (4, 1))
        self.assertEqual(row[5], bytes(24) + b"\x00\x01")


class Tables(unittest.TestCase):
    def test_field_names(self):
        rows = {(row[0], row[3]): row[4] for row in tool.field_rows(IMAGE)}
        self.assertEqual(rows[("Staking", "active_epoch")], "0x48")
        self.assertEqual(rows[("Staking", "cur_epoch")], "0x50")
        self.assertEqual(rows[("ValidatorState", "hot_user")], "0x18")
        self.assertEqual(rows[("ValidatorState", "cold_user")], "0x2c")
        self.assertEqual(rows[("ForceIncreaseEpochAction", "nonce")], "0x20")

    def test_field_table_refuses_a_changed_key(self):
        with self.assertRaises(tool.EvidenceError):
            tool.field_rows(corrupted(0x58A79F, 0x41))

    def test_field_table_refuses_a_changed_offset(self):
        with self.assertRaises(tool.EvidenceError):
            tool.field_rows(corrupted(0x3365DE6, 0x2D))

    def test_constant_table_refuses_a_changed_limit(self):
        with self.assertRaises(tool.EvidenceError):
            tool.constant_rows(corrupted(0x3368458, 0x12))

    def test_constant_table_refuses_a_changed_string(self):
        with self.assertRaises(tool.EvidenceError):
            tool.constant_rows(corrupted(0x58C012, 0x46))

    def test_status_text(self):
        rows = {row[0]: row[2] for row in tool.status_rows(IMAGE)}
        self.assertEqual(rows["0x99"], "Quorum not reached")
        self.assertEqual(rows["0x98"], "Force increase epoch failed")
        self.assertEqual(rows["0x11f"], "Signer does not match expected user")

    def test_callers(self):
        rows = {row[1]: row[3] for row in tool.caller_rows(IMAGE)}
        self.assertEqual(rows, {"force_increase_epoch": 3, "last_epoch_key": 6, "validator_user": 2, "advance_epoch": 5, "stake_quorum": 8, "signature_tracker_slot": 6, "signed_tuple_encode": 4})

    def test_caller_table_refuses_a_lost_call(self):
        with self.assertRaises(tool.EvidenceError):
            tool.caller_rows(corrupted(0x3368E49, 0x90))

    def test_calendar_rows(self):
        rows = {row[0]: row for row in RESULT["calendar"]}
        self.assertEqual(rows["2000-03-01"][3], 951868800)
        self.assertEqual(rows["9999-12-31"][3], 253402214400)
        self.assertTrue(all(row[4:] == (1, 0) for row in RESULT["calendar"]))


class Mutants(unittest.TestCase):
    def test_strict_quorum_compare_is_needed(self):
        case = tool.Case("t", tool.QUORUM, target=5, validators=(1, 2, 3), stakes=((1, 2), (2, 2), (3, 2)), set_keys=(1, 2))
        self.assertFalse(mutated({}, case))
        self.assertTrue(mutated({0x336739E: 0x93}, case))

    def test_signature_limit_is_needed(self):
        self.assertTrue(mutated({0x3368458: 0x12}, tool.Case("t", tool.FORCE, n_word=10001)))

    def test_chain_id_is_needed(self):
        self.assertTrue(mutated({0x3368AB7: 0x38}, tool.Case("t", tool.FORCE)))

    def test_source_base_is_needed(self):
        self.assertTrue(mutated({0x3368780: 0x63}, tool.Case("t", tool.FORCE)))

    def test_prune_bound_is_needed(self):
        self.assertTrue(mutated({0x3369A1F: 0xE8}, tool.Case("t", tool.ROLL, now=LATE, len_word=999)))

    def test_active_store_is_needed(self):
        self.assertTrue(mutated({0x3368E59: 0x50}, tool.Case("t", tool.FORCE)))

    def test_evaluator_fails_on_an_unmodelled_call(self):
        harness = tool.Harness(IMAGE)
        del harness.machine.calls[tool.CLONE_VALIDATORS]
        with self.assertRaises(tool.Halt):
            harness.run(tool.Case("t", tool.ROLL, now=LATE))

    def test_spec_notices_a_changed_fixture_byte(self):
        case = tool.Case("t", tool.FORCE)
        got = HARNESS.run(case)
        want = tool.spec_run(case, HARNESS.before, HARNESS.where)
        broken = bytearray(want[2])
        broken[0] ^= 1
        self.assertNotEqual(got, (want[0], want[1], bytes(broken)))


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
        self.assertEqual(data["functions"]["force_increase_epoch"]["bytes"], 3378)

    def test_mutation_table_is_explained(self):
        rows = [line.split("\t") for line in (FOLDER / "mutations.tsv").read_text().splitlines()[1:]]
        self.assertTrue(rows)
        for row in rows:
            if row[2] == "survived":
                self.assertNotEqual(row[3], "UNEXPLAINED")

    def test_manifest(self):
        for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)


if __name__ == "__main__":
    unittest.main()
