"""Tests for tools/spot_genesis_staging.py: real node #94 bytes with corruption controls."""

import copy
import hashlib
import importlib.util
import json
import pathlib
import struct
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FOLDER = ROOT / "research" / "work-items" / "RE-004-spot-genesis-staging-94"
spec_ = importlib.util.spec_from_file_location("spot_genesis_staging", ROOT / "tools" / "spot_genesis_staging.py")
tool = importlib.util.module_from_spec(spec_)
sys.modules["spot_genesis_staging"] = tool
spec_.loader.exec_module(tool)

IMAGE = None
HARNESS = None
RESULT = None
U = tool.U
TOP = 0xFFFFFFFFFFFFFFFF


def setUpModule():
    global IMAGE, HARNESS, RESULT
    IMAGE = tool.load_image()
    RESULT = tool.analyse(IMAGE, mutate=False, vectors=60)
    HARNESS = tool.Harness(IMAGE)


def run(entry, **fields):
    case = tool.Case("t", entry, **fields)
    before, got = HARNESS.run(case)
    want = tool.spec_run(case, before)
    assert tool.same(got, want), (got[:4], want[:4])
    return got


def word(got):
    return struct.unpack_from("<H", got[1])[0]


def flag(got):
    return got[1][2]


def text(got):
    at, size = struct.unpack_from("<QQ", got[1], 8)
    return bytes(IMAGE.blob[IMAGE.offset(at):IMAGE.offset(at) + size]).decode()


def row(got, token):
    return next(item for item in got[2] if item[0] == token)


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
        for target, size in ((tool.CAP_GATE, 1115), (tool.BLACK_GATE, 943), (tool.STORE_USERS, 538), (tool.STORE_TOKENS, 521), (tool.BLACK_SET, 462)):
            start, end = IMAGE.exact_fde(target)
            self.assertEqual((start, end - start), (target, size))

    def test_address_inside_a_function_is_not_a_start(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.exact_fde(tool.CAP_GATE + 1)


class Caps(unittest.TestCase):
    def test_empty_action_is_admitted(self):
        got = run(tool.CAP_GATE)
        self.assertEqual((word(got), flag(got)), (tool.OK, 1))

    def test_list_count_bound_is_exclusive_at_10001(self):
        self.assertEqual(flag(run(tool.CAP_GATE, n=10001, m=0)), 0)
        self.assertEqual(flag(run(tool.CAP_GATE, users=tuple((0x100000 + i, 1) for i in range(10000)), model=True)), 1)

    def test_token_row_count_bound(self):
        self.assertEqual(flag(run(tool.CAP_GATE, m=3, tokens=((1, 1), (2, 1), (3, 1)))), 0)
        self.assertEqual(flag(run(tool.CAP_GATE, tokens=((1, 1), (2, 1)))), 1)

    def test_count_is_cumulative_over_stored_users(self):
        self.assertEqual(flag(run(tool.CAP_GATE, users=tool.users(1), seed_users=9999, model=True)), 1)
        self.assertEqual(flag(run(tool.CAP_GATE, users=tool.users(1), seed_users=10000, model=True)), 0)

    def test_repeat_of_a_stored_user_does_not_count(self):
        self.assertEqual(flag(run(tool.CAP_GATE, users=((U[2], 1),), seed_users=9999, state={7: tool.rec(tool.users(2))}, model=True)), 1)

    def test_all_ones_address_never_counts(self):
        self.assertEqual(flag(run(tool.CAP_GATE, users=((tool.ONES, 1),), seed_users=10000, model=True)), 1)
        self.assertEqual(flag(run(tool.CAP_GATE, keep_seeded=True, seed_users=10000, model=True)), 1)

    def test_distinct_tokens_are_cumulative(self):
        stored = {7: tool.rec((), ((1, 9), (2, 9)))}
        self.assertEqual(flag(run(tool.CAP_GATE, tokens=((1, 1),), state=stored)), 1)
        self.assertEqual(flag(run(tool.CAP_GATE, tokens=((3, 1),), state=stored)), 0)

    def test_token_bound_is_a_separate_refusal(self):
        got = run(tool.CAP_GATE, tokens=((64, 1),))
        self.assertEqual(word(got), tool.TAG_TOKEN)
        self.assertEqual(flag(run(tool.CAP_GATE, tokens=((63, 1),))), 1)

    def test_user_limit_comes_before_the_token_bound(self):
        got = run(tool.CAP_GATE, users=tool.users(1), seed_users=10000, tokens=((64, 1),), model=True)
        self.assertEqual((word(got), flag(got)), (tool.OK, 0))

    def test_bad_token_beats_a_late_third_token(self):
        got = run(tool.CAP_GATE, tokens=((3, 1), (64, 1)), state={7: tool.rec((), ((1, 9), (2, 9)))})
        self.assertEqual(word(got), tool.TAG_TOKEN)

    def test_stored_three_tokens_refuse_with_no_rows(self):
        self.assertEqual(flag(run(tool.CAP_GATE, state={7: tool.rec((), ((1, 9), (2, 9), (3, 9)))})), 0)

    def test_gates_write_no_map(self):
        state = {7: tool.rec(tool.users(1), ((1, 1),))}
        self.assertEqual(run(tool.CAP_GATE, users=tool.users(2), state=state)[2], tool.flat({7: (state[7][0], state[7][1], set())}))


class Blacklist(unittest.TestCase):
    def test_no_list_and_a_held_user(self):
        got = run(tool.BLACK_GATE, users=tool.users(2), state={7: tool.rec((), (), (U[2],))})
        self.assertEqual(word(got), tool.TAG_TEXT)
        self.assertIn("for blacklisted user", text(got))

    def test_held_user_of_another_token_is_ignored(self):
        self.assertEqual(word(run(tool.BLACK_GATE, users=tool.users(2), state={8: tool.rec((), (), (U[2],))})), tool.OK)

    def test_list_bound(self):
        self.assertEqual(word(run(tool.BLACK_GATE, black=((U[1], 1),) * 1000)), tool.OK)
        self.assertEqual(text(run(tool.BLACK_GATE, black=((U[1], 1),) * 1001)), "blacklist users to update exceeds 1000")

    def test_list_bound_comes_before_the_row_rule(self):
        self.assertIn("exceeds 1000", text(run(tool.BLACK_GATE, black=((U[1], 1),) * 1001, users=tool.users(1))))

    def test_rows_in_the_same_action_are_refused(self):
        self.assertIn("is non-empty", text(run(tool.BLACK_GATE, black=(), users=tool.users(1))))
        self.assertIn("is non-empty", text(run(tool.BLACK_GATE, black=(), tokens=((1, 1),))))

    def test_stored_balances_do_not_block_a_list(self):
        self.assertEqual(word(run(tool.BLACK_GATE, black=((U[1], 1),), state={7: tool.rec(tool.users(1), ((1, 1),))})), tool.OK)

    def test_held_scan_is_skipped_with_a_list(self):
        self.assertEqual(word(run(tool.BLACK_GATE, black=(), state={7: tool.rec((), (), (U[2],))})), tool.OK)


class Writers(unittest.TestCase):
    def test_repeat_keeps_the_last_amount_and_does_not_add(self):
        got = run(tool.STORE_USERS, users=((U[1], 5), (U[1], 9)))
        self.assertEqual(row(got, 7)[1], ((tool.address(U[1]), 9),))

    def test_overwrite_of_a_stored_amount(self):
        got = run(tool.STORE_USERS, users=((U[1], 9),), state={7: tool.rec(((U[1], 5),))})
        self.assertEqual(row(got, 7)[1], ((tool.address(U[1]), 9),))

    def test_amount_words_are_kept_whole(self):
        for wei in (0, TOP):
            self.assertEqual(row(run(tool.STORE_USERS, users=((U[1], wei),)), 7)[1][0][1], wei)

    def test_no_rows_makes_no_record(self):
        self.assertEqual(run(tool.STORE_USERS)[2], ())
        self.assertEqual(run(tool.STORE_TOKENS)[2], ())

    def test_token_rows_overwrite(self):
        self.assertEqual(row(run(tool.STORE_TOKENS, tokens=((3, 8), (3, 9))), 7)[2], ((3, 9),))

    def test_once_word_only_matters_on_a_changed_amount(self):
        self.assertEqual(run(tool.STORE_USERS, once=1, users=((U[1], 9),), state={7: tool.rec(((U[1], 5),))})[3], ("once",))
        self.assertEqual(run(tool.STORE_USERS, once=1, users=((U[1], 5),), state={7: tool.rec(((U[1], 5),))})[3], ())

    def test_tree_helpers_grow_and_split(self):
        got = run(tool.STORE_USERS, users=tool.users(*range(20)))
        self.assertEqual(len(row(got, 7)[1]), 20)


class BlacklistRows(unittest.TestCase):
    def test_empty_list_still_makes_a_record(self):
        self.assertEqual(row(run(tool.BLACK_SET, black=()), 7)[1:], ((), (), ()))

    def test_add_drops_the_balance(self):
        got = row(run(tool.BLACK_SET, black=((U[1], 1),), state={7: tool.rec(tool.users(1, 2))}), 7)
        self.assertEqual([key for key, _ in got[1]], [tool.address(U[2])])
        self.assertEqual(got[3], (tool.address(U[1]),))

    def test_remove_keeps_the_balance(self):
        got = row(run(tool.BLACK_SET, black=((U[1], 0),), state={7: tool.rec(tool.users(1), (), (U[1],))}), 7)
        self.assertEqual((len(got[1]), got[3]), (1, ()))

    def test_token_rows_are_never_touched(self):
        self.assertEqual(row(run(tool.BLACK_SET, black=((U[1], 1),), state={7: tool.rec(tool.users(1), ((3, 4),))}), 7)[2], ((3, 4),))

    def test_flag_is_zero_or_any_other_byte(self):
        for value in (1, 2, 255):
            self.assertEqual(row(run(tool.BLACK_SET, black=((U[1], value),)), 7)[3], (tool.address(U[1]),))

    def test_rows_apply_in_order(self):
        self.assertEqual(row(run(tool.BLACK_SET, black=((U[1], 1), (U[1], 0))), 7)[3], ())
        self.assertEqual(row(run(tool.BLACK_SET, black=((U[1], 0), (U[1], 1))), 7)[3], (tool.address(U[1]),))

    def test_rows_with_balances_of_another_token_stay(self):
        got = run(tool.BLACK_SET, black=((U[1], 1),), state={7: tool.rec(), 8: tool.rec(tool.users(1))})
        self.assertEqual(len(row(got, 8)[1]), 1)


class Names(unittest.TestCase):
    def test_texts_from_bytes(self):
        texts = {name: value for name, _, _, value in tool.text_rows(IMAGE)}
        self.assertEqual(texts["genesis_limit"], "at most 10000 genesis users and 2 anchor tokens are allowed")
        self.assertEqual(texts["too_many_blacklist"], "blacklist users to update exceeds 1000")

    def test_serde_names(self):
        self.assertEqual([text_row[1] for text_row in tool.serde_rows(IMAGE)], [item.decode() for item in tool.SERDE])

    def test_corrupt_serde_name_is_refused(self):
        blob = bytes(IMAGE.blob)
        bad = copy.copy(IMAGE)
        bad.blob = blob.replace(tool.SERDE[0], b"X" * len(tool.SERDE[0]))
        with self.assertRaises(tool.EvidenceError):
            tool.serde_rows(bad)

    def test_kept_address_constant(self):
        self.assertEqual(tool.constant_rows(IMAGE)[0][1], "ff" * 20)

    def test_corrupt_kept_address_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.constant_rows(corrupted(tool.KEEP_AT + 3, 0))

    def test_slots_hold_the_targets(self):
        rows = tool.slot_rows(IMAGE)
        self.assertEqual([row_[0] for row_ in rows], ["%#x" % target for target in tool.TARGETS])
        self.assertTrue(all(row_[4] >= 3 for row_ in rows))

    def test_wrong_slot_is_refused(self):
        saved = dict(tool.SLOTS)
        tool.SLOTS[tool.CAP_GATE] = saved[tool.BLACK_GATE]
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.slot_rows(IMAGE)
        finally:
            tool.SLOTS.update(saved)


class Controls(unittest.TestCase):
    def test_limit_edit_is_seen(self):
        case = tool.Case("c", tool.CAP_GATE, users=tuple((0x100000 + i, 1) for i in range(10000)), model=True)
        self.assertTrue(mutated({0x371F272: 0x10}, case))

    def test_cumulative_limit_edit_is_seen(self):
        case = tool.Case("c", tool.CAP_GATE, users=tool.users(1), seed_users=10000, model=True)
        self.assertTrue(mutated({0x371F4C3: 0x11}, case))

    def test_branch_edit_on_the_keep_row_is_seen(self):
        case = tool.Case("c", tool.BLACK_SET, black=((U[1], 1),), state={7: tool.rec(tool.users(1))})
        self.assertTrue(mutated({0x3721756: 0x74}, case))

    def test_unedited_case_passes_the_same_check(self):
        case = tool.Case("c", tool.BLACK_SET, black=((U[1], 1),), state={7: tool.rec(tool.users(1))})
        self.assertFalse(mutated({}, case))

    def test_a_tree_with_a_bad_order_is_refused(self):
        harness = tool.Harness(IMAGE)
        harness.fresh(tool.Case("c", tool.CAP_GATE, state={7: tool.rec(tool.users(1, 2))}))
        memory = harness.machine.memory
        root = memory.read(tool.ROOT_AT, 8)
        users = memory.read(root + 0x60, 8)
        memory.put_bytes(users + tool.L_USERS.key_at, b"\xff" * 20)
        with self.assertRaises(tool.Halt):
            harness.state_now()


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
        self.assertFalse([row_ for row_ in survivors if row_[3] == "UNEXPLAINED"])

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

    def test_folder_holds_only_the_generated_set(self):
        names = {path.name for path in FOLDER.iterdir()}
        self.assertEqual(names, {"README.md", "MANIFEST.sha256", "evidence.json", "function-rows.tsv", "texts.tsv", "serde.tsv", "constants.tsv", "slots.tsv", "outcomes.tsv", "mutations.tsv"})

    def test_no_external_tool_is_called(self):
        text_ = (ROOT / "tools" / "spot_genesis_staging.py").read_text()
        self.assertNotIn("subprocess", text_)


if __name__ == "__main__":
    unittest.main()
