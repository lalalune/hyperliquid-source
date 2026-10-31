"""Tests for tools/outcome_deploy_action.py. Expected numbers here are literals, not calls to the tool's closed forms."""
import hashlib
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import outcome_deploy_action as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-004-outcome-deploy-action-94"
TOP = 2 ** 64 - 1
ONE = 0x3FF0000000000000
HANDLERS = (0x2749880, 0x4D66400, 0x4D67E10)
WRAPS = (0x274B290, 0x4D69820, 0x4D69AE0)


class Shared:
    image = None
    harness = None
    full = None


def image_get():
    if Shared.image is None:
        Shared.image = tool.load_image()
    return Shared.image


def harness_get():
    if Shared.harness is None:
        Shared.harness = tool.Harness(image_get())
    return Shared.harness


def full_get():
    if Shared.full is None:
        Shared.full = tool.render(tool.analyse(image_get()))
    return Shared.full


def run(entry=HANDLERS[0], **fields):
    case = tool.Case("t", entry=entry, **fields)
    before, got = harness_get().run(case)
    want = tool.spec_run(case, before)
    if got[:5] != want[:5]:
        raise AssertionError(tool.diff_text(got, want))
    return case, got


def word_at(got, address, size=8):
    at = address - tool.HEAP_BASE
    return int.from_bytes(got[1][at:at + size], "little")


def out_tag(**fields):
    """(result byte, tag) of a handler run; tag 0 for the ok forms."""
    _, got = run(**fields)
    first = word_at(got, tool.OUT, 1)
    return first, word_at(got, tool.OUT + 8, 2) if first == 0xE else 0


def words(got, address, count):
    return [word_at(got, address + 8 * index) for index in range(count)]


def flip(va, mask=1):
    image = image_get()
    return {va: image.blob[image.offset(va)] ^ mask}


def fails(patch, entry=HANDLERS[0], **fields):
    case = tool.Case("t", entry=entry, **fields)
    return tool.first_failure(tool.Harness(image_get(), patch), [case]) is not None


class Input(unittest.TestCase):
    def test_wrong_hash_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_changed_last_byte_is_refused(self):
        blob = bytearray(image_get().blob)
        blob[-1] ^= 1
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "copy"
            path.write_bytes(blob)
            with self.assertRaises(tool.EvidenceError):
                tool.load_image(path)

    def test_function_bounds_are_fde_starts(self):
        image = image_get()
        for target in tool.TARGETS:
            self.assertEqual(image.exact_fde(target)[0], target)
        with self.assertRaises(tool.EvidenceError):
            image.exact_fde(tool.GATE + 1)

    def test_address_outside_every_section_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            image_get().offset(0x7000000000)

    def test_no_function_named_in_the_packet_is_a_stub_for_itself(self):
        for target in tool.TARGETS:
            case = tool.Case("t", entry=target)
            if target == tool.NAME:
                case.nd_lens = (1, 1)
            harness_get().run(case)
            self.assertIn(target, harness_get().machine.real)


class Gates(unittest.TestCase):
    def test_system_user_or_chain_zero_only(self):
        for entry in HANDLERS:
            self.assertEqual(out_tag(entry=entry, arm=7, chain=3), (0xE, 0x8E))
            self.assertEqual(out_tag(entry=entry, arm=7, chain=1), (0xE, 0x8E))
            self.assertEqual(out_tag(entry=entry, arm=7, chain=0), (0xD, 0))
            self.assertEqual(out_tag(entry=entry, arm=7, chain=3, user=0), (0xD, 0))

    def test_every_user_byte_counts(self):
        self.assertEqual(out_tag(arm=7, chain=3, user=1), (0xE, 0x8E))
        self.assertEqual(out_tag(arm=7, chain=3, user=1 << 152), (0xE, 0x8E))
        self.assertEqual(out_tag(arm=7, chain=3, user=1 << 24), (0xE, 0x8E))

    def test_poison_comes_after_the_chain(self):
        self.assertEqual(out_tag(arm=7, chain=3, poison=1), (0xE, 0x8E))
        _, got = run(arm=7, poison=1)
        self.assertEqual(word_at(got, tool.OUT + 8, 2), 0x17D)
        self.assertEqual(word_at(got, tool.OUT + 10, 1), 7)

    def test_daily_limit_by_chain_byte(self):
        for arm in (1, 2):
            self.assertEqual(out_tag(arm=arm, user=0, chain=2, used=499), (0xD, 0))
            self.assertEqual(out_tag(arm=arm, user=0, chain=2, used=500), (0xE, 0x17B))
            self.assertEqual(out_tag(arm=arm, user=0, chain=3, used=49), (0xD, 0))
            self.assertEqual(out_tag(arm=arm, user=0, chain=3, used=50), (0xE, 0x17B))
            self.assertEqual(out_tag(arm=arm, user=0, chain=1, used=TOP), (0xD, 0))
            self.assertEqual(out_tag(arm=arm, user=0, chain=3, used=TOP), (0xE, 0x17B))

    def test_question_batch_counts_names_plus_fallback(self):
        self.assertEqual(out_tag(arm=3, user=0, chain=3, used=47, n=2), (0xD, 0))
        self.assertEqual(out_tag(arm=3, user=0, chain=3, used=48, n=2), (0xE, 0x17B))
        self.assertEqual(out_tag(arm=3, n=50), (0xD, 0))
        self.assertEqual(out_tag(arm=3, n=51), (0xE, 0x143))

    def test_lifetime_caps(self):
        self.assertEqual(out_tag(arm=3, nextq=9999), (0xD, 0))
        self.assertEqual(out_tag(arm=3, nextq=10000), (0xE, 0x17B))
        self.assertEqual(out_tag(arm=3, nexto=19997, n=2), (0xD, 0))
        self.assertEqual(out_tag(arm=3, nexto=19998, n=2), (0xE, 0x17B))
        self.assertEqual(out_tag(arm=3, nexto=TOP, n=2), (0xE, 0x17B))
        _, got = run(arm=3, nexto=20000)
        self.assertEqual(word_at(got, tool.OUT + 0x18), 14)

    def test_quote_bound_only_on_register_outcome(self):
        self.assertEqual(out_tag(arm=1, quote=9), (0xD, 0))
        self.assertEqual(out_tag(arm=1, quote=10), (0xE, 0xEA))
        self.assertEqual(out_tag(arm=2, quote=10), (0xD, 0))

    def test_token_amount_cap(self):
        self.assertEqual(out_tag(arm=0, x=0x0CCCCCCCCCCCCCCB), (7, 0))
        self.assertEqual(out_tag(arm=0, x=0x0CCCCCCCCCCCCCCC), (0xE, 0x13F))
        _, got = run(arm=0, x=TOP)
        self.assertEqual(word_at(got, tool.OUT + 0x10), TOP)
        _, got = run(arm=0, x=9, ret=0x77)
        self.assertEqual(word_at(got, tool.OUT + 8), 0x77)

    def test_settle_lengths(self):
        self.assertEqual(out_tag(arm=4, flen=100), (0xD, 0))
        self.assertEqual(out_tag(arm=4, flen=101), (0xE, 0x143))
        self.assertEqual(out_tag(arm=4, dlen=2000), (0xD, 0))
        self.assertEqual(out_tag(arm=4, dlen=2001), (0xE, 0x143))
        self.assertEqual(out_tag(arm=5, mlen=50), (0xD, 0))
        self.assertEqual(out_tag(arm=5, mlen=51), (0xE, 0x143))

    def test_missing_ids(self):
        self.assertEqual(out_tag(arm=4, oid=77), (0xE, 0xEC))
        self.assertEqual(out_tag(arm=6, oid=77), (0xE, 0xEC))
        self.assertEqual(out_tag(arm=7, oid=77), (0xE, 0xEC))
        self.assertEqual(out_tag(arm=5, qid=77), (0xE, 0xED))
        self.assertEqual(out_tag(arm=8, qid=77), (0xE, 0xED))
        self.assertEqual(out_tag(arm=9, qid=77), (0xE, 0xED))

    def test_all_three_copies_agree(self):
        cases = [dict(arm=arm) for arm in range(10)] + [dict(arm=3, n=51), dict(arm=1, user=0, chain=3, used=50), dict(arm=4, flen=101)]
        for fields in cases:
            self.assertEqual(len({out_tag(entry=entry, **fields) for entry in HANDLERS}), 1)

    def test_copy_rows_differ_in_the_chain_offset_only(self):
        rows, changed = tool.copy_rows(image_get())
        self.assertEqual(changed, {0x4D66445})
        self.assertEqual(rows[1][4], "")
        self.assertEqual(rows[0][1], 1307)


class Settlement(unittest.TestCase):
    def test_price_gate_in_the_wrapper(self):
        for entry in WRAPS:
            for bits in (0, 1 << 63, 1, 0x3FE0000000000000, ONE, ONE - 1):
                _, got = run(entry=entry, bits=bits)
                self.assertEqual(word_at(got, tool.OUT, 2), 0x186)
            for bits in (ONE + 1, 0x4000000000000000, (1 << 63) | 1, 0xBFF0000000000000, 0x7FF0000000000000, 0xFFF0000000000000, 0x7FF8000000000000, 0xFFF8000000000001, 0x7FF0000000000001):
                _, got = run(entry=entry, bits=bits)
                self.assertEqual(word_at(got, tool.OUT, 2), 0x17B)
                self.assertEqual(word_at(got, tool.OUT + 0x10), 24)

    def test_failed_settlement_sets_the_sticky_word(self):
        for entry, offset in zip(WRAPS, (0x8B8, 0x1338, 0x8B8)):
            _, got = run(entry=entry, settle=(0x11,))
            self.assertEqual(word_at(got, tool.OUT, 2), 0x140)
            self.assertEqual(word_at(got, tool.S + 0x1E8, 1), 1)
            self.assertIn(("insert", tool.S + offset), got[3])

    def test_system_failure_inserts_no_user(self):
        _, got = run(entry=WRAPS[0], settle=(0x11,), user=0)
        self.assertEqual(word_at(got, tool.OUT, 2), 0x140)
        self.assertFalse([event for event in got[3] if event[0] == "insert"])

    def test_winner_settles_the_fallback_to_zero_with_empty_details(self):
        _, got = run(entry=WRAPS[0], bits=ONE, gate=("some", 21), settle=(0x27, 0x27), oid=22)
        settles = [event for event in got[3] if event[0] == "settle"]
        self.assertEqual(settles[0][1:3], (22, ONE))
        self.assertEqual(settles[1][1:], (21, 0, 1))

    def test_gate_tiers(self):
        fields = dict(entry=tool.GATE, links={21: 41, 22: 41}, questions={41: dict(fallback=21, named=(22,))}, oid=22)
        _, got = run(bits=0, **fields)
        self.assertEqual((word_at(got, tool.OUT, 2), word_at(got, tool.OUT + 8)), (0x186, 0))
        _, got = run(bits=ONE, **fields)
        self.assertEqual((word_at(got, tool.OUT, 2), word_at(got, tool.OUT + 8), word_at(got, tool.OUT + 0x10)), (0x186, 1, 21))
        _, got = run(bits=0x3FE0000000000000, **fields)
        self.assertEqual((word_at(got, tool.OUT, 2), word_at(got, tool.OUT + 0x10)), (0x17B, 0x33))
        _, got = run(bits=1 << 63, **fields)
        self.assertEqual((word_at(got, tool.OUT, 2), word_at(got, tool.OUT + 8)), (0x186, 0))

    def test_one_needs_a_single_named_outcome_left(self):
        for count, tag in ((0, 0x17B), (1, 0x186), (2, 0x17B), (3, 0x17B), (18, 0x17B)):
            fields = dict(entry=tool.GATE, bits=ONE, links={22: 41}, oid=22, questions={41: dict(fallback=21, named=tuple(range(22, 22 + count)))})
            _, got = run(**fields)
            self.assertEqual(word_at(got, tool.OUT, 2), tag)

    def test_fallback_cannot_be_settled(self):
        _, got = run(entry=tool.GATE, links={21: 41}, oid=21, bits=0)
        self.assertEqual((word_at(got, tool.OUT, 2), word_at(got, tool.OUT + 0x10)), (0x17B, 0x1E))

    def test_unlinked_outcome_takes_any_fraction(self):
        for bits in (0x3FE0000000000000, ONE, 0):
            _, got = run(entry=tool.GATE, bits=bits)
            self.assertEqual((word_at(got, tool.OUT, 2), word_at(got, tool.OUT + 8)), (0x186, 0))

    def test_linked_to_lost_question_is_status_8(self):
        _, got = run(entry=tool.GATE, links={22: 42}, oid=22)
        self.assertEqual((word_at(got, tool.OUT, 2), word_at(got, tool.OUT + 2, 1)), (0x17D, 8))


class Records(unittest.TestCase):
    def test_name_and_text_lengths(self):
        for lengths, tag, payload in (((100, 2000), 0x186, None), ((101, 0), 0x143, 101), ((0, 2001), 0x143, 2001), ((101, 2001), 0x143, 101)):
            case = tool.Case("t", entry=tool.NAME, nd=(b"abcd", b"efgh"))
            case.nd_lens = lengths
            before, got = harness_get().run(case)
            self.assertEqual(got[:5], tool.spec_run(case, before)[:5])
            self.assertEqual(word_at(got, tool.OUT, 2), tag)
            if payload is not None:
                self.assertEqual(word_at(got, tool.OUT + 0x18), payload)

    def test_change_text_edge(self):
        for entry in (tool.DESC_Q, tool.DESC_O):
            _, got = run(entry=entry, dlen=2000)
            self.assertEqual(word_at(got, tool.OUT, 2), 0x186)
            _, got = run(entry=entry, dlen=2001)
            self.assertEqual(word_at(got, tool.OUT, 2), 0x143)

    def test_change_text_swaps_the_right_field(self):
        case, got = run(entry=tool.DESC_O, dlen=7)
        self.assertEqual(words(got, case.at_record[21] + 0x70, 3), [16, 0xCC00, 7])
        case, got = run(entry=tool.DESC_Q, dlen=7)
        self.assertEqual(words(got, case.at_record[41] + 0x20, 3), [16, 0xCC00, 7])

    def test_question_record(self):
        _, got = run(entry=tool.QBUILD, nextq=9999)
        self.assertEqual(word_at(got, tool.OUT + 0x68), 9999)
        self.assertEqual(word_at(got, tool.OUT + 0x70), 21)
        self.assertEqual(word_at(got, tool.OUT + 0x30), 21)
        self.assertEqual(word_at(got, tool.OUT + 0x38), 0)
        self.assertEqual(word_at(got, tool.OUT + 0x60), 0)
        _, got = run(entry=tool.QBUILD, nextq=10000)
        self.assertEqual((word_at(got, tool.OUT), word_at(got, tool.OUT + 8, 2)), (2 ** 63, 0x17B))

    def test_fallback_with_supply_is_status_9(self):
        for fail in ({0: 1}, {1: 1}, {0: 1 << 40}):
            _, got = run(entry=tool.QBUILD, fail=fail)
            self.assertEqual((word_at(got, tool.OUT + 8, 2), word_at(got, tool.OUT + 10, 1)), (0x17D, 9))

    def test_failed_side_lookup_is_status_8(self):
        _, got = run(entry=tool.QBUILD, fail={1: "error"})
        self.assertEqual((word_at(got, tool.OUT + 8, 2), word_at(got, tool.OUT + 10, 1)), (0x17D, 8))

    def test_circulation_is_supply_minus_system_row(self):
        for side, want in ((0, 6), (1, 6)):
            _, got = run(entry=tool.OPEN, side=side, supply={11: 9, 12: 8}, balances={11: 3, 12: 2})
            self.assertEqual(word_at(got, tool.OUT, 1), 0)
            self.assertEqual(word_at(got, tool.OUT + 8), want)
        self.assertEqual(word_at(run(entry=tool.OPEN, supply={11: 9, 12: 8})[1], tool.OUT + 8), 9)

    def test_circulation_codes(self):
        for fields, code in ((dict(oid=77), 4), (dict(), 0x16), (dict(supply={5: 1}), 0x16), (dict(supply={11: 9, 12: 8}, balances={11: 10, 12: 1}), 0x12)):
            _, got = run(entry=tool.OPEN, **fields)
            self.assertEqual((word_at(got, tool.OUT, 1), word_at(got, tool.OUT + 1, 1)), (1, code))

    def test_system_address_bytes(self):
        _, got = run(entry=tool.OPEN, supply={11: 9, 12: 8})
        self.assertIn(("spot user", 11), got[3])

    def test_question_id_counter(self):
        _, got = run(entry=tool.QINSERT, status=2 ** 63, nextq=8)
        self.assertEqual(word_at(got, tool.T + 0x138), 9)
        _, got = run(entry=tool.QINSERT, status=2 ** 63, nextq=TOP)
        self.assertEqual(word_at(got, tool.T + 0x138), TOP)

    def test_default_side_names(self):
        _, got = run(entry=tool.YESNO)
        self.assertEqual(words(got, tool.OUT, 6), [3, tool.ALLOC_AT, 3, 2, tool.ALLOC_AT + 0x10, 2])
        at = tool.ALLOC_AT - tool.HEAP_BASE
        self.assertEqual(got[1][at:at + 3], b"Yes")
        self.assertEqual(got[1][at + 0x10:at + 0x12], b"No")

    def test_duplicates(self):
        pool = {21: dict(name=b"alpha", desc=b"one"), 22: dict(name=b"beta", desc=b"two")}
        _, got = run(entry=tool.DUP_O, nd=(b"beta", b"two"), outcomes=pool)
        self.assertEqual((word_at(got, tool.OUT, 2), word_at(got, tool.OUT + 0x10)), (0x17B, 28))
        _, got = run(entry=tool.DUP_O, nd=(b"beta", b"two"), outcomes=pool, links={22: 41})
        self.assertEqual(word_at(got, tool.OUT, 2), 0x186)
        _, got = run(entry=tool.DUP_O, nd=(b"beta", b"one"), outcomes=pool)
        self.assertEqual(word_at(got, tool.OUT, 2), 0x186)
        questions = {41: dict(fallback=21, name=b"beta", desc=b"two")}
        _, got = run(entry=tool.DUP_Q, nd=(b"beta", b"two"), questions=questions)
        self.assertEqual((word_at(got, tool.OUT, 2), word_at(got, tool.OUT + 0x10)), (0x17B, 18))


class Controls(unittest.TestCase):
    """Each edit bends one fact; the rule list must then disagree, and the unedited bytes must agree."""

    def test_price_upper_bound(self):
        self.assertFalse(fails({}, WRAPS[0], bits=ONE + 1))
        self.assertTrue(fails(flip(0x274B325), WRAPS[0], bits=ONE + 1))

    def test_exact_one_gate(self):
        fields = dict(entry=tool.GATE, bits=0x3FE0000000000000, links={22: 41}, oid=22, questions={41: dict(fallback=21, named=(22,))})
        self.assertFalse(fails({}, **fields))
        self.assertTrue(fails(flip(0x3729FF0), **fields))

    def test_remaining_count(self):
        fields = dict(entry=tool.GATE, bits=ONE, links={22: 41}, oid=22, questions={41: dict(fallback=21, named=(22,))})
        self.assertFalse(fails({}, **fields))
        self.assertTrue(fails(flip(0x372A070), **fields))

    def test_name_bound(self):
        case = tool.Case("t", entry=tool.NAME, nd=(b"abcd", b"efgh"))
        case.nd_lens = (101, 0)
        self.assertIsNone(tool.first_failure(tool.Harness(image_get()), [case]))
        self.assertIsNotNone(tool.first_failure(tool.Harness(image_get(), flip(0x3C00F75, 2)), [case]))

    def test_text_bound(self):
        self.assertFalse(fails({}, arm=4, dlen=2001))
        self.assertTrue(fails(flip(0x274A2D2), arm=4, dlen=2001))

    def test_daily_constant(self):
        self.assertFalse(fails({}, arm=1, user=0, chain=2, used=500))
        self.assertTrue(fails(flip(0x2749E9C), arm=1, user=0, chain=2, used=500))

    def test_lifetime_constant(self):
        self.assertFalse(fails({}, arm=3, nexto=19998, n=2))
        self.assertTrue(fails(flip(0x2749D40), arm=3, nexto=19998, n=2))

    def test_fake_winner_row_is_noticed(self):
        self.assertTrue(fails(flip(0x274B382, 0x08), WRAPS[0], bits=ONE, gate=("some", 21), settle=(0x27, 0x27)))

    def test_control_edit_outside_reached_rows_changes_nothing(self):
        self.assertFalse(fails(flip(0x274B546), WRAPS[0]))

    def test_mutated_copy_chain_offset(self):
        self.assertFalse(fails({}, HANDLERS[1], arm=7, chain=0))
        self.assertTrue(fails(flip(0x4D66449, 8), HANDLERS[1], arm=7, chain=0))

    def test_limit_text_differs_by_copy(self):
        for entry, address in zip(HANDLERS, (0x3F0121, 0x715522, 0x715522)):
            _, got = run(entry=entry, arm=3, nextq=10000)
            self.assertEqual(word_at(got, tool.OUT + 0x10), address)


class Output(unittest.TestCase):
    def test_folder_holds_exactly_the_generated_set(self):
        files = full_get()
        names = {path.name for path in FOLDER.iterdir()}
        self.assertEqual(names, set(files) | {"README.md", "MANIFEST.sha256"})

    def test_generated_files_match(self):
        for name, text in full_get().items():
            self.assertEqual((FOLDER / name).read_text(encoding="ascii"), text, name)

    def test_manifest_matches(self):
        for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)

    def test_summary_numbers(self):
        summary = json.loads(full_get()["evidence.json"])
        self.assertGreater(summary["named_cases"], 400)
        self.assertEqual(summary["vector_cases"], 400)
        self.assertEqual(summary["functions"]["outcome_deploy"]["instructions"], 1307)
        self.assertEqual(summary["functions"]["settle_gate"]["address"], "0x3729df0")
        mutations = summary["mutations"]
        self.assertEqual(mutations["total"], mutations["killed"] + mutations["survived"])

    def test_no_survivor_is_unexplained(self):
        self.assertNotIn("UNEXPLAINED", full_get()["mutations.tsv"])

    def test_texts(self):
        text = full_get()["texts.tsv"]
        for line in ("too many outcomes deployed today", "Outcome already has supply", "cannot settle to 1 until all other outcomes are settled to 0", "question outcomes must be settled to exactly 0 or 1"):
            self.assertIn(line, text)


if __name__ == "__main__":
    unittest.main()
