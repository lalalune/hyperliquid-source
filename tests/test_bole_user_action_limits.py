"""Tests for tools/bole_user_action_limits.py. Expected numbers here are literals, not calls to the tool's closed forms."""
import hashlib
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import bole_user_action_limits as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-004-bole-user-action-limits-94"
TOP = 2 ** 64 - 1
HANDLERS = (0x2764D60, 0x4D95A70, 0x4D96040)
APPLIES = (0x2732AE0, 0x4D44AE0, 0x4D49EE0)
WRAPPERS = (0x28CC390, 0x4592880, 0x4592950)
BASE = 1793458200000


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


def run(entry, **fields):
    case = tool.Case("t", entry=entry, **fields)
    before, got = harness_get().run(case)
    want = tool.spec_run(case, before)
    if got[:5] != want[:5]:
        raise AssertionError(tool.diff_text(got, want))
    return case, got


def word_at(got, address, size=8):
    at = address - tool.HEAP_BASE
    return int.from_bytes(got[1][at:at + size], "little")


def status(entry, **fields):
    _, got = run(entry, **fields)
    return word_at(got, tool.OUT, 2)


def limiter(old, new, window, limit, count):
    case = tool.limit_case("t", old, new, window, limit, count)
    before, got = harness_get().run(case)
    want = tool.spec_run(case, before)
    if got[:5] != want[:5]:
        raise AssertionError(tool.diff_text(got, want))
    return word_at(got, tool.LREC), got[4]


def fails(patch, entry, **fields):
    case = tool.Case("t", entry=entry, **fields)
    return tool.first_failure(tool.Harness(image_get(), patch), [case]) is not None


def flip(va, mask=1):
    image = image_get()
    return {va: image.blob[image.offset(va)] ^ mask}


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
            image.exact_fde(tool.LIMIT + 1)

    def test_address_outside_every_section_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            image_get().offset(0x7000000000)

    def test_no_function_named_in_the_packet_is_a_stub(self):
        harness = harness_get()
        harness.select_calls(tool.REC_A)
        for target in (tool.LIMIT, tool.TIER, tool.PROBE_A, tool.REC_A):
            self.assertIn(target, harness.machine.real)


class Limiter(unittest.TestCase):
    def test_same_bucket_adds_one(self):
        self.assertEqual(limiter(BASE + 1500, BASE + 1999, 1000, 10, 3), (4, 1))

    def test_first_ms_of_next_bucket_resets(self):
        self.assertEqual(limiter(BASE + 999, BASE + 1000, 1000, 10, 3), (1, 1))

    def test_limit_is_inclusive(self):
        self.assertEqual(limiter(BASE, BASE + 1, 1000, 4, 3), (4, 1))
        self.assertEqual(limiter(BASE, BASE + 1, 1000, 3, 3), (4, 0))

    def test_refused_call_still_counts(self):
        self.assertEqual(limiter(BASE + 1, BASE + 2, 1000, 3, 7), (8, 0))

    def test_reset_with_limit_zero_is_refused_and_stored(self):
        self.assertEqual(limiter(BASE, BASE + 1000, 1000, 0, 7), (1, 0))

    def test_clock_moving_back_counts_and_stores_the_earlier_time(self):
        case, got = run(tool.LIMIT, rec=(3,) + tool.time_of(BASE + 5000), now=tool.time_of(BASE), window=1000)
        self.assertEqual(word_at(got, tool.LREC), 4)
        self.assertEqual(got[1][tool.LREC - tool.HEAP_BASE + 8:tool.LREC - tool.HEAP_BASE + 20], tool.stamp(case.now))

    def test_saturates(self):
        self.assertEqual(limiter(BASE, BASE + 1, 1000, TOP, TOP), (TOP, 1))

    def test_window_zero_divides_by_zero(self):
        _, got = run(tool.LIMIT, window=0)
        self.assertEqual(got[0], "fault")

    def test_bucket_is_by_window_multiples_not_distance(self):
        self.assertEqual(limiter(1999, 2000, 2000, 10, 5), (1, 1))
        self.assertEqual(limiter(2000, 3999, 2000, 10, 5), (6, 1))

    def test_both_divide_widths_agree(self):
        self.assertEqual(limiter(2 ** 32 + 1999, 2 ** 32 + 2000, 2000, 10, 5)[0], 6)
        self.assertEqual(limiter(1000, 3000, 2 ** 40, 10, 5)[0], 6)

    def test_mutants_change_the_answer(self):
        self.assertTrue(fails({0x37DA09F: 0x73}, tool.LIMIT, rec=(3,) + tool.time_of(BASE), now=tool.time_of(BASE + 1), window=1000))
        self.assertTrue(fails({0x37DA0C4 + 1: 0x92}, tool.LIMIT, limit=1))


class TwoWindows(unittest.TestCase):
    def setUp(self):
        self.new = tool.time_of(5000000000000)
        self.near = (9,) + tool.time_of(5000000000000 - 1)

    def test_either_window_admits(self):
        for entry in WRAPPERS:
            fields = dict(now=self.new, rec1=self.near, rec2=self.near, w1p=60000, w2p=3600000)
            self.assertEqual(status(entry, l1=9, l2=100, **fields), 0x186)
            self.assertEqual(status(entry, l1=100, l2=9, **fields), 0x186)
            self.assertEqual(status(entry, l1=9, l2=9, **fields), 0x170)

    def test_refusal_keeps_usage_but_counts_both_windows(self):
        for entry in WRAPPERS:
            _, got = run(entry, now=self.new, rec1=self.near, rec2=self.near, l1=9, l2=9, w1p=60000, w2p=3600000, usage=3, total=4)
            self.assertEqual(word_at(got, tool.REC_AT), 10)
            self.assertEqual(word_at(got, tool.REC_AT + 0x18), 10)
            self.assertEqual(word_at(got, tool.REC_AT + 0x30), 3)

    def test_pass_bumps_usage_and_total_with_saturation(self):
        _, got = run(0x28CC390, usage=TOP, total=5)
        self.assertEqual(word_at(got, tool.REC_AT + 0x30), TOP)
        self.assertEqual(word_at(got, tool.S + 0x7D0), 6)

    def test_shifted_copy_uses_the_shifted_total(self):
        _, got = run(0x4592880, total=5)
        self.assertEqual(word_at(got, tool.S + 0x1250), 6)
        self.assertEqual(word_at(got, tool.S + 0x7D0), 5)


class Tier(unittest.TestCase):
    def setUp(self):
        self.near = (5,) + tool.NOW
        self.later = (tool.NOW[0], tool.NOW[1], tool.NOW[2] + 1000000)

    def test_user_then_global(self):
        self.assertEqual(run(tool.TIER, urec=self.near, ul=6, grec=self.near, gl=6, now=self.later)[1][4], 10)
        self.assertEqual(run(tool.TIER, urec=self.near, ul=5, grec=self.near, gl=100, now=self.later)[1][4], 7)
        self.assertEqual(run(tool.TIER, urec=self.near, ul=100, grec=self.near, gl=5, now=self.later)[1][4], 7)

    def test_user_refusal_does_not_touch_the_global_word(self):
        _, got = run(tool.TIER, urec=self.near, ul=5, grec=self.near, gl=100, now=self.later)
        self.assertEqual(word_at(got, tool.B + 0x90), 5)

    def test_global_refusal_keeps_the_user_count(self):
        case, got = run(tool.TIER, urec=self.near, ul=100, grec=self.near, gl=5, now=self.later)
        self.assertEqual(word_at(got, case.addr["user_value"]), 6)
        self.assertEqual(word_at(got, tool.B + 0x90), 6)

    def test_missing_user_gets_a_1970_record(self):
        _, got = run(tool.TIER, u_shape="miss", ul=1, now=self.later)
        self.assertEqual(got[3], (("insert",),))
        self.assertEqual(got[4], 10)

    def test_every_tree_shape(self):
        for shape, event in (("leaf", ()), ("deep", ()), ("deep left", ()), ("miss", (("insert",),)), ("empty", (("insert",),)), ("short", (("insert",),))):
            self.assertEqual(run(tool.TIER, u_shape=shape, now=self.later)[1][3], event)


class Record(unittest.TestCase):
    def test_hit_returns_the_word_after_the_key(self):
        for entry in (tool.REC_A, tool.REC_B):
            _, got = run(entry, table=((11, 0x5B, tool.USER),))
            self.assertEqual(got[4], tool.CTRL - 0xE0 * 12 + 0x18)

    def test_insert_writes_both_windows_at_1970(self):
        for entry in (tool.REC_A, tool.REC_B):
            _, got = run(entry)
            at = tool.CTRL - 0xE0 * 12
            self.assertEqual(got[4], at + 0x18)
            self.assertEqual(word_at(got, at + 0x18), 0)
            self.assertEqual(word_at(got, at + 0x20, 4), tool.EPOCH)
            self.assertEqual(word_at(got, at + 0x38, 4), tool.EPOCH)
            self.assertEqual(word_at(got, at + 0x48), 0)

    def test_tombstone_does_not_spend_growth(self):
        _, got = run(tool.REC_A, table=((11, 0x80, None),), grow_left=5)
        self.assertEqual(word_at(got, tool.S + 0x780), 5)
        _, got = run(tool.REC_A, grow_left=5)
        self.assertEqual(word_at(got, tool.S + 0x780), 4)

    def test_grow_only_on_a_miss(self):
        self.assertIn(("grow",), run(tool.REC_A, grow_left=0)[1][3])
        self.assertNotIn(("grow",), run(tool.REC_A, grow_left=0, table=((11, 0x5B, tool.USER),))[1][3])

    def test_mirror_is_written_for_a_low_slot(self):
        _, got = run(tool.REC_B, hash=(tool.ROUTE_HASH & ~63) | 2)
        self.assertEqual(word_at(got, tool.CTRL + 2, 1), 0x5B)
        self.assertEqual(word_at(got, tool.CTRL + 66, 1), 0x5B)


class Core(unittest.TestCase):
    def inner(self, **fields):
        _, got = run(tool.CORE, **fields)
        self.assertEqual(word_at(got, tool.OUT), 3)
        return word_at(got, tool.OUT + 8, 1)

    def test_selector_table(self):
        self.assertEqual(self.inner(sel=0, a=0), 8)
        self.assertEqual(self.inner(sel=0, a=1, c=1), 8)
        self.assertEqual(self.inner(sel=0, a=1, b=1), 4)
        self.assertEqual(self.inner(sel=1, a=0), 8)
        self.assertEqual(self.inner(sel=2, a=0), 8)
        self.assertEqual(self.inner(sel=3, a=0), 8)
        self.assertEqual(self.inner(sel=3, a=1, c=1), 8)

    def test_only_selector_0_reads_the_supply_only_flag(self):
        for sel in (1, 2, 3):
            self.assertEqual(word_at(run(tool.CORE, sel=sel, b=1)[1], tool.OUT), 0)

    def test_selector_1_and_2_ignore_flag_c(self):
        for sel in (1, 2):
            self.assertEqual(word_at(run(tool.CORE, sel=sel, c=1)[1], tool.OUT), 0)

    def test_spot_room_edges(self):
        self.assertEqual(word_at(run(tool.CORE, changed=900, bal=(1000, 100, 7))[1], tool.OUT), 0)
        self.assertEqual(self.inner(changed=901, bal=(1000, 100, 7)), 10)
        self.assertEqual(self.inner(changed=TOP, bal=(TOP, 2, 7)), 10)
        self.assertEqual(self.inner(changed=1, bal=(5, 10, 7)), 10)

    def test_room_needs_an_increase(self):
        self.assertEqual(word_at(run(tool.CORE, inc=0, changed=TOP)[1], tool.OUT), 0)
        self.assertEqual(word_at(run(tool.CORE, core_tag=2, changed=TOP)[1], tool.OUT), 2)

    def test_absent_row_is_zero_room(self):
        self.assertEqual(self.inner(bal_shape="empty", changed=1), 10)
        self.assertEqual(word_at(run(tool.CORE, bal_shape="empty", changed=0)[1], tool.OUT), 0)

    def test_absent_user_uses_the_shared_default(self):
        _, got = run(tool.CORE, u_shape="miss")
        self.assertEqual(got[3][0][1], 0x5786350)


class Apply(unittest.TestCase):
    def test_results(self):
        for entry in APPLIES:
            self.assertEqual(status(entry), 0x186)
            self.assertEqual(status(entry, core_tag=2), 0xE2)
            self.assertEqual(status(entry, changed=0), 0xE2)
            self.assertEqual(status(entry, apply=0x10), 0xE1)
            self.assertEqual(word_at(run(entry, apply=0x10)[1], tool.OUT + 2, 1), 10)
            self.assertEqual(word_at(run(entry, core_tag=3, core_byte=6)[1], tool.OUT + 2, 1), 6)

    def test_all_with_zero_word_stops_first(self):
        _, got = run(0x2732AE0, w0=1, w1=0)
        self.assertEqual(got[3], ())

    def test_lock_word_returns(self):
        for lock, final in ((0, 0), (3, 3), (TOP, TOP - 1)):
            self.assertEqual(word_at(run(0x2732AE0, lock=lock)[1], tool.S + 0x58), final)

    def test_flag_is_word_equal_to_one(self):
        for word, flag in ((1, 1), (0, 0), (2, 0), (0x101, 0)):
            self.assertEqual(run(0x2732AE0, vault_shape="leaf", vault_word=word)[1][3][1][5], flag)

    def test_shifted_copy_reads_the_shifted_map(self):
        self.assertEqual(run(0x4D44AE0, vault_shape="leaf", vault_word=1)[1][3][1][5], 1)


class Handler(unittest.TestCase):
    def test_portfolio_margin_gate(self):
        for entry in HANDLERS:
            self.assertEqual(status(entry, cls=4, f5b0=0), 0x173)
            self.assertEqual(status(entry, cls=4, f5b0=1), 0x186)
            self.assertEqual(status(entry, cls=3, f5b0=0), 0x186)

    def test_rate_limit_comes_before_the_asset(self):
        for entry in HANDLERS:
            _, got = run(entry, asset_shape="miss", urec=(5,) + tool.NOW, ul=5)
            self.assertEqual(word_at(got, tool.OUT + 2, 1), 7)
            _, got = run(entry, asset_shape="miss")
            self.assertEqual(word_at(got, tool.OUT + 2, 1), 0)

    def test_vault_rule(self):
        for entry in HANDLERS:
            self.assertEqual(status(entry, vault_shape="leaf", op=0, sel=0, asset=0), 0x15)
            self.assertEqual(status(entry, vault_shape="leaf", op=2, sel=2, asset=0), 0x15)
            self.assertEqual(status(entry, vault_shape="leaf", op=1, asset=5), 0x15)
            self.assertEqual(status(entry, vault_shape="leaf", op=3, sel=3, asset=0, vault_flag=0), 0x15)
            self.assertEqual(status(entry, vault_shape="leaf", op=1, asset=0), 0x186)
            self.assertEqual(status(entry, vault_shape="leaf", op=3, sel=3, asset=0), 0x186)

    def test_routes(self):
        def names(**fields):
            return [event[0] for event in run(0x2764D60, **fields)[1][3]]
        self.assertEqual(names(cls=2), ["class", "class", "direct"])
        self.assertEqual(names(cls=3), ["class", "class", "rec", "pre", "direct", "post"])
        self.assertEqual(names(cls=3, f5b1=1), ["class", "class", "direct"])
        self.assertEqual(names(cls=4), ["class", "class", "direct"])

    def test_abstraction_limit_only_for_class_3(self):
        new = tool.time_of(5000000000000)
        near = (9,) + tool.time_of(5000000000000 - 1)
        fields = dict(now=new, rec1=near, rec2=near, l1=9, l2=9, w1p=60000, w2p=3600000)
        for entry in HANDLERS:
            self.assertEqual(status(entry, cls=3, **fields), 0x170)
            self.assertEqual(status(entry, cls=3, f5b1=1, **fields), 0x186)
            self.assertEqual(status(entry, cls=2, **fields), 0x186)

    def test_post_failure_changes_nothing_in_the_result(self):
        self.assertEqual(status(0x2764D60, cls=3, post_tag=0x15), 0x186)
        self.assertEqual(run(0x2764D60, cls=3, post_tag=0x15)[1][3][-1], ("post drop",))

    def test_the_final_call_is_reached_only_if_the_gate_is_removed(self):
        for cls in range(6):
            for f0 in (0, 1):
                for f1 in (0, 1):
                    self.assertFalse(fails({}, 0x2764D60, cls=cls, f5b0=f0, f5b1=f1))
        harness = tool.Harness(image_get(), {0x2764DAB: 0xEB})
        with self.assertRaisesRegex(tool.Halt, "pre flag"):
            harness.run(tool.Case("t", entry=0x2764D60, cls=4, f5b0=0))
        harness.machine.calls[0x272FE00] = lambda machine: None
        with self.assertRaisesRegex(tool.Halt, "final call"):
            harness.run(tool.Case("t", entry=0x2764D60, cls=4, f5b0=0))

    def test_stub_argument_checks_can_fail(self):
        self.assertTrue(fails(flip(0x2765194), 0x2764D60, cls=3))


class Bytes_(unittest.TestCase):
    def test_texts(self):
        rows = {(kind, str(code)): text for kind, code, text in tool.text_rows(image_get())}
        self.assertEqual(rows["inner", "7"], "Too many operations")
        self.assertEqual(rows["inner", "4"], "Only supplying is enabled")
        self.assertEqual(rows["inner", "8"], "Operation not allowed")
        self.assertEqual(rows["inner", "10"], "Internal error")
        self.assertEqual(rows["tag", "0x173"], "Manual borrow/lend not allowed with portfolio margin")
        self.assertTrue(rows["tag", "0x170"].startswith("Too many abstraction operations."))

    def test_text_scan_refuses_a_row_without_text(self):
        with self.assertRaises(tool.EvidenceError):
            tool.text_at(image_get(), tool.LIMIT)

    def test_vote_stores(self):
        rows = tool.vote_rows(image_get())
        self.assertEqual(len(rows), 21)
        offsets = sorted({row[2] for row in rows})
        self.assertEqual(offsets, ["0x4f0", "0x4f8", "0x500", "0x508", "0x510", "0x518", "0x520"])

    def test_tables(self):
        rows = tool.table_rows(image_get())
        self.assertEqual(rows[0][2], "0x2764f8b")
        self.assertEqual(rows[1][2], "0x2764f9a")
        self.assertEqual(rows[2][2], "0x2764f8b")
        self.assertEqual(rows[3][2], "0x2764f9a")
        self.assertEqual(rows[4][2], "0x232bcb2")
        self.assertEqual(rows[5][2], "0x232bc9c")
        self.assertEqual(rows[7][2], "0x232bcda")

    def test_limiter_has_many_holders(self):
        rows = {row[0]: row for row in tool.holder_rows(image_get())}
        self.assertEqual(rows["0x37d9ef0"][2], "0x5774748")
        self.assertGreater(rows["0x37d9ef0"][5], 30)


class Packet(unittest.TestCase):
    def test_folder_is_exactly_the_generated_set(self):
        files = full_get()
        names = {path.name for path in FOLDER.iterdir()}
        self.assertEqual(names, set(files) | {"README.md", "MANIFEST.sha256"})

    def test_generated_files_match(self):
        for name, text in full_get().items():
            self.assertEqual((FOLDER / name).read_text(encoding="ascii"), text, name)

    def test_manifest(self):
        lines = (FOLDER / "MANIFEST.sha256").read_text().splitlines()
        names = {path.name for path in FOLDER.iterdir()} - {"MANIFEST.sha256"}
        self.assertEqual({line.split("  ")[1] for line in lines}, names)
        for line in lines:
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_every_survivor_has_a_reason(self):
        rows = [line.split("\t") for line in full_get()["mutations.tsv"].splitlines()[1:]]
        self.assertGreater(len(rows), 500)
        for row in rows:
            self.assertNotEqual(row[3], "UNEXPLAINED")

    def test_summary_counts(self):
        summary = json.loads(full_get()["evidence.json"])
        self.assertEqual(summary["named_cases"], len(tool.named_cases()))
        self.assertEqual(summary["sha256"], "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f")
        self.assertGreater(summary["mutations"]["killed"], summary["mutations"]["survived"])

    def test_unedited_image_passes_the_mutant_limit(self):
        harness = tool.Harness(image_get())
        harness.machine.step_limit = tool.MUTANT_STEP_LIMIT
        self.assertIsNone(tool.first_failure(harness, tool.named_cases()))


if __name__ == "__main__":
    unittest.main()
