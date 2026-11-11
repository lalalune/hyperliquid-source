import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import re014_funding_collect_115 as fc  # noqa: E402


class Fixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = fc.load_image()
        cls.harness = fc.Harness(cls.image)
        cls.cases = list(fc.make_cases(240, seed=0xBEEF1234))


def entries_of(case):
    return (fc.FOLD,) if case.name.startswith("fold") else fc.BRIDGES


class TestImage(Fixture):
    def test_digest_is_pinned(self):
        self.assertEqual(fc.SHA256, "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
        with self.assertRaises(fc.EvidenceError):
            fc.load_image(fc.fp.BINARY, "0" * 64)

    def test_three_exact_fdes(self):
        sizes = {entry: self.image.exact_fde(entry)[1] - entry for entry in (fc.FOLD,) + fc.BRIDGES}
        self.assertEqual(sizes, {0x24E5D00: 647, 0x5B34D90: 1446, 0x5B39440: 1446})

    def test_interior_and_foreign_addresses_are_refused(self):
        for address in (fc.FOLD + 1, 0x1000, 1 << 40):
            with self.assertRaises(fc.EvidenceError):
                self.image.exact_fde(address)

    def test_exactly_three_premium_call_sites(self):
        sites = [site for site, _ in fc.scan_call_sites(self.image)]
        self.assertEqual(sites, [0x24E5E57, 0x5B34F8C, 0x5B3963C])

    def test_panic_locations_and_direct_calls(self):
        for entry in (fc.FOLD,) + fc.BRIDGES:
            self.assertEqual(sorted(self.harness.locs[entry].values()), ["A", "B"])
        self.assertEqual(self.harness.targets[fc.BRIDGES[0]], [0x5BBD780, 0x59EE9F0])
        self.assertEqual(self.harness.targets[fc.BRIDGES[1]], [0x5BBD780, 0x59EF040])


class TestModel(Fixture):
    def test_real_bytes_match_model(self):
        for case in self.cases:
            for entry in entries_of(case):
                got, want = fc.compare(self.harness, case, entry)
                self.assertEqual(got, want, (case.name, hex(entry)))

    def test_grow_happens_exactly_when_full(self):
        case = fc.Case(name="fold-x", ids=[1, 2, 3], members=set(), height=0, chunks=[], stale=None, len_a=9, len_b=9,
                       oracles=list(range(9)), premium=7, cap=2, len0=2, left=None, right=None, lens=(0, 0), weird=False,
                       total=0, mig=0, splits=0, minimum=0, nthreads=0, worker=0)
        got, want = fc.compare(self.harness, case, fc.FOLD)
        self.assertEqual(got, want)
        self.assertEqual([row for row in got[1] if row[0] == "grow"], [("grow", 2), ("grow", 4)])
        self.assertEqual(got[0][1], 8)

    def test_set_members_are_skipped(self):
        case = next(c for c in fc.make_cases(400) if c.name.startswith("fold") and c.members & set(c.ids))
        got, _ = fc.compare(self.harness, case, fc.FOLD)
        logged = {row[1] for row in got[1] if row[0] == "premium"}
        self.assertFalse(logged & case.members)

    def test_bounds_panics_name_the_vector(self):
        case = fc.Case(name="fold-y", ids=[5], members=set(), height=0, chunks=[], stale=None, len_a=3, len_b=9,
                       oracles=list(range(9)), premium=1, cap=1, len0=0, left=None, right=None, lens=(0, 0), weird=False,
                       total=0, mig=0, splits=0, minimum=0, nthreads=0, worker=0)
        got, want = fc.compare(self.harness, case, fc.FOLD)
        self.assertEqual(got[0], ("panic", "A", 5, 3))
        self.assertEqual(got, want)
        case.len_a, case.len_b = 9, 3
        self.assertEqual(self.harness.run(case, fc.FOLD)[0], ("panic", "B", 5, 3))

    def test_split_underflow_panics(self):
        case = next(c for c in fc.make_cases(2000) if c.name.startswith("bridge") and len(c.ids) >= 1 and c.total >> 1 > len(c.ids)
                    and c.total >> 1 >= c.minimum and (c.mig or c.splits))
        for entry in fc.BRIDGES:
            self.assertEqual(self.harness.run(case, entry)[0][:2], ("panic", "split"))


class TestControls(Fixture):
    def test_wrong_readings_are_refused(self):
        for name in fc.VARIANTS:
            refused = 0
            for case in self.cases:
                entry = entries_of(case)[0]
                got = self.harness.run(case, entry)
                other = fc.model_fold(case, name) if entry == fc.FOLD else fc.model_bridge(case, name)
                refused += got != (other[0], other[1])
            self.assertGreater(refused, 0, name)

    def test_corrupted_code_byte_is_refused(self):
        at = fc.FOLD + 0xFB
        flipped = fc.Harness(self.image, {at: self.image.blob[self.image.offset(at)] ^ 0xFF})
        flipped.machine.step_limit = 20000
        case = next(c for c in self.cases if c.name.startswith("fold") and len(c.ids) >= 2 and not c.members)
        got, want = fc.compare(flipped, case, fc.FOLD)
        self.assertNotEqual(got, want)

    def test_flipped_condition_is_refused(self):
        start, end = self.image.exact_fde(fc.FOLD)
        jumps = [row for row in fc.decode_range(self.image, start, end) if row.op == "jcc"]
        killed = 0
        pool = [c for c in self.cases if c.name.startswith("fold")][:60]
        for row in jumps[:6]:
            at = 0 if 0x70 <= row.data[0] <= 0x7F else 1
            harness = fc.Harness(self.image, {row.va + at: row.data[at] ^ 1})
            harness.machine.step_limit = 20000
            killed += any(got != want for got, want in (fc.compare(harness, c, fc.FOLD) for c in pool))
        self.assertEqual(killed, 6)


def bridge_case(ids, total, mig, splits, minimum, left, right, lens=(11, 7), weird=False, nthreads=3, worker=1):
    return fc.Case(name="bridge-hand", ids=ids, members=set(), height=0, chunks=[], stale=None, len_a=9, len_b=9,
                   oracles=list(range(9)), premium=5, cap=0, len0=0, total=total, mig=mig, splits=splits, minimum=minimum,
                   nthreads=nthreads, worker=worker, left=left, right=right, lens=lens, weird=weird)


class TestBridgeBranches(Fixture):
    """Hand written rows of the split and merge decision table; every row is run on both bridge bodies."""

    def both(self, case):
        out = []
        for entry in fc.BRIDGES:
            got, want = fc.compare(self.harness, case, entry)
            self.assertEqual(got, want, (hex(entry), case.ids))
            out.append(got)
        self.assertEqual(out[0], out[1])
        return out[0]

    def test_twins_differ_only_in_the_join_target(self):
        rows = fc.twin_rows(self.image)
        self.assertEqual(rows[0][1:3], ("1446", "1446"))
        self.assertEqual(rows[1][1:3], ("327", "327"))
        self.assertEqual([row[0] for row in rows[2:]], ["external-target"])
        self.assertEqual((rows[2][1], rows[2][2], rows[2][3]), ("0x406", "0x59ee9f0", "0x59ef040"))

    def test_below_minimum_runs_the_leaf_even_with_budget(self):
        outcome, log = self.both(bridge_case([10000, 10001], total=2, mig=1, splits=8, minimum=2, left=[1], right=[1]))
        self.assertEqual(outcome[0], "node")
        self.assertNotIn(("tls",), log)

    def test_empty_slice_returns_empty_list(self):
        outcome, log = self.both(bridge_case([], total=0, mig=0, splits=0, minimum=1, left=[], right=[]))
        self.assertEqual(outcome, ("list", 0, 0, 0))
        self.assertEqual(log, [])

    def test_zero_budget_without_migration_stays_sequential(self):
        outcome, log = self.both(bridge_case([20000, 30001, 40002], total=3, mig=0, splits=0, minimum=0, left=[1], right=[1]))
        self.assertEqual(outcome[0], "node")
        self.assertEqual(len(outcome[2]), 3)
        self.assertFalse([row for row in log if row[0] == "join"])

    def test_budget_halves_and_split_point_is_half_the_total(self):
        _, log = self.both(bridge_case([1, 2, 3, 4, 5, 6], total=6, mig=0, splits=5, minimum=1, left=[2], right=[2]))
        self.assertEqual([row for row in log if row[0] == "join"], [("join", 3, 2, 3)])

    def test_migrated_budget_is_at_least_the_thread_count(self):
        for worker in (0, 1):
            _, log = self.both(bridge_case([1, 2, 3, 4], total=4, mig=1, splits=2, minimum=1, left=[2], right=[2], nthreads=6,
                                           worker=worker))
            self.assertEqual([row for row in log if row[0] == "join"], [("join", 2, 6, 2)])
            self.assertEqual(("global",) in log, worker == 0)

    def test_left_only_right_only_and_linked_merges(self):
        base = dict(ids=[1, 2, 3, 4], total=4, mig=0, splits=2, minimum=1)
        left_only = self.both(bridge_case(left=[2, 0], right=[], **base))
        self.assertEqual(left_only[0], ("list", ("node", "L", 0), ("node", "L", 1), 11))
        right_only = self.both(bridge_case(left=[], right=[2, 0], **base))
        self.assertEqual(right_only[0], ("list", ("node", "R", 0), ("node", "R", 1), 7))
        linked = self.both(bridge_case(left=[2, 0], right=[4, 2], **base))
        self.assertEqual(linked[0], ("list", ("node", "L", 0), ("node", "R", 1), 18))
        self.assertIn(("link", ("node", "L", 1), ("node", "R", 0)), linked[1])

    def test_left_chain_is_freed_buffer_first_when_the_tail_is_empty(self):
        base = dict(ids=[1, 2, 3, 4], total=4, mig=0, splits=2, minimum=1)
        outcome, log = self.both(bridge_case(left=[2, 0, 4], right=[2], weird=True, **base))
        self.assertEqual(outcome, ("list", ("node", "R", 0), ("node", "R", 0), 7))
        frees = [row for row in log if row[0] == "free"]
        self.assertEqual(frees, [("free", "buf", "L", 0, 48), ("free", "node", "L", 0, 40), ("free", "node", "L", 1, 40),
                                 ("free", "buf", "L", 2, 96), ("free", "node", "L", 2, 40)])

    def test_split_point_beyond_the_slice_panics_before_the_join(self):
        for entry in fc.BRIDGES:
            case = bridge_case([1, 2], total=10, mig=0, splits=1, minimum=1, left=[], right=[])
            got, want = fc.compare(self.harness, case, entry)
            self.assertEqual(got[0], ("panic", "split", 2, 5))
            self.assertEqual(got, want)
            self.assertFalse([row for row in got[1] if row[0] == "join"])

    def test_leaf_panic_stops_the_whole_run(self):
        case = bridge_case([1, 20009], total=2, mig=0, splits=0, minimum=5, left=[], right=[])
        outcome, log = self.both(case)
        self.assertEqual(outcome, ("panic", "A", 9, 9))
        self.assertEqual([row[0] for row in log], ["premium", "grow"])


class TestDivisionAndFields(Fixture):
    def test_every_body_divides_by_10000_exactly_for_all_u64(self):
        rows = fc.division_rows(self.image)
        self.assertEqual(len(rows), 3)
        for row in rows:
            self.assertEqual(row[2], "0x346dc5d63886594b")
            self.assertEqual((row[5], row[6], row[7]), (432, 1, 1))
            magic = int(row[2], 16)
            # the identity holds because 0 <= magic * 10000 - 2^75 <= 2^11; a wrong magic breaks it
            self.assertTrue(0 <= magic * 10000 - (1 << 75) <= 1 << 11)
            self.assertFalse(0 <= (magic + 1) * 10000 - (1 << 75) <= 1 << 11)
            self.assertFalse(0 <= (magic - 1) * 10000 - (1 << 75) <= 1 << 11 and (magic - 1) * 10000 >= 1 << 75)

    def test_identity_holds_on_a_dense_sweep(self):
        magic = 0x346DC5D63886594B
        stream = fc.lcg(0x1D)
        samples = [next(stream) << 11 | next(stream) & 0x7FF for _ in range(30000)]
        samples += [k * 10000 + d for k in (0, 1, 1844674407370955, 1844674407370954) for d in (-1, 0, 1, 9999) if 0 <= k * 10000 + d < 1 << 64]
        for x in samples:
            x &= fc.MASK[8]
            self.assertEqual((x * magic >> 64) >> 11, x // 10000)

    def test_wrong_magic_is_caught_by_the_edges(self):
        edges = [9999, 10000, (fc.MASK[8] // 10000) * 10000 - 1, fc.MASK[8]]
        magic = 0x346DC5D63886594B + 0x1000000
        self.assertTrue(any((x * magic >> 64) >> 11 != x // 10000 for x in edges))

    def test_missing_pattern_is_refused(self):
        class Short:
            def exact_fde(self, va):
                return va, va + 4

            offset = staticmethod(lambda va: 0)
            blob = bytes(16)

        with self.assertRaises(fc.EvidenceError):
            fc.division_rows(Short())

    def test_field_rows_cover_the_folder_and_context_words(self):
        rows = {(row[0], row[1], row[2]) for row in fc.field_rows(self.image)}
        for entry in ("0x24e5d00",):
            self.assertIn((entry, "r14", "0x18"), rows)      # context word of the folder
            self.assertIn((entry, "r15", "0x8"), rows)       # metadata vector
            self.assertIn((entry, "r15", "0x18"), rows)      # oracle vector
            self.assertIn((entry, "rax", "0x62"), rows)      # B-tree key count
            self.assertIn((entry, "rax", "0x68"), rows)      # B-tree edges
        self.assertTrue(all(row[3] >= 1 for row in fc.field_rows(self.image)))


def fold_case(ids, members=(), height=0, cap=0, len0=0, oracles=None, premium=3, len_a=9, len_b=9):
    return fc.Case(name="fold-hand", ids=list(ids), members=set(members), height=height, chunks=[3, 2, 4], stale=None, len_a=len_a,
                   len_b=len_b, oracles=oracles or [0x7FF8000000000000 | i for i in range(9)], premium=premium, cap=cap, len0=len0,
                   left=None, right=None, lens=(0, 0), weird=False, total=0, mig=0, splits=0, minimum=0, nthreads=0, worker=0)


class TestFoldRows(Fixture):
    def test_deep_tree_membership_is_exact(self):
        members = {k * 10000 + j for k in range(1, 9) for j in range(0, 9, 2)}
        ids = sorted(members) + [k * 10000 + 1 for k in range(1, 9)] + [5, 99999]
        for height in (2, 3):
            case = fold_case([i for i in ids if i % 10000 < 9], members, height)
            got, want = fc.compare(self.harness, case, fc.FOLD)
            self.assertEqual(got, want)
            kept = {item[0] for item in got[0][2]}
            self.assertEqual(kept & members, set())
            self.assertEqual(kept, {i for i in case.ids if i not in members})

    def test_existing_records_survive_a_grow(self):
        case = fold_case([10003, 20004, 30005], cap=2, len0=2)
        got, want = fc.compare(self.harness, case, fc.FOLD)
        self.assertEqual(got, want)
        items = got[0][2]
        self.assertEqual(items[:2], tuple((fc.sentinel_word(i), i & 1, fc.sentinel_word(100 + i)) for i in range(2)))
        self.assertEqual([item[0] for item in items[2:]], [10003, 20004, 30005])

    def test_tag_zero_keeps_the_oracle_word_and_other_tags_keep_the_premium(self):
        case = fold_case(range(10001, 10009), premium=11)
        got, _ = fc.compare(self.harness, case, fc.FOLD)
        for ident, flag, value in got[0][2]:
            w0, tag, _ = fc.premium_of(case, ident)
            self.assertEqual((flag, value), (1, case.oracles[ident % 10000]) if tag == 0 else (0, w0))

    def test_nan_oracles_pass_through_untouched(self):
        case = fold_case([10000, 10001], oracles=[0x7FF8000000000001, 0xFFF0000000000000] + [0] * 7, premium=1)
        got, want = fc.compare(self.harness, case, fc.FOLD)
        self.assertEqual(got, want)
        self.assertEqual([row[2] for row in got[1] if row[0] == "premium"], [0x7FF8000000000001, 0xFFF0000000000000])

    def test_empty_slice_returns_the_folder_unchanged(self):
        case = fold_case([], cap=3, len0=2)
        got, want = fc.compare(self.harness, case, fc.FOLD)
        self.assertEqual(got, want)
        self.assertEqual((got[0][1], len(got[0][2]), got[1]), (3, 2, []))

    def test_stale_key_past_the_node_length_is_ignored(self):
        case = fold_case([10002])
        case.members, case.height, case.stale = {10004}, 1, 10002
        got, want = fc.compare(self.harness, case, fc.FOLD)
        self.assertEqual(got, want)
        self.assertEqual([item[0] for item in got[0][2]], [10002])


if __name__ == "__main__":
    unittest.main()
