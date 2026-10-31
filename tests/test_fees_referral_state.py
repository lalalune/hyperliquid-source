"""Tests of tools/fees_referral_state.py: digest binding, real outcomes, corrupted bytes and the packet files."""

import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
SPEC = importlib.util.spec_from_file_location('fees_referral_state', ROOT / 'tools' / 'fees_referral_state.py')
tool = importlib.util.module_from_spec(SPEC)
sys.modules['fees_referral_state'] = tool
SPEC.loader.exec_module(tool)
FOLDER = ROOT / 'research' / 'work-items' / 'fees-referral-state-94'
A = tool.A
FOLD_A, FOLD_B = tuple(tool.FOLDS)


class Base(unittest.TestCase):
    data = (ROOT / tool.BINARY).read_bytes()
    built = tool.build(data)
    ctx = (built[0], built[1], built[3], built[4])

    def passes(self, v, ctx=None):
        self.assertIsNone(tool.check(ctx or self.ctx, v))

    def patched(self, patch):
        """The same run on an image with `patch` VA -> byte applied; subjects decoded again."""
        img, code, _, slots, got = self.built
        mimg = tool.Image(self.data, patch)
        mcode = dict(code)
        for s in tool.RANGES:
            mcode.update({i.va: i for i in tool.decode_subject(mimg, s)})
        return (mimg, mcode, slots, got)

    def broken(self, v, patch):
        """True when the corrupted image no longer matches the model on `v`."""
        try:
            return tool.check(self.patched(patch), v) is not None
        except (tool.Unmodelled, tool.Panicked):
            return True


def one(w):
    return tool.stage('t', rows={A: [w]})


class Digest(Base):
    def test_digest_accepted(self):
        self.assertEqual(tool.check_digest(self.data), tool.SHA256)

    def test_wrong_digest_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.check_digest(self.data[:-1] + bytes([self.data[-1] ^ 1]))

    def test_wrong_binary_refused_by_build(self):
        with self.assertRaises(tool.EvidenceError):
            tool.build(self.data[:100] + bytes([self.data[100] ^ 1]) + self.data[101:])


class Model(unittest.TestCase):
    def test_total_order(self):
        keys = [0x7ff8000000000000, 0x7ff0000000000000, 0x4024000000000000, 0, 1 << 63, 0xc024000000000000, 0xfff0000000000000, 0xfff8000000000000]
        self.assertEqual([k for k, _ in tool.rank([(k, 0) for k in reversed(keys)])], keys)

    def test_rank_is_stable(self):
        self.assertEqual([x for _, x in tool.rank([(5, 'a'), (9, 'b'), (5, 'c')])], ['b', 'a', 'c'])

    def test_sum_saturates_and_counts(self):
        self.assertEqual(tool.volume([tool.U64, 1, 1]), (tool.U64, 2))
        self.assertEqual(tool.volume([1, 2]), (3, 0))

    def test_stage_rule(self):
        self.assertEqual(tool.stage_rule(tool.stage('t'))['required'], 10000.0)
        self.assertEqual(tool.stage_rule(one(999999))['required'], 0.01)
        self.assertEqual(tool.stage_rule(one(1000000))['tag'], 'create')

    def test_total_counts_rows_before_the_cap(self):
        v = tool.ready('t', 3, have=lambda i: i != 1)
        w = tool.stage_rule(v)
        self.assertEqual((w['total'], len(w['rows'])), (2, 2))


class Stage(Base):
    def test_no_table(self):
        self.passes(tool.stage('t'))

    def test_miss_uses_the_default(self):
        self.passes(tool.stage('t', rows={tool.addr(2): [1]}))

    def test_row_with_no_tokens_needs_the_whole_amount(self):
        v = tool.stage('t', rows={A: []})
        self.assertEqual(tool.stage_rule(v)['required'], 10000.0)
        self.passes(v)

    def test_threshold_edges(self):
        for w in (0, 1, 999999, 1000000, 1000001, tool.U64):
            self.passes(one(w))

    def test_sum_of_tokens(self):
        self.passes(tool.stage('t', rows={A: [500000, 499999]}))
        self.passes(tool.stage('t', rows={A: [500000, 500000]}))

    def test_saturation_records(self):
        self.passes(tool.stage('t', rows={A: [tool.U64, 1, 1]}))

    def test_tall_token_trees(self):
        for h in (3, 8, 9, 17):
            self.passes(tool.stage('t', rows={A: [1, 2, 3, 4]}, token_height=h))

    def test_probe_past_clashing_tags(self):
        self.passes(tool.stage('t', rows={A: [7]}, decoys=[(tool.addr(300 + i), A) for i in range(34)]))
        self.passes(tool.stage('t', rows={}, decoys=[(tool.addr(300 + i), A) for i in range(34)]))

    def test_ready_rows(self):
        for n in (0, 1, 2, 5, 20):
            self.passes(tool.ready('t', n))

    def test_long_sort_path(self):
        self.passes(tool.ready('t', 21))

    def test_user_without_row_is_dropped(self):
        self.passes(tool.ready('t', 6, have=lambda i: i % 2 == 0))
        self.passes(tool.ready('t', 4, have=lambda i: False))

    def test_tall_joined_trees(self):
        for h in (1, 3, 8, 9, 16, 17):
            self.passes(tool.ready('t', 5, height=h))

    def test_empty_code(self):
        self.passes(tool.ready('t', 1, code=b''))

    def test_flag_reads_one_byte(self):
        self.passes(tool.ready('t', 3, flag=0x100))

    def test_cap(self):
        for wide, flag in ((5000, 1), (5001, 1), (5001, 0)):
            self.passes(tool.stage('t', profiles={A: dict(code=b'w', joined=[], height=0)}, flag=flag, wide=wide))

    def test_length_past_the_tree_panics(self):
        self.passes(tool.ready('t', 3, short=1))

    def test_allocator_failure_panics(self):
        self.passes(tool.ready('t', 1, fail_alloc=0x140, fail_args=(8, 0x140)))
        self.passes(tool.ready('t', 1, code=b'abc', fail_alloc=3, fail_args=(1, 3)))

    def test_stale_key_past_the_length_is_not_a_hit(self):
        high = bytes(range(200, 220))
        users = tool.spread(4, 5)
        self.passes(tool.stage('t', user=high, rows={high: [3]}, profiles={u: dict(code=b'y', joined=[], height=0) for u in users if u < high}, stale=True))

    def test_second_tag_match_in_a_group(self):
        self.passes(tool.stage('t', rows={A: [7]}, decoys=[(tool.addr(900), A), (tool.addr(901), A)], first=True))

    def test_key_at_the_first_byte_of_a_later_group(self):
        for c in (16, 32):
            self.passes(tool.stage('t', rows={A: [7]}, decoys=[(tool.addr(900 + i), A) for i in range(c)], first=True, table_n=128))

    def test_two_rows_are_sorted(self):
        self.passes(tool.ready('t', 2, keyset=(1, 1 << 62)))

    def test_threshold_corrupted(self):
        self.assertTrue(self.broken(one(1000000), {0x2a2b517: 0x41}))

    def test_base_corrupted(self):
        self.assertTrue(self.broken(one(5), {0x2a2b532: 0x41}))

    def test_divisor_corrupted(self):
        self.assertTrue(self.broken(one(5), {0x20a966: 0x69}))

    def test_default_corrupted(self):
        self.assertTrue(self.broken(tool.stage('t'), {0x20a836: 0xd3}))

    def test_cap_corrupted(self):
        v = tool.stage('t', profiles={A: dict(code=b'w', joined=[], height=0)}, flag=1, wide=5001)
        self.assertTrue(self.broken(v, {0x2a2b3bf: 0x89}))

    def test_count_store_corrupted(self):
        self.assertTrue(self.broken(tool.ready('t', 2), {0x2a2b3f9: 0x38}))

    def test_small_sort_bound_corrupted(self):
        self.assertTrue(self.broken(tool.ready('t', 20), {0x2a2b573: 0x14}))

    def test_tree_key_stride_corrupted(self):
        high = bytes(range(200, 220))
        users = tool.spread(4, 5)
        v = tool.stage('t', user=high, rows={high: [3]}, profiles={u: dict(code=b'y', joined=[], height=0) for u in users if u < high}, stale=True)
        self.assertTrue(self.broken(v, {0x2a2b15a: 0xed}))


class Sort(Base):
    def test_order(self):
        self.passes(dict(kind='sort', group='t', keys=list(tool.PRIMES)))

    def test_equal_keys_keep_order(self):
        self.passes(dict(kind='sort', group='t', keys=[5, 5, 5]))

    def test_compare_corrupted(self):
        self.assertTrue(self.broken(dict(kind='sort', group='t', keys=[1, 1 << 62]), {0x2a1ffdd: 0x72}))

    def test_sign_rule_corrupted(self):
        self.assertTrue(self.broken(dict(kind='sort', group='t', keys=[1, 2]), {0x2a1ffc3: 0x48}))


class Take(Base):
    def test_values(self):
        for n, k in ((0, 0), (1, 0), (3, 2), (3, 3), (3, 5)):
            self.passes(dict(kind='take', group='t', n=n, take=k))

    def test_consumed_source(self):
        self.passes(dict(kind='take', group='t', n=4, take=2, skip=1))

    def test_stride_corrupted(self):
        self.assertTrue(self.broken(dict(kind='take', group='t', n=3, take=2), {0x2a39c18: 0x51}))


class ListBuilders(Base):
    def row(self, n, **kw):
        return dict(kind='list', group='t', user=A, rows={A: [1]}, profiles={}, builders={A: tool.spread(n, 3)}, **kw)

    def test_values(self):
        for n in (0, 1, 7, 12):
            self.passes(self.row(n))

    def test_no_row(self):
        self.passes(dict(kind='list', group='t', user=A, rows={}, profiles={}, builders={}))

    def test_tall(self):
        for h in (3, 8, 9):
            self.passes(self.row(5, builder_height=h))

    def test_length_overflow_panics(self):
        self.passes(self.row(3, builder_length=1 << 60, fail_args=(0, ((1 << 60) * 20) & tool.U64)))

    def test_stride_corrupted(self):
        self.assertTrue(self.broken(self.row(3), {0x2a2b717: 0x15}))


class Fold(Base):
    def row(self, fn, **kw):
        u = tool.spread(9, 2)
        return dict(dict(kind='fold', group='t', fn=fn, users=u[:6], members=u[::2]), **kw)

    def test_both_copies(self):
        for fn in tool.FOLDS:
            self.passes(self.row(fn))

    def test_empty_tree_skips_all(self):
        for fn in tool.FOLDS:
            self.passes(self.row(fn, members=[]))

    def test_option_none_is_not_pushed(self):
        u = tool.spread(9, 2)
        self.passes(self.row(FOLD_A, none=[u[2]]))

    def test_niche_corrupted(self):
        u = tool.spread(9, 2)
        self.assertTrue(self.broken(self.row(FOLD_A, none=[u[2]]), {0x251c1ba: 3}))

    def test_tracker_offset_corrupted(self):
        self.assertTrue(self.broken(self.row(FOLD_A), {0x251c178: 0xd8}))

    def test_tree_offset_corrupted(self):
        self.assertTrue(self.broken(self.row(FOLD_B), {0x251c868: 0x58}))


class Static(Base):
    def test_pins_read_back(self):
        keys = [r['key'] for r in tool.pins(self.built[0]) if 'key' in r]
        for k in ('cumVlm', 'cumRewardedFeesSinceReferred', 'cumFeesRewardedToReferrer', 'timeJoined', 'tokenToState', 'needToTrade', 'needToCreateCode', 'ready', 'nReferrals', 'referralStates'):
            self.assertIn(k, keys)

    def test_corrupted_pin_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.pins(tool.Image(self.data, {0x251c1aa: 0}))

    def test_two_users_of_the_stage_slot(self):
        starts = sorted(f['start'] for f in tool.eh_frame_records(self.data)[1])
        rows = tool.slot_users(self.built[0], tool.SLOT_STAGE, starts)
        self.assertEqual({r['function'] for r in rows}, {hex(x) for x in tool.FOLDS})

    def test_range_outside_any_fde_refused(self):
        with self.assertRaises(Exception):
            self.built[2].range_of(0x10)

    def test_location_keeps_a_relative_path(self):
        self.assertTrue(tool.location(self.built[0], tool.LOC_ADD)['path'].startswith('l1/src/'))


class Packet(Base):
    folder = FOLDER

    def test_regenerated_files_match(self):
        with tempfile.TemporaryDirectory() as t:
            tool.generate(self.data, t, with_survey=False)
            for name in ('vectors.tsv', 'instructions.tsv', 'reference-diff.tsv', 'call-sites.tsv'):
                self.assertEqual((Path(t) / name).read_bytes(), (self.folder / name).read_bytes(), name)

    def test_evidence_numbers(self):
        ev = json.loads((self.folder / 'evidence.json').read_text())
        self.assertEqual(ev['sha256'], tool.SHA256)
        self.assertEqual(ev['mismatches'], 0)
        self.assertEqual(ev['mutants'], ev['killed'] + len([1 for line in (self.folder / 'mutations.tsv').read_text().splitlines()[1:] if line.split('\t')[4] == 'equivalent']))

    def test_manifest(self):
        for line in (self.folder / 'MANIFEST.sha256').read_text().splitlines():
            digest, name = line.split('  ')
            self.assertEqual(hashlib.sha256((self.folder / name).read_bytes()).hexdigest(), digest, name)

    def test_tool_runs_no_external_program(self):
        src = (ROOT / 'tools' / 'fees_referral_state.py').read_text()
        self.assertNotIn('subprocess', src)
        self.assertNotIn('os.system', src)


if __name__ == '__main__':
    unittest.main()
