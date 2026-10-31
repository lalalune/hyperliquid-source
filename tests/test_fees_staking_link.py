"""Tests of tools/fees_staking_link.py: digest binding, real outcomes, corrupted bytes and the packet files."""

import hashlib
import importlib.util
import json
import math
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
SPEC = importlib.util.spec_from_file_location('fees_staking_link', ROOT / 'tools' / 'fees_staking_link.py')
tool = importlib.util.module_from_spec(SPEC)
sys.modules['fees_staking_link'] = tool
SPEC.loader.exec_module(tool)
FOLDER = ROOT / 'research' / 'work-items' / 'fees-staking-link-94'
A, B, C = tool.A, tool.B, tool.C
STAKED = {B: (1, 2, 3)}


class Base(unittest.TestCase):
    data = (ROOT / tool.BINARY).read_bytes()
    built = tool.build(data)
    ctx = (built[0], built[1], built[3], built[4])

    def clean(self, v):
        self.assertIsNone(tool.check(self.ctx, v))

    def patched(self, patch):
        """The same run on an image with `patch` VA -> byte applied; subjects decoded again."""
        img, code, _, slots, got, _ = self.built
        mimg = tool.Image(self.data, patch)
        mcode = dict(code)
        for s in tool.RANGES:
            mcode.update({i.va: i for i in tool.decode_subject(mimg, s)})
        return (mimg, mcode, slots, got)

    def broken(self, v, patch):
        """True when the corrupted image no longer matches the model on `v`."""
        try:
            return tool.check(self.patched(patch), v) is not None
        except (tool.Unmodelled, tool.Panicked, KeyError):
            return True


def request(links=None, staked=None, signer=A, payload=B, copy=tool.WRAP):
    return tool.act('t', copy, False, signer, payload, links or {}, STAKED if staked is None else staked)


def final(links, signer=B, payload=A, copy=tool.WRAP):
    return tool.act('t', copy, True, signer, payload, links, {})


class Digest(Base):
    def test_digest_accepted(self):
        self.assertEqual(tool.check_digest(self.data), tool.SHA256)

    def test_wrong_digest_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.check_digest(self.data[:-1] + bytes([self.data[-1] ^ 1]))

    def test_outside_address_refused(self):
        with self.assertRaises(tool.EvidenceError):
            self.built[0].read(0x7fff0000, 8)

    def test_no_fde_refused(self):
        with self.assertRaises(tool.EvidenceError):
            self.built[2].range_of(tool.WRAP + 1)

    def test_bss_refused(self):
        bss = self.built[0].sec['.bss'][0]
        with self.assertRaises(tool.EvidenceError):
            self.built[0].read(bss, 8)

    def test_constants_pinned(self):
        constants, pins = tool.pinned(self.built[0])
        self.assertEqual(constants, dict(scale=10000.0, one=1.0))
        self.assertEqual(len(pins), len(tool.PINS))

    def test_pin_refuses_changed_bytes(self):
        site = tool.PINS[0][1]
        img = tool.Image(self.data, {site: 0})
        with self.assertRaises(tool.EvidenceError):
            tool.pinned(img)

    def test_names_refuse_changed_bytes(self):
        site = tool.NAMES[0][1]
        with self.assertRaises(tool.EvidenceError):
            tool.name_rows(tool.Image(self.data, {site: 0}))

    def test_bad_tree_leaf_refused(self):
        v = request(dict(tool.PAD))
        with self.assertRaises(tool.EvidenceError):
            tool.check(self.ctx, v)


class Request(Base):
    def test_writes_pending_row(self):
        for copy in tool.ACTIONS:
            v = request(copy=copy)
            self.assertEqual(tool.link_rule(v), dict(text=None, inserts=[(A, 0, B)]))
            self.clean(v)

    def test_no_stake_comes_first(self):
        v = request({A: (1, C), B: (1, C)}, staked={})
        self.assertEqual(tool.link_rule(v)['text'], 'no_stake')
        self.clean(v)

    def test_self_comes_before_rows(self):
        v = request({B: (1, C)}, signer=B)
        self.assertEqual(tool.link_rule(v)['text'], 'itself')
        self.clean(v)

    def test_trading_row_before_staking_row(self):
        v = request({A: (2, C), B: (1, C)})
        self.assertEqual(tool.link_rule(v)['text'], 'trading_set')
        self.clean(v)

    def test_staking_row(self):
        v = request({B: (2, C)})
        self.assertEqual(tool.link_rule(v)['text'], 'staking_set')
        self.clean(v)

    def test_pending_row_is_replaced(self):
        v = request({A: (0, C), B: (0, C)})
        self.assertEqual(tool.link_rule(v), dict(text=None, inserts=[(A, 0, B)]))
        self.clean(v)

    def test_zero_value_row_still_passes(self):
        v = request(staked={B: (0, 0, 0)})
        self.assertIsNone(tool.link_rule(v)['text'])
        self.clean(v)

    def test_flipped_self_test_caught(self):
        self.assertTrue(self.broken(request(signer=B), {0x3b45f79 + 1: 0x85}))

    def test_flipped_tag_test_caught(self):
        self.assertTrue(self.broken(request({A: (1, C)}), {0x3b460d3: 0x75}))


class Final(Base):
    def test_writes_both_rows(self):
        for copy in tool.ACTIONS:
            v = final({A: (0, B)}, copy=copy)
            self.assertEqual(tool.link_rule(v), dict(text=None, inserts=[(A, 1, B), (B, 2, A)]))
            self.clean(v)

    def test_other_address_refused(self):
        v = final({A: (0, C)})
        self.assertEqual(tool.link_rule(v)['text'], 'first')
        self.clean(v)

    def test_settled_row_refused(self):
        for tag in (1, 2, 3):
            v = final({A: (tag, B)})
            self.assertEqual(tool.link_rule(v)['text'], 'first')
            self.clean(v)

    def test_flag_is_any_nonzero_byte(self):
        v = tool.act('t', tool.WRAP, True, B, A, {A: (0, B)}, {}, truth=0x80)
        self.assertIsNone(tool.link_rule(v)['text'])
        self.clean(v)

    def test_second_tag_byte_caught(self):
        self.assertTrue(self.broken(final({A: (0, B)}), {0x3b464a6: 3}))


class Mark(Base):
    def test_trading_row_of_signer_marks(self):
        for copy in tool.CHECKS:
            v = tool.mark('t', copy, B, A, {A: (1, B)})
            self.assertEqual(tool.check_rule(v), dict(text=None, marks=[A]))
            self.clean(v)

    def test_other_rows_refused(self):
        for links in ({}, {A: (0, B)}, {A: (2, B)}, {A: (1, C)}):
            v = tool.mark('t', tool.CHECK, B, A, links)
            self.assertEqual(tool.check_rule(v)['text'], 'not_linked')
            self.clean(v)

    def test_tag_compare_caught(self):
        self.assertTrue(self.broken(tool.mark('t', tool.CHECK, B, A, {A: (1, B)}), {0x1e649cb: 2}))


class View(Base):
    def share(self, **kw):
        v = tool.view('t', tool.HEAD_A, **kw)
        for copy in tool.VIEWS:
            self.clean(dict(v, copy=copy))
        return tool.view_rule(v)

    def test_basis_points_of_supply(self):
        w = self.share(stakes={A: 10 ** 12}, supply=10 ** 15)
        self.assertEqual(w['share'], 10.0)
        self.assertEqual(w['cut'], 0.1)

    def test_trading_row_counts_the_other_stake(self):
        self.assertEqual(self.share(links={A: (1, B)}, stakes={A: 1, B: 10 ** 13})['share'], 100.0)

    def test_requested_row_counts_own_stake(self):
        self.assertEqual(self.share(links={A: (0, B)}, stakes={A: 10 ** 12, B: 10 ** 13})['share'], 10.0)

    def test_staking_row_counts_nothing(self):
        w = self.share(links={A: (2, B)}, stakes={A: 10 ** 13, B: 10 ** 13})
        self.assertEqual((w['share'], w['stake_calls']), (0.0, 0))

    def test_no_option_counts_nothing(self):
        self.assertEqual(self.share(some=0)['share'], 0.0)

    def test_mode_two_fixes_the_supply(self):
        self.assertEqual(self.share(mode=2, stakes={A: 10 ** 13}, supply=1)['share'], 1.0)

    def test_zero_supply_counts_nothing(self):
        self.assertEqual(self.share(supply=0)['share'], 0.0)

    def test_list_above_credit_comes_off(self):
        w = self.share(stakes={A: 10 ** 12}, staked={A: (4 * 10 ** 11, 0, 0)}, list=(5 * 10 ** 11, 6 * 10 ** 11), list_cap=2)
        self.assertEqual(w['share'], 3e11 / 1e15 * 10000.0)  # division first: one ulp under 3.0

    def test_credit_above_list_takes_nothing(self):
        self.assertEqual(self.share(staked={A: (5, 0, 0)}, list=(4,), list_cap=1)['share'], 10.0)

    def test_list_above_stake_counts_nothing(self):
        self.assertEqual(self.share(list=(10 ** 12 + 1,), list_cap=1)['share'], 0.0)

    def test_sum_saturates_with_a_hook(self):
        w = self.share(list=(2 ** 64 - 1, 5), list_cap=2)
        self.assertEqual((w['hooks'], w['share']), (1, 0.0))

    def test_list_error_counts_nothing(self):
        w = self.share(list_error=True, list_cap=3)
        self.assertEqual((w['share'], w['drops']), (0.0, 1))

    def test_ladder_equal_step_is_taken(self):
        self.assertEqual(self.share(stakes={A: 10 ** 13}, supply=10 ** 15)['cut'], 0.15)

    def test_ladder_below_first_step(self):
        self.assertEqual(self.share(stakes={A: 10 ** 10}, supply=10 ** 15)['cut'], 0.0)

    def test_ladder_stops_at_first_higher_step(self):
        self.assertEqual(self.share(ladder=[(0.0, 0.1), (1e9, 0.5), (0.0, 0.25)])['cut'], 0.1)

    def test_rebate_keeps_its_value(self):
        w = self.share()
        self.assertEqual(w['rates'][2], tool.RATES[2])
        self.assertEqual(w['rates'][0], tool.RATES[0] * 0.9)

    def test_not_a_number_rate_kept(self):
        self.clean(tool.view('t', tool.HEAD_A, rates=(math.nan, 1.0, 1.0, 1.0)))

    def test_scale_constant_caught(self):
        self.assertTrue(self.broken(tool.view('t', tool.HEAD_A), {tool.SCALE + 6: 0xd3}))

    def test_supply_immediate_caught(self):
        at = 0x4ce2658 + 6
        v = tool.view('t', tool.HEAD_A, mode=2, stakes={A: 10 ** 13})
        self.assertTrue(self.broken(v, {at: self.data[self.built[0].off(at)] ^ 1}))

    def test_tag_branch_caught(self):
        v = tool.view('t', tool.HEAD_A, links={A: (2, B)}, stakes={A: 10 ** 12, B: 10 ** 12})
        self.assertTrue(self.broken(v, {0x4ce2526: 0x86}))


class Packet(unittest.TestCase):
    def test_manifest(self):
        for line in (FOLDER / 'MANIFEST.sha256').read_text().splitlines():
            digest, name = line.split('  ')
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)

    def test_vectors_match_the_tool(self):
        vecs = tool.all_vectors()
        rows = (FOLDER / 'vectors.tsv').read_text().splitlines()[1:]
        self.assertEqual(len(rows), len(vecs))
        for line, v in zip(rows, vecs):
            self.assertEqual(line.split('\t')[2], tool.digest_of(v))

    def test_evidence_counts(self):
        ev = json.loads((FOLDER / 'evidence.json').read_text())
        rows = (FOLDER / 'mutations.tsv').read_text().splitlines()[1:]
        self.assertEqual(ev['mutants'], len(rows))
        self.assertEqual(ev['killed'], sum(1 for r in rows if r.split('\t')[4] == 'killed'))
        self.assertEqual(ev['mismatches'], 0)
        self.assertEqual(sum(ev['groups'].values()), ev['vectors'])

    def test_each_survivor_has_a_reason(self):
        ev = json.loads((FOLDER / 'evidence.json').read_text())
        for line in (FOLDER / 'mutations.tsv').read_text().splitlines()[1:]:
            parts = line.split('\t')
            if parts[4] == 'equivalent':
                self.assertIn(parts[2], ev['equivalent'])

    def test_no_absolute_paths(self):
        bad = tuple(chr(0x2f) + x for x in ('tmp', 'home', 'srv', 'mnt'))
        for p in FOLDER.iterdir():
            text = p.read_text()
            for b in bad:
                self.assertNotIn(b, text, p.name)


if __name__ == '__main__':
    unittest.main()
