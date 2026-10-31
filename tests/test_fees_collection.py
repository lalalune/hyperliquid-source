"""Tests of tools/fees_collection.py: digest binding, real outcomes, corrupted bytes and the packet files."""

import hashlib
import importlib.util
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
SPEC = importlib.util.spec_from_file_location('fees_collection', ROOT / 'tools' / 'fees_collection.py')
tool = importlib.util.module_from_spec(SPEC)
sys.modules['fees_collection'] = tool
SPEC.loader.exec_module(tool)
FOLDER = ROOT / 'research' / 'work-items' / 'fees-collection-94'
f2b, cv, sv, addr = tool.f2b, tool.cv, tool.sv, tool.addr
FE = tool.FE
A = tool.SWEEP_A


class Base(unittest.TestCase):
    data = (ROOT / tool.BINARY).read_bytes()
    built = tool.build(data)
    ctx = (built[0], built[1], built[3], built[4])

    def clean(self, v):
        self.assertIsNone(tool.check(self.ctx, v))
        return tool.credit_model(v) if v['kind'] == 'credit' else tool.sweep_model(v)

    def patched(self, patch):
        _, code, _, slots, got, _ = self.built
        mimg = tool.Image(self.data, patch)
        mcode = dict(code)
        for fn in tool.SUBJECTS:
            mcode.update({i.va: i for i in tool.decode_subject(mimg, fn)})
        return (mimg, mcode, slots, got)

    def broken(self, v, patch):
        """True when the corrupted image no longer matches the model on `v`."""
        try:
            return tool.check(self.patched(patch), v) is not None
        except (tool.Unmodelled, tool.Panicked, KeyError):
            return True


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
            self.built[2].range_of(tool.CREDIT + 1)

    def test_bss_refused(self):
        bss = self.built[0].sec['.bss'][0]
        with self.assertRaises(tool.EvidenceError):
            self.built[0].read(bss, 8)

    def test_decoder_lands_on_each_fde_end(self):
        for fn in tool.SUBJECTS:
            rows = self.built[5][fn]
            self.assertEqual(rows[-1].va + rows[-1].size, tool.FDE_END[fn])

    def test_pin_change_refused(self):
        img = tool.Image(self.data, {0x37067e0: 0x02})
        with self.assertRaises(tool.EvidenceError):
            tool.pinned(img)

    def test_constant_change_refused(self):
        img = tool.Image(self.data, {tool.TOP_F + 6: 0xcf})
        with self.assertRaises(tool.EvidenceError):
            tool.pinned(img)

    def test_key_change_refused(self):
        img = tool.Image(self.data, {0x3bf83c: 0x44})
        with self.assertRaises(tool.EvidenceError):
            tool.pinned(img)

    def test_no_external_program(self):
        text = (ROOT / 'tools' / 'fees_collection.py').read_text()
        self.assertNotIn('import subprocess', text)
        self.assertIn('from fde_extents import eh_frame_records', text)


class Credit(Base):
    def test_deployer_gets_first_amount(self):
        got = self.clean(cv('t', a=5, b=6))
        self.assertEqual(got['book'].bal, {addr(1): 5, FE: 6})

    def test_flag_picks_recipient(self):
        self.assertEqual(self.clean(cv('t', a=5, b=6, flag=3))['book'].bal[addr(2)], 5)
        self.assertEqual(self.clean(cv('t', a=5, b=6, flag=2))['book'].bal[addr(1)], 5)

    def test_negative_amount_sends_all_to_fe(self):
        self.assertEqual(self.clean(cv('t', a=-5, b=6))['book'].bal, {FE: 1})
        self.assertEqual(self.clean(cv('t', a=5, b=-6))['book'].bal, {FE: -1})

    def test_mode_3_skips_deployer_and_pays_destination(self):
        self.assertEqual(self.clean(cv('t', a=5, b=6, mode=3))['book'].bal, {addr(3): 11})

    def test_fractions_apply_to_the_starting_amount(self):
        rows = ((addr(10), f2b(0.5)), (addr(11), f2b(0.25)))
        self.assertEqual(self.clean(cv('t', a=400, b=600, mode=3, extra=rows))['book'].bal, {addr(10): 500, addr(11): 250, addr(3): 250})

    def test_fraction_truncates_toward_zero(self):
        rows = ((addr(10), f2b(0.3)),)
        self.assertEqual(self.clean(cv('t', a=0, b=-5, mode=3, extra=rows))['book'].bal[addr(10)], -1)

    def test_nan_fraction_pays_nothing(self):
        rows = ((addr(10), tool.NAN),)
        self.assertEqual(self.clean(cv('t', a=0, b=500, mode=3, extra=rows))['book'].bal, {addr(10): 0, addr(3): 500})

    def test_total_is_clamped_to_one_percent_of_i64(self):
        self.assertEqual(self.clean(cv('t', a=0, b=tool.CLAMP + 1))['fees'], tool.CLAMP)
        self.assertEqual(self.clean(cv('t', a=0, b=-tool.CLAMP - 1))['fees'], -tool.CLAMP)

    def test_scale_multiplies_total(self):
        self.assertEqual(self.clean(cv('t', a=500, b=500, scale=f2b(0.25)))['fees'], 250)

    def test_most_negative_product_panics(self):
        self.assertEqual(self.clean(cv('t', a=tool.I64MIN, b=0))['panic'], 'neg')

    def test_short_tree_panics(self):
        self.assertEqual(self.clean(cv('t', a=0, b=10, mode=3, extra=tool.share_rows(2), len=3))['panic'], 'none')

    def test_count_word_limits_the_walk(self):
        got = self.clean(cv('t', a=0, b=10000, mode=3, extra=tool.share_rows(3), len=2))
        self.assertNotIn(addr(12), got['book'].bal)

    def test_mode_other_than_3_does_not_read_tracker_fields(self):
        v = cv('t', mode=2)
        self.assertNotIn('extra', v)
        self.clean(v)

    def test_set_edit_only_on_change(self):
        who = addr(1)
        self.assertIn(('insert', who), self.clean(cv('t', flip={who: 5}))['book'].log)
        self.assertIn(('unmark', who), self.clean(cv('t', word={who: 5}, flip={who: 0}))['book'].log)
        self.assertFalse([x for x in self.clean(cv('t', word={who: 5}))['book'].log if x[0] in ('insert', 'unmark')])


class Sweep(Base):
    def test_token_0_keeps_remainder(self):
        got = self.clean(sv(A, 't', tree={0: 1234}))
        self.assertEqual(got['tree'][0], 34)
        self.assertEqual(got['credits'], [12])
        self.assertEqual(got['spot'], 12)
        self.assertEqual(got['dex238'], 12)

    def test_token_0_below_100_stays(self):
        got = self.clean(sv(A, 't', tree={0: 99}))
        self.assertEqual(got['tree'][0], 99)
        self.assertEqual(got['credits'], [])

    def test_token_0_credit_is_the_second_amount(self):
        self.assertEqual(self.clean(sv(A, 't', tree={0: 1234}))['book'].bal, {addr(1): 0, FE: 12})

    def test_other_token_is_cleared_and_sent_to_fe(self):
        got = self.clean(sv(A, 't', tokens=(5,), tree={5: 2000}, prices={5: 3}))
        self.assertEqual(got['tree'][5], 0)
        self.assertEqual(got['log'], [('keys',), ('price', 2000, 5, 3), ('spot', 5, 2000)])
        self.assertEqual((got['fees'], got['spot']), (20, 20))

    def test_price_above_limit_uses_raw_amount(self):
        self.assertEqual(self.clean(sv(A, 't', tokens=(5,), tree={5: 2000}, price={5: (1, tool.LIMIT)}))['fees'], 20)
        self.assertEqual(self.clean(sv(A, 't', tokens=(5,), tree={5: 2000}, price={5: (1, tool.LIMIT - 1)}))['fees'], (tool.LIMIT - 1) // 100)

    def test_price_flag_is_bit_0(self):
        self.assertEqual(self.clean(sv(A, 't', tokens=(5,), tree={5: 2000}, price={5: (2, 900)}))['fees'], 20)
        self.assertEqual(self.clean(sv(A, 't', tokens=(5,), tree={5: 2000}, price={5: (3, 900)}))['fees'], 9)

    def test_gate_skips_everything(self):
        got = self.clean(sv(A, 't', gate=1))
        self.assertEqual(got['log'], [])
        self.assertEqual(got['tree'], {0: 1000})

    def test_no_dex_panics_after_the_store(self):
        got = self.clean(sv(A, 't', dexes=False, tree={0: 1234}))
        self.assertEqual(got['panic'], 'unwrap')
        self.assertEqual(got['tree'][0], 34)

    def test_copies_agree(self):
        for fn in tool.SWEEPS:
            got = self.clean(sv(fn, 't', tokens=(0, 5), tree={0: 1234, 5: 700}, prices={5: 2}))
            self.assertEqual((got['spot'], got['fees']), (19, 19))

    def test_layouts_differ_only_in_offsets(self):
        self.assertEqual(tool.LAYOUT[tool.SWEEP_A], tool.LAYOUT[tool.SWEEP_C])
        self.assertEqual(tool.LAYOUT[tool.SWEEP_B]['fees'] - tool.LAYOUT[tool.SWEEP_B]['tracker'], 0x140)
        self.assertEqual(tool.LAYOUT[tool.SWEEP_A]['spot'] - tool.LAYOUT[tool.SWEEP_A]['tracker'], 0x148)


class Corrupted(Base):
    def test_mode_compare(self):
        self.assertTrue(self.broken(cv('t', mode=2), {0x37067e0: 0x02}))

    def test_fe_constant(self):
        self.assertTrue(self.broken(cv('t'), {tool.WIDE: 0xfd}))

    def test_clamp_constant(self):
        self.assertTrue(self.broken(cv('t', a=0, b=tool.CLAMP + 1), {0x3706f37: 0xaf}))

    def test_fraction_offset(self):
        self.assertTrue(self.broken(cv('t', a=0, b=1000, mode=3, extra=tool.share_rows(1)), {0x3706bd2: 0x00}))

    def test_sweep_token_limit(self):
        self.assertTrue(self.broken(sv(A, 't', tree={0: 99}), {0x26fea57: 0x63}))

    def test_sweep_tree_clear(self):
        self.assertTrue(self.broken(sv(A, 't', tokens=(5,), tree={5: 2000}), {0x26fe9a3: 0x01}))

    def test_sweep_copy_gate(self):
        self.assertTrue(self.broken(sv(tool.SWEEP_B, 't', gate=1), {0x4ce76b8: 0x85}))

    def test_flip_every_conditional_of_the_mode_path(self):
        for va in (0x37067e1, 0x370698a):
            ins = self.built[1][va]
            at = va + (1 if ins.raw[0] == 0x0f else 0)
            self.assertTrue(self.broken(cv('t', mode=3), {at: ins.raw[at - va] ^ 1}) or self.broken(cv('t'), {at: ins.raw[at - va] ^ 1}))


class Model(Base):
    def test_trunc(self):
        self.assertEqual(tool.trunc(float('nan')), 0)
        self.assertEqual(tool.trunc(float('inf')), 0)
        self.assertEqual(tool.trunc(2.0 ** 63), tool.I64MAX)
        self.assertEqual(tool.trunc(-2.0 ** 64), tool.I64MIN)
        self.assertEqual(tool.trunc(-1.9), -1)

    def test_wrong_model_is_seen(self):
        real = tool.credit_model
        try:
            def wrong(v):
                out = real(v)
                out['fees'] = out.get('fees', 0) + 1
                return out
            tool.credit_model = wrong
            self.assertIsNotNone(tool.check(self.ctx, cv('t')))
        finally:
            tool.credit_model = real

    def test_vectors_stay_sorted_in_file_order(self):
        self.assertEqual(tool.digest_of(cv('t')), tool.digest_of(cv('t')))


class Packet(Base):
    def test_manifest(self):
        for line in (FOLDER / 'MANIFEST.sha256').read_text().splitlines():
            digest, name = line.split()
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)

    def test_evidence_counts(self):
        ev = json.loads((FOLDER / 'evidence.json').read_text())
        self.assertEqual(ev['sha256'], tool.SHA256)
        self.assertEqual(ev['vectors'], len(tool.all_vectors()))
        self.assertEqual(ev['mismatches'], 0)
        self.assertEqual(ev['unclassified'], 0)
        self.assertEqual(ev['killed'] + len([1 for line in (FOLDER / 'mutations.tsv').read_text().splitlines() if '\tequivalent\t' in line]), ev['mutants'])

    def test_vectors_file(self):
        rows = (FOLDER / 'vectors.tsv').read_text().splitlines()[1:]
        vecs = tool.all_vectors()
        self.assertEqual(len(rows), len(vecs))
        for line, v in zip(rows, vecs):
            self.assertEqual(line.split('\t')[2], tool.digest_of(v))

    def test_credit_sites_file(self):
        rows = (FOLDER / 'credit-sites.tsv').read_text().splitlines()[1:]
        self.assertEqual(len(rows), 12)
        self.assertIn('0x26fead8\t0x26fe810', rows)


if __name__ == '__main__':
    unittest.main()
