"""Tests for tools/fees_trade_fee.py on node #94 bytes."""

import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import fees_trade_fee as t  # noqa: E402

FOLDER = ROOT / 'research/work-items/fees-trade-fee-94'
DATA = (ROOT / t.BINARY).read_bytes()
IMG, CODE, FDES = t.build(DATA)
SCALE = t.scale_of(IMG)
VECTORS = t.all_vectors()
PICKED = t.sample(VECTORS)
CTX = dict(entries_on=False, table=(), base=(1e-4, 3.5e-4, 2.5e-4, 7e-4), discount=0.04, share=0.1, f90=0.5, f98=2.0)
PERP = dict(side='perp', user=t.addr(1), ntli=10 ** 12, flag=0, builder=None, ctx=CTX, entries={}, dex=0, assets=8, asset=3, full=1,
            trial=0, dep_tag=0, x=0.0, b4c=0, group='test')
SPOT = dict(side='spot', user=t.addr(1), ntli=10 ** 12, flag=0, builder=None, ctx=CTX, entries={}, cat=0, weight=1.0, bpl=1, tk=0, al=0,
            group='test')
ROW = dict(tag=1, rates=CTX['base'], key=0.0, d=0, over=(0.0,) * 4, w70=1.0, flag=1, referrer=t.addr(2), values=[1000], height=0)


def run(v, img=IMG, code=CODE):
    want = t.model(v, SCALE)
    m, res = t.run_fee(img, code, v)
    return want, t.compare(m, res, want)


def mutate(fn, patch):
    img = t.Image(DATA, patch)
    code = dict(CODE)
    if fn is not None:
        code.update({i.va: i for i in t.decode_range(img, fn, t.FDE_END[fn])})
    return img, code


def fails(img, code, vectors):
    for v in vectors:
        try:
            _, msg = run(v, img, code)
        except (t.Unmodelled, t.EvidenceError, KeyError, ValueError, TypeError):
            return True
        if msg:
            return True
    return False


class Input(unittest.TestCase):
    def test_digest(self):
        self.assertEqual(t.check_digest(DATA), t.SHA256)
        with self.assertRaises(t.EvidenceError):
            t.check_digest(DATA[:-1] + bytes([DATA[-1] ^ 1]))

    def test_section_refused(self):
        with self.assertRaises(t.EvidenceError):
            IMG.off(0x5788300 + 16, 8)  # .bss has no file bytes

    def test_fde_required(self):
        with self.assertRaises(t.EvidenceError):
            FDES.range_of(t.PERP + 1)


class Decoder(unittest.TestCase):
    def test_lands_on_fde_end(self):
        counts = {fn: len(t.decode_range(IMG, fn, t.FDE_END[fn])) for fn in t.DECODED}
        self.assertEqual(counts, {t.PERP: 723, t.SPOT: 662, t.RATES: 128, t.DISCOUNT: 218, t.WINDOW: 231})

    def test_overrun_refused(self):
        with self.assertRaises(t.EvidenceError):
            t.decode_range(IMG, t.PERP, t.FDE_END[t.PERP] - 1)

    def test_unlisted_encoding_refused(self):
        with self.assertRaises(t.EvidenceError):
            t.decode_one(b'\xd9\xe8' + b'\x90' * 16, 0, 0x1000)


class Model(unittest.TestCase):
    def outcome(self, **kw):
        return t.perp_model(dict(PERP, **kw), SCALE)

    def test_taker_and_maker_rates(self):
        self.assertEqual(self.outcome()['gross'], 350000000)
        self.assertEqual(self.outcome(b4c=1)['gross'], 100000000)

    def test_asset_byte_scales_by_a_tenth(self):
        self.assertEqual(self.outcome(full=0)['gross'], 35000000)

    def test_deployer_scale_below_and_above_one(self):
        low, high = self.outcome(x=0.5), self.outcome(x=2.0)
        # 1.5 * 3.5e-4 * 1e12 is just below 525000000 in binary64 and the conversion truncates.
        self.assertEqual(low['gross'], 524999999)
        self.assertEqual(low['deployer'], 174999999)
        self.assertEqual(high['gross'], 1400000000)
        self.assertEqual(high['deployer'], 700000000)

    def test_negative_rate_keeps_its_size(self):
        ctx = dict(CTX, base=(-2e-5, 3.5e-4, 0.0, 0.0))
        got = self.outcome(x=1.0, b4c=1, ctx=ctx)
        self.assertEqual((got['gross'], got['rebate']), (0, 20000000))
        self.assertEqual(got['deployer'], -10000000)

    def test_builder_units_are_one_in_100000(self):
        self.assertEqual(self.outcome(builder=(10, t.addr(3)))['bamt'], 100000000)

    def test_exempt_addresses_pay_nothing(self):
        for who in (t.FF_ADDR, t.FE_ADDR):
            self.assertEqual(self.outcome(user=who)['gross'], 0)

    def test_to_i64(self):
        self.assertEqual(t.to_i64(float('nan')), 0)
        self.assertEqual(t.to_i64(float('inf')), 0)
        self.assertEqual(t.to_i64(1e30), (1 << 63) - 1)
        self.assertEqual(t.to_i64(-1e30), -(1 << 63))
        self.assertEqual(t.to_i64(-1.9), -1)


class Machine(unittest.TestCase):
    def test_sample_matches(self):
        bad = t.run_vectors(IMG, CODE, PICKED, SCALE)
        self.assertEqual(bad, [])

    def test_directed_paths(self):
        v = dict(PERP, flag=1, ctx=dict(CTX, entries_on=True), entries={t.addr(1): ROW})
        want, msg = run(v)
        self.assertEqual(msg, '')
        self.assertEqual(want['ref'], 33600000)
        self.assertEqual(want['tag'], 1)

    def test_spot_buckets(self):
        for kw, gross in ((dict(), 700000000), (dict(cat=1), 140000000), (dict(cat=2, weight=0.25), 175000000)):
            want, msg = run(dict(SPOT, **kw))
            self.assertEqual(msg, '')
            self.assertEqual(want['gross'], gross)

    def test_strict_memory(self):
        v = dict(PERP, group='test')
        m = t.machine(IMG, CODE)
        a = m.arena(16)
        m.store(a.base, 8, 1)
        with self.assertRaises(t.Unmodelled):
            m.load(a.base + 8, 8)

    def test_stubs_spoil_caller_saved(self):
        m = t.machine(IMG, CODE)
        m.regs[t.R['rcx']] = 7
        m.regs[t.R['rbx']] = 9
        m.clobber()
        self.assertNotEqual(m.regs[t.R['rcx']], 7)
        self.assertEqual(m.regs[t.R['rbx']], 9)

    def test_bad_input_is_a_mismatch(self):
        want = t.model(PERP, SCALE)
        m, res = t.run_fee(IMG, CODE, dict(PERP, ntli=10 ** 12 + 10 ** 9))
        self.assertNotEqual(t.compare(m, res, want), '')


class Controls(unittest.TestCase):
    """One byte changed in the node's code or data must change an outcome."""

    def perp(self, group):
        return [v for v in PICKED if v['side'] == 'perp' and v['group'] == group]

    def spot(self, group):
        return [v for v in PICKED if v['side'] == 'spot' and v['group'] == group]

    def test_half_cap(self):
        raw = IMG.read(0x20a940, 8)
        img, code = mutate(None, {0x20a940 + 6: raw[6] ^ 0x10})
        self.assertTrue(fails(img, code, self.perp('deployer')))

    def test_builder_divisor(self):
        raw = IMG.read(0x20a9e8, 8)
        img, code = mutate(None, {0x20a9e8 + 6: raw[6] ^ 0x10})
        self.assertTrue(fails(img, code, self.perp('builder_tier')))

    def test_discount_limit(self):
        img, code = mutate(t.DISCOUNT, {0x3743378 + 2: IMG.read(0x3743378 + 2, 1)[0] ^ 1})
        self.assertTrue(fails(img, code, self.perp('discount')))

    def test_window_limit(self):
        img, code = mutate(t.PERP, {0x3713940 + 2: IMG.read(0x3713940 + 2, 1)[0] ^ 1})
        self.assertTrue(fails(img, code, self.perp('referrer')))

    def test_flip_rate_sign_branch(self):
        at = 0x37132e3
        img, code = mutate(t.PERP, {at: IMG.read(at, 1)[0] ^ 1})
        self.assertTrue(fails(img, code, self.perp('deployer')))

    def test_flip_spot_bucket_branch(self):
        at = 0x37424fc
        img, code = mutate(t.SPOT, {at: IMG.read(at, 1)[0] ^ 1})
        self.assertTrue(fails(img, code, self.spot('rate')))


class Evidence(unittest.TestCase):
    def setUp(self):
        self.evidence = json.loads((FOLDER / 'evidence.json').read_text())

    def test_manifest(self):
        rows = (FOLDER / 'MANIFEST.sha256').read_text().splitlines()
        self.assertTrue(rows)
        for row in rows:
            digest, name = row.split('  ', 1)
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_no_mismatch_and_vector_count(self):
        ev = self.evidence
        self.assertEqual(ev['mismatches'], 0)
        self.assertEqual(ev['vectors'], len(VECTORS))
        lines = (FOLDER / 'vectors.tsv').read_text().splitlines()
        self.assertEqual(len(lines) - 1, len(VECTORS))

    def test_facts_recomputed(self):
        listing = {s: t.decode_range(IMG, s, t.FDE_END[s]) for s in t.DECODED}
        self.assertEqual(self.evidence['facts'], json.loads(json.dumps(t.facts(IMG, listing))))

    def test_callers(self):
        sites = self.evidence['perp_callers']
        self.assertEqual(len(sites), 7)
        self.assertEqual([s['site'] for s in sites if s['notional'] == 'register'], ['0x3710d45'])
        self.assertEqual(len(self.evidence['spot_callers']), 5)

    def test_copy_map(self):
        rows = {r['side_block']: r['output'] for r in self.evidence['fill_copy']}
        self.assertEqual(rows['0x58'], '0x0')
        self.assertEqual(rows['0xa8'], '0x50')
        self.assertEqual(rows['0xc8'], '0x70')

    def test_every_survivor_has_a_reason(self):
        lines = (FOLDER / 'mutations.tsv').read_text().splitlines()[1:]
        kept = [x.split('\t') for x in lines if x.split('\t')[4] == 'equivalent']
        self.assertEqual(len(kept), len(self.evidence['equivalent']))
        for row in kept:
            self.assertTrue(row[6])

    def test_no_absolute_paths(self):
        for name in ('evidence.json', 'mutations.tsv', 'reference-diff.tsv'):
            text = (FOLDER / name).read_text()
            self.assertNotIn(chr(47) + 'home' + chr(47), text)
            self.assertNotIn(chr(0x40), text)


if __name__ == '__main__':
    unittest.main()
