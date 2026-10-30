"""Tests for tools/fees_schedule_admission.py: bytes against the model, with byte-level negative controls."""

import hashlib
import json
import math
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import fees_schedule_admission as T  # noqa: E402

PACKET = ROOT / 'research/work-items/fees-schedule-admission-94'
DATA = IMG = FDES = CODE = LISTING = VECS = UPDATES = None


def setUpModule():
    global DATA, IMG, FDES, CODE, LISTING, VECS, UPDATES
    DATA = (ROOT / T.BINARY).read_bytes()
    IMG, FDES, CODE, LISTING, VECS = T.build(DATA)
    UPDATES = T.update_vectors()


def patched_code(patches):
    """Image and code with `patches` applied, decoded again, for a negative control."""
    img = T.Image(DATA, patches)
    code = dict(CODE)
    for start in (T.UPDATE, T.LADDER, T.FLOORS):
        for ins in T.decode_range(img, *T.LISTING_RANGE[start]):
            code[ins.va] = ins
    return img, code


def f64_patch(va, value):
    return {va + i: b for i, b in enumerate(struct.pack('<d', value))}


def bad_names(img, code, names):
    want = dict(VECS)
    return T.run_vectors(img, code, [(n, want[n]) for n in names], True)['bad']


class Inputs(unittest.TestCase):
    def test_digest(self):
        self.assertEqual(T.check_digest(DATA), T.SHA256)
        with self.assertRaises(T.EvidenceError):
            T.check_digest(DATA[:-1] + bytes([DATA[-1] ^ 1]))

    def test_fde_extents(self):
        self.assertEqual(FDES.range_of(T.LADDER)['end'], 0x3c042ee)
        self.assertEqual(FDES.range_of(T.FLOORS)['end'], 0x3c06090)
        with self.assertRaises(T.EvidenceError):
            FDES.range_of(T.LADDER + 1)

    def test_decoder_lands_on_the_fde_end(self):
        r = FDES.range_of(T.FLOORS)
        self.assertEqual(sum(i.size for i in T.decode_range(IMG, r['start'], r['end'])), r['end'] - r['start'])
        with self.assertRaises(T.EvidenceError):
            T.decode_range(IMG, r['start'], r['end'] - 1)

    def test_addresses_outside_file_bytes(self):
        with self.assertRaises(T.EvidenceError):
            IMG.read(0x7fff_0000_0000, 8)
        bss = IMG.sec['.bss']
        self.assertEqual(bss[3], 8)
        with self.assertRaises(T.EvidenceError):
            IMG.read(bss[0] + 16, 8)

    def test_constants(self):
        self.assertEqual(T.constants_check(IMG)['rate_cap']['bits'], '0x3f50624dd2f1a9fc')
        with self.assertRaises(T.EvidenceError):
            T.constants_check(T.Image(DATA, f64_patch(0x20afb8, 0.002)))

    def test_field_names(self):
        rows = {(r['owner'], r['offset']): r['name'] for r in T.fields(IMG)}
        self.assertEqual(rows['FeeSchedule', '0x48'], 'cross')
        self.assertEqual(rows['FeeSchedule', '0x68'], 'referralDiscount')
        self.assertEqual(rows['FeeSchedule', '0x30'], 'stakingDiscountTiers')
        self.assertEqual(rows['stake tier', '0x0'], 'bpsOfMaxSupply')
        self.assertEqual(rows['mm tier', '0x0'], 'makerFractionCutoff')
        name = 0x4204ce
        with self.assertRaises(T.EvidenceError):
            T.fields(T.Image(DATA, {name: ord('X')}))

    def test_caller_anchors(self):
        self.assertEqual(T.anchors(IMG)['reject_text'], 'Invalid fees')
        with self.assertRaises(T.EvidenceError):
            T.anchors(T.Image(DATA, {T.UPDATE_REJECT_SITE + 3: 0x9e}))
        with self.assertRaises(T.EvidenceError):
            T.anchors(T.Image(DATA, {T.UPDATE_CALL + 1: 0}))

    def test_fma_binding(self):
        self.assertEqual(T.fma_binding(IMG)['native_bytes'], 'c4e2f1a9c2')
        with self.assertRaises(T.EvidenceError):
            T.fma_binding(T.Image(DATA, {T.FMA_NATIVE: 0x90}))


class Model(unittest.TestCase):
    def test_base_passes(self):
        self.assertEqual(T.model(T.base_schedule())[:3], (True, None, None))

    def test_order_of_two_faults(self):
        b = T.base_schedule()
        s = T.with_(b, keep=2.0, aligned=(2.0, 1.0, 1.0))
        self.assertEqual(T.model(s)[1], 'keep_high')
        s = T.with_(b, vip=T.replace_row(b['vip'], 2, 4, 1), stake=[(0.0, 0.1)])
        self.assertEqual(T.model(s)[1], 'ntl_order')

    def test_fma_is_exact(self):
        self.assertEqual(T.fma(0.1, 10.0, -1.0), 2.0 ** -54 * 1.0)
        self.assertEqual(0.1 * 10.0 - 1.0, 0.0)

    def test_sum_starts_negative_zero(self):
        self.assertEqual(math.copysign(1.0, IMG.f64(0x20a910)), -1.0)


class Bytes(unittest.TestCase):
    def test_all_vectors_agree(self):
        res = T.run_vectors(IMG, CODE, VECS)
        self.assertEqual(res['bad'], [])
        seen = res['seen'] | T.run_update(IMG, CODE, UPDATES)['seen']
        self.assertEqual(T.unexecuted(LISTING, seen), [])

    def test_strict_memory_faults_on_unset_bytes(self):
        m = T.Machine(IMG, ())
        a = m.arena(16)
        with self.assertRaises(T.Unmodelled):
            m.load(a.base, 8)

    def test_keys_of_the_map_are_never_read(self):
        s = T.with_(T.base_schedule(), extra=[0.25] * 12)
        self.assertIsNone(T.outcome_mismatch(s, T.evaluate(IMG, CODE, s)))

    def test_heap_rejects_wrong_free(self):
        m = T.fresh_machine(IMG, CODE)
        heap = T.Heap(m)
        m.regs[T.R['rdi']] = 8
        heap.alloc()
        ptr = m.regs[0]
        m.regs[T.R['rdi']], m.regs[T.R['rsi']], m.regs[T.R['rdx']] = ptr, 16, 0
        with self.assertRaises(T.Unmodelled):
            heap.free()

    def test_changed_constants_are_seen(self):
        for va, value, names in ((0x20afb8, 0.002, ['cross_base_over_cap']),
                                 (0x20a890, 6.0, ['stake_bps_over_cap']),
                                 (0x20a940, 0.6, ['stake_discount_over_cap']),
                                 (0x20a730, 2.0, ['referral_over']),
                                 (0x20a840, 6e-06, ['floor_zero_add_keep0.0_stake0_edge0']),
                                 (0x20c108, 0.3, ['base'])):
            img, code = patched_code(f64_patch(va, value))
            self.assertTrue(bad_names(img, code, names), hex(va))

    def test_each_failure_site_flip_is_seen(self):
        names = {'ntl_order': 'vip1_ntl_equal', 'stake_bps_cap': 'stake_bps_over_cap', 'extra_sum': 'extra_over_one',
                 'aligned2_low': 'aligned2_half', 'add_cap': 'base'}
        for label, name in names.items():
            va = T.SITE[label]
            ins = CODE[va]
            if ins.op == 'jmp':
                continue
            img, code = patched_code(T.flip_patch(ins))
            self.assertTrue(bad_names(img, code, [name]), label)

    def test_equality_side_of_a_rate_list(self):
        # jbe to jb at the cross list makes equal neighbours fail
        va = 0x3c035c6
        self.assertEqual(CODE[va].op, 'jbe')
        img, code = patched_code({va: 0x72})
        self.assertTrue(bad_names(img, code, ['vip1_cross_equal']))

    def test_expected_failure_is_compared_with_the_site(self):
        s = T.with_(T.base_schedule(), keep=2.0)
        got = T.evaluate(IMG, CODE, s)
        self.assertIsNone(T.outcome_mismatch(s, got))
        got['hits'] = [(T.SITE['referral_low'], T.SILENT)]
        self.assertIsNotNone(T.outcome_mismatch(s, got))

    def test_grid_refusal_stops_the_ladder(self):
        s = T.with_(T.base_schedule(), grid=('fail_text', 'ok'))
        got = T.evaluate(IMG, CODE, s)
        self.assertFalse(got['accepted'])
        self.assertEqual(len(got['calls']), 1)


class Update(unittest.TestCase):
    def test_all_update_vectors_agree(self):
        res = T.run_update(IMG, CODE, UPDATES)
        self.assertEqual(res['bad'], [])

    def test_every_mask_runs_on_the_first_shape(self):
        masks = {u['mask'] for n, u in UPDATES if n.startswith('update_a_') and 'expect_panic' not in u}
        self.assertEqual(masks, set(range(T.ALL_PARTS + 1)))

    def test_rejected_patch_leaves_the_state(self):
        shape = T.old_shapes()['a']
        no = T.evaluate_update(IMG, CODE, dict(shape=shape, mask=T.ALL_PARTS, accept=False))
        yes = T.evaluate_update(IMG, CODE, dict(shape=shape, mask=T.ALL_PARTS, accept=True))
        self.assertEqual(no['final'], T.original(shape))
        self.assertEqual(no['tag'], T.TAG_REJECT)
        self.assertEqual(yes['final'], no['cand'])
        self.assertEqual(yes['tag'], T.TAG_ACCEPT)
        self.assertNotEqual(yes['final'], no['final'])

    def test_mismatch_is_reported(self):
        u = dict(shape=T.old_shapes()['a'], mask=3, accept=False)
        got = T.evaluate_update(IMG, CODE, u)
        self.assertIsNone(T.update_mismatch(u, got))
        for key, value in (('tag', T.TAG_ACCEPT), ('final', {}), ('cand', {})):
            self.assertIsNotNone(T.update_mismatch(u, dict(got, **{key: value})), key)

    def test_changed_tag_is_seen(self):
        img, code = patched_code({T.UPDATE_REJECT_SITE + 3: 0x9e})
        self.assertTrue(T.run_update(img, code, UPDATES[:4], True)['bad'])

    def test_flipped_verdict_is_seen(self):
        va = 0x3744a73
        self.assertEqual(CODE[va].op, 'je')
        img, code = patched_code(T.flip_patch(CODE[va]))
        self.assertTrue(T.run_update(img, code, UPDATES[:4], True)['bad'])


class Packet(unittest.TestCase):
    def test_manifest(self):
        for line in (PACKET / 'MANIFEST.sha256').read_text().splitlines():
            digest, name = line.split('  ')
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), digest, name)

    def test_regeneration_is_byte_identical(self):
        with tempfile.TemporaryDirectory() as tmp:
            T.generate(DATA, tmp)
            for name in ('evidence.json', 'checks.tsv', 'fields.tsv', 'instructions.tsv', 'reference-diff.tsv', 'vectors.tsv'):
                self.assertEqual((Path(tmp) / name).read_bytes(), (PACKET / name).read_bytes(), name)

    def test_evidence_counts(self):
        ev = json.loads((PACKET / 'evidence.json').read_text())
        self.assertEqual(ev['vectors']['mismatches'], 0)
        self.assertEqual(ev['vectors']['total'], ev['vectors']['compared'])
        self.assertEqual(ev['branch_survey']['branches'],
                         ev['branch_survey']['killed'] + len(ev['branch_survey']['equivalent']))


if __name__ == '__main__':
    unittest.main()
