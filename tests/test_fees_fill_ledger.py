"""Tests for tools/fees_fill_ledger.py on node #94 bytes."""

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import fees_fill_ledger as t  # noqa: E402

FOLDER = ROOT / 'research/work-items/fees-fill-ledger-94'
DATA = (ROOT / t.BINARY).read_bytes()
IMG, CODE, FDES = t.build(DATA)
VECTORS = t.all_vectors()
USER, REF, BLD = t.addr(1), t.addr(2), t.addr(3)
SEED = [101, 202, 303, 404, 505, 606]


def run(v, img=IMG, code=CODE):
    want = t.apply_model(v)
    m, ctx = t.run_ledger(img, code, v)
    return want, t.compare(m, ctx, v, want)


def mutate(fn, patch):
    img = t.Image(DATA, patch)
    code = dict(CODE)
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


def full_case(**rec):
    base = dict(tag=1, ref=100, ref_addr=REF, btag=1, bamt=25, b_addr=BLD, gross=1000, rebate=50, extra=30)
    base.update(rec)
    return t.vector('test', tables={USER: {0x168: list(SEED)}, REF: {0x168: list(SEED)}, BLD: {0x168: list(SEED)}},
                    builders={BLD: {0x168: 7}}, rec=base)


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
            FDES.range_of(t.LEDGER + 1)


class Decoder(unittest.TestCase):
    def test_lands_on_fde_end(self):
        counts = {fn: len(t.decode_range(IMG, fn, t.FDE_END[fn])) for fn in t.DECODED}
        self.assertEqual(counts, {t.LEDGER: 540, t.ENTRY: 75, t.FIND: 87})

    def test_unlisted_encoding_refused(self):
        with self.assertRaises(t.EvidenceError):
            t.decode_range(t.Image(DATA, {t.LEDGER: 0x0f, t.LEDGER + 1: 0x0b + 0xf0}), t.LEDGER, t.FDE_END[t.LEDGER])


class Vectors(unittest.TestCase):
    def test_all_match_and_every_instruction_runs(self):
        seen = set()
        self.assertEqual(t.run_vectors(IMG, CODE, VECTORS, seen), [])
        for fn in t.DECODED:
            left = [i.va for i in t.decode_range(IMG, fn, t.FDE_END[fn]) if i.va not in seen and i.op != 'nop']
            self.assertEqual(left, [], hex(fn))

    def test_group_sizes(self):
        groups = {}
        for v in VECTORS:
            groups[v['group']] = groups.get(v['group'], 0) + 1
        self.assertEqual(sum(groups.values()), len(VECTORS))
        self.assertEqual(set(groups), {'shapes', 'plain', 'tags', 'subtraction', 'saturation', 'alias', 'builder', 'probe', 'collision', 'random'})

    def test_vectors_are_deterministic(self):
        again = t.all_vectors()
        self.assertEqual([t.digest_of(v) for v in again], [t.digest_of(v) for v in VECTORS])


class Model(unittest.TestCase):
    def word(self, v, who, field):
        return t.apply_model(v)[0][who][0x168][field]

    def test_full_record(self):
        v = full_case()
        self.assertEqual(self.word(v, USER, t.T), 606 + 30)
        self.assertEqual(self.word(v, USER, t.F), 505 + 1000 - 50 - 30)
        self.assertEqual(self.word(v, USER, t.r_), 404 + 100)
        self.assertEqual(self.word(v, REF, t.U), 202 + 100)
        self.assertEqual(self.word(v, BLD, t.U), 202 + 25)
        self.assertEqual(t.apply_model(v)[1][BLD][0x168], 32)
        self.assertEqual(self.word(v, USER, t.V), 101)
        self.assertEqual(self.word(v, USER, t.C), 303)
        self.assertIsNone(run(v)[1])

    def test_no_referrer_touches_only_t(self):
        v = full_case(tag=0, btag=0)
        tables = t.apply_model(v)[0]
        self.assertEqual(tables[USER][0x168], SEED[:5] + [606 + 30])
        self.assertEqual(tables[REF][0x168], SEED)
        self.assertIsNone(run(v)[1])

    def test_builder_amount_zero_skips_both_maps(self):
        v = full_case(tag=0, bamt=0)
        tables, builders = t.apply_model(v)[:2]
        self.assertEqual(tables[BLD][0x168], SEED)
        self.assertEqual(builders[BLD][0x168], 7)
        self.assertIsNone(run(v)[1])

    def test_tag_widths(self):
        for tag, on in ((1, True), ((1 << 32) + 1, True), (0x100, False), (2, False)):
            v = full_case(tag=tag, btag=0)
            self.assertEqual(self.word(v, REF, t.U) != 202, on)
            self.assertIsNone(run(v)[1])
        for btag, on in ((1, True), (0xff, True), (0x100, False), (0x101, True)):
            v = full_case(tag=0, btag=btag)
            self.assertEqual(self.word(v, BLD, t.U) != 202, on)
            self.assertIsNone(run(v)[1])

    def test_floors_record_twice(self):
        v = full_case(gross=5, rebate=9, extra=1, btag=0)
        records = t.apply_model(v)[2]
        self.assertEqual(records, [t.LOC_SUB, t.LOC_SUB])
        self.assertEqual(self.word(v, USER, t.F), 505)
        self.assertIsNone(run(v)[1])

    def test_saturation_records_add(self):
        v = t.vector('test', tables={USER: {0x168: [0, 0, 0, 0, 0, t.U64 - 1]}}, rec=dict(extra=5))
        self.assertEqual(t.apply_model(v)[2], [t.LOC_ADD])
        self.assertEqual(self.word(v, USER, t.T), t.U64)
        self.assertIsNone(run(v)[1])

    def test_referrer_is_user_adds_to_one_value(self):
        v = full_case(ref_addr=USER, btag=0)
        self.assertEqual(self.word(v, USER, t.U), 202 + 100)
        self.assertEqual(self.word(v, USER, t.r_), 404 + 100)
        self.assertIsNone(run(v)[1])

    def test_new_bucket_order(self):
        v = t.vector('test', tables={}, rec=dict(tag=1, ref=1, ref_addr=REF, btag=1, bamt=2, b_addr=BLD))
        self.assertEqual(t.apply_model(v)[3], [USER, REF, BLD])
        self.assertIsNone(run(v)[1])


class Slots(unittest.TestCase):
    def test_free_slot_skips_a_full_group(self):
        ctrl = [0x11] * 16 + [0xff] * 16
        h = 0
        self.assertEqual(t.free_slot(ctrl, h), 16)

    def test_free_slot_takes_a_tombstone(self):
        self.assertEqual(t.free_slot([0x80] + [0x11] * 31, 0), 0)

    def test_small_table_restarts_at_zero(self):
        self.assertEqual(t.free_slot([0x11, 0x11, 0xff, 0x11], 3), 2)

    def test_plan_counts_reserve(self):
        key = t.addr(9)
        slots, reserves, growth = t.insert_plan([0xff] * 32, 0, [key])
        self.assertEqual((len(slots), reserves, growth), (1, 1, t.RESERVE_GROWTH - 1))


class Negative(unittest.TestCase):
    def test_wrong_expected_value_is_reported(self):
        v = full_case()
        tables, builders, records, order = t.apply_model(v)
        tables[USER][0x168][t.T] += 1
        m, ctx = t.run_ledger(IMG, CODE, v)
        self.assertIn('tables differ', t.compare(m, ctx, v, (tables, builders, records, order)))

    def test_wrong_builder_map_is_reported(self):
        v = full_case()
        tables, builders, records, order = t.apply_model(v)
        builders[BLD][0x168] += 1
        m, ctx = t.run_ledger(IMG, CODE, v)
        self.assertEqual(t.compare(m, ctx, v, (tables, builders, records, order)), 'builder map differs')

    def test_wrong_records_are_reported(self):
        v = full_case()
        tables, builders, _, order = t.apply_model(v)
        m, ctx = t.run_ledger(IMG, CODE, v)
        self.assertIn('recorder', t.compare(m, ctx, v, (tables, builders, [t.LOC_ADD], order)))

    def test_flipped_referrer_branch_is_caught(self):
        img, code = mutate(t.LEDGER, {0x3745b56 + 0: IMG.read(0x3745b56, 1)[0] ^ 1})
        self.assertTrue(fails(img, code, [full_case()]))

    def test_tag_compare_constant_is_caught(self):
        img, code = mutate(t.LEDGER, {0x3745b55: 3})
        self.assertTrue(fails(img, code, [full_case()]))

    def test_value_field_offset_is_caught(self):
        for va in (0x3745b4e + 3,):
            img, code = mutate(t.LEDGER, {va: IMG.read(va, 1)[0] ^ 8})
            self.assertTrue(fails(img, code, [full_case()]))

    def test_reserve_skip_is_caught(self):
        img, code = mutate(t.LEDGER, {0x3745d51: IMG.read(0x3745d51, 1)[0] ^ 1})
        v = t.vector('test', tables={USER: {}}, growth=0, rec=dict(tag=1, ref=1, ref_addr=REF))
        self.assertTrue(fails(img, code, [v]))

    def test_uninitialised_read_faults(self):
        m = t.Machine(IMG, ())
        a = m.arena(16)
        m.cur = 0
        with self.assertRaises(t.Unmodelled):
            m.load(a.base, 8)

    def test_vacant_handle_above_a_leaf_refused(self):
        m = t.machine(IMG, CODE)
        a = m.arena(0x30)
        for off, val in ((0, a.base + 0x28), (8, 5), (0x10, a.base), (0x18, 1), (0x20, 0)):
            m.store(a.base + off, 8, val)
        m.regs[t.R['rdi']] = a.base
        with self.assertRaises(t.Unmodelled):
            t.entry_stub(m, t.TOKEN)()

    def test_stub_refuses_a_leaf_split(self):
        m = t.machine(IMG, CODE)
        node = m.arena(t.BRANCH)
        m.store(node.base + t.TOKEN.len, 2, t.CAP)
        cell = m.arena(0x18)
        m.store(cell.base + 16, 8, t.CAP)
        with self.assertRaises(t.Unmodelled):
            t.insert(m, t.TOKEN, node.base, 0, 5, cell.base + 16)


class Static(unittest.TestCase):
    def test_token_value_keys(self):
        self.assertEqual(t.token_keys(IMG), [('V', 0), ('U', 8), ('C', 16), ('r', 24), ('F', 32), ('T', 40)])

    def test_tracker_fields(self):
        fields = {f['name']: f['offset'] for f in t.tracker_fields(IMG)}
        self.assertEqual(fields, {'fee_schedule': '0x0', 'user_states': '0xc0', 'unrewarded_users': '0xf0', 'referrer_states': '0x108',
                                  'code_to_referrer': '0x120', 'referral_bucket_millis': '0x138', 'total_fees_collected': '0x140',
                                  'total_spot_fees_collected': '0x148', 'collected_builder_fees': '0x150', 'trials_disabled': '0x168'})

    def test_field_lea_required(self):
        with self.assertRaises(t.EvidenceError):
            t.rip_lea(IMG, t.LEDGER)
        with self.assertRaises(t.EvidenceError):
            t.field_offset(IMG, t.LEDGER)

    def test_pinned_bytes(self):
        self.assertEqual(len(t.pinned(IMG)), len(t.PINNED))
        va = t.PINNED[0][0]
        with self.assertRaises(t.EvidenceError):
            t.pinned(t.Image(DATA, {va: IMG.read(va, 1)[0] ^ 1}))

    def test_locations(self):
        self.assertEqual((t.location(IMG, t.LOC_ADD)['path'], t.location(IMG, t.LOC_ADD)['line']), ('l1/src/qtys/mod.rs', 831))
        self.assertEqual((t.location(IMG, t.LOC_SUB)['path'], t.location(IMG, t.LOC_SUB)['line']), ('l1/src/qtys/impl_wei.rs', 6))


class Evidence(unittest.TestCase):
    def test_manifest(self):
        for line in (FOLDER / 'MANIFEST.sha256').read_text().splitlines():
            digest, name = line.split('  ')
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)

    def test_regenerated_files_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            t.generate(DATA, tmp, with_survey=False)
            for name in ('vectors.tsv', 'instructions.tsv', 'reference-diff.tsv'):
                self.assertEqual((Path(tmp) / name).read_bytes(), (FOLDER / name).read_bytes(), name)

    def test_evidence_counts(self):
        ev = json.loads((FOLDER / 'evidence.json').read_text())
        self.assertEqual(ev['vectors'], len(VECTORS))
        self.assertEqual(ev['mismatches'], 0)
        self.assertEqual(ev['sha256'], t.SHA256)
        self.assertEqual(ev['mutants'], ev['killed'] + len(ev['equivalent']))
        self.assertEqual({c['function'] for c in ev['callers']}, {hex(t.PERP_CALLER), hex(t.SPOT_CALLER)})
        rows = (FOLDER / 'mutations.tsv').read_text().splitlines()[1:]
        self.assertEqual(len(rows), ev['mutants'])

    def test_no_absolute_paths_in_evidence(self):
        for name in ('evidence.json', 'README.md', 'vectors.tsv', 'mutations.tsv', 'reference-diff.tsv'):
            text = (FOLDER / name).read_text()
            for word in ('tmp', 'home', 'srv', 'mnt'):
                self.assertNotIn(chr(0x2f) + word, text, name)
            self.assertNotIn(chr(0x40), text, name)


if __name__ == '__main__':
    unittest.main()
