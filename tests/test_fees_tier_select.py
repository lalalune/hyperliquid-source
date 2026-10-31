"""Tests of tools/fees_tier_select.py: digest binding, real outcomes, corrupted bytes and the packet files."""

import hashlib
import importlib.util
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
SPEC = importlib.util.spec_from_file_location('fees_tier_select', ROOT / 'tools' / 'fees_tier_select.py')
tool = importlib.util.module_from_spec(SPEC)
sys.modules['fees_tier_select'] = tool
SPEC.loader.exec_module(tool)
FOLDER = ROOT / 'research' / 'work-items' / 'fees-tier-select-94'
MAIN, COPY_A, COPY_B = tool.HEAD_MAIN, tool.HEAD_A, tool.HEAD_B
U, L1, L2 = tool.U, tool.L1, tool.L2
days, dex, head, fl = tool.days, tool.dex, tool.head, tool.fl
f2b = tool.f2b
CUT = [(f2b(0.0004), 5 * 10 ** 10, f2b(0.8), f2b(0.0003), f2b(0.0001), f2b(0.0005)),
       (f2b(0.0003), 25 * 10 ** 10, f2b(0.7), f2b(0.0002), f2b(0.00009), f2b(0.0004))]


class Base(unittest.TestCase):
    data = (ROOT / tool.BINARY).read_bytes()
    built = tool.build(data)
    ctx = (built[0], built[1], built[3], built[4])

    def clean(self, v):
        self.assertIsNone(tool.check(self.ctx, v))
        return tool.tier_rule(v) if v['kind'] == 'head' else None

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
            self.built[2].range_of(MAIN + 1)

    def test_bss_refused(self):
        bss = self.built[0].sec['.bss'][0]
        with self.assertRaises(tool.EvidenceError):
            self.built[0].read(bss, 8)

    def test_constants_pinned(self):
        constants, pins = tool.pinned(self.built[0])
        self.assertEqual(constants['mm_cap'], 2.0 ** 64)
        self.assertEqual(constants['high'], 2.0 ** 64 - 2048)
        self.assertEqual(len(pins), len(tool.PINS))

    def test_pin_refuses_changed_bytes(self):
        with self.assertRaises(tool.EvidenceError):
            tool.pinned(tool.Image(self.data, {tool.PINS[0][1]: 0}))

    def test_constant_refuses_changed_bytes(self):
        with self.assertRaises(tool.EvidenceError):
            tool.pinned(tool.Image(self.data, {tool.CAP_MM + 7: 0}))

    def test_names_read_from_bytes(self):
        rows = tool.name_rows(self.built[0])
        self.assertIn('staking_keep_frac_for_referrer', [r['text'] for r in rows])
        with self.assertRaises(tool.EvidenceError):
            tool.name_rows(tool.Image(self.data, {tool.NAMES[0][0]: 0}))

    def test_no_external_program(self):
        text = (ROOT / 'tools' / 'fees_tier_select.py').read_text()
        self.assertNotIn('import subprocess', text)
        self.assertNotIn('os.system', text)

    def test_three_copies_end_at_their_tables(self):
        for fn, c in tool.COPIES.items():
            self.assertEqual(tool.RANGES[fn][-1][1], tool.FDE_END[fn])
            self.assertEqual(len(c['entries']), 4)
            self.assertGreaterEqual(c['entries'][0], c['stop'])


class DaySum(Base):
    def days_vector(self, **kw):
        v = dict(kind='days', group='t', copy=tool.DAYS, date=tool.D0, count=14, tree=[])
        v.update(kw)
        return v

    def test_day_zero_and_day_fifteen_left_out(self):
        v = self.days_vector(tree=days((0, 1, 2), (1, 10, 20), (14, 100, 200), (15, 1000, 2000)))
        self.clean(v)
        self.assertEqual(tool.day_sum(v['tree'], tool.D0, 14, [0]), (110, 220))

    def test_saturates_and_records(self):
        tally = [0]
        self.assertEqual(tool.day_sum(days((1, tool.TOP, 1), (2, 5, 1)), tool.D0, 14, tally), (tool.TOP, 2))
        self.assertEqual(tally[0], 1)

    def test_zero_count(self):
        self.clean(self.days_vector(count=0, tree=days((1, 1, 1))))

    def test_date_zero_panics(self):
        self.clean(self.days_vector(date=3, count=3, tree=days((1, 1, 1), date=3)))

    def test_range_limit(self):
        self.assertTrue(tool.range_allows(1 << 31))
        self.assertFalse(tool.range_allows((1 << 31) + 1))

    def test_range_constant_corrupted(self):
        v = dict(kind='range', group='t', copy=tool.DAYS, date=tool.D0, k=(1 << 31) + 1, start=0x3425a80, after=0x3425abd)
        self.clean(v)
        self.assertTrue(self.broken(v, {0x3425a97: 0x3e}))

    def test_tree_descent_in_all_heights(self):
        for h in range(5):
            self.clean(self.days_vector(height=h, tree=days(*[(k, k + 1, k + 2) for k in range(30)])))


class Selection(Base):
    def test_three_copies_agree(self):
        for copy in tool.COPIES:
            w = self.clean(head('t', copy, vip=CUT, rows={U: days((1, 3 * 10 ** 6, 4 * 10 ** 6))}))
            self.assertEqual(w['vip'], 0)
            self.assertEqual(w['scale'], f2b(0.8))

    def test_block_map_returns_no_rows(self):
        for copy in tool.COPIES:
            w = self.clean(head('t', copy, blocked=[U], blocked_items=1))
            self.assertTrue(w['empty'])

    def test_linked_addresses_are_summed(self):
        w = self.clean(head('t', MAIN, links={U: [L1, L2]}, link_items=2, rows={U: days((1, 1, 2)), L1: days((2, 10, 20)), L2: days((3, 100, 200))}))
        self.assertEqual((w['a'], w['b']), (111, 222))

    def test_double_covers_only_the_first_map(self):
        w = self.clean(head('t', MAIN, double=1, rows={U: days((1, 6, 8))}, dexes=[dex(0, {U: days((1, 30, 50))})]))
        self.assertEqual((w['a'], w['b']), (42, 66))

    def test_filter_only_in_mode_2(self):
        row = {U: days((1, 30, 50))}
        self.assertEqual(self.clean(head('t', MAIN, mode=2, dexes=[dex(77, row)]))['a'], 100)
        self.assertEqual(self.clean(head('t', MAIN, mode=2, dexes=[dex(109, row)]))['a'], 130)
        self.assertEqual(self.clean(head('t', MAIN, mode=1, dexes=[dex(77, row)]))['a'], 130)

    def test_allowed_words(self):
        self.assertEqual(tool.ALLOWED, (0, 18, 44, 53, 55, 58, 59, 108, 109))

    def test_lazy_row_forced_also_on_a_hit(self):
        w = self.clean(head('t', MAIN, once=3, dexes=[dex(0, {U: days((1, 5, 6))})]))
        self.assertEqual(w['once'], 1)

    def test_vip_exact_cutoff(self):
        hit = self.clean(head('t', MAIN, vip=[CUT[0]], rows={U: days((1, 2 * 10 ** 6, 3 * 10 ** 6))}))
        miss = self.clean(head('t', MAIN, vip=[CUT[0]], rows={U: days((1, 2 * 10 ** 6, 3 * 10 ** 6 - 1))}))
        self.assertEqual((hit['vip'], miss['vip']), (0, None))

    def test_vip_picks_last_row_that_passes(self):
        w = self.clean(head('t', MAIN, vip=CUT, rows={U: days((1, 25 * 10 ** 6, 1))}))
        self.assertEqual(w['vip'], 1)

    def test_vip_rate_is_a_minimum(self):
        w = self.clean(head('t', MAIN, vip=[CUT[0]], rates=fl(0.0002, 0.1, 0.1, 0.1), rows={U: days((1, 5 * 10 ** 6, 0))}))
        self.assertEqual(w['rates'][0], f2b(0.0002))
        self.assertEqual(w['rates'][1], f2b(0.0001))

    def test_mm_touches_add_slots_only(self):
        w = self.clean(head('t', MAIN, mm=[(f2b(0.5), f2b(-0.00001))], pool=100, rows={U: days((1, 50, 0))}))
        self.assertEqual(w['rates'], fl(0.00045) + fl(-0.00001) + fl(0.0007) + fl(-0.00001))

    def test_mm_bound_edges(self):
        self.assertEqual(tool.mm_bound(f2b(float('nan')), 5), 0)
        self.assertEqual(tool.mm_bound(f2b(float('inf')), 5), 0)
        self.assertEqual(tool.mm_bound(f2b(-1.0), 5), 0)
        self.assertEqual(tool.mm_bound(f2b(1.0), tool.TOP), tool.TOP)
        self.assertEqual(tool.mm_bound(f2b(0.5), 7), 3)

    def test_mm_compares_only_the_first_sum(self):
        w = self.clean(head('t', MAIN, mm=[(f2b(0.5), f2b(-0.00001))], pool=100, rows={U: days((1, 49, 10 ** 6))}))
        self.assertIsNone(w['mm'])

    def test_rust_min(self):
        nan = tool.NAN
        self.assertEqual(tool.rust_min(f2b(1.0), nan), f2b(1.0))
        self.assertEqual(tool.rust_min(nan, f2b(1.0)), f2b(1.0))
        self.assertEqual(tool.rust_min(f2b(1.0), f2b(2.0)), f2b(1.0))


class Corrupted(Base):
    def test_window_constant(self):
        self.assertTrue(self.broken(head('t', MAIN, rows={U: days((15, 5, 6))}), {0x26fbe80: 0x0f}))

    def test_dex_window_constant(self):
        v = head('t', MAIN, dexes=[dex(0, {U: days((15, 5, 6))})])
        self.assertTrue(self.broken(v, {0x26fc08e: 0x0f}))

    def test_filter_mask(self):
        self.assertTrue(self.broken(head('t', MAIN, mode=2, dexes=[dex(1, {U: days((1, 5, 6))})]), {0x26fbefb: 0x03}))

    def test_divisor(self):
        v = head('t', MAIN, vip=[CUT[0]], rows={U: days((1, 5 * 10 ** 6 - 1, 0))})
        self.assertTrue(self.broken(v, {0x26fc2de: 0x4a}))

    def test_vip_stride(self):
        self.assertTrue(self.broken(head('t', MAIN, vip=CUT, rows={U: days((1, 5 * 10 ** 6, 0))}), {0x26fc304 + 3: 0xd8}))

    def test_rate_table_entry(self):
        v = head('t', MAIN, vip=[CUT[0]], rows={U: days((1, 5 * 10 ** 6, 0))})
        table = tool.COPIES[MAIN]['table']
        self.assertTrue(self.broken(v, {table: self.built[0].read(table, 1)[0] ^ 8}))

    def test_hit_branch(self):
        self.assertTrue(self.broken(head('t', MAIN, blocked=[U], blocked_items=1), {0x26fbbcd: 0x85}))


class Vectors(unittest.TestCase):
    def test_same_set_each_copy(self):
        lengths = {len(tool.group_vectors(c)) for c in tool.COPIES}
        self.assertEqual(len(lengths), 1)

    def test_vectors_are_stable(self):
        a, b = tool.group_vectors(MAIN), tool.group_vectors(MAIN)
        self.assertEqual([tool.digest_of(x) for x in a], [tool.digest_of(x) for x in b])

    def test_every_outcome_is_covered(self):
        names = {tool.outcome_name(v) for v in tool.group_vectors(MAIN)}
        for want in ('no rows', 'date panic', 'vip none, mm none', 'vip row, mm none', 'vip none, mm row', 'vip row, mm row'):
            self.assertIn(want, names)


class Packet(unittest.TestCase):
    def setUp(self):
        self.ev = json.loads((FOLDER / 'evidence.json').read_text())

    def test_manifest(self):
        rows = (FOLDER / 'MANIFEST.sha256').read_text().splitlines()
        self.assertTrue(rows)
        for row in rows:
            digest, name = row.split('  ')
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_evidence_counts(self):
        self.assertEqual(self.ev['sha256'], tool.SHA256)
        self.assertEqual(self.ev['mismatches'], 0)
        self.assertEqual(self.ev['vectors'], len(tool.all_vectors()))
        self.assertEqual(self.ev['killed'] + len(self.ev['equivalent']), self.ev['mutants'])

    def test_vectors_file_matches(self):
        rows = (FOLDER / 'vectors.tsv').read_text().splitlines()[1:]
        vecs = tool.all_vectors()
        self.assertEqual(len(rows), len(vecs))
        self.assertEqual([r.split('\t')[2] for r in rows], [tool.digest_of(v) for v in vecs])

    def test_no_absolute_location(self):
        for key in ('overflow_location', 'both_location', 'date_location'):
            self.assertFalse(self.ev[key]['path'].startswith(chr(0x2f)))

    def test_mutation_file_lists_every_mutant(self):
        rows = (FOLDER / 'mutations.tsv').read_text().splitlines()[1:]
        self.assertEqual(len(rows), self.ev['mutants'])
        self.assertEqual(sum(r.split('\t')[4] == 'killed' for r in rows), self.ev['killed'])


if __name__ == '__main__':
    unittest.main()
