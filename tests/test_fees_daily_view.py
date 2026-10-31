"""Tests of tools/fees_daily_view.py: digest binding, real outcomes, corrupted bytes and the packet files."""

import hashlib
import importlib.util
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
SPEC = importlib.util.spec_from_file_location('fees_daily_view', ROOT / 'tools' / 'fees_daily_view.py')
tool = importlib.util.module_from_spec(SPEC)
sys.modules['fees_daily_view'] = tool
SPEC.loader.exec_module(tool)
FOLDER = ROOT / 'research' / 'work-items' / 'fees-daily-view-94'
f2b, b2f, dv, sv, seq, dk, U = tool.f2b, tool.b2f, tool.dv, tool.sv, tool.seq, tool.dk, tool.U


class Base(unittest.TestCase):
    data = (ROOT / tool.BINARY).read_bytes()
    built = tool.build(data)
    ctx = (built[0], built[1], built[3], built[4])

    def clean(self, v):
        self.assertIsNone(tool.check(self.ctx, v))
        return tool.expected_daily(v) if v['kind'] == 'daily' else None

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
            self.built[2].range_of(tool.DAILY + 1)

    def test_bss_refused(self):
        bss = self.built[0].sec['.bss'][0]
        with self.assertRaises(tool.EvidenceError):
            self.built[0].read(bss, 8)

    def test_decoder_lands_on_each_fde_end(self):
        for fn in tool.SUBJECTS:
            rows = self.built[5][fn]
            self.assertEqual(rows[-1].va + rows[-1].size, tool.FDE_END[fn])

    def test_pin_change_refused(self):
        img = tool.Image(self.data, {0x2586b80: 0x01})
        with self.assertRaises(tool.EvidenceError):
            tool.pinned(img)

    def test_constant_change_refused(self):
        img = tool.Image(self.data, {tool.MILLION + 6: 0x3e})
        with self.assertRaises(tool.EvidenceError):
            tool.pinned(img)

    def test_no_external_program(self):
        text = (ROOT / 'tools' / 'fees_daily_view.py').read_text()
        self.assertNotIn('import subprocess', text)
        self.assertIn('from fde_extents import eh_frame_records', text)


class Daily(Base):
    def test_fifteen_rows_oldest_first_today_last(self):
        got = self.clean(dv('t'))
        self.assertEqual(len(got['rows']), 15)
        self.assertEqual(got['rows'][0][3], tool.day_of(dv('t'), 14))
        self.assertEqual(got['rows'][-1][3], tool.D0)
        self.assertEqual(got['days'], list(range(14, -1, -1)))

    def test_word_one_is_user_cross(self):
        got = self.clean(dv('t', spot={U: seq((700, 300), days=(0,))}))
        self.assertEqual(b2f(got['rows'][-1][0]), 3.0)
        self.assertEqual(b2f(got['rows'][-1][1]), 7.0)

    def test_exchange_reads_word_zero_only(self):
        got = self.clean(dv('t', total=seq((500, 999), days=(0,))))
        self.assertEqual(b2f(got['rows'][-1][2]), 5.0)

    def test_linked_owner_is_added(self):
        o = tool.user(40)
        got = self.clean(dv('t', links=[o], spot={U: seq((100, 0), days=(0,)), o: seq((200, 0), days=(0,))}))
        self.assertEqual(b2f(got['rows'][-1][1]), 3.0)

    def test_double_skips_dex_rows(self):
        got = self.clean(dv('t', double=1, spot={U: seq((100, 0), days=(0,))}, dex=[dict(word=1, users={U: seq((100, 0), days=(0,))})]))
        self.assertEqual(b2f(got['rows'][-1][1]), 3.0)

    def test_filter_drops_a_dex_row(self):
        for word, want in ((18, 1.0), (19, 0.0), (108, 1.0), (110, 0.0)):
            got = self.clean(dv('t', mode=2, dex=[dict(word=word, users={U: seq((100, 0), days=(0,))})]))
            self.assertEqual(b2f(got['rows'][-1][1]), want)

    def test_saturation_is_recorded(self):
        got = self.clean(dv('t', double=1, spot={U: seq((1 << 63, 0), days=(0,))}))
        self.assertEqual(got['rec'], 1)
        self.assertEqual(got['rows'][-1][1], f2b(float(tool.U64) / 100.0))

    def test_signed_day_key(self):
        got = self.clean(dv('t', spot={U: ((-3, 100, 0), (dk(0), 300, 0))}))
        self.assertEqual(b2f(got['rows'][-1][1]), 3.0)

    def test_range_top(self):
        self.clean(dv('t', range=(1 << 31, 1 << 31)))
        self.assertEqual(tool.expected_daily(dv('t', range=((1 << 31) + 1, (1 << 31) + 1))), 'date')

    def test_exhausted_and_inverted_ranges_are_empty(self):
        self.assertEqual(self.clean(dv('t', tag=1))['cap'], 0)
        self.assertEqual(self.clean(dv('t', range=(5, 2)))['cap'], 0)

    def test_bad_byte_keeps_the_capacity(self):
        got = self.clean(dv('t', tag=2))
        self.assertEqual((got['cap'], len(got['rows'])), (15, 0))

    def test_every_vector_matches(self):
        for v in tool.all_vectors():
            self.assertIsNone(tool.check(self.ctx, v), v['group'])


class Schedule(Base):
    def test_cutoff_is_over_1e6(self):
        got = tool.expected_schedule(sv('t', vip=((5 * 10 ** 12, tool.RATES, 0),)))
        self.assertEqual(b2f(got['vip'][0][0]), 5e6)

    def test_row_word_0x28_is_dropped(self):
        a = sv('t', vip=((1, tool.RATES, f2b(0.5)),))
        self.clean(a)
        self.assertEqual(len(tool.expected_schedule(a)['vip'][0]), 5)

    def test_ladder_gains_a_zero_row(self):
        got = tool.expected_schedule(sv('t', ladder=((7, 8),)))
        self.assertEqual(got['ladder'], [(0, 0), (7, 8)])
        self.clean(sv('t', ladder=((7, 8),)))

    def test_empty_lists(self):
        self.clean(sv('t'))

    def test_units_meet(self):
        cutoff = 5 * 10 ** 12
        self.assertEqual(cutoff // 10000 / 100.0, cutoff / 1e6)


class Outer(Base):
    def w(self, a, b, **kw):
        return dict(kind='outer', group='t', waits=(f2b(a), f2b(b)), **kw)

    def test_three_seconds_exactly_is_quiet(self):
        self.assertEqual(tool.expected_outer(self.w(1.5, 1.5, level=13, lazy=1, cell=1)), [])
        self.clean(self.w(1.5, 1.5, level=13, lazy=1, cell=1))

    def test_slow_branch_forces_cells(self):
        v = self.w(1.0, 2.5, level=13, lazy=1, cell=1)
        self.assertEqual(tool.expected_outer(v), [0x50, 'lazy'])
        self.clean(v)

    def test_nan_wait_is_quiet(self):
        v = dict(kind='outer', group='t', waits=(tool.NAN, f2b(5.0)), level=13, lazy=1, cell=1)
        self.assertEqual(tool.expected_outer(v), [])
        self.clean(v)


class Corrupted(Base):
    FULL = dv('t', links=[tool.user(40)], spot={U: seq(), tool.user(40): seq((3, 4))}, total=seq(), double=1, mode=2, dex=[dict(word=18, users={U: seq((7, 9))}, total=seq((11, 13)))])
    SCHED = sv('t', vip=((5 * 10 ** 12, tool.RATES, f2b(0.5)),), mm=((f2b(0.01), f2b(-0.0001)),), ladder=((f2b(1.0), f2b(0.1)),), base=(1, 2, 3, 4), referral=9)
    SLOW = dict(kind='outer', group='t', waits=(f2b(2.0), f2b(2.0)), level=13, lazy=1, cell=1)

    def test_clean_image_passes(self):
        self.assertFalse(self.broken(self.FULL, {}))
        self.assertFalse(self.broken(self.SCHED, {}))
        self.assertFalse(self.broken(self.SLOW, {}))

    def test_cent_divisor(self):
        self.assertTrue(self.broken(self.FULL, {tool.CENT + 6: 0x49}))

    def test_pair_divisor(self):
        self.assertTrue(self.broken(self.FULL, {tool.PAIR + 6: 0x49}))

    def test_million_divisor(self):
        self.assertTrue(self.broken(self.SCHED, {tool.MILLION + 6: 0x3e}))

    def test_wait_limit(self):
        v = dict(self.SLOW, waits=(f2b(1.0), f2b(1.5)))
        self.assertTrue(self.broken(v, {tool.THREE + 7: 0x3f}))

    def test_total_tree_field(self):
        self.assertTrue(self.broken(self.FULL, {0x26f990e: 0xd0}))

    def test_allow_mask(self):
        self.assertTrue(self.broken(self.FULL, {0x26f9707: 0x10}))

    def test_row_count_of_ladder(self):
        self.assertTrue(self.broken(self.SCHED, {0x2a3bdeb: 0}))

    def test_row_store_swap(self):
        self.assertTrue(self.broken(self.FULL, {0x28f0ed2: 0xc1}))


class Packet(Base):
    evidence = json.loads((FOLDER / 'evidence.json').read_text())

    def test_manifest(self):
        rows = (FOLDER / 'MANIFEST.sha256').read_text().split('\n')
        seen = set()
        for line in rows:
            if line:
                digest, name = line.split('  ')
                self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)
                seen.add(name)
        self.assertEqual(seen, {p.name for p in FOLDER.iterdir() if p.name != 'MANIFEST.sha256'})

    def test_sha(self):
        self.assertEqual(self.evidence['sha256'], tool.SHA256)

    def test_vector_rows(self):
        vecs = tool.all_vectors()
        rows = (FOLDER / 'vectors.tsv').read_text().split('\n')[1:-1]
        self.assertEqual(len(rows), len(vecs))
        self.assertEqual(self.evidence['vectors'], len(vecs))
        self.assertEqual(self.evidence['mismatches'], 0)
        for v, line in zip(vecs, rows):
            self.assertEqual(line.split('\t')[2], tool.digest_of(v))

    def test_mutation_rows(self):
        rows = [x.split('\t') for x in (FOLDER / 'mutations.tsv').read_text().split('\n')[1:-1]]
        self.assertEqual(len(rows), self.evidence['mutants'])
        self.assertEqual(sum(r[3] == 'killed' for r in rows), self.evidence['killed'])
        self.assertLessEqual({int(r[1], 16) for r in rows if r[3] == 'equivalent'}, set(tool.EQUIVALENT))
        self.assertEqual(sum(r[3] == 'unclassified' for r in rows), self.evidence['unclassified'])

    def fields(self, name):
        return {r['text']: r['offset'] for r in self.evidence['serializer_fields'][name]['fields']}

    def test_daily_row_keys(self):
        self.assertEqual(self.fields('daily row'), dict(date=0x18, userCross=0, userAdd=8, exchange=0x10))

    def test_vip_row_keys(self):
        self.assertEqual(self.fields('vip row'), dict(ntlCutoff=0, cross=8, add=0x10, spotCross=0x18, spotAdd=0x20))

    def test_mm_row_keys(self):
        self.assertEqual(self.fields('mm row'), dict(makerFractionCutoff=0, add=8))

    def test_ladder_row_keys(self):
        self.assertEqual(self.fields('ladder row'), dict(bpsOfMaxSupply=0, discount=8))

    def test_schedule_keys(self):
        self.assertEqual(self.fields('schedule'), dict(cross=0x48, add=0x50, spotCross=0x58, spotAdd=0x60, tiers=0, referralDiscount=0x68, stakingDiscountTiers=0x30))

    def test_no_unlisted_gap(self):
        for row in self.evidence['functions']:
            self.assertEqual(row['instructions'], len(self.built[5][int(row['start'], 16)]))


if __name__ == '__main__':
    unittest.main()
