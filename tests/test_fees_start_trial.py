"""Tests for tools/fees_start_trial.py on node #94 bytes."""

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

import fees_start_trial as t  # noqa: E402

FOLDER = ROOT / 'research/work-items/fees-start-trial-94'
DATA = (ROOT / t.BINARY).read_bytes()
IMG, CODE, FDES = t.build(DATA)
VECTORS = t.all_vectors()
USER, OTHER = t.addr(1), t.addr(2)


def run(v, img=IMG, code=CODE):
    want = t.apply_model(v)
    m, ctx, out = t.run_writer(img, code, v)
    return want, t.compare(m, ctx, out, v, want), m, out


def status(v):
    want, msg, m, out = run(v)
    if msg:
        raise AssertionError(msg)
    return None if want['panic'] else m.load(out.base, 2)


def mutate(fn, patch):
    img = t.Image(DATA, patch)
    code = dict(CODE)
    code.update({i.va: i for i in t.decode_range(img, fn, t.FDE_END[fn])})
    return img, code


def fails(img, code, vectors):
    for v in vectors:
        try:
            _, msg, _, _ = run(v, img, code)
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
            FDES.range_of(t.WRITER + 1)

    def test_digest_checked_before_work(self):
        with self.assertRaises(t.EvidenceError):
            t.build(DATA[:-1] + bytes([DATA[-1] ^ 1]))


class Decoder(unittest.TestCase):
    def test_lands_on_fde_end(self):
        for fn in t.DECODED:
            listing = t.decode_range(IMG, fn, t.FDE_END[fn])
            self.assertEqual(listing[-1].va + listing[-1].size, t.FDE_END[fn])

    def test_short_range_overruns(self):
        with self.assertRaises(t.EvidenceError):
            t.decode_range(IMG, t.WRITER, t.WRITER + 2)

    def test_unlisted_opcode_refused(self):
        with self.assertRaises(t.EvidenceError):
            t.decode_one(b'\x0f\xff' + b'\x90' * 16, 0, 0x1000)

    def test_unlisted_predicate_refused(self):
        with self.assertRaises(t.EvidenceError):
            t.decode_one(b'\x66\x0f\xc2\xc1\x06' + b'\x90' * 16, 0, 0x1000)


class Static(unittest.TestCase):
    def test_slots(self):
        self.assertEqual(IMG.relative(t.WRITER_SLOT), t.WRITER)
        for slot, target in t.SLOTS.items():
            self.assertEqual(IMG.relative(slot), target)

    def test_three_callers(self):
        starts = sorted(f['start'] for f in t.eh_frame_records(DATA)[1])
        sites = t.slot_sites(IMG, t.WRITER_SLOT, starts)
        self.assertEqual([int(s['site'], 16) for s in sites], list(t.CALLERS))
        self.assertEqual(sites[0]['function'], hex(t.HANDLER))

    def test_handler_copies(self):
        same, wider = t.handler_copies(IMG, FDES)
        self.assertEqual(same['differs'], [])
        self.assertTrue(wider['differs'])
        self.assertEqual({row['delta'] for row in wider['differs']}, {'0xa80'})

    def test_handler_copies_refuse_a_changed_opcode(self):
        va = 0x46775bd
        bad = t.Image(DATA, {va: IMG.read(va, 1)[0] ^ 8})
        with self.assertRaises(t.EvidenceError):
            t.handler_copies(bad, FDES)

    def test_pinned(self):
        self.assertEqual(len(t.pinned(IMG)), len(t.PINNED))

    def test_pinned_refuses_other_bytes(self):
        bad = t.Image(DATA, {t.PINNED[0][0]: 0})
        with self.assertRaises(t.EvidenceError):
            t.pinned(bad)

    def test_status_text(self):
        self.assertEqual(t.status_text(IMG, t.ACTIVE), 'Fee trial has already started.')
        self.assertEqual(t.status_text(IMG, t.NO_RATE), 'Fee trial rate does not exist.')
        self.assertEqual(t.status_text(IMG, t.NO_EFFECT), 'Fee trial rates are already met.')
        self.assertEqual(t.status_text(IMG, t.COOLDOWN), 'Fee trial ended too recently.')
        self.assertEqual(t.status_text(IMG, t.DISABLED), 'Fee trials are disabled.')
        self.assertEqual(t.status_text(IMG, 0x8d), 'Action only allowed on testnet')

    def test_calendar_tables(self):
        self.assertEqual(t.calendar_tables(IMG)['mismatches'], 0)

    def test_calendar_tables_refuse_a_changed_byte(self):
        for va in (0x2504e5 + 123, 0x250354 + 200):
            bad = t.Image(DATA, {va: IMG.read(va, 1)[0] ^ 1})
            with self.assertRaises(t.EvidenceError):
                t.calendar_tables(bad)

    def test_date_panic_text(self):
        self.assertEqual(t.panic_text(IMG), '`NaiveDate + TimeDelta` overflowed')

    def test_field_names(self):
        self.assertEqual(t.field_names(IMG)[:4], ['perpAddBaseRate', 'perpCrossBaseRate', 'spotAddBaseRate', 'spotCrossBaseRate'])


class Calendar(unittest.TestCase):
    def test_pack_round_trip(self):
        for z in (-100000, -1, 0, 1, 20000, 20574, 100000, 90000000):
            self.assertEqual(t.unpack_day(t.pack_day(z)), z)

    def test_year_end(self):
        self.assertEqual(t.unpack_day(t.add_days(t.date(2026, 12, 18), 14)), t.days_from_civil(2027, 1, 1))

    def test_leap_day(self):
        self.assertEqual(t.unpack_day(t.add_days(t.date(2024, 2, 15), 14)), t.days_from_civil(2024, 2, 29))
        self.assertEqual(t.unpack_day(t.add_days(t.date(2023, 2, 15), 14)), t.days_from_civil(2023, 3, 1))

    def test_max_date(self):
        self.assertIsNone(t.add_days(t.date(t.MAX_YEAR, 12, 31), 1))

    def test_plain_add_is_not_the_date(self):
        p = t.date(2026, 12, 18)
        self.assertNotEqual(p + 14, t.add_days(p, 14))

    def test_examples_use_real_helper(self):
        rows = t.date_examples(IMG, CODE)
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0]['end']['year'], 2027)
        self.assertEqual(rows[0]['end']['ordinal'], 1)


class Paths(unittest.TestCase):
    def test_all_vectors_match(self):
        self.assertEqual(t.run_vectors(IMG, CODE, VECTORS), [])

    def test_disabled_before_active(self):
        self.assertEqual(status(t.vector('t', disabled=True, users={USER: t.user(end=t.TODAY)})), t.DISABLED)

    def test_active_needs_the_date_not_the_tag(self):
        self.assertEqual(status(t.vector('t', users={USER: t.user(end=t.TODAY)})), t.ACTIVE)
        self.assertEqual(status(t.vector('t', users={USER: t.user(end=0)})), t.OK)
        self.assertEqual(status(t.vector('t', users={USER: t.user(end=t.TODAY, tag=0)})), t.OK)

    def test_active_before_parsing(self):
        want, msg, m, _ = run(t.vector('t', users={USER: t.user(end=t.TODAY)}, action=t.act(*t.LOW, pad=300)))
        self.assertIsNone(msg)
        self.assertEqual((want['status'], m.parses), (t.ACTIVE, 0))

    def test_length_limit(self):
        for pos in range(4):
            spec = t.act(*t.LOW)
            spec[pos]['pad'] = t.MAX_LEN - t.HEAD
            self.assertEqual(status(t.vector('t', action=spec)), t.OK)
            spec[pos]['pad'] = t.MAX_LEN - t.HEAD + 1
            self.assertEqual(status(t.vector('t', action=spec)), t.LONG)

    def test_conversion_failure(self):
        for pos in range(4):
            spec = t.act(*t.LOW)
            spec[pos]['fail'] = True
            self.assertEqual(status(t.vector('t', action=spec)), t.CONVERT)

    def test_parse_error_passes_through(self):
        for pos in range(4):
            spec = t.act(*t.LOW)
            spec[pos].update(tag=0x77, word=0x1234)
            _, msg, m, out = run(t.vector('t', action=spec))
            self.assertIsNone(msg)
            self.assertEqual((m.load(out.base, 2), m.load(out.base + 8, 8)), (0x77, 0x1234))

    def test_template_row_needs_all_four(self):
        for pos in range(4):
            spec = list(t.LOW)
            spec[pos] = 0.00011
            self.assertEqual(status(t.vector('t', action=t.act(*spec))), t.NO_RATE)

    def test_override_needs_add_rates_and_both_cross(self):
        x, add = 0.00031, (t.LOW[0], 0.9, t.LOW[2], 0.8)
        v = dict(templates=[t.template(add)], overrides=[(0.0, x)])
        self.assertEqual(status(t.vector('t', action=t.act(t.LOW[0], x, t.LOW[2], x), **v)), t.OK)
        self.assertEqual(status(t.vector('t', action=t.act(t.LOW[0], x, t.LOW[2], 0.0004), **v)), t.NO_RATE)
        self.assertEqual(status(t.vector('t', action=t.act(0.1, x, t.LOW[2], x), **v)), t.NO_RATE)

    def test_add_hit_persists_past_later_rows(self):
        x, add = 0.00031, (t.LOW[0], 0.9, t.LOW[2], 0.8)
        rows = [t.template(add), t.template((0.7,) * 4)]
        self.assertEqual(status(t.vector('t', templates=rows, overrides=[(0.0, x)], action=t.act(t.LOW[0], x, t.LOW[2], x))), t.OK)

    def test_cooldown_boundary(self):
        day = t.unpack_day(t.TODAY)
        self.assertEqual(status(t.vector('t', users={USER: t.user(base=t.pack_day(day - 90))})), t.OK)
        self.assertEqual(status(t.vector('t', users={USER: t.user(base=t.pack_day(day - 89))})), t.COOLDOWN)

    def test_cooldown_ignores_the_tag_and_the_row_date(self):
        day = t.unpack_day(t.TODAY)
        self.assertEqual(status(t.vector('t', users={USER: t.user(tag=0, base=t.pack_day(day - 1))})), t.COOLDOWN)
        self.assertEqual(status(t.vector('t', users={USER: t.user(tag=0, base=0, end=t.TODAY)})), t.OK)

    def test_writer_leaves_the_cooldown_word(self):
        base = t.date(2026, 1, 1)
        v = t.vector('t', users={USER: t.user(base=base)})
        _, msg, m, _ = run(v)
        self.assertIsNone(msg)
        keys = m.table.mem.find(USER)
        self.assertEqual(struct.unpack_from('<I', m.table.mem, keys + 0xc8)[0], base)
        self.assertEqual(struct.unpack_from('<I', m.table.mem, keys + 0x88)[0], t.add_days(t.TODAY, 14))

    def test_second_call_is_active(self):
        v = t.vector('t')
        _, _, m, _ = run(v)
        keys = m.table.mem.find(USER)
        end = struct.unpack_from('<I', m.table.mem, keys + 0x88)[0]
        self.assertEqual(status(t.vector('t', users={USER: t.user(rates=t.LOW, end=end)})), t.ACTIVE)

    def test_no_effect(self):
        self.assertEqual(status(t.vector('t', users={USER: t.user(rates=(0.00001,) * 4)})), t.NO_EFFECT)

    def test_one_rate_is_enough(self):
        self.assertEqual(status(t.vector('t', users={USER: t.user(rates=(0.00001, 0.00001, 0.00001, 0.5))})), t.OK)

    def test_discount_scales_positive_rates_only(self):
        neg = (-0.0001, 0.0002, 0.00005, 0.0003)
        want = t.apply_model(t.vector('t', tiers=[(0.0, 0.5)], templates=[t.template(neg)], action=t.act(*neg)))
        self.assertEqual(want['row']['rates'], (-0.0001, 0.0001, 0.000025, 0.00015))
        self.assertEqual(status(t.vector('t', tiers=[(0.0, 0.5)], templates=[t.template(neg)], action=t.act(*neg))), t.OK)

    def test_tier_walk(self):
        ladder = [(10.0, 0.1), (20.0, 0.2), (30.0, 0.5)]
        for vol, disc in ((5.0, 0.0), (10.0, 0.1), (19.0, 0.1), (20.0, 0.2), (30.0, 0.5), (99.0, 0.5)):
            self.assertEqual(t.discount(ladder, vol), disc)
        self.assertEqual(t.discount(ladder, math.nan), 0.5)
        self.assertEqual(t.discount([], 5.0), 0.0)

    def test_fixed_addresses_zero_row(self):
        for d in (t.ALL_FF, t.ALL_FE):
            self.assertEqual(status(t.vector('t', sender=d)), t.NO_EFFECT)
            neg = (-0.0001, 0.0002, 0.00005, 0.0003)
            self.assertEqual(status(t.vector('t', sender=d, templates=[t.template(neg)], action=t.act(*neg))), t.OK)

    def test_rejected_call_leaves_the_table(self):
        v = t.vector('t', linked=[OTHER], action=t.act(0.9, 0.9, 0.9, 0.9))
        _, msg, m, _ = run(v)
        self.assertIsNone(msg)
        self.assertEqual(bytes(m.table.mem), m.snap_table)

    def test_date_overflow_panics(self):
        self.assertIsNone(status(t.vector('t', date=t.date(t.MAX_YEAR, 12, 31))))


class Controls(unittest.TestCase):
    """Each check must fail when its input or expectation is wrong."""

    def test_wrong_status_seen(self):
        v = t.vector('t')
        want = t.apply_model(v)
        want['status'] = t.DISABLED
        m, ctx, out = t.run_writer(IMG, CODE, v)
        self.assertIn('status', t.compare(m, ctx, out, v, want))

    def test_wrong_end_date_seen(self):
        v = t.vector('t')
        want = t.apply_model(v)
        want['row'] = dict(want['row'], end=want['row']['end'] + 16)
        m, ctx, out = t.run_writer(IMG, CODE, v)
        self.assertIn('table byte', t.compare(m, ctx, out, v, want))

    def test_wrong_rate_seen(self):
        v = t.vector('t')
        want = t.apply_model(v)
        want['row'] = dict(want['row'], rates=(1.0, 1.0, 1.0, 1.0))
        m, ctx, out = t.run_writer(IMG, CODE, v)
        self.assertIn('table byte', t.compare(m, ctx, out, v, want))

    def test_wrong_panic_seen(self):
        v = t.vector('t')
        want = t.apply_model(v)
        want['panic'] = True
        m, ctx, out = t.run_writer(IMG, CODE, v)
        self.assertIn('panic', t.compare(m, ctx, out, v, want))

    def test_unset_read_faults(self):
        m = t.machine(IMG, CODE)
        a = m.arena(16)
        m.cur = 1
        with self.assertRaises(t.Unmodelled):
            m.load(a.base, 8)

    def test_flip_of_disabled_branch(self):
        img, code = mutate(t.WRITER, {0x3744059: IMG.read(0x3744059, 1)[0] ^ 1})
        self.assertTrue(fails(img, code, VECTORS[:5]))

    def test_trial_days_mutant(self):
        img, code = mutate(t.WRITER, {0x3744320: 15})
        self.assertTrue(fails(img, code, VECTORS[:5] + [t.vector('t')]))

    def test_cooldown_days_mutant(self):
        day = t.unpack_day(t.TODAY)
        img, code = mutate(t.WRITER, {0x3744308: 0x5b})
        self.assertTrue(fails(img, code, [t.vector('t', users={USER: t.user(base=t.pack_day(day - 90))})]))

    def test_cooldown_offset_mutant(self):
        day = t.unpack_day(t.TODAY)
        img, code = mutate(t.WRITER, {0x3744302: 0xe8})
        self.assertTrue(fails(img, code, [t.vector('t', users={USER: t.user(base=t.pack_day(day - 1))})]))

    def test_signed_compare_mutant(self):
        img, code = mutate(t.WRITER, {0x3744314: 0x76})
        p = t.date(-1, 12, 25)
        self.assertTrue(fails(img, code, [t.vector('t', date=p, users={USER: t.user(base=p)})]))

    def test_max_to_min_mutant(self):
        img, code = mutate(t.BUILD, {0x37464f8 - 1 + 0: 0x5f})
        self.assertTrue(fails(img, code, [t.vector('t')]))

    def test_limit_mutant(self):
        img, code = mutate(t.VALIDATE, {0x3c05904: 0x65})
        spec = t.act(*t.LOW)
        spec[0]['pad'] = t.MAX_LEN - t.HEAD + 1
        self.assertTrue(fails(img, code, [t.vector('t', action=spec)]))


class Output(unittest.TestCase):
    def test_folder_matches_a_fresh_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = t.generate(DATA, tmp, with_survey=False)
            self.assertEqual(ev['mismatches'], 0)
            for name in ('vectors.tsv', 'instructions.tsv', 'reference-diff.tsv'):
                self.assertEqual((Path(tmp) / name).read_bytes(), (FOLDER / name).read_bytes(), name)

    def test_manifest(self):
        seen = {}
        for line in (FOLDER / 'MANIFEST.sha256').read_text().splitlines():
            digest, name = line.split('  ')
            seen[name] = digest
        self.assertEqual(set(seen), {p.name for p in FOLDER.iterdir()} - {'MANIFEST.sha256'})
        for name, digest in seen.items():
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_no_absolute_paths_in_evidence(self):
        for name in ('evidence.json', 'README.md', 'vectors.tsv', 'mutations.tsv', 'reference-diff.tsv'):
            text = (FOLDER / name).read_text()
            for word in ('tmp', 'home', 'srv', 'mnt'):
                self.assertNotIn(chr(0x2f) + word, text, name)
            self.assertNotIn(chr(0x40), text, name)

    def test_mutation_rows_match_the_count(self):
        ev = json.loads((FOLDER / 'evidence.json').read_text())
        rows = (FOLDER / 'mutations.tsv').read_text().splitlines()[1:]
        self.assertEqual(len(rows), ev['mutants'])

    def test_evidence_numbers(self):
        ev = json.loads((FOLDER / 'evidence.json').read_text())
        self.assertEqual(ev['sha256'], t.SHA256)
        self.assertEqual(ev['vectors'], len(VECTORS))
        self.assertEqual(ev['mismatches'], 0)
        self.assertEqual(ev['killed'] + len(ev['equivalent']), ev['mutants'])
        self.assertEqual(ev['writer_slot'], hex(t.WRITER))


if __name__ == '__main__':
    unittest.main()
