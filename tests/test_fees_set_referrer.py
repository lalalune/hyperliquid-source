"""Tests for tools/fees_set_referrer.py on node #94 bytes."""

import hashlib
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import fees_set_referrer as t  # noqa: E402

FOLDER = ROOT / 'research/work-items/fees-set-referrer-94'
DATA = (ROOT / t.BINARY).read_bytes()
IMG, CODE, FDES, SLOTS, GOT = t.build(DATA)
FAULTS = (t.Unmodelled, t.Panicked, t.EvidenceError, KeyError, ValueError, TypeError, struct.error, StopIteration)
ME, YOU = t.ME, t.YOU
BUCKET = t.NOW_MS // t.DAY_MS


def result(v, img=IMG, code=CODE):
    return t.run(img, code, SLOTS, GOT, v)


def status(v):
    return result(v)[0]


def passes(v, img=IMG, code=CODE):
    return t.check(img, code, SLOTS, GOT, v) is None


def mutate(fn, patch):
    img = t.Image(DATA, patch)
    code = dict(CODE)
    code.update({i.va: i for i in t.decode_range(img, fn, t.FDE_END[fn])})
    return img, code


def fails(fn, patch, vectors):
    img, code = mutate(fn, patch)
    for v in vectors:
        try:
            if not passes(v, img, code):
                return True
        except FAULTS:
            return True
    return False


def vec(**kw):
    return t.vec('test', **kw)


def flip(fn, va, vectors, bit=1):
    return fails(fn, {va: IMG.read(va, 1)[0] ^ bit}, vectors)


def row_of(m, key):
    tab = m.table
    mem = tab['arena'].mem
    for i in range(tab['size']):
        at = tab['ctrl_off'] - (i + 1) * t.STRIDE
        if not mem[tab['ctrl_off'] + i] & 0x80 and bytes(mem[at:at + 20]) == key:
            return bytes(mem[at:at + t.STRIDE])
    return None


class Input(unittest.TestCase):
    def test_digest(self):
        self.assertEqual(t.check_digest(DATA), t.SHA256)
        with self.assertRaises(t.EvidenceError):
            t.check_digest(DATA[:-1] + bytes([DATA[-1] ^ 1]))

    def test_decoder_lands_on_each_end(self):
        for fn in t.SUBJECTS:
            listing = t.decode_range(IMG, fn, t.FDE_END[fn])
            self.assertEqual(listing[-1].va + listing[-1].size, t.FDE_END[fn])

    def test_decoder_refuses_a_cut_range(self):
        with self.assertRaises(t.EvidenceError):
            t.decode_range(IMG, t.HELPER, t.HELPER + 2)

    def test_no_fde_at_a_middle_address(self):
        with self.assertRaises(t.EvidenceError):
            FDES.range_of(t.HELPER + 1)

    def test_nobits_is_outside_the_image(self):
        with self.assertRaises(t.EvidenceError):
            IMG.read(IMG.sec['.bss'][0], 8)

    def test_pinned_bytes(self):
        self.assertEqual(len(t.pinned(IMG)), len(t.PINNED))
        va = t.PINNED[0][0]
        with self.assertRaises(t.EvidenceError):
            t.pinned(t.Image(DATA, {va: IMG.read(va, 1)[0] ^ 1}))

    def test_slot(self):
        self.assertEqual(IMG.relative(t.HELPER_SLOT), t.HELPER)
        with self.assertRaises(t.EvidenceError):
            IMG.relative(t.HELPER_SLOT + 1)

    def test_status_texts(self):
        self.assertEqual(t.status_text(IMG, t.SELF_CODE), 'Cannot self-refer')
        self.assertEqual(t.status_text(IMG, t.ALREADY_SET), 'Referrer already set')
        self.assertEqual(t.status_text(IMG, t.UNKNOWN_CODE), 'Referral code not registered')
        self.assertTrue(t.status_text(IMG, t.NO_ROOM).startswith('Referral code has no more referrals left'))

    def test_drop_of_the_prepared_status_is_a_plain_return(self):
        self.assertEqual(t.drop_case(IMG, t.NO_ROOM), t.DROP_PLAIN)
        self.assertNotEqual(t.drop_case(t.Image(DATA, {t.DROP_TABLE + 4 * (t.NO_ROOM - t.DROP_FIRST): 0}), t.NO_ROOM), t.DROP_PLAIN)


class Callers(unittest.TestCase):
    def test_helper_sites(self):
        sites = t.slot_sites(IMG, t.HELPER_SLOT, sorted(FDES.by_start))
        self.assertEqual([s['function'] for s in sites], ['0x27de270', '0x4676f80', '0x4677030'])

    def test_bucket_step_has_one_caller(self):
        rows = t.direct_sites(IMG, t.BUCKET, sorted(FDES.by_start))
        self.assertEqual([r['function'] for r in rows], [hex(t.HELPER)])

    def test_wrapper_copies(self):
        rows = t.copy_rows(IMG, FDES, t.WRAPPER, (0x4676f80, 0x4677030))
        self.assertEqual([len(r['differs']) for r in rows], [1, 0])
        self.assertIn('0x1050', rows[0]['differs'][0]['here'])


class Gates(unittest.TestCase):
    def test_wrapper_limit(self):
        long_text = b'x' * 101
        self.assertEqual(status(vec(entry='wrapper', code=long_text, codes={long_text: YOU})), t.TOO_LONG_ENTRY)
        self.assertEqual(status(vec(entry='wrapper', code=b'x' * 100, codes={b'x' * 100: YOU})), t.OK)

    def test_helper_has_no_length_limit(self):
        long_text = b'x' * 101
        self.assertEqual(status(vec(code=long_text, codes={long_text: YOU})), t.OK)

    def test_order(self):
        self.assertEqual(status(vec(code=b'none', rows=[(ME, None, YOU)])), t.UNKNOWN_CODE)
        self.assertEqual(status(vec(codes={b'abc': ME}, rows=[(ME, None, YOU)])), t.SELF_CODE)
        self.assertEqual(status(vec(rows=[(ME, None, YOU)], bucket_ms=0)), t.ALREADY_SET)
        self.assertEqual(status(vec(bucket_ms=0)), t.NO_ROOM)

    def test_self_test_needs_all_twenty_bytes(self):
        for i in (0, 15, 16, 19):
            near = ME[:i] + bytes([ME[i] ^ 1]) + ME[i + 1:]
            self.assertEqual(status(vec(codes={b'abc': near}, profiles={near: t.prof()})), t.OK)


class Binding(unittest.TestCase):
    def test_success_stores_twenty_owner_bytes(self):
        _, m = result(vec())
        row = row_of(m, ME)
        self.assertEqual(row[t.ROW_FLAG], 1)
        self.assertEqual(row[t.ROW_OWNER:t.ROW_OWNER + 20], YOU)

    def test_no_profile_is_success_with_flag_clear(self):
        v = vec(profiles={})
        got, m = result(v)
        self.assertEqual(got, t.OK)
        self.assertEqual(row_of(m, ME)[t.ROW_FLAG], 0)
        self.assertTrue(passes(v))

    def test_refused_first_call_keeps_a_new_row(self):
        for v in (vec(bucket_ms=0), vec(profiles={YOU: t.prof(0, BUCKET, 0)})):
            got, m = result(v)
            self.assertEqual(got, t.NO_ROOM)
            self.assertEqual(row_of(m, ME)[t.ROW_FLAG], 0)
            self.assertTrue(passes(v))

    def test_earlier_refusals_make_no_row(self):
        for v in (vec(code=b'none'), vec(codes={b'abc': ME})):
            self.assertIsNone(row_of(result(v)[1], ME))
            self.assertTrue(passes(v))

    def test_first_row_refused_then_taken(self):
        first = vec(bucket_ms=0)
        self.assertEqual(status(first), t.NO_ROOM)
        self.assertEqual(status(vec(rows=[(ME, None, None)])), t.OK)


class Quota(unittest.TestCase):
    def left(self, p, **kw):
        v = vec(profiles={YOU: p}, **kw)
        self.assertTrue(passes(v))
        return t.model(v)['profile'][1]

    def test_same_bucket_counts_down(self):
        self.assertEqual(self.left(t.prof(5, BUCKET, 0)), 4)

    def test_same_bucket_at_zero_refused(self):
        self.assertEqual(status(vec(profiles={YOU: t.prof(0, BUCKET, 5000)})), t.NO_ROOM)

    def test_new_bucket_floor_is_1000(self):
        self.assertEqual(self.left(t.prof(0, BUCKET - 1, 0)), 999)
        self.assertEqual(self.left(t.prof(0, BUCKET + 1, 1000)), 999)
        self.assertEqual(self.left(t.prof(0, BUCKET - 1, 1001)), 1000)

    def test_stored_bucket_zero_counts_as_a_change(self):
        self.assertEqual(self.left(t.prof(0, 0, 7)), 999)

    def test_time_before_the_width_is_bucket_zero(self):
        v = vec(profiles={YOU: t.prof(0, 0, 0)}, time=(t.packed(1969, 1), 0, 0))
        self.assertEqual(status(v), t.NO_ROOM)

    def test_division_paths_agree(self):
        just = (t.packed(1970, 50), 61367, 297000000)
        self.assertGreaterEqual(t.millis(just), 1 << 32)
        self.assertTrue(passes(vec(time=just, bucket_ms=1, profiles={YOU: t.prof(3, t.millis(just), 0)})))
        self.assertTrue(passes(vec(time=just, bucket_ms=1, profiles={YOU: t.prof(3, 1, 0)})))


class Clock(unittest.TestCase):
    def test_known_dates(self):
        self.assertEqual(t.millis((t.packed(1970, 1), 0, 0)), 0)
        self.assertEqual(t.raw_millis((t.packed(1969, 365), 86399, 0)), -1000)
        self.assertEqual(t.millis((t.packed(1969, 365), 86399, 0)), 0)
        self.assertEqual(t.raw_millis((t.packed(2000, 60), 0, 5000000)), 951782400005)

    def test_machine_reaches_the_same_signed_time(self):
        for year in (-5, 0, 1, 1969, 2101):
            when = (t.packed(year, 100), 5, 7000000)
            _, m = result(vec(time=when))
            self.assertEqual(m.raw_ms, t.raw_millis(when))

    def test_cycle_count_mutants_keep_days(self):
        """The three survivors of the cycle count: every year at or below 0, as the machine does it, 32-bit."""
        def days(year, one, mult, shift):
            excess = one - year
            k = ((excess * mult) >> shift) + 1
            y = year - 1 + 400 * k
            return y, 365 * y + y // 4 - y // 100 + y // 400 - 146097 * k
        for year in range(-262143, 1):
            plain = days(year, 1, 0x51eb851f, 0x27)
            for variant in ((0, 0x51eb851f, 0x27), (1, 0x51eb851e, 0x27), (1, 0x51eb851f, 0x26)):
                y, d = days(year, *variant)
                self.assertGreaterEqual(y, 0)
                self.assertEqual(d, plain[1])


class Log(unittest.TestCase):
    def test_new_key_on_an_empty_log_makes_a_root(self):
        v = vec()
        self.assertTrue(passes(v))
        self.assertEqual(result(v)[1].log_result[:4], bytes(4))

    def test_repeat_replaces_and_still_counts_down(self):
        old = (t.packed(2020, 5), 9, 11)
        v = vec(profiles={YOU: t.prof(5, BUCKET, 0, log={ME: old})})
        got, m = result(v)
        self.assertEqual(got, t.OK)
        self.assertEqual(m.log_result, t.time_bytes(old))
        self.assertEqual(t.model(v)['profile'], (YOU, 4, BUCKET, False))
        self.assertTrue(passes(v))

    def test_new_key_on_a_tree_goes_to_the_vacant_entry(self):
        v = vec(profiles={YOU: t.prof(log={t.addr(9): t.NOW})})
        calls = result(v)[1].calls
        self.assertEqual(calls[-1], ('log', ME, t.time_bytes(t.NOW)))

    def test_allocation_failure_panics(self):
        self.assertTrue(passes(vec(alloc=0, panic='allocation')))


class Table(unittest.TestCase):
    def test_tombstone_keeps_growth(self):
        v = vec(deleted=(0,), growth=1)
        self.assertTrue(passes(v))
        _, m = result(v)
        self.assertEqual(t.read(m.ex.mem, t.TABLE + 0x10), 1)

    def test_empty_slot_uses_growth(self):
        _, m = result(vec(growth=2))
        self.assertEqual(t.read(m.ex.mem, t.TABLE + 0x10), 1)
        self.assertEqual(t.read(m.ex.mem, t.TABLE + 0x18), 1)

    def test_growth_zero_reserves_and_uses_the_new_table(self):
        v = vec(size=8, growth=0, rows=[(t.addr(30), None, None)])
        _, m = result(v)
        self.assertEqual(m.calls[0], ('reserve',))
        self.assertEqual(m.table['size'], 16)
        self.assertTrue(passes(v))

    def test_small_table_wraps_off_the_mirror(self):
        base = (0x2a << 57) | 6
        rows = [(t.addr(40 + i), base + (i + 1 << 58), None) for i in range(6)]
        v = vec(size=8, user_hash=base, rows=rows, growth=1)
        self.assertTrue(passes(v))
        self.assertTrue(flip(t.HELPER, 0x374368b, [v]))

    def test_free_slot_model_refuses_nothing_on_an_empty_table(self):
        ctrl = [0xff] * (32 + 16)
        self.assertEqual(t.free_slot(ctrl, 31, 7), 7)
        t.set_ctrl(ctrl, 31, 7, 1)
        self.assertEqual(t.free_slot(ctrl, 31, 7), 8)


class Controls(unittest.TestCase):
    def test_floor_constant(self):
        va = 0x394b8e6
        self.assertTrue(flip(t.BUCKET, va, [vec(profiles={YOU: t.prof(0, 1, 0)})]))

    def test_zero_width_jump(self):
        self.assertTrue(flip(t.BUCKET, 0x394b833, [vec(bucket_ms=0), vec()]))

    def test_clamp(self):
        va = 0x394b8a2
        self.assertTrue(flip(t.BUCKET, va, [vec(time=(t.packed(1969, 1), 0, 0), profiles={YOU: t.prof(3, 1, 0)})]))

    def test_flag_store(self):
        self.assertTrue(flip(t.HELPER, 0x374383e, [vec()]))

    def test_owner_dword_store(self):
        self.assertTrue(flip(t.HELPER, 0x3743850, [vec()], bit=8))

    def test_length_limit_byte(self):
        va = 0x27de28e
        v = [vec(entry='wrapper', code=b'x' * 100, codes={b'x' * 100: YOU}), vec(entry='wrapper', code=b'x' * 101, codes={b'x' * 101: YOU})]
        self.assertTrue(flip(t.WRAPPER, va, v))

    def test_model_catches_a_wrong_expectation(self):
        v = vec()
        real = t.model
        t.model = lambda _v: dict(status=t.NO_ROOM, insert=True, bind=None, profile=None)
        try:
            self.assertFalse(passes(v))
        finally:
            t.model = real

    def test_stub_refuses_a_wrong_reserve_argument(self):
        img, code = mutate(t.HELPER, {0x37438f3: IMG.read(0x37438f3, 1)[0] ^ 2})
        with self.assertRaises(t.Unmodelled):
            result(vec(growth=0), img, code)


class Packet(unittest.TestCase):
    def test_every_vector_of_the_sample_matches(self):
        vecs = t.all_vectors()
        for v in vecs[::37]:
            self.assertTrue(passes(v), v['group'])

    def test_static_generation_matches_the_folder(self):
        ev = json.loads((FOLDER / 'evidence.json').read_text())
        with tempfile.TemporaryDirectory() as tmp:
            fresh = t.generate(DATA, tmp, with_survey=False)
            for name in ('vectors.tsv', 'instructions.tsv', 'reference-diff.tsv'):
                self.assertEqual((Path(tmp) / name).read_bytes(), (FOLDER / name).read_bytes())
        for key in ('vectors', 'functions', 'helper_callers', 'wrapper_copies', 'outcomes', 'status_text', 'bucket_callers', 'log_insert_callers', 'drop_case'):
            self.assertEqual(fresh[key], ev[key], key)
        self.assertEqual(ev['mismatches'], 0)
        rows = (FOLDER / 'mutations.tsv').read_text().splitlines()
        self.assertEqual(ev['killed'] + sum(1 for x in rows if '\tequivalent\t' in x), ev['mutants'])

    def test_manifest(self):
        for line in (FOLDER / 'MANIFEST.sha256').read_text().splitlines():
            digest, name = line.split('  ')
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)


if __name__ == '__main__':
    unittest.main()
