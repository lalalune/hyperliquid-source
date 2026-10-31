"""Tests for tools/fees_register_referrer.py on node #94 bytes."""

import hashlib
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import fees_register_referrer as t  # noqa: E402

FOLDER = ROOT / 'research/work-items/fees-register-referrer-94'
DATA = (ROOT / t.BINARY).read_bytes()
IMG, CODE, FDES, SLOTS, GOT = t.build(DATA)
FAULTS = (t.Unmodelled, t.Panicked, t.EvidenceError, KeyError, ValueError, TypeError, struct.error)
ME, YOU = t.addr(1), t.addr(2)


def status(v, img=IMG, code=CODE):
    return t.run(img, code, SLOTS, GOT, v)[0]


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
    kw.setdefault('group', 'test')
    return t.vec(**kw)


def arm(code=b'new', tag=0, value=0, **kw):
    return t.vec('test', 'arm', 1, code=code, volume=None, tag=tag, value=value, **kw)


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

    def test_slots(self):
        self.assertEqual(IMG.relative(t.HELPER_SLOT), t.HELPER)
        self.assertEqual(IMG.relative(t.RECORDER_SLOT), t.RECORDER)
        with self.assertRaises(t.EvidenceError):
            IMG.relative(t.HELPER_SLOT + 1)

    def test_status_texts(self):
        self.assertEqual(t.status_text(IMG, t.TOO_LONG_HELPER), 'Referral code too long')
        self.assertEqual(t.status_text(IMG, t.CODE_TAKEN), 'Referral code already registered by another user')
        self.assertEqual(t.status_text(IMG, t.USER_TAKEN), 'Referral code already registered for this user')
        self.assertEqual(t.status_text(IMG, t.LOW_VOLUME), 'Cannot generate referral code until enough volume traded')

    def test_locations_are_cut(self):
        here = t.location(IMG, t.OVERFLOW_LOCATION)
        self.assertEqual((here['path'], here['line']), ('l1/src/qtys/impl_ntl.rs', 664))
        self.assertTrue(t.location(IMG, t.NONE_LOCATION)['path'].startswith('library/'))


class Callers(unittest.TestCase):
    def test_flags(self):
        starts = sorted(FDES.by_start)
        sites = t.slot_sites(IMG, t.HELPER_SLOT, starts)
        self.assertEqual(len(sites), 6)
        flags = {s['site']: t.site_facts(IMG, int(s['site'], 16))['flag'] for s in sites}
        self.assertEqual(sum(flags.values()), 3)
        self.assertEqual({k for k, x in flags.items() if x}, {hex(a) for a in t.ARM_FLAG_SITES})

    def test_each_flag_one_caller_has_a_limit_test_past_the_clear(self):
        starts = sorted(FDES.by_start)
        for site in t.ARM_FLAG_SITES:
            row = t.arm_copy(IMG, site, starts)
            self.assertLess(int(row['join'], 16), site)

    def test_site_pattern_refuses_another_address(self):
        with self.assertRaises(t.EvidenceError):
            t.site_facts(IMG, t.HELPER + 0x10)

    def test_wrapper_copies(self):
        rows = t.copy_rows(IMG, FDES, t.WRAPPER, t.WRAPPER_COPIES)
        self.assertEqual([len(r['differs']) for r in rows], [1, 0])
        self.assertIn('0x1050', rows[0]['differs'][0]['here'])


class Flag0(unittest.TestCase):
    def test_threshold(self):
        self.assertEqual(status(vec(volume=(t.MIN_VOLUME,))), t.OK)
        self.assertEqual(status(vec(volume=(t.MIN_VOLUME - 1,))), t.LOW_VOLUME)
        self.assertEqual(status(vec(volume=(t.MIN_VOLUME - 1, 1))), t.OK)

    def test_saturation_and_recorder(self):
        result = t.run(IMG, CODE, SLOTS, GOT, vec(volume=(t.U64, 1, 0, 5)))
        self.assertEqual(result[0], t.OK)
        self.assertEqual(result[1].overflows, 2)
        self.assertEqual(t.saturating_sum((t.U64, 1, 0, 5)), (t.U64, 2))

    def test_no_row(self):
        self.assertEqual(status(vec(volume=None)), t.LOW_VOLUME)
        self.assertEqual(status(vec(items=0)), t.LOW_VOLUME)

    def test_row_key_needs_all_twenty_bytes(self):
        h = t.key_hash(ME)
        for i in (0, 15, 16, 19):
            near = ME[:i] + bytes([ME[i] ^ 1]) + ME[i + 1:]
            self.assertEqual(status(vec(volume=None, decoys=[(near, h)])), t.LOW_VOLUME)

    def test_row_at_the_third_probe(self):
        h = t.key_hash(ME)
        wall = [(t.addr(800 + i), h) for i in range(32)]
        v = vec(decoys=wall, third=1)
        self.assertEqual(status(v), t.OK)
        va = 0x3744fdf
        self.assertTrue(fails(t.HELPER, {va: IMG.read(va, 1)[0] ^ 1}, [v]))

    def test_order_volume_then_length_then_owner_then_code(self):
        long_text = b'x' * 101
        p, c = {ME: b'mine'}, {b'mine': ME}
        self.assertEqual(status(vec(code=long_text, volume=(1,), profiles=p, codes=c)), t.LOW_VOLUME)
        self.assertEqual(status(vec(code=long_text, profiles=p, codes=c)), t.TOO_LONG_HELPER)
        self.assertEqual(status(vec(code=b'mine', profiles=p, codes=c)), t.USER_TAKEN)
        self.assertEqual(status(vec(code=b'x', profiles={YOU: b'x'}, codes={b'x': YOU})), t.CODE_TAKEN)

    def test_wrapper_limit(self):
        self.assertEqual(status(vec(entry='wrapper', code=b'x' * 101, volume=None)), t.TOO_LONG_ENTRY)
        self.assertEqual(status(vec(entry='wrapper', code=b'x' * 100)), t.OK)

    def test_tall_tree(self):
        n = 2 ** 10 - 1
        v = vec(volume=[1000] * n, fan=1, height=9)
        self.assertEqual(status(v), t.OK)
        self.assertTrue(passes(v))

    def test_tree_shorter_than_its_length_panics(self):
        v = vec(group='test', volume=[1] * 5, length=6, panic='none')
        self.assertTrue(passes(v))


class Flag1(unittest.TestCase):
    def test_no_volume_test(self):
        self.assertEqual(status(vec(flag=1, volume=None)), t.OK)

    def test_length_comes_first(self):
        self.assertEqual(status(vec(flag=1, code=b'x' * 101, volume=None)), t.TOO_LONG_HELPER)

    def test_replace(self):
        v = vec(flag=1, code=b'new', profiles={ME: b'old'}, codes={b'old': ME}, extra=7)
        result = t.run(IMG, CODE, SLOTS, GOT, v)
        self.assertEqual(result[0], t.OK)
        self.assertEqual(result[1].calls, [('remove', b'old'), ('insert', b'new', ME)])
        self.assertTrue(passes(v))

    def test_same_code_again(self):
        self.assertEqual(status(vec(flag=1, code=b'old', profiles={ME: b'old'}, codes={b'old': ME})), t.OK)

    def test_code_of_another(self):
        self.assertEqual(status(vec(flag=1, code=b'x', profiles={ME: b'old', YOU: b'x'}, codes={b'old': ME, b'x': YOU})), t.CODE_TAKEN)

    def test_own_code_without_a_profile(self):
        self.assertEqual(status(vec(flag=1, code=b'x', codes={b'x': ME})), t.CODE_TAKEN)

    def test_allocation_failure_panics(self):
        for alloc in (0, 1):
            self.assertTrue(passes(vec(flag=1, alloc=alloc, panic='allocation')))


class Arm(unittest.TestCase):
    def test_none_sends_zero(self):
        result = t.run(IMG, CODE, SLOTS, GOT, arm(tag=0, value=5))
        self.assertEqual(result[1].calls[0][3], 0)

    def test_some_sends_value(self):
        result = t.run(IMG, CODE, SLOTS, GOT, arm(tag=1, value=t.ARM_LIMIT - 1))
        self.assertEqual(result[1].calls[0][3], t.ARM_LIMIT - 1)

    def test_limit(self):
        self.assertEqual(status(arm(tag=1, value=t.ARM_LIMIT)), t.BAD_NUMBER)
        self.assertEqual(status(arm(tag=0, value=t.ARM_LIMIT)), t.OK)

    def test_length_before_limit(self):
        self.assertEqual(status(arm(code=b'x' * 101, tag=1, value=t.ARM_LIMIT)), t.TOO_LONG_ENTRY)
        self.assertEqual(status(arm(code=b'x' * 100, tag=1, value=t.ARM_LIMIT)), t.BAD_NUMBER)

    def test_helper_failure_reaches_the_arm(self):
        self.assertEqual(status(arm(code=b'x', profiles={YOU: b'x'}, codes={b'x': YOU})), t.CODE_TAKEN)


class Controls(unittest.TestCase):
    def test_threshold_byte(self):
        va = 0x37454e3
        self.assertTrue(fails(t.HELPER, {va: IMG.read(va, 1)[0] ^ 1}, [vec(volume=(t.MIN_VOLUME,)), vec(volume=(t.MIN_VOLUME - 1,))]))

    def test_length_limit_byte(self):
        va = 0x3744ede
        self.assertTrue(fails(t.HELPER, {va: IMG.read(va, 1)[0] ^ 1}, [vec(flag=1, code=b'x' * 100, volume=None), vec(flag=1, code=b'x' * 101, volume=None)]))

    def test_flag_jump(self):
        va = 0x3744ed9
        self.assertTrue(fails(t.HELPER, {va: IMG.read(va, 1)[0] ^ 1}, [vec(flag=1, volume=None), vec(volume=None)]))

    def test_arm_limit_jump(self):
        va = 0x2356a74
        self.assertTrue(fails(t.ARM, {va + 1: IMG.read(va + 1, 1)[0] ^ 1}, [arm(tag=1, value=1), arm(tag=1, value=t.ARM_LIMIT)]))

    def test_tag_branch_of_the_wrapper(self):
        va = 0x27e30eb
        self.assertTrue(fails(t.WRAPPER, {va: IMG.read(va, 1)[0] ^ 1}, [vec(entry='wrapper'), vec(entry='wrapper', volume=None)]))

    def test_model_catches_a_wrong_expectation(self):
        v = vec(volume=(t.MIN_VOLUME,))
        real = t.model
        t.model = lambda _v: dict(status=t.LOW_VOLUME, effect=(), overflows=0)
        try:
            self.assertFalse(passes(v))
        finally:
            t.model = real


class Packet(unittest.TestCase):
    def test_every_vector_of_the_sample_matches(self):
        vecs = t.all_vectors()
        picked = [v for i, v in enumerate(vecs) if i % 19 == 0]
        for v in picked:
            self.assertTrue(passes(v), v['group'])

    def test_static_generation_matches_the_folder(self):
        ev = json.loads((FOLDER / 'evidence.json').read_text())
        with tempfile.TemporaryDirectory() as tmp:
            fresh = t.generate(DATA, tmp, with_survey=False)
            self.assertEqual((Path(tmp) / 'vectors.tsv').read_bytes(), (FOLDER / 'vectors.tsv').read_bytes())
            self.assertEqual((Path(tmp) / 'instructions.tsv').read_bytes(), (FOLDER / 'instructions.tsv').read_bytes())
            self.assertEqual((Path(tmp) / 'reference-diff.tsv').read_bytes(), (FOLDER / 'reference-diff.tsv').read_bytes())
        for key in ('vectors', 'functions', 'helper_callers', 'arm_copies', 'outcomes', 'status_text'):
            self.assertEqual(fresh[key], ev[key], key)
        self.assertEqual(ev['mismatches'], 0)
        self.assertEqual(ev['killed'] + sum(1 for x in (FOLDER / 'mutations.tsv').read_text().splitlines() if '\tequivalent\t' in x), ev['mutants'])

    def test_manifest(self):
        for line in (FOLDER / 'MANIFEST.sha256').read_text().splitlines():
            digest, name = line.split('  ')
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)


if __name__ == '__main__':
    unittest.main()
