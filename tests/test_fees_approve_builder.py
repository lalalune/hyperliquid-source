"""Tests for tools/fees_approve_builder.py on node #94 bytes."""

import hashlib
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import fees_approve_builder as t  # noqa: E402

FOLDER = ROOT / 'research/work-items/fees-approve-builder-94'
DATA = (ROOT / t.BINARY).read_bytes()
IMG, CODE, FDES, SLOTS, GOT = t.build(DATA)
FAULTS = (t.Unmodelled, t.Panicked, t.EvidenceError, KeyError, ValueError, TypeError, struct.error)


def text(raw, img=IMG, code=CODE):
    return t.run_text(img, code, SLOTS, GOT, raw)


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


def steps(*items, **kw):
    return t.seq('test', list(items), **kw)


class Input(unittest.TestCase):
    def test_digest(self):
        self.assertEqual(t.check_digest(DATA), t.SHA256)
        with self.assertRaises(t.EvidenceError):
            t.check_digest(DATA[:-1] + bytes([DATA[-1] ^ 1]))

    def test_decoder_lands_on_each_fde_end(self):
        for fn in t.DECODED:
            listing = t.decode_range(IMG, fn, t.FDE_END[fn])
            self.assertEqual(listing[-1].va + listing[-1].size, t.FDE_END[fn])

    def test_decoder_refuses_a_cut_range(self):
        with self.assertRaises(t.EvidenceError):
            t.decode_range(IMG, t.WRITER, t.WRITER + 3)

    def test_no_fde_at_a_middle_address(self):
        with self.assertRaises(t.EvidenceError):
            FDES.range_of(t.WRITER + 1)

    def test_nobits_is_outside_the_image(self):
        with self.assertRaises(t.EvidenceError):
            IMG.read(IMG.sec['.bss'][0], 8)

    def test_pinned_bytes(self):
        self.assertEqual(len(t.pinned(IMG)), len(t.PINNED))
        va = t.PINNED[0][0]
        with self.assertRaises(t.EvidenceError):
            t.pinned(t.Image(DATA, {va: IMG.read(va, 1)[0] ^ 1}))

    def test_slots(self):
        self.assertEqual(IMG.relative(t.PARSER_SLOT), t.PARSER)
        self.assertEqual(IMG.relative(t.WRITER_SLOT), t.WRITER)
        self.assertEqual(IMG.relative(t.WRAP_SLOT), t.WRAP)
        self.assertEqual(IMG.relative(t.SCALE_SLOT), t.SCALE)
        with self.assertRaises(t.EvidenceError):
            IMG.relative(t.PARSER_SLOT + 1)

    def test_status_texts(self):
        self.assertEqual(t.status_text(IMG, t.TOO_SMALL), 'Builder has insufficient balance to be approved.')
        self.assertEqual(t.status_text(IMG, t.BAD_RATE), 'Percentage is invalid.')
        self.assertTrue(t.status_text(IMG, t.TOO_MANY).startswith('Too many builders approved.'))
        self.assertEqual(t.status_text(IMG, t.NO_DEX), 'Invalid perp DEX')


class Text(unittest.TestCase):
    def test_accepted_outside_the_reference_rule(self):
        for raw, want in ((b'+1%', 1000), (b'1_0%', 10000), (b'1_%', 1000), (b'1._5%', 1500), (b'0.0010%', 1), (b'-0%', 0), (b'1e1%', 10000),
                          (b'1E2%', 100000), (b'1e-3%', 1), (b'-1e-400%', 0), (b'1.00000000000000000000000000049%', 1000)):
            self.assertEqual(text(raw), (t.OK, want), raw)
            self.assertIsNone(t.reference_parse(raw), raw)

    def test_refused(self):
        for raw in (b'', b'%', b'1', b'-1%', b'._5%', b'_1%', b'0.0001%', b'0.29e-2%', b'inf%', b'NaN%', b'1e400%', b'abc%', b'1%%',
                    b'9223372036854775.807%', b'1e16%'):
            self.assertEqual(text(raw), (t.BAD_RATE, None), raw)

    def test_largest_rate(self):
        self.assertEqual(text(b'9223372036854775.806%'), (t.OK, t.MAX_MILLIS))

    def test_rounding_of_the_f64_path(self):
        self.assertEqual(text(b'1.5e-1%'), (t.OK, 150))
        self.assertEqual(text(b'0.1e-2%'), (t.OK, 1))

    def test_subnormal_goes_to_zero(self):
        self.assertEqual(text(b'4.9e-324%'), (t.OK, 0))
        self.assertEqual(t.path_of(b'4.9e-324%'), 'float')

    def test_curated_agree_with_the_model(self):
        for raw in t.CURATED:
            self.assertEqual(text(raw), t.parse_model(raw), raw)

    def test_model_detects_a_wrong_answer(self):
        v = dict(type='text', group='x', text=b'1%')
        self.assertIsNone(t.check_text(IMG, CODE, SLOTS, GOT, v))
        real, t.parse_model = t.parse_model, lambda raw: (t.OK, 999)
        try:
            self.assertIn('parser', t.check_text(IMG, CODE, SLOTS, GOT, v))
        finally:
            t.parse_model = real


class Gate(unittest.TestCase):
    def test_limit_uses_the_builder_address(self):
        v = steps(t.s(1, 2, 5), t.u(1, 3, b'1%'))
        self.assertTrue(passes(v))
        # mov r14, rcx becomes mov r14, rdx: the lookup then gets the sender, and the stub refuses it
        self.assertTrue(fails(t.GATE, {0x2758342: 0x89, 0x2758343: 0xd6}, [v]))

    def test_value_boundary_is_signed(self):
        for value, ok in ((t.MIN_VALUE, True), (t.MIN_VALUE - 1, False), (t._v(-1), False), (t._v(-(1 << 63)), False), ((1 << 63) - 1, True)):
            world = t.World()
            want = world.apply(t.s(1, 2, 5, value))
            self.assertEqual(want['status'], t.OK if ok else t.TOO_SMALL)
            self.assertTrue(passes(steps(t.s(1, 2, 5, value))))

    def test_zero_fee_skips_the_value_test(self):
        self.assertTrue(passes(steps(t.u(1, 2, b'0%', 0), t.s(1, 2, 0, 0))))

    def test_no_dex_panics_for_a_fee_only(self):
        self.assertTrue(passes(steps(t.u(1, 2, b'0%', 0), dex=False)))
        self.assertTrue(passes(steps(t.u(1, 2, b'1%'), dex=False)))
        world = t.World()
        self.assertTrue(world.apply(t.u(1, 2, b'1%'), False)['panic'])

    def test_cap_refuses_an_overwrite(self):
        fill = [t.s(1, 10 + i, 1 + i) for i in range(t.MAX_BUILDERS)]
        world = t.World()
        for f in fill:
            self.assertEqual(world.apply(f)['status'], t.OK)
        self.assertEqual(world.apply(t.s(1, 40, 1))['status'], t.TOO_MANY)
        self.assertEqual(world.apply(t.s(1, 10, 9))['status'], t.TOO_MANY)
        self.assertEqual(world.apply(t.s(1, 10, 0))['status'], t.OK)
        self.assertTrue(passes(steps(*fill, t.s(1, 40, 1), t.s(1, 10, 9), t.s(1, 10, 0), t.s(1, 40, 1))))

    def test_order_of_checks(self):
        self.assertTrue(passes(steps(t.u(1, 2, b'bad%', 0), t.s(1, 2, t.SYSTEM_LIMIT, 0), t.u(1, 2, b'x' * 101, 0))))

    def test_length_boundary(self):
        self.assertTrue(passes(steps(t.u(1, 2, b'0' * 99 + b'%', 0), t.u(1, 2, b'0' * 100 + b'%', 0))))
        self.assertEqual(t.World().apply(t.u(1, 2, b'0' * 100 + b'%'))['status'], t.TOO_LONG)

    def test_system_limit(self):
        self.assertEqual(t.World().apply(t.s(1, 2, t.SYSTEM_LIMIT - 1))['status'], t.OK)
        self.assertEqual(t.World().apply(t.s(1, 2, t.SYSTEM_LIMIT))['status'], t.FEE_LIMIT)

    def test_copy_cases(self):
        for v in t.copy_vectors():
            self.assertTrue(passes(v), v['name'])

    def test_all_sequences(self):
        for v in t.sequence_vectors():
            self.assertTrue(passes(v))


class Mutants(unittest.TestCase):
    STATE = t.sequence_vectors()[:14]

    def test_threshold(self):
        self.assertTrue(fails(t.GATE, {0x27583ca + 5: 0xfe}, self.STATE))

    def test_gate_jump(self):
        self.assertTrue(fails(t.GATE, {0x27583d9: 0x7e}, self.STATE))

    def test_cap_immediate(self):
        self.assertTrue(fails(t.WRITER, {0x3745a11: 0x0b}, self.STATE))

    def test_cap_jump(self):
        self.assertTrue(fails(t.WRITER, {0x3745a12: 0x76}, self.STATE))

    def test_percent_byte(self):
        v = dict(type='text', group='x', text=b'1%')
        self.assertTrue(fails(t.PARSER, {0x3364cdc: 0x26}, [v]))

    def test_scale_digits(self):
        v = dict(type='text', group='x', text=b'1%')
        self.assertTrue(fails(t.PARSER, {0x3364d1c: 0x02}, [v]))

    def test_system_limit_byte(self):
        self.assertTrue(fails(t.ENTRY_SYSTEM, {0x1e6463f: 0xcd}, self.STATE))

    def test_length_byte(self):
        vec = [t.seq('x', [t.u(1, 2, b'0' * 100 + b'%', 0)])]
        self.assertTrue(fails(t.ENTRY_USER, {0x1e60aab: 0x66}, vec))


class Evidence(unittest.TestCase):
    EV = json.loads((FOLDER / 'evidence.json').read_text())

    def test_manifest(self):
        lines = (FOLDER / 'MANIFEST.sha256').read_text().splitlines()
        names = sorted(p.name for p in FOLDER.iterdir() if p.name != 'MANIFEST.sha256')
        self.assertEqual(sorted(x.split()[1] for x in lines), names)
        for line in lines:
            digest, name = line.split()
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_counts(self):
        ev = self.EV
        self.assertEqual(ev['sha256'], t.SHA256)
        self.assertEqual(ev['mismatches'], 0)
        self.assertEqual(ev['vectors'], len(t.all_vectors()))
        rows = (FOLDER / 'mutations.tsv').read_text().splitlines()[1:]
        self.assertEqual(len(rows), ev['mutants'])
        self.assertEqual(sum(r.split('\t')[4] == 'killed' for r in rows), ev['killed'])
        self.assertEqual({r.split('\t')[2] for r in rows if r.split('\t')[4] == 'equivalent'}, set(ev['equivalent']))
        self.assertEqual(sum(ev['groups'].values()), ev['vectors'])

    def test_copies(self):
        rows = {r['start']: r for r in self.EV['copies']}
        self.assertEqual(len(rows['0x4d81120']['differs']), 3)
        self.assertEqual(len(rows['0x4d80fb0']['differs']), 0)

    def test_unexecuted_are_listed(self):
        for row in self.EV['functions'].values():
            self.assertLessEqual(row['executed'], row['instructions'])

    def test_vectors_file_matches_a_new_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            t.generate(DATA, tmp, with_survey=False)
            for name in ('vectors.tsv', 'instructions.tsv', 'reference-diff.tsv'):
                self.assertEqual((Path(tmp) / name).read_bytes(), (FOLDER / name).read_bytes(), name)


if __name__ == '__main__':
    unittest.main()
