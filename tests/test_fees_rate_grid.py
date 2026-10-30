"""Tests of tools/fees_rate_grid.py: bytes against the closed-form model, with negative controls."""

import hashlib
import json
import math
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import fees_rate_grid as g  # noqa: E402

DATA = (ROOT / g.BINARY).read_bytes()
IMG, CODE = g.build(DATA)
VECTORS = g.point_vectors()
FOLDER = ROOT / 'research' / 'work-items' / 'fees-rate-grid-94'


def exit_of(img, code, v):
    return g.run_point(img, code, v)[1]


class Identity(unittest.TestCase):
    def test_digest_accepts_the_pinned_binary(self):
        self.assertEqual(g.check_digest(DATA), g.SHA256)

    def test_digest_rejects_one_changed_byte(self):
        bad = bytearray(DATA[:4096])
        bad[100] ^= 1
        with self.assertRaises(g.EvidenceError):
            g.check_digest(bytes(bad))

    def test_build_rejects_a_changed_binary(self):
        with self.assertRaises(g.EvidenceError):
            g.build(DATA[:-1])

    def test_read_outside_every_section_fails(self):
        with self.assertRaises(g.EvidenceError):
            IMG.read(0x7fff_0000_0000, 8)

    def test_bss_has_no_file_bytes(self):
        addr = IMG.sec['.bss'][0]
        with self.assertRaises(g.EvidenceError):
            IMG.read(addr, 8)


class Decoder(unittest.TestCase):
    def test_every_function_lands_on_its_fde_end(self):
        for start in g.DECODED:
            listing = g.decode_range(IMG, start, g.FDE_END[start])
            self.assertEqual(listing[-1].va + listing[-1].size, g.FDE_END[start])

    def test_a_cut_range_is_refused(self):
        with self.assertRaises(g.EvidenceError):
            g.decode_range(IMG, g.POINT, g.FDE_END[g.POINT] - 1)

    def test_unknown_opcode_is_refused(self):
        with self.assertRaises(g.EvidenceError):
            g.decode_one(b'\x06' + b'\x90' * 15, 0, 0x1000)

    def test_fs_access_cannot_run(self):
        ins = g.decode_one(bytes.fromhex('64498b17') + b'\x90' * 12, 0, 0x1000)
        self.assertEqual(ins.op, 'fs_mov')


class Model(unittest.TestCase):
    def test_conversion_edges(self):
        self.assertEqual(g.to_i64(math.nan), 0)
        self.assertEqual(g.to_i64(math.inf), 0)
        self.assertEqual(g.to_i64(-math.inf), 0)
        self.assertEqual(g.to_i64(1e300), g.I64MAX)
        self.assertEqual(g.to_i64(-1e300), g.I64MIN)
        self.assertEqual(g.to_i64(2.0 ** 63), g.I64MAX)
        self.assertEqual(g.to_i64(-(2.0 ** 63)), g.I64MIN)
        self.assertEqual(g.to_i64(-1.9), -1)
        self.assertEqual(g.to_i64(1.9), 1)

    def test_each_exit_has_vectors(self):
        got = {g.point_model(v)['exit'] for v in VECTORS}
        self.assertEqual(got, {'ok', 'panic', 'discounted_fee', 'max_fee', 'ntli', 'rounding'})

    def test_fold_keeps_the_first_item_on_the_left(self):
        self.assertEqual(g.fold_model(g.vec(tag=0, pos=0, best=3, boundary=9))[0], 'keep')
        self.assertEqual(g.fold_model(g.vec(tag=2, pos=0, best=13, boundary=9)), ('take', 9))
        self.assertEqual(g.fold_model(g.vec(tag=2, pos=0, best=3, boundary=9))[0], 'keep')
        self.assertEqual(g.fold_model(g.vec(tag=0, pos=1, best=3, boundary=9)), ('take', 9))


class Bytes(unittest.TestCase):
    def test_a_slice_of_each_group_matches(self):
        seen = {}
        for v in VECTORS:
            if seen.get(v['group'], 0) < 40:
                seen[v['group']] = seen.get(v['group'], 0) + 1
                self.assertIsNone(exit_of(IMG, CODE, v)['mismatch'], v)

    def test_named_rejects(self):
        cases = ((g.vec(L=-1.0, k=0.25, n=1000), 'discounted_fee'), (g.vec(a=-1.0, k=0.0, n=1000), 'ntli'),
                 (g.vec(c=-0.5, a=0.0, n=1000), 'max_fee'), (g.vec(c=0.5, k=1.0, a=0.0, n=1000), 'rounding'),
                 (g.vec(n=1), 'ok'))
        for v, name in cases:
            res = exit_of(IMG, CODE, v)
            self.assertIsNone(res['mismatch'])
            self.assertEqual(res['exit'], name)

    def test_top_bit_ntli_panics(self):
        self.assertEqual(exit_of(IMG, CODE, g.vec(n=1 << 63))['exit'], 'panic')

    def test_rates_in_range_never_read_the_argument_block(self):
        m, res = g.run_point(IMG, CODE, g.vec(n=1000))
        self.assertEqual(res['exit'], 'ok')
        self.assertFalse(m.formats)

    def test_wrong_expected_value_is_seen(self):
        v = g.vec(L=-1.0, k=0.25, n=1000)
        real = g.point_model
        try:
            g.point_model = lambda x: dict(real(x), d=real(x)['d'] + 1)
            self.assertEqual(exit_of(IMG, CODE, v)['mismatch'], 'format arguments')
        finally:
            g.point_model = real

    def test_flipped_sign_branch_is_caught(self):
        img = g.Image(DATA, {0x36e2ee9: IMG.read(0x36e2ee9, 1)[0] ^ 1})
        code = g.code_of(img, (g.POINT,))
        self.assertIsNotNone(exit_of(img, code, g.vec(L=-1.0, k=0.25, n=1000))['mismatch'])

    def test_changed_one_is_caught(self):
        raw = IMG.read(g.ONE_ADDR, 8)
        img = g.Image(DATA, {g.ONE_ADDR + 6: raw[6] ^ 0x10})
        self.assertIsNotNone(exit_of(img, g.code_of(img, (g.POINT,)), g.vec(L=-1.0, k=0.25, n=1000))['mismatch'])

    def test_clamp_mutants_are_equivalent(self):
        img = g.Image(DATA, {0x36e2e34: IMG.read(0x36e2e34, 1)[0] ^ 1})
        code = g.code_of(img, (g.POINT,))
        for x in (1e300, -1e300, 2.0 ** 63, -(2.0 ** 63)):
            self.assertIsNone(exit_of(img, code, g.vec(L=x, r=0.0, k=0.5, a=0.0, c=1.0, n=1))['mismatch'])

    def test_equivalent_list_has_only_clamps(self):
        self.assertEqual(len(g.EQUIVALENT), 12)
        self.assertTrue(all('clamp' in why for why in g.EQUIVALENT.values()))


class Chain(unittest.TestCase):
    def test_bound_immediates(self):
        words = g.facts(IMG, g.decode_range(IMG, g.SCALE_LEAF, g.FDE_END[g.SCALE_LEAF]))
        self.assertEqual({k: v[1] for k, v in words.items()}, {0x38: 1, 0x40: g.BOUND, 0x48: 0})

    def test_scale_list_bytes(self):
        rows = g.scale_list(IMG, g.decode_range(IMG, g.FLOORS, g.FDE_END[g.FLOORS]))
        self.assertEqual(rows[1][2] + rows[0][2], g.SCALES)

    def test_range_is_inclusive(self):
        log, tag = g.run_range(IMG, CODE, g.vec(), g.BOUND - 2, g.BOUND)
        self.assertEqual([n for _, n in log], [g.BOUND - 2, g.BOUND - 1, g.BOUND])
        self.assertEqual(tag, 2)

    def test_exhausted_range_calls_nothing(self):
        self.assertEqual(g.run_range(IMG, CODE, g.vec(), 1, 9, 1), ([], 2))

    def test_order_on_a_patched_bound(self):
        img = g.Image(DATA, g.patched_bound(DATA, 3))
        res = g.run_entry(img, g.decode_all(img), g.vec())
        self.assertEqual(res['log'], [(m, n) for m in g.SCALES for n in (1, 2, 3)])
        self.assertEqual(res['tag'], 2)

    def test_first_failure_stops_the_real_bound(self):
        res = g.run_entry(IMG, CODE, g.vec(L=-1.0, k=0.25))
        self.assertEqual(res['log'], [(1.0, 1), (1.0, 2)])
        self.assertEqual(res['tag'], 1)

    def test_changed_bound_changes_the_calls(self):
        for bound in (2, 3):
            img = g.Image(DATA, g.patched_bound(DATA, bound))
            self.assertEqual(len(g.run_entry(img, g.decode_all(img), g.vec())['log']), 4 * bound)

    def test_floors_pass_inputs_and_verdicts(self):
        rows = {r['name']: r for r in g.floors_results(DATA, CODE, IMG)}
        self.assertTrue(rows['accepted']['accepted'])
        self.assertFalse(rows['negative_word90']['accepted'])
        self.assertEqual(rows['negative_word90']['first_failure'], 'discounted_fee')
        self.assertTrue(rows['negative_word90_no_keep']['accepted'])
        self.assertFalse(rows['wide_rate']['accepted'])

    def test_ladder_gap(self):
        gap = g.ladder_gap(IMG, CODE)
        self.assertEqual(gap['first_reject'], gap['last_pass'] + 1)


class Study(unittest.TestCase):
    def test_short_search(self):
        row = g.study(100)
        self.assertEqual(row['claim_failures'], 0)
        self.assertGreater(row['claim_points'], 1000)
        self.assertTrue(row['control_failures'])


class Packet(unittest.TestCase):
    def test_format_text_has_the_four_rejects(self):
        for name in g.EXITS:
            row = g.format_row(IMG, name, g.EXITS[name][0])
            self.assertIn('invalid fee', row['text'])
            self.assertNotIn(g.AT, row['text'])

    def test_locations_are_repository_relative(self):
        for slot in (g.LOC_NTLI, g.LOC_SUM, g.LOC_TRY):
            self.assertTrue(g.location(IMG, slot)['path'].startswith('l1/src/'))

    def test_regeneration_matches_the_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            evidence = g.generate(DATA, tmp)
            self.assertEqual(evidence['killed'] + len(g.EQUIVALENT), evidence['mutants'])
            lines = (FOLDER / 'MANIFEST.sha256').read_text().splitlines()
            for line in lines:
                digest, name = line.split('  ')
                if name != 'README.md':
                    self.assertEqual(hashlib.sha256((Path(tmp) / name).read_bytes()).hexdigest(), digest, name)
            self.assertEqual(json.loads((FOLDER / 'evidence.json').read_text())['vectors'], len(VECTORS))


if __name__ == '__main__':
    unittest.main()
