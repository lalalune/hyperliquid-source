"""Controls for tools/fees_spot_volume.py (fees, node #94)."""

import hashlib
import importlib.util
import math
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools' / 'fees_spot_volume.py'
PACKET = ROOT / 'research' / 'work-items' / 'fees-spot-volume-94'

spec = importlib.util.spec_from_file_location('fees_spot_volume', TOOL)
fsv = importlib.util.module_from_spec(spec)
sys.modules['fees_spot_volume'] = fsv
spec.loader.exec_module(fsv)

BINARY = ROOT / fsv.BINARY
CACHE = {}
OWN, OTHER = fsv.USER_BYTES[0], fsv.USER_BYTES[1]


def fixture():
    if not CACHE:
        CACHE['data'] = BINARY.read_bytes()
        CACHE['img'] = fsv.Image(CACHE['data'])
        CACHE['fdes'] = fsv.Fdes(CACHE['img'])
        r = CACHE['fdes'].range_of(fsv.FN)
        CACHE['range'] = r
        CACHE['insns'] = fsv.decode_range(CACHE['img'], r['start'], r['end'])
    return CACHE


def quick():
    """The grids that reach every branch, with the two large ones thinned."""
    yield from fsv.dispatch_grid()
    yield from fsv.admission_grid()
    yield from fsv.saturation_grid()
    yield from fsv.tree_grid()
    yield from list(fsv.route_grid())[::7]
    rows = list(fsv.arithmetic_grid())
    yield from rows[:12]
    yield from rows[12::3]


def mutated(patches):
    return fsv.analyse(fixture()['data'], patches, quick)


def run(**kw):
    c = fixture()
    s = fsv.scenario(**kw)
    return s, fsv.evaluate(c['img'], c['insns'], s)


class Input(unittest.TestCase):
    def test_digest_of_the_binary(self):
        self.assertEqual(fsv.check_digest(fixture()['data']), fsv.SHA256)

    def test_wrong_digest_is_refused(self):
        with self.assertRaises(fsv.EvidenceError):
            fsv.analyse(b'not the binary')

    def test_cli_fails_on_another_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            wrong = Path(tmp) / 'wrong'
            wrong.write_bytes(b'\x7fELF\x02\x01 not it')
            out = Path(tmp) / 'out'
            done = subprocess.run([sys.executable, str(TOOL), '--binary', str(wrong), '--out', str(out)],
                                  capture_output=True, text=True)
            self.assertEqual(done.returncode, 1)
            self.assertFalse(out.exists())

    def test_addresses_outside_the_image(self):
        c = fixture()
        with self.assertRaises(fsv.EvidenceError):
            c['img'].read(0xffff_ffff_0000, 4)
        with self.assertRaises(fsv.EvidenceError):
            c['fdes'].range_of(0x10)

    def test_uleb_rejects_truncation_and_width(self):
        self.assertEqual(fsv.uleb(b'\xe5\x8e\x26', 0), (624485, 3))
        with self.assertRaises(fsv.EvidenceError):
            fsv.uleb(b'\x80\x80', 0)
        with self.assertRaises(fsv.EvidenceError):
            fsv.uleb(b'\xff' * 9 + b'\x02', 0)


class Decoder(unittest.TestCase):
    def test_walks_exactly_to_the_fde_end(self):
        c = fixture()
        self.assertEqual((c['range']['start'], c['range']['end']), (fsv.FN, 0x3730b3d))
        self.assertEqual(len(c['insns']), 889)
        self.assertEqual(sum(i.size for i in c['insns']), 0x3730b3d - fsv.FN)

    def test_unlisted_opcode_is_refused(self):
        c = fixture()
        img = fsv.Image(c['data'], {fsv.FN: 0x0f, fsv.FN + 1: 0x0b})
        with self.assertRaises(fsv.EvidenceError):
            fsv.decode_range(img, fsv.FN, c['range']['end'])

    def test_overrun_of_the_fde_end_is_refused(self):
        c = fixture()
        end = c['range']['end']
        img = fsv.Image(c['data'], {end - 6: 0x48, end - 5: 0xb8})
        with self.assertRaises(fsv.EvidenceError):
            fsv.decode_range(img, fsv.FN, end)


class Constants(unittest.TestCase):
    def test_divisions_are_exact(self):
        self.assertTrue(fsv.division_exact(fsv.FIVE_MAGIC, 2, 5))
        self.assertTrue(fsv.division_exact(fsv.MILLION_MAGIC, 18, fsv.SCALE))
        self.assertFalse(fsv.division_exact(fsv.FIVE_MAGIC + 1, 2, 5))
        self.assertFalse(fsv.division_exact(fsv.MILLION_MAGIC - 1, 18, fsv.SCALE))
        self.assertFalse(fsv.division_exact(fsv.MILLION_MAGIC, 17, fsv.SCALE))
        self.assertFalse(fsv.division_exact(fsv.MILLION_MAGIC, 18, fsv.SCALE + 1))

    def test_changed_immediates_are_refused(self):
        for patches in ({0x372ff30 + 2: 0xce}, {0x372fff5 + 2: 0xdc}, {0x372fb9f + 2: 0xff}, {0x372fc5a + 2: 0x5d}):
            with self.assertRaises(fsv.EvidenceError):
                mutated(patches)

    def test_changed_float_constants_are_refused(self):
        for va in (fsv.LOW_VA, fsv.HIGH_VA, fsv.BIG_VA):
            with self.assertRaises(fsv.EvidenceError):
                fsv.constants(fsv.Image(fixture()['data'], {va: 0x11}))

    def test_changed_pointer_slot_is_refused(self):
        with self.assertRaises(fsv.EvidenceError):
            fixture()['img'].relative(fsv.POINTER_SLOT + 4)


class Evaluation(unittest.TestCase):
    def test_table_index_panics_in_spot_meta(self):
        want = f"panic:{fsv.LOCATIONS['table_index']:#x}"
        self.assertEqual(run(t=4)[1]['status'], want)
        self.assertEqual(run(t=3)[1]['status'], 'ok')
        got = fsv.decode_location(fixture()['img'], fsv.LOCATIONS['table_index'])
        self.assertEqual((got['path'], got['line'], got['column']), ('l1/src/spot_meta.rs', 565, 25))

    def test_product_above_the_limit_becomes_zero(self):
        for a, b, raw in ((fsv.MUL_MAX, 1, fsv.MUL_MAX // fsv.SCALE), (fsv.MUL_MAX + 1, 1, 0), (1 << 32, 1 << 32, 0),
                          (1 << 32, 1 << 31, 0)):
            _, got = run(a=a, b=b, t1=(fsv.Q_ID,))
            self.assertEqual(got['users'][OWN]['raw'], raw)

    def test_priced_route_has_the_same_product_rule(self):
        self.assertEqual(run(t3=(fsv.X_ID,), default_price=fsv.MUL_MAX, b=1)[1]['users'][OWN]['raw'],
                         fsv.MUL_MAX // fsv.SCALE)
        self.assertEqual(run(t3=(fsv.X_ID,), default_price=fsv.MUL_MAX + 1, b=1)[1]['users'][OWN]['raw'], 0)

    def test_routes(self):
        self.assertEqual(run(q=0, a=2 * 10 ** 6, b=1)[1]['users'][OWN]['raw'], 2)
        self.assertEqual(run(t1=(fsv.Q_ID,), a=2 * 10 ** 6, b=1)[1]['users'][OWN]['raw'], 2)
        self.assertEqual(run(t3=(fsv.X_ID,), default_price=5 * 10 ** 6, b=1)[1]['users'][OWN]['raw'], 5)
        self.assertEqual(run(a=2 * 10 ** 6, b=1)[1]['users'][OWN]['raw'], 0)

    def test_conversion_is_kept_below_the_limit_only(self):
        base = dict(t1=(fsv.Q_ID,), a=2 * 10 ** 6, b=1)
        self.assertEqual(run(conv=(1, 7 * 10 ** 6), **base)[1]['users'][OWN]['raw'], 7)
        self.assertEqual(run(conv=(0, 7 * 10 ** 6), **base)[1]['users'][OWN]['raw'], 2)
        self.assertEqual(run(conv=(1, fsv.LIMIT), **base)[1]['users'][OWN]['raw'], 2)
        self.assertEqual(run(conv=(1, fsv.LIMIT - 1), **base)[1]['users'][OWN]['raw'], (fsv.LIMIT - 1) // fsv.SCALE)

    def test_flag_applies_the_multiplier_to_the_scaled_value_only(self):
        _, got = run(t1=(fsv.Q_ID,), a=4 * 10 ** 6, b=1, t4={fsv.Q_ID: 1}, m=0.5)
        self.assertEqual((got['users'][OWN]['scaled'], got['users'][OWN]['raw']), (2, 4))
        _, got = run(t1=(fsv.Q_ID,), a=4 * 10 ** 6, b=1, t4={fsv.Q_ID: 2}, m=0.5)
        self.assertEqual(got['users'][OWN]['scaled'], 4)

    def test_five_wins_over_the_predicate(self):
        base = dict(t1=(fsv.Q_ID,), a=10 ** 7, b=1, weight=0.3)
        self.assertEqual(run(t5=(fsv.X_ID,), **base)[1]['users'][OWN]['scaled'], 2)
        self.assertEqual(run(t5=(fsv.X_ID,), pred=1, mode=1, gross=1, **base)[1]['users'][OWN]['scaled'], 2)
        self.assertEqual(run(pred=1, mode=1, gross=1, **base)[1]['users'][OWN]['scaled'], 3)

    def test_threshold_splits_the_two_updates(self):
        _, low = run(t1=(fsv.Q_ID,), a=999999, b=1)
        self.assertEqual(low['users'][OWN], dict(scaled=0, raw=0, ext=0, day=(0, 0)))
        self.assertNotIn('day_add', [c[0] for c in low['calls']])
        _, high = run(t1=(fsv.Q_ID,), a=10 ** 6, b=1)
        self.assertEqual(high['users'][OWN], dict(scaled=1, raw=1, ext=0, day=(0, 1)))
        self.assertIn('day_add', [c[0] for c in high['calls']])

    def test_raw_is_kept_when_the_scaled_value_is_below_the_threshold(self):
        _, got = run(t1=(fsv.Q_ID,), a=3 * 10 ** 6, b=1, t4={fsv.Q_ID: 1}, m=0.0)
        self.assertEqual(got['users'][OWN], dict(scaled=0, raw=3, ext=0, day=(0, 0)))

    def test_mode_2_with_the_predicate_records_nothing(self):
        _, got = run(t1=(fsv.Q_ID,), mode=2, pred=1)
        self.assertEqual(got['users'], {})
        self.assertEqual(got['total'], (0, 0))

    def test_predicate_with_zero_gross_stops_after_the_split(self):
        _, got = run(t1=(fsv.Q_ID,), mode=0, pred=1, gross=0, side=1)
        self.assertEqual([c[0] for c in got['calls'] if c[0] not in ('pred', 'default_price', 'conv')], ['split'])
        self.assertEqual(got['total'], (0, 0))

    def test_predicate_with_gross_credits_both_users(self):
        _, got = run(t1=(fsv.Q_ID,), mode=0, pred=1, gross=2, a=3 * 10 ** 6, b=1, side=0, tag=0)
        self.assertEqual(got['users'][OWN]['day'], (0, 3))
        self.assertEqual(got['users'][OTHER]['day'], (3, 0))
        self.assertEqual(got['users'][OWN]['ext'], 3)
        self.assertEqual(got['users'][OTHER]['ext'], 3)
        self.assertEqual(got['total'], (3, 3))

    def test_totals_follow_the_side_on_the_single_user_path(self):
        self.assertEqual(run(t1=(fsv.Q_ID,), a=3 * 10 ** 6, b=1, side=0)[1]['total'], (0, 0))
        self.assertEqual(run(t1=(fsv.Q_ID,), a=3 * 10 ** 6, b=1, side=1)[1]['total'], (3, 3))

    def test_overflow_saturates_and_reports(self):
        top = fsv.U64 - 3
        start = {OWN: dict(scaled=top, raw=top, ext=top, day=(top, top))}
        s, got = run(t1=(fsv.Q_ID,), a=3 * 10 ** 7, b=1, start=start)
        self.assertEqual(got['users'][OWN]['raw'], fsv.U64)
        hooks = [c[1] for c in got['calls'] if c[0] == 'overflow_hook']
        self.assertEqual(hooks, [fsv.LOCATIONS['add']] * 3)
        self.assertEqual(fsv.compare(s, got, fsv.model(s)), [])

    def test_nonfinite_factor_gives_zero(self):
        for m in (math.inf, math.nan):
            _, got = run(t1=(fsv.Q_ID,), a=4 * 10 ** 6, b=1, t4={fsv.Q_ID: 1}, m=m)
            self.assertEqual(got['users'][OWN]['scaled'], 0)
            self.assertEqual(got['users'][OWN]['raw'], 4)

    def test_negative_factor_gives_zero(self):
        _, got = run(t1=(fsv.Q_ID,), a=4 * 10 ** 6, b=1, t4={fsv.Q_ID: 1}, m=-1.0)
        self.assertEqual(got['users'][OWN]['scaled'], 0)

    def test_model_catches_a_wrong_outcome(self):
        s, got = run(t1=(fsv.Q_ID,), a=4 * 10 ** 6, b=1)
        want = fsv.model(s)
        want['users'][OWN]['raw'] += 1
        self.assertEqual(fsv.compare(s, got, want), ['users'])
        self.assertFalse(fsv.tree_ok((21, 'vacant', 0), 21, (-3, 20), False))

    def test_unset_memory_is_a_fault(self):
        c = fixture()
        m = fsv.Machine(c['img'], c['insns'])
        a = m.arena(16)
        with self.assertRaises(fsv.Unmodelled):
            m.load(a.base, 8)
        with self.assertRaises(fsv.Unmodelled):
            m.load(0x7fff_0000_0000, 8)

    def test_unlisted_unexecuted_code_is_refused(self):
        insns = fixture()['insns']
        listed = {i.va for i in insns for lo, hi, _ in fsv.UNREACHED if lo <= i.va < hi}
        seen = {i.va for i in insns if i.va not in listed}
        fsv.check_unreached(insns, seen)
        with self.assertRaises(fsv.EvidenceError):
            fsv.check_unreached(insns, seen - {fsv.FN})
        with self.assertRaises(fsv.EvidenceError):
            fsv.check_unreached(insns, seen | {0x37309c9})


class Mutations(unittest.TestCase):
    def assert_disagrees(self, patches):
        with self.assertRaises((fsv.EvidenceError, fsv.Unmodelled)):
            mutated(patches)

    def test_clean_bytes_agree(self):
        self.assertEqual(mutated(None)[0]['summary']['mismatches'], 0)

    def test_threshold_at_both_sites(self):
        self.assert_disagrees({0x3730508 + 3: 0x40})
        self.assert_disagrees({0x37307b9 + 3: 0x40})

    def test_division_shifts(self):
        self.assert_disagrees({0x372ff43 + 3: 0x03})
        self.assert_disagrees({0x3730005 + 3: 0x11})
        self.assert_disagrees({0x3730014 + 3: 0x11})

    def test_limit_branch(self):
        self.assert_disagrees({0x372fc67 + 2: 0x47})

    def test_product_limit_on_both_routes(self):
        self.assert_disagrees({0x372fbac + 2: 0x43})
        self.assert_disagrees({0x37309a7 + 2: 0x43})

    def test_flag_value_and_stride(self):
        self.assert_disagrees({0x372fd07 + 5: 0x02})
        self.assert_disagrees({0x372fcd5 + 3: 0x38})

    def test_tag_compares(self):
        self.assert_disagrees({0x373007e + 2: 0x95})
        self.assert_disagrees({0x37304e5 + 1: 0x95})

    def test_record_stride(self):
        self.assert_disagrees({0x37307a2 + 1: 0x16})

    def test_day_compare_as_unsigned(self):
        self.assert_disagrees({0x37305bd + 2: 0x92})

    def test_predicate_branch(self):
        self.assert_disagrees({0x372ff5c + 1: 0x85})

    def test_field_offsets(self):
        self.assert_disagrees({0x372ff78 + 4: 0x58})
        self.assert_disagrees({0x372fadd + 4: 0xa8})
        self.assert_disagrees({0x372ff29 + 4: 0x68})

    def test_mode_and_gross_gates(self):
        self.assert_disagrees({0x373006a + 3: 0x03})
        self.assert_disagrees({0x3730860 + 8: 0x01})


class Packet(unittest.TestCase):
    def test_paths_stay_below_the_build_root(self):
        self.assertEqual(fsv.path_suffix(b'x/y/l1/src/spot_meta.rs'), 'l1/src/spot_meta.rs')
        with self.assertRaises(fsv.EvidenceError):
            fsv.path_suffix(b'/elsewhere/other.rs')

    def test_regeneration_is_byte_identical(self):
        names = ('evidence.json', 'instructions.tsv', 'vectors.tsv')
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(fsv.main(['--out', tmp]), 0)
            for name in names:
                self.assertEqual((Path(tmp) / name).read_bytes(), (PACKET / name).read_bytes(), name)

    def test_manifest(self):
        rows = (PACKET / 'MANIFEST.sha256').read_text().splitlines()
        listed = sorted(r.split('  ', 1)[1] for r in rows)
        present = sorted(p.name for p in PACKET.iterdir() if p.name != 'MANIFEST.sha256')
        self.assertEqual(listed, present)
        for r in rows:
            digest, name = r.split('  ', 1)
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), digest)


if __name__ == '__main__':
    unittest.main()
