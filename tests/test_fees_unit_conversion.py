"""Controls for tools/fees_unit_conversion.py (fees, node #94)."""

import hashlib
import importlib.util
import math
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools' / 'fees_unit_conversion.py'
PACKET = ROOT / 'research' / 'work-items' / 'fees-unit-conversion-94'

spec = importlib.util.spec_from_file_location('fees_unit_conversion', TOOL)
fuc = importlib.util.module_from_spec(spec)
sys.modules['fees_unit_conversion'] = fuc
spec.loader.exec_module(fuc)

BINARY = ROOT / fuc.BINARY
CACHE = {}


def fixture():
    if not CACHE:
        CACHE['data'] = BINARY.read_bytes()
        CACHE['img'] = fuc.Image(CACHE['data'])
        CACHE['fdes'] = fuc.Fdes(CACHE['img'])
        r = CACHE['fdes'].range_of(fuc.FN)
        CACHE['range'] = r
        CACHE['insns'] = fuc.decode_range(CACHE['img'], r['start'], r['end'])
    return CACHE


def quick():
    """Every group except the large rate grid, plus the rows that reach the branches."""
    for n in (1, 10000, fuc.RATE_LIMIT, fuc.RATE_LIMIT + 1):
        for rate in (1.0, 0.5, -1.0):
            yield 'rate', fuc.scenario(ntli=n, rate=rate)
            yield 'rate', fuc.scenario(ntli=n, rate=rate, flag29=0)
    yield from fuc.admission_grid()
    yield from fuc.saturation_grid()
    yield from fuc.split_grid()
    yield from fuc.tree_grid()
    yield from fuc.transition_grid()


def mutated(patches):
    c = fixture()
    return fuc.analyse(c['data'], patches, quick)


class Input(unittest.TestCase):
    def test_digest_of_the_binary(self):
        self.assertEqual(fuc.check_digest(fixture()['data']), fuc.SHA256)

    def test_wrong_digest_is_refused(self):
        with self.assertRaises(fuc.EvidenceError):
            fuc.check_digest(b'not the binary')
        with self.assertRaises(fuc.EvidenceError):
            fuc.analyse(b'not the binary')

    def test_cli_fails_on_another_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            wrong = Path(tmp) / 'wrong'
            wrong.write_bytes(b'\x7fELF\x02\x01 not it')
            out = Path(tmp) / 'out'
            run = subprocess.run([sys.executable, str(TOOL), '--binary', str(wrong), '--out', str(out)],
                                 capture_output=True, text=True)
            self.assertEqual(run.returncode, 1)
            self.assertFalse(out.exists())

    def test_addresses_outside_the_image(self):
        c = fixture()
        with self.assertRaises(fuc.EvidenceError):
            c['img'].read(0xffff_ffff_0000, 4)
        with self.assertRaises(fuc.EvidenceError):
            c['fdes'].range_of(0x10)

    def test_uleb_rejects_truncation_and_width(self):
        self.assertEqual(fuc.uleb(b'\xe5\x8e\x26', 0), (624485, 3))
        with self.assertRaises(fuc.EvidenceError):
            fuc.uleb(b'\x80\x80', 0)
        with self.assertRaises(fuc.EvidenceError):
            fuc.uleb(b'\xff' * 9 + b'\x02', 0)
        with self.assertRaises(fuc.EvidenceError):
            fuc.uleb(b'\xff' * 10 + b'\x01', 0)


class Decoder(unittest.TestCase):
    def test_walks_exactly_to_the_fde_end(self):
        c = fixture()
        self.assertEqual((c['range']['start'], c['range']['end']), (fuc.FN, 0x3715e8b))
        self.assertEqual(len(c['insns']), 576)
        self.assertEqual(sum(i.size for i in c['insns']), 2715)

    def test_rip_operands_resolve_from_the_end_of_the_instruction(self):
        by = {i.va: i for i in fixture()['insns']}
        self.assertEqual(by[0x3715494].ops[1][4], fuc.ONE_VA)
        self.assertEqual(by[0x37154b6].ops[1][4], fuc.TENTH_VA)
        self.assertEqual(by[0x3715bc9].ops[1][4], fuc.LOCATIONS['asset_or_dex'])

    def test_unlisted_opcode_is_refused(self):
        c = fixture()
        img = fuc.Image(c['data'], {fuc.FN: 0x0f, fuc.FN + 1: 0x0b})
        with self.assertRaises(fuc.EvidenceError):
            fuc.decode_range(img, fuc.FN, c['range']['end'])

    def test_overrun_of_the_fde_end_is_refused(self):
        c = fixture()
        end = c['range']['end']
        img = fuc.Image(c['data'], {end - 6: 0x48, end - 5: 0xb8})
        with self.assertRaises(fuc.EvidenceError):
            fuc.decode_range(img, fuc.FN, end)


class Constants(unittest.TestCase):
    def test_division_is_exact(self):
        self.assertTrue(fuc.division_exact(fuc.DIV_MAGIC, fuc.DIV_SHIFT, fuc.DIVISOR))
        self.assertFalse(fuc.division_exact(fuc.DIV_MAGIC + 1, fuc.DIV_SHIFT, fuc.DIVISOR))
        self.assertFalse(fuc.division_exact(fuc.DIV_MAGIC - 1, fuc.DIV_SHIFT, fuc.DIVISOR))
        self.assertFalse(fuc.division_exact(fuc.DIV_MAGIC, fuc.DIV_SHIFT - 1, fuc.DIVISOR))
        self.assertFalse(fuc.division_exact(fuc.DIV_MAGIC, fuc.DIV_SHIFT, fuc.DIVISOR + 1))

    def test_limit_relations(self):
        self.assertEqual(fuc.RATE_LIMIT, fuc.U64 // 100)
        self.assertEqual(fuc.CLAMP, fuc.I64_MAX // 100)
        self.assertEqual(fuc.CLAMP_NEG, (1 << 64) - fuc.CLAMP)
        self.assertEqual(fuc.REFERENCE_CLAMP, fuc.CLAMP >> 4)

    def test_reference_constant_is_the_one_in_the_tree(self):
        text = (ROOT / 'references/can1357-hl/l1/fees/compute.rs').read_text()
        m = re.search(r'MAX_POST_RATE_PRODUCT: u64 = (0x[0-9a-f_]+);', text)
        self.assertEqual(int(m.group(1).replace('_', ''), 16), fuc.REFERENCE_CLAMP)

    def test_changed_constants_are_refused(self):
        for patches in ({0x37155d5 + 2: 0xad}, {0x3715689 + 2: 0xad}, {0x3715446 + 2: 0x4c},
                        {0x3715534 + 2: 0x5d}, {0x37155e4 + 2: 0x53}):
            with self.assertRaises(fuc.EvidenceError):
                mutated(patches)

    def test_changed_float_constants_are_refused(self):
        low = fuc.Image(fixture()['data']).off(fuc.TENTH_VA)
        self.assertGreater(low, 0)
        for va in (fuc.TENTH_VA, fuc.ONE_VA, fuc.LOW_VA, fuc.HIGH_VA, fuc.BIG_VA):
            with self.assertRaises(fuc.EvidenceError):
                fuc.constants(fuc.Image(fixture()['data'], {va: 0x11}))

    def test_changed_pointer_slot_is_refused(self):
        with self.assertRaises(fuc.EvidenceError):
            fixture()['img'].relative(fuc.POINTER_SLOT + 4)


class Evaluation(unittest.TestCase):
    def run_one(self, **kw):
        c = fixture()
        s = fuc.scenario(**kw)
        return s, fuc.evaluate(c['img'], c['insns'], s)

    def test_floor_division_after_the_rate(self):
        self.assertEqual(self.run_one(ntli=9999)[1]['paid_u'], 0)
        self.assertEqual(self.run_one(ntli=10000)[1]['paid_u'], 1)
        self.assertEqual(self.run_one(ntli=19999)[1]['paid_u'], 1)

    def test_rate_stops_above_the_limit(self):
        self.assertEqual(self.run_one(ntli=fuc.RATE_LIMIT, rate=1.0)[1]['paid_u'], fuc.CLAMP // 10000)
        self.assertEqual(self.run_one(ntli=fuc.RATE_LIMIT + 1, rate=-1.0)[1]['paid_u'], (fuc.RATE_LIMIT + 1) // 10000)

    def test_nonfinite_product_is_zero_and_i64_min_panics(self):
        self.assertEqual(self.run_one(ntli=10 ** 9, rate=math.inf)[1]['paid_u'], 0)
        self.assertEqual(self.run_one(ntli=10 ** 9, rate=math.nan)[1]['paid_u'], 0)
        self.assertEqual(self.run_one(ntli=1, rate=-1e300)[1]['status'], f"panic:{fuc.LOCATIONS['abs']:#x}")

    def test_admission_panics_differ_by_location(self):
        self.assertEqual(self.run_one(asset=10007)[1]['status'], f"panic:{fuc.LOCATIONS['asset_or_dex']:#x}")
        self.assertEqual(self.run_one(asset=16)[1]['status'], f"panic:{fuc.LOCATIONS['asset_or_dex']:#x}")
        self.assertEqual(self.run_one(ntli=-1)[1]['status'], f"panic:{fuc.LOCATIONS['unwrap']:#x}")

    def test_saturating_add_reports_and_continues(self):
        s, got = self.run_one(ntli=10 ** 9, paid_s=fuc.U64 - 3)
        self.assertEqual(got['paid_s'], fuc.U64)
        hooks = [c for c in got['calls'] if c[0] == 'overflow_hook']
        self.assertEqual([c[1] for c in hooks], [fuc.LOCATIONS['add']])
        self.assertEqual(fuc.compare(s, got, fuc.model(s)), [])

    def test_matching_tag_selects_the_second_word(self):
        self.assertEqual(self.run_one(ntli=10 ** 9, side=0, tag=0)[1]['day'], (0, 100000))
        self.assertEqual(self.run_one(ntli=10 ** 9, side=0, tag=1)[1]['day'], (100000, 0))
        self.assertEqual(self.run_one(ntli=10 ** 9, side=1, tag=1)[1]['day'], (0, 100000))

    def test_side_zero_leaves_the_day_totals(self):
        self.assertEqual(self.run_one(ntli=10 ** 9, side=0)[1]['total'], (0, 0))
        self.assertEqual(self.run_one(ntli=10 ** 9, side=1)[1]['total'], (100000, 100000))

    def test_day_key_compares_as_signed_32_bit(self):
        got = self.run_one(ntli=5, day=21, day_keys=(-3, 20))[1]
        self.assertEqual([c[1] for c in got['calls'] if c[0] == 'day_add'], [(21, 'vacant', 2)])

    def test_set_calls_need_a_change_of_the_word(self):
        calls = lambda **kw: [c[0] for c in self.run_one(ntli=5, **kw)[1]['calls']]
        self.assertNotIn('set_add', calls(active=1))
        self.assertNotIn('set_remove', calls(active=0))
        self.assertIn('set_add', calls(active=0, flip_active=1))
        self.assertIn('set_remove', calls(active=1, flip_active=1))

    def test_model_catches_a_wrong_outcome(self):
        s, got = self.run_one(ntli=10 ** 9)
        want = fuc.model(s)
        want['paid_u'] += 1
        self.assertEqual(fuc.compare(s, got, want), ['paid_u'])
        self.assertFalse(fuc.entry_ok((21, 'vacant', 0), 21, (-3, 20), False))

    def test_unset_memory_and_unknown_calls_are_faults(self):
        c = fixture()
        m = fuc.Machine(c['img'], c['insns'])
        a = m.arena(16)
        with self.assertRaises(fuc.Unmodelled):
            m.load(a.base, 8)
        with self.assertRaises(fuc.Unmodelled):
            m.load(0x7fff_0000_0000, 8)
        m.regs[4] = m.arena(0x1000, strict=False).base + 0x800
        with self.assertRaises(fuc.Unmodelled):
            m.run(fuc.FN + 1)


class Mutations(unittest.TestCase):
    def assert_disagrees(self, patches):
        with self.assertRaises((fuc.EvidenceError, fuc.Unmodelled)):
            mutated(patches)

    def test_clean_bytes_agree(self):
        self.assertEqual(mutated(None)[0]['summary']['mismatches'], 0)

    def test_rate_field_offset(self):
        self.assert_disagrees({0x3715549 + 5: 0xa8})

    def test_integer_boundary_of_the_unscaled_branch(self):
        self.assert_disagrees({0x3715611 + 1: 0x83})

    def test_tag_compare(self):
        self.assert_disagrees({0x3715b24 + 2: 0x95})

    def test_division_shift(self):
        self.assert_disagrees({0x37156ca + 3: 0x0a})

    def test_multiplier_of_100(self):
        self.assert_disagrees({0x37158a9 + 2: 0x65})

    def test_second_multiplier_of_100(self):
        self.assert_disagrees({0x371594c + 1: 0x65})

    def test_panic_location_of_the_multiplication(self):
        self.assert_disagrees({0x3715bd6 + 3: 0x34})

    def test_hook_location(self):
        self.assert_disagrees({0x3715be3 + 3: 0x7f})

    def test_side_branch(self):
        self.assert_disagrees({0x3715cad + 1: 0x85})

    def test_day_compare_as_unsigned(self):
        self.assert_disagrees({0x3715aac + 2: 0x92})

    def test_scaled_branch_equality_cannot_occur(self):
        # The input of this branch came from a double and RATE_LIMIT has none, so
        # jg and jge agree.  This control keeps that claim honest in both directions.
        self.assertNotEqual(int(float(fuc.RATE_LIMIT)), fuc.RATE_LIMIT)
        self.assertEqual(mutated({0x3715555 + 1: 0x8d})[0]['summary']['mismatches'], 0)


class Reference(unittest.TestCase):
    def rows(self):
        c = fixture()
        return {r[0]: r for r in fuc.reference_rows(c['img'], c['insns'])}

    def test_first_difference_and_the_row_before(self):
        rows = self.rows()
        self.assertEqual(rows['one below that'][-1], 'same')
        first = rows['first n that differs at rate 1']
        self.assertEqual(first[-1], 'differs')
        self.assertEqual(first[4], first[5] + 1)

    def test_clamp_ratio_shows_at_the_limit(self):
        row = self.rows()['largest rated input']
        self.assertEqual(row[4], fuc.CLAMP // 10000)
        self.assertEqual(row[5], fuc.REFERENCE_CLAMP // 10000)

    def test_rate_skip_agrees(self):
        self.assertEqual(self.rows()['rate skipped'][-1], 'same')

    def test_panic_row_differs(self):
        row = self.rows()['i64::MIN product']
        self.assertTrue(row[3].startswith('panic:'))
        self.assertEqual(row[5], 0)


class Packet(unittest.TestCase):
    def test_paths_stay_below_the_build_root(self):
        self.assertEqual(fuc.path_suffix(b'x/y/l1/src/fees/compute.rs'), 'l1/src/fees/compute.rs')
        self.assertEqual(fuc.path_suffix(b'z/library/core/src/num/mod.rs'), 'library/core/src/num/mod.rs')
        with self.assertRaises(fuc.EvidenceError):
            fuc.path_suffix(b'/elsewhere/other.rs')

    def test_locations(self):
        img = fixture()['img']
        want = {'mul_100': ('l1/src/fees/compute.rs', 50, 42), 'add': ('l1/src/qtys/impl_ntl.rs', 664, 1),
                'asset_or_dex': ('l1/src/perp_meta.rs', 194, 38), 'abs': ('library/core/src/num/mod.rs', 320, 5),
                'unwrap': ('l1/src/qtys/mod.rs', 843, 1)}
        for name, (path, line, col) in want.items():
            got = fuc.decode_location(img, fuc.LOCATIONS[name])
            self.assertEqual((got['path'], got['line'], got['column']), (path, line, col))

    def test_one_record_names_the_fee_source_file(self):
        got = fuc.records_naming(fixture()['img'], fuc.LOCATIONS['mul_100'])
        self.assertEqual(got, {'string_copies': 1, 'relative_relocations_to_it': 1})

    def test_regeneration_is_byte_identical(self):
        names = ('evidence.json', 'instructions.tsv', 'vectors.tsv', 'reference-diff.tsv')
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(fuc.main(['--out', tmp]), 0)
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
