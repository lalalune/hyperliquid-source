"""Controls for tools/fees_credit_distribution_115.py (fees, node #115)."""

import importlib.util
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools' / 'fees_credit_distribution_115.py'
PACKET = ROOT / 'research' / 'work-items' / 'fees-credit-distribution-115'

spec = importlib.util.spec_from_file_location('fees_credit_distribution_115', TOOL)
fcd = importlib.util.module_from_spec(spec)
sys.modules['fees_credit_distribution_115'] = fcd
spec.loader.exec_module(fcd)

CACHE = {}


def fixture():
    if not CACHE:
        data = (ROOT / fcd.GROUND).read_bytes()
        img = fcd.Image(data)
        fdes = fcd.Fdes(img)
        CACHE.update(data=data, img=img, fdes=fdes, insns=fcd.decode_all(img, fdes))
        CACHE['vectors'] = list(fcd.all_vectors())
        CACHE['control'] = fcd.control_set(CACHE['vectors'])
    return CACHE


def run(s):
    c = fixture()
    return fcd.evaluate(c['img'], c['insns'], s)


class Input(unittest.TestCase):
    def test_digest_of_the_binary(self):
        self.assertEqual(fcd.check_digest(fixture()['data']), fcd.SHA256)

    def test_wrong_digest_is_refused(self):
        with self.assertRaises(fcd.EvidenceError):
            fcd.check_digest(b'not the node')

    def test_decoder_lands_on_every_fde_end(self):
        c = fixture()
        counts = {}
        for f in fcd.SUBJECTS:
            r = c['fdes'].range_of(f)
            self.assertEqual(r['start'], f)
            counts[f] = len(fcd.decode_range(c['img'], r['start'], r['end']))
        self.assertEqual(counts, {fcd.F_CREDIT: 107, fcd.F_EXT: 76, fcd.F_DIST: 293})
        self.assertEqual(len(c['insns']), 476)

    def test_constants(self):
        got = fcd.constants(fixture()['img'])
        self.assertEqual(got['cutoff'], 1.01)
        self.assertEqual(got['one_e5'], 100000.0)

    def test_nobits_sections_have_no_bytes(self):
        c = fixture()
        with self.assertRaises(fcd.EvidenceError):
            c['img'].read(c['img'].sec['.bss'][0] + 8, 8)

    def test_address_outside_the_image(self):
        with self.assertRaises(fcd.EvidenceError):
            fixture()['img'].read(0x10, 4)

    def test_pointer_slot_that_does_not_exist(self):
        with self.assertRaises(fcd.EvidenceError):
            fixture()['img'].relative(0x10)

    def test_unlisted_opcode_is_an_error(self):
        with self.assertRaises(fcd.EvidenceError):
            fcd.decode_one(b'\x06' + bytes(15), 0, 0x1000)

    def test_truncated_uleb(self):
        with self.assertRaises(fcd.EvidenceError):
            fcd.uleb(b'\x80', 0)

    def test_input_controls_are_all_refused(self):
        rows = fcd.input_control_rows(fixture()['data'])
        self.assertTrue(rows)
        self.assertTrue(all(o.startswith('killed') for _, o in rows), rows)


class Hand(unittest.TestCase):
    """Values worked out by hand from the model's rules, then read back from the evaluated bytes."""

    def test_split_and_remainder(self):
        s = fcd.scenario(sec=1000, cap_none=False, elems=((70000, 3), (20000, 4)), known=frozenset(range(10)))
        got = run(s)
        d = fcd.default_init
        self.assertEqual(got['cells'][('L', 3, 5, 8)], d('L', 3, 5, 8) + 700)
        self.assertEqual(got['cells'][('L', 4, 5, 8)], d('L', 4, 5, 8) + 200)
        self.assertEqual(got['cells'][('L', 2, 5, 8)], d('L', 2, 5, 8) + 100)
        self.assertEqual(got['cells'][('S', 2, 5, 0)], d('S', 2, 5, 0) + 100)
        self.assertEqual(got['touch'][-1], ('S', 2, 5))
        self.assertEqual(got['hooks'], [])

    def test_cutoff_is_inclusive_at_one_point_zero_one(self):
        d = fcd.default_init
        inside = run(fcd.scenario(sec=10, cap_none=False, elems=((101000, 3),)))
        outside = run(fcd.scenario(sec=10, cap_none=False, elems=((101001, 3),)))
        self.assertEqual(inside['cells'][('L', 3, 5, 8)], d('L', 3, 5, 8) + 10)
        self.assertNotIn(('L', 3, 5, 8), outside['cells'])
        self.assertEqual(outside['cells'][('L', 2, 5, 8)], d('L', 2, 5, 8) + 10)

    def test_amount_over_the_remainder_is_skipped(self):
        d = fcd.default_init
        got = run(fcd.scenario(sec=100, cap_none=False, elems=((60000, 3), (60000, 4))))
        self.assertEqual(got['cells'][('L', 3, 5, 8)], d('L', 3, 5, 8) + 60)
        self.assertNotIn(('L', 4, 5, 8), got['cells'])
        self.assertEqual(got['cells'][('L', 2, 5, 8)], d('L', 2, 5, 8) + 40)

    def test_zero_amount_touches_nothing(self):
        got = run(fcd.scenario(fn='credit', amt=0))
        self.assertEqual(got['touch'], [])
        self.assertEqual(got['cells'], {})

    def test_saturating_add_calls_the_hook_once(self):
        init = ((('L', 0, 5, 8), fcd.U64 - 2),)
        got = run(fcd.scenario(fn='credit', amt=7, init=init))
        self.assertEqual(got['cells'][('L', 0, 5, 8)], fcd.U64)
        self.assertEqual(got['hooks'], [fcd.LOC_ADD])

    def test_extra_credit_uses_its_own_location(self):
        init = ((('L', 0, 5, 0), fcd.U64),)
        got = run(fcd.scenario(fn='ext', amt=1, init=init))
        self.assertEqual(got['hooks'], [fcd.LOC_EXT])

    def test_ledger_double_borrow_calls_the_hook_twice(self):
        got = run(fcd.scenario(flag=1, gross=5, rebate=6, prot=1, amt=3, cap_none=True))
        self.assertEqual(got['hooks'], [fcd.LOC_SUB, fcd.LOC_SUB])
        self.assertEqual(got['cells'][('L', 0, 5, 0x20)], fcd.default_init('L', 0, 5, 0x20))

    def test_flag_zero_leaves_the_primary_cells_alone(self):
        got = run(fcd.scenario(flag=0, gross=50, rebate=1, prot=2, amt=9, cap_none=True))
        d = fcd.default_init
        self.assertEqual(got['cells'][('L', 0, 5, 0x28)], d('L', 0, 5, 0x28) + 2)
        self.assertEqual(got['cells'][('L', 0, 5, 0x20)], d('L', 0, 5, 0x20))
        self.assertEqual(got['cells'][('L', 0, 5, 0x18)], d('L', 0, 5, 0x18))

    def test_u64_double_conversion_edges(self):
        self.assertEqual(fcd.u64_of_double(float(fcd.U64)), fcd.U64)
        self.assertEqual(fcd.u64_of_double(2.0 ** 63), 1 << 63)
        self.assertEqual(fcd.u64_of_double(float('inf')), 0)
        self.assertEqual(fcd.u64_of_double(0.5), 0)


class Agreement(unittest.TestCase):
    def test_edge_groups_agree_with_the_model(self):
        c = fixture()
        edge = [v for v in c['vectors'] if v[0] in ('saturate', 'sweep', 'ledger')]
        self.assertGreater(len(edge), 200)
        for group, s in edge:
            self.assertEqual(fcd.compare(s, fcd.evaluate(c['img'], c['insns'], s), fcd.model(s)), [], group)

    def test_every_40th_vector_agrees_with_the_model(self):
        c = fixture()
        for group, s in c['vectors'][::40]:
            self.assertEqual(fcd.compare(s, fcd.evaluate(c['img'], c['insns'], s), fcd.model(s)), [], group)

    def test_vector_list_is_deterministic(self):
        a = [(g, repr(sorted(s.items(), key=str))) for g, s in fcd.random_grid(50)]
        b = [(g, repr(sorted(s.items(), key=str))) for g, s in fcd.random_grid(50)]
        self.assertEqual(a, b)

    def test_vector_count_target(self):
        self.assertGreaterEqual(len(fixture()['vectors']), 10000)


class Negative(unittest.TestCase):
    def test_each_wrong_spec_is_caught(self):
        c = fixture()
        rows = fcd.wrong_spec_rows(c['img'], c['insns'], c['control'])
        self.assertEqual(len(rows), len(fcd.WRONG_SPECS))
        self.assertTrue(all(o.startswith('killed') for _, o in rows), rows)
        self.assertEqual(fcd.SPEC['cutoff'], 1.01)

    def test_sampled_byte_mutants_are_caught(self):
        c = fixture()
        patches = fcd.mutant_patches(c['insns'])
        self.assertGreater(len(patches), 60)
        for name, patch in patches[::6]:
            img = fcd.Image(c['data'], patch)
            try:
                mut = fcd.decode_all(img, c['fdes'])
            except fcd.EvidenceError:
                continue
            self.assertIsNotNone(fcd.run_subset(img, mut, c['control']), name)

    def test_corrupted_cutoff_constant_moves_a_vector(self):
        c = fixture()
        img = fcd.Image(c['data'], {fcd.CONST['cutoff'] + 6: 0xf1})
        hit = fcd.run_subset(img, c['insns'], c['control'])
        self.assertIsNotNone(hit)

    def test_wrong_hook_slot_is_not_modelled(self):
        c = fixture()
        s = fcd.scenario(fn='credit', amt=7, init=((('L', 0, 5, 8), fcd.U64),))
        stubs_before = fcd.HOOK_SLOT
        self.assertEqual(stubs_before, 0x64e4ea8)
        self.assertEqual(run(s)['hooks'], [fcd.LOC_ADD])
        self.assertNotEqual(fcd.LOC_ADD, fcd.LOC_EXT)


class Packet(unittest.TestCase):
    def test_measure_file_if_present(self):
        path = PACKET / 'measure.json'
        if not path.exists():
            return
        m = json.loads(path.read_text())
        self.assertGreaterEqual(m['cases'], 10000)
        self.assertEqual(m['negative_controls'], m['negative_detected'])
        self.assertGreaterEqual(m['negative_controls'], 30)


class Conversions(unittest.TestCase):
    def test_u64_to_double_is_correctly_rounded(self):
        edge = (0, 1, 2, 2 ** 32 - 1, 2 ** 32, 2 ** 53, 2 ** 53 + 1, 2 ** 53 + 2, 2 ** 53 + 3, 2 ** 63 - 1, 2 ** 63,
                2 ** 64 - 2049, 2 ** 64 - 2048, 2 ** 64 - 1025, 2 ** 64 - 1024, fcd.U64)
        for x in edge:
            self.assertEqual(fcd.u64_to_double(x), float(x), x)

    def test_u64_to_double_on_generated_values(self):
        g = fcd.Lcg(7)
        for _ in range(3000):
            x = (g.next(1 << 31) << 33 | g.next(1 << 31) << 2 | g.next(4)) >> g.next(64)
            self.assertEqual(fcd.u64_to_double(x), float(x), x)

    def test_double_to_u64_table(self):
        two64 = 2.0 ** 64
        table = ((0.0, 0), (0.4, 0), (1.0, 1), (1.9, 1), (2.0 ** 53, 2 ** 53), (2.0 ** 63 - 1024, 2 ** 63 - 1024),
                 (2.0 ** 63, 2 ** 63), (2.0 ** 63 + 4096, 2 ** 63 + 4096), (two64 - 4096, 2 ** 64 - 4096),
                 (two64 - 2048, 2 ** 64 - 2048), (two64, fcd.U64), (two64 * 4, fcd.U64), (float('inf'), 0),
                 (float('nan'), 0), (-1.0, 0), (-0.5, 0))
        for x, want in table:
            self.assertEqual(fcd.double_to_u64(x), want, x)

    def test_double_to_u64_agrees_with_the_closed_form(self):
        g = fcd.Lcg(11)
        for _ in range(3000):
            x = fcd.bits_to_double(g.next(1 << 31) << 33 | g.next(1 << 31) << 2 | g.next(4))
            if x != x:
                continue
            self.assertEqual(fcd.double_to_u64(x), fcd.u64_of_double(x), x)

    def test_truncation_indefinite_value(self):
        self.assertEqual(fcd.truncate_to_i64(float('nan')), 1 << 63)
        self.assertEqual(fcd.truncate_to_i64(2.0 ** 63), 1 << 63)
        self.assertEqual(fcd.truncate_to_i64(-1.5), fcd.U64)
        self.assertEqual(fcd.truncate_to_i64(-(2.0 ** 63)), 1 << 63)


class Reconstruction(unittest.TestCase):
    def test_record_bytes_round_trip(self):
        for s in (fcd.scenario(flag=1, amt=9, gross=5, rebate=2, prot=1, cap_none=False, sec=77, elems=((5, 3), (6, 4))),
                  fcd.scenario(flag=0, gross=1, cap_none=True), fcd.scenario(flag=1, amt=3, cap_none=True),
                  fcd.scenario(flag=0, cap_none=False, sec=0, elems=())):
            rec = fcd.FeeRecord.from_scenario(s)
            mem = {}
            for off, raw in rec.words().items():
                for k, b in enumerate(raw):
                    mem[0x1000 + off + k] = b
            if rec.rows is not None:
                for i, (n, addr) in enumerate(rec.rows):
                    for k, b in enumerate(n.to_bytes(8, 'little') + addr):
                        mem[0x9000 + 32 * i + k] = b
                for k, b in enumerate((0x9000).to_bytes(8, 'little')):
                    mem[0x1030 + k] = b
            back = fcd.FeeRecord.parse(lambda a, n: bytes(mem[a + k] for k in range(n)), 0x1000)
            self.assertTrue(rec.same_as(back))

    def test_absent_parts_are_not_written(self):
        rec = fcd.FeeRecord.from_scenario(fcd.scenario(flag=0, cap_none=True))
        self.assertEqual(sorted(rec.words()), [0x00, 0x28, 0x60, 0x68, 0x70])
        rec = fcd.FeeRecord.from_scenario(fcd.scenario(flag=1, cap_none=False, elems=((1, 3),)))
        self.assertEqual(sorted(rec.words()), [0x00, 0x08, 0x10, 0x28, 0x38, 0x40, 0x48, 0x60, 0x68, 0x70])

    def test_reconstruction_matches_the_bytes_on_edge_groups_and_a_sample(self):
        c = fixture()
        picked = [v for v in c['vectors'] if v[0] in ('saturate', 'sweep', 'ledger')] + c['vectors'][::25]
        for group, s in picked:
            got = fcd.evaluate(c['img'], c['insns'], s)
            alt = fcd.ledger_result(s)
            self.assertEqual((alt['cells'], alt['touch'], alt['hooks']), (got['cells'], got['touch'], got['hooks']), group)

    def test_steps_record_saturation(self):
        led = fcd.Ledger({(('L', 0, 5, 8), fcd.U64 - 1)})
        led.init = {('L', 0, 5, 8): fcd.U64 - 1}
        led.credit(fcd.addr_of(0), 5, 4)
        self.assertEqual(led.steps[0], (8, 4, fcd.U64, True))
        self.assertEqual(led.steps[1][3], False)
        self.assertEqual(led.hooks, [fcd.LOC_ADD])

    def test_zero_remainder_credits_nobody(self):
        led = fcd.Ledger({})
        rec = fcd.FeeRecord(0, None, None, [(100000, fcd.addr_of(3))], 50, fcd.addr_of(2), 0, 0, 0)
        led.distribute(fcd.addr_of(0), 5, rec)
        self.assertEqual([t for t in led.touch if t[1] == 2], [])
        self.assertEqual(led.cells[('L', 3, 5)][8], fcd.default_init('L', 3, 5, 8) + 50)

    def test_same_row_twice_accumulates(self):
        led = fcd.Ledger({})
        rec = fcd.FeeRecord(0, None, None, [(40000, fcd.addr_of(3)), (40000, fcd.addr_of(3))], 100, fcd.addr_of(2),
                            0, 0, 0)
        led.distribute(fcd.addr_of(0), 5, rec)
        self.assertEqual(led.cells[('L', 3, 5)][8], fcd.default_init('L', 3, 5, 8) + 80)
        self.assertEqual(led.cells[('L', 2, 5)][8], fcd.default_init('L', 2, 5, 8) + 20)
        self.assertEqual(led.totals[('S', 3, 5)][0], fcd.default_init('S', 3, 5, 0) + 80)

    def test_total_is_ignored_without_a_list(self):
        led = fcd.Ledger({})
        led.distribute(fcd.addr_of(0), 5, fcd.FeeRecord(0, None, None, None, None, None, 1, 2, 3))
        self.assertEqual(led.touch, [('L', 0, 5)])
        self.assertEqual(led.cells[('L', 0, 5)][0x28], fcd.default_init('L', 0, 5, 0x28) + 3)

    def test_list_with_zero_total_touches_only_the_primary_cell(self):
        led = fcd.Ledger({})
        led.distribute(fcd.addr_of(0), 5, fcd.FeeRecord(0, None, None, [(1, fcd.addr_of(3))], 0, fcd.addr_of(2), 0, 0, 0))
        self.assertEqual(led.touch, [('L', 0, 5)])

    def test_primary_recipient_gets_the_amount(self):
        led = fcd.Ledger({})
        led.distribute(fcd.addr_of(0), 5, fcd.FeeRecord(1, 11, fcd.addr_of(1), None, None, None, 10, 4, 3))
        self.assertEqual(led.cells[('L', 1, 5)][8], fcd.default_init('L', 1, 5, 8) + 11)
        self.assertEqual(led.cells[('L', 0, 5)][0x20], fcd.default_init('L', 0, 5, 0x20) + 3)
        self.assertEqual(led.cells[('L', 0, 5)][0x18], fcd.default_init('L', 0, 5, 0x18) + 11)

    def test_extra_credit_of_zero_still_creates_the_cell(self):
        led = fcd.Ledger({})
        led.extra_credit(fcd.addr_of(4), 9, 0)
        self.assertEqual(led.touch, [('L', 4, 9)])

    def test_unknown_address_is_an_error(self):
        with self.assertRaises(KeyError):
            fcd.Ledger({}).credit(bytes(20), 1, 1)

    def test_reconstruction_and_model_agree_on_every_generated_vector(self):
        for group, s in fixture()['vectors'][::7]:
            alt, want = fcd.ledger_result(s), fcd.model(s)
            self.assertEqual((alt['cells'], alt['touch'], alt['hooks']), (want['cells'], want['touch'], want['hooks']), group)


class Table(unittest.TestCase):
    """Hand-worked expectations: (scenario keywords, {cell word: delta}, hooks)."""

    D = staticmethod(fcd.default_init)

    def check(self, kw, deltas, hooks=()):
        s = fcd.scenario(**kw)
        got = run(s)
        for (kind, uid, key, off), delta in deltas.items():
            self.assertEqual(got['cells'][(kind, uid, key, off)], self.D(kind, uid, key, off) + delta,
                             (kind, uid, key, off))
        self.assertEqual(got['hooks'], list(hooks))
        alt = fcd.ledger_result(s)
        self.assertEqual(alt['cells'], got['cells'])

    def test_even_split_three_ways(self):
        self.check(dict(sec=300, cap_none=False, elems=((33333, 3), (33333, 4), (33333, 5))),
                   {('L', 3, 5, 8): 99, ('L', 4, 5, 8): 99, ('L', 5, 5, 8): 99, ('L', 2, 5, 8): 3})

    def test_fraction_of_one_takes_the_whole_total(self):
        self.check(dict(sec=500, cap_none=False, elems=((100000, 3),)), {('L', 3, 5, 8): 500, ('S', 3, 5, 0): 500})

    def test_second_full_fraction_is_skipped_for_lack_of_funds(self):
        self.check(dict(sec=500, cap_none=False, elems=((100000, 3), (100000, 4))), {('L', 3, 5, 8): 500})

    def test_fraction_truncates_toward_zero(self):
        self.check(dict(sec=7, cap_none=False, elems=((50000, 3),)), {('L', 3, 5, 8): 3, ('L', 2, 5, 8): 4})

    def test_row_with_zero_numerator_credits_nothing_but_remainder_is_paid(self):
        self.check(dict(sec=9, cap_none=False, elems=((0, 3),)), {('L', 2, 5, 8): 9})

    def test_numerator_above_the_cut_off_is_ignored(self):
        self.check(dict(sec=1000, cap_none=False, elems=((101001, 3), (50000, 4))),
                   {('L', 4, 5, 8): 500, ('L', 2, 5, 8): 500})

    def test_primary_amounts_with_a_net_fee(self):
        self.check(dict(flag=1, gross=100, rebate=30, prot=20, amt=40),
                   {('L', 0, 5, 0x28): 20, ('L', 0, 5, 0x20): 50, ('L', 0, 5, 0x18): 40, ('L', 1, 5, 8): 40})

    def test_net_fee_below_zero_is_clamped_with_one_hook(self):
        self.check(dict(flag=1, gross=10, rebate=30, prot=0, amt=1), {('L', 0, 5, 0x20): 0}, [fcd.LOC_SUB])

    def test_protocol_above_net_clamps_with_one_hook(self):
        self.check(dict(flag=1, gross=10, rebate=2, prot=9, amt=1), {('L', 0, 5, 0x20): 0}, [fcd.LOC_SUB])

    def test_gross_zero_rebate_one_protocol_one_has_two_hooks(self):
        self.check(dict(flag=1, gross=0, rebate=1, prot=1, amt=1), {('L', 0, 5, 0x20): 0},
                   [fcd.LOC_SUB, fcd.LOC_SUB])

    def test_known_and_unknown_users_give_the_same_cells(self):
        a = run(fcd.scenario(sec=100, cap_none=False, elems=((25000, 3),), known=frozenset()))
        b = run(fcd.scenario(sec=100, cap_none=False, elems=((25000, 3),), known=frozenset(range(10))))
        self.assertEqual(a['cells'], b['cells'])
        self.assertEqual(a['touch'], b['touch'])

    def test_huge_total_saturates_one_row_and_pays_the_rest(self):
        self.check(dict(sec=fcd.U64, cap_none=False, elems=((100000, 3),)),
                   {('L', 3, 5, 8): fcd.U64 - self.D('L', 3, 5, 8), ('S', 3, 5, 0): fcd.U64 - self.D('S', 3, 5, 0)},
                   [fcd.LOC_ADD, fcd.LOC_ADD])

    def test_explain_lists_each_written_word(self):
        lines = fcd.explain(fcd.scenario(flag=1, gross=10, rebate=30, prot=0, amt=1, cap_none=True))
        self.assertEqual(lines[-1], 'borrow hook at ' + hex(fcd.LOC_SUB))
        self.assertTrue(any(l.startswith('word +0x28') for l in lines))
        self.assertEqual(len([l for l in lines if l.startswith('word')]), 4)


class Evidence(unittest.TestCase):
    def test_instruction_listing_matches_the_decoder(self):
        path = PACKET / 'instructions.tsv'
        if not path.exists():
            return
        rows = path.read_text().splitlines()[1:]
        insns = fixture()['insns']
        self.assertEqual(len(rows), len(insns))
        for row, ins in zip(rows, insns):
            va, size, raw, text = row.split('\t')
            self.assertEqual((int(va, 16), int(size), raw, text), (ins.va, ins.size, ins.raw.hex(), fcd.show(ins)))

    def test_evidence_json_counts(self):
        path = PACKET / 'evidence.json'
        if not path.exists():
            return
        ev = json.loads(path.read_text())
        self.assertEqual(ev['sha256'], fcd.SHA256)
        self.assertEqual(ev['instructions'], 476)
        self.assertEqual(ev['evaluation']['mismatches'], 0)
        self.assertEqual(ev['evaluation']['vectors'], len(fixture()['vectors']))
        self.assertEqual(ev['subjects']['0x3c1ae50']['direct_callers'], ['0x3c10000', '0x44896f0'])
        self.assertEqual(len(ev['hook_slot_callers_in_subjects']), 9)


class Facts(unittest.TestCase):
    def test_hook_sites_inside_the_subjects(self):
        sites = fcd.sites(fixture()['insns'])
        self.assertEqual(len(sites), 9)
        self.assertEqual({loc for _, loc in sites}, {fcd.LOC_ADD, fcd.LOC_SUB, fcd.LOC_EXT})
        self.assertEqual(sum(loc == fcd.LOC_SUB for _, loc in sites), 2)
        self.assertEqual(sum(loc == fcd.LOC_EXT for _, loc in sites), 1)

    def test_caller_census_by_byte_scan(self):
        c = fixture()
        self.assertEqual(fcd.callers(c['img'], c['fdes'], fcd.F_DIST), [0x3c10000, 0x44896f0])
        self.assertEqual(fcd.callers(c['img'], c['fdes'], fcd.F_EXT), [0x44896f0])
        self.assertEqual(fcd.callers(c['img'], c['fdes'], fcd.F_CREDIT), [fcd.F_DIST])

    def test_locations_decoded_from_relocations(self):
        img = fixture()['img']
        got = {hex(v): fcd.decode_location(img, v) for v in (fcd.LOC_ADD, fcd.LOC_SUB, fcd.LOC_EXT)}
        self.assertEqual([(g['path'].rsplit('/', 1)[1], g['line'], g['column']) for g in got.values()],
                         [('mod.rs', 835, 1), ('impl_wei.rs', 6, 1), ('impl_ntl.rs', 682, 1)])

    def test_mutant_list_is_deterministic_and_varied(self):
        a = fcd.mutant_patches(fixture()['insns'])
        b = fcd.mutant_patches(fixture()['insns'])
        self.assertEqual(a, b)
        kinds = {name.split(' ')[0] for name, _ in a}
        self.assertEqual(kinds, {'invert', 'bump', 'displacement'})
        self.assertGreaterEqual(len(a), 70)
        for _, patch in a:
            self.assertEqual(len(patch), 1)

    def test_control_set_leads_with_the_edge_groups(self):
        control = fixture()['control']
        edge = sum(g in ('saturate', 'sweep', 'ledger') for g, _ in fixture()['vectors'])
        self.assertTrue(all(g in ('saturate', 'sweep', 'ledger') for g, _ in control[:edge]))
        self.assertGreater(len(control), edge)

    def test_wrong_spec_names_are_unique(self):
        names = [n for n, _ in fcd.WRONG_SPECS]
        self.assertEqual(len(names), len(set(names)))
        for _, change in fcd.WRONG_SPECS:
            self.assertTrue(set(change) <= set(fcd.SPEC))

    def test_addresses_and_defaults_are_distinct(self):
        self.assertEqual(len(fcd.ADDR_UID), fcd.USERS)
        self.assertEqual(len({fcd.addr_of(u)[0] for u in range(fcd.USERS)}), fcd.USERS)
        seen = {fcd.default_init('L', u, 5, off) for u in range(fcd.USERS) for off in range(0, 0x30, 8)}
        self.assertEqual(len(seen), fcd.USERS * 6)

    def test_scenario_rejects_nothing_but_keeps_defaults(self):
        s = fcd.scenario()
        self.assertEqual((s['fn'], s['key'], s['flag'], s['cap_none']), ('dist', 5, 0, True))
        self.assertEqual(fcd.scenario(key=9)['key'], 9)


if __name__ == '__main__':
    unittest.main()
