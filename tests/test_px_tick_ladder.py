import filecmp
import hashlib
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import px_tick_ladder as tool  # noqa: E402

PACKET = ROOT / 'research' / 'work-items' / 'RE-004-px-tick-ladder-94'
CACHE = {}


def state():
    """One full analysis for the whole file; it takes about 25 seconds."""
    if not CACHE:
        binary = ROOT / tool.BINARY
        data = binary.read_bytes()
        analysis = tool.analyse(binary, data)
        img = tool.Image(data)
        CACHE.update(binary=binary, data=data, analysis=analysis, img=img, fdes=tool.Fdes(img))
    return CACHE


def function_rows(fn):
    extent = state()['fdes'].range_of(fn)
    return tool.read_rows(state()['binary'], extent['start'], extent['end'])


def edit(rows, va, mnemonic=None, ops=None):
    """A copy of a listing with one instruction changed; the edit must hit that row."""
    out = []
    hit = False
    for row in rows:
        if row[0] == va:
            hit = True
            row = (row[0], mnemonic or row[1], row[2] if ops is None else ops, row[3])
        out.append(row)
    if not hit:
        raise AssertionError(f'no row at {va:#x}')
    return out


def machine_for(rows):
    img = state()['img']
    slots = img.slots()
    slots[tool.FLAG_SLOT] = tool.FLAG_STUB
    machine = tool.Machine(rows, img, slots)
    machine.flag_calls = []
    machine.flag_result = None
    machine.stubs[tool.FLAG_STUB] = tool.partial(tool.flag_stub, machine)
    return machine


def first_va(rows, mnemonic, predicate=lambda ops: True):
    return next(r[0] for r in rows if r[1] == mnemonic and predicate(r[2]))


class Packet(unittest.TestCase):
    def test_outputs_match_the_packet_byte_for_byte(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'x'
            tool.write_outputs(out, state()['analysis'], state()['data'])
            names = sorted(p.name for p in out.iterdir())
            self.assertEqual(names, ['call-sites.tsv', 'evidence.json', 'exponent-table.tsv',
                                     'ladder-copies.tsv', 'step-intervals.tsv'])
            for name in names:
                self.assertTrue(filecmp.cmp(out / name, PACKET / name, shallow=False), name)

    def test_manifest_lists_every_file(self):
        rows = (PACKET / 'MANIFEST.sha256').read_text().split('\n')
        listed = {}
        for line in filter(None, rows):
            digest, name = line.split('  ', 1)
            listed[name] = digest
        have = {p.name for p in PACKET.iterdir() if p.name != 'MANIFEST.sha256'}
        self.assertEqual(set(listed), have)
        for name, digest in listed.items():
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), digest, name)


class Boundaries(unittest.TestCase):
    def test_a_changed_digest_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.check_digest(state()['data'][:-1] + bytes([state()['data'][-1] ^ 1]))

    def test_an_address_outside_the_image_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            state()['img'].read(0x7fffffff0000, 8)

    def test_an_address_outside_every_fde_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            state()['fdes'].range_of(0x10)

    def test_every_ladder_starts_an_fde(self):
        self.assertEqual(len(tool.PERP + tool.SPOT + tool.FLOOR), 11)
        for fn in tool.PERP + tool.SPOT + tool.FLOOR:
            self.assertEqual(state()['fdes'].range_of(fn)['start'], fn)

    def test_census_finds_exactly_the_family(self):
        fdes = state()['fdes']
        for imm in (tool.FAMILY_A, tool.FAMILY_B):
            sites = tool.census(state()['img'], struct.pack('<I', imm))
            self.assertEqual(sorted(fdes.range_of(v)['start'] for v in sites),
                             sorted(tool.PERP + tool.SPOT + tool.FLOOR))

    def test_the_digit_count_lookalike_is_not_a_ladder(self):
        with self.assertRaises(tool.EvidenceError):
            tool.locate_window(function_rows(tool.DIGIT_COUNT))


class Model(unittest.TestCase):
    def test_step_at_the_decade_edges(self):
        cases = {0: 1, 9: 1, 99_999: 1, 100_000: 10, 999_999: 10, 10 ** 6: 100, 10 ** 19 - 1: 10 ** 14,
                 10 ** 19: 10 ** 15, tool.MASK: 10 ** 15}
        for x, step in cases.items():
            self.assertEqual(tool.step_model(x), step, x)

    def test_intervals_cover_u64_without_gaps(self):
        pieces = tool.intervals()
        self.assertEqual(len(pieces), 16)
        self.assertEqual(pieces[0][0], 0)
        self.assertEqual(pieces[-1][1], tool.MASK)
        for (_, high), (low, _) in zip(pieces, pieces[1:]):
            self.assertEqual(high + 1, low)

    def test_reference_differs_in_four_decades_only(self):
        rows = state()['analysis']['reference']
        self.assertEqual([r[0] for r in rows if r[2] != r[3]], [10 ** 11, 10 ** 12, 10 ** 13, 10 ** 19])

    def test_large_exponents_cannot_change_the_tick(self):
        for x in tool.endpoints():
            for k in (15, 16, 19, 20, 255):
                self.assertEqual(tool.spot_model(x, k), tool.step_model(x))
        self.assertLess(tool.spot_model(tool.MASK, 14), tool.step_model(tool.MASK))

    def test_the_cap_admits_a_whole_price_the_ladder_alone_rejects(self):
        rows = state()['analysis']['result']['worked_examples']
        by_x = {r['x']: r for r in rows}
        whole = by_x[123_456_000_000]
        self.assertEqual((whole['step'], whole['tick'], whole['remainder']), (10 ** 7, 10 ** 6, 0))
        self.assertNotEqual(whole['x'] % whole['step'], 0)
        self.assertNotEqual(by_x[12_345_600_000]['remainder'], 0)
        self.assertEqual(by_x[12_345_000_000]['remainder'], 0)

    def test_a_four_figure_model_is_detected(self):
        window = state()['analysis']['windows'][0][2]
        machine = state()['analysis']['machine']
        got = tool.run_window(machine, window, 12_345)
        self.assertEqual(got, tool.step_model(12_345))
        self.assertNotEqual(got, tool.step_model(12_345, figures=4))

    def test_rounding_up_from_an_exact_multiple_moves_one_tick(self):
        probe = {(p['x'], p['tick']): p for p in state()['analysis']['result']['exact_multiple_probe']}
        self.assertEqual(probe[(1000, 10)]['up'], 1010)
        self.assertEqual(probe[(1000, 10)]['down'], 1000)
        self.assertEqual(probe[(0, 10)]['down'], 1)


class Shape(unittest.TestCase):
    """The static argument that makes the endpoints a proof must reject other shapes."""

    def setUp(self):
        self.rows = function_rows(tool.PERP[0])
        self.window = tool.locate_window(self.rows)
        self.body = tool.window_rows(self.rows, self.window)

    def test_the_real_window_gives_the_fifteen_powers(self):
        self.assertEqual(tuple(tool.breakpoints(self.body, self.window)), tool.BREAKPOINTS)

    def test_a_changed_threshold_changes_the_set(self):
        va = first_va(self.body, 'cmp', lambda ops: ops[1] == ('i', tool.FIRST_LIMIT))
        body = edit(self.body, va, ops=(self.body[1][2][0], ('i', tool.FIRST_LIMIT + 1)))
        self.assertNotEqual(tuple(tool.breakpoints(body, self.window)), tool.BREAKPOINTS)

    def test_step_taken_from_x_is_rejected(self):
        va = first_va(self.body, 'mov', lambda ops: ops[1] == ('i', 10))
        body = edit(self.body, va, ops=(('r', tool.RCX, 8), ('r', tool.RDX, 8)))
        with self.assertRaises(tool.EvidenceError):
            tool.breakpoints(body, self.window)

    def test_a_compare_of_another_register_is_rejected(self):
        va = first_va(self.body, 'cmp')
        body = edit(self.body, va, ops=(('r', tool.R9, 8), ('i', tool.FIRST_LIMIT)))
        with self.assertRaises(tool.EvidenceError):
            tool.breakpoints(body, self.window)

    def test_an_arithmetic_step_is_rejected(self):
        va = first_va(self.body, 'inc')
        body = edit(self.body, va, mnemonic='imul')
        with self.assertRaises(tool.EvidenceError):
            tool.breakpoints(body, self.window)

    def test_a_write_to_x_is_rejected(self):
        va = first_va(self.body, 'mov', lambda ops: ops[1] == ('i', 10))
        body = edit(self.body, va, ops=(('r', tool.RDX, 8), ('i', 10)))
        with self.assertRaises(tool.EvidenceError):
            tool.breakpoints(body, self.window)


class Mutations(unittest.TestCase):
    """Each control changes one reached instruction and must change an observed result."""

    def test_perp_threshold_off_by_one(self):
        rows = function_rows(tool.PERP[0])
        window = tool.locate_window(rows)
        va = first_va(rows, 'cmp', lambda ops: ops[1] == ('i', tool.FIRST_LIMIT))
        machine = machine_for(edit(rows, va, ops=(('r', tool.RDX, 8), ('i', tool.FIRST_LIMIT + 1))))
        self.assertEqual(tool.run_window(machine, window, tool.FIRST_LIMIT), 1)
        self.assertNotEqual(tool.step_model(tool.FIRST_LIMIT), 1)

    def test_perp_top_decade(self):
        rows = function_rows(tool.PERP[0])
        window = tool.locate_window(rows)
        va = first_va(rows, 'cmovb')
        machine = machine_for(edit(rows, va, mnemonic='cmovae'))
        self.assertEqual(tool.run_window(machine, window, 10 ** 19), 10 ** 14)
        self.assertEqual(tool.run_window(state()['analysis']['machine'], window, 10 ** 19), 10 ** 15)

    def test_perp_panic_bound(self):
        rows = function_rows(tool.PERP[0])
        va = first_va(rows, 'cmp', lambda ops: ops[1] == ('i', 7))
        machine = machine_for(edit(rows, va, ops=(('r', tool.RAX, 4), ('i', 8))))
        got = tool.run_perp(machine, tool.PERP[0], 1, 7)
        self.assertEqual(got[0], 'ok')
        self.assertEqual(tool.run_perp(state()['analysis']['machine'], tool.PERP[0], 1, 7)[0], 'panic')

    def test_perp_min_direction(self):
        rows = function_rows(tool.PERP[0])
        vas = [r[0] for r in rows if r[1] == 'cmovb']
        machine = machine_for(edit(rows, vas[-1], mnemonic='cmovae'))
        self.assertNotEqual(tool.run_perp(machine, tool.PERP[0], tool.MASK, 3), ('ok', 1000))

    def test_spot_flag_constant(self):
        rows = function_rows(tool.SPOT[1])
        va = first_va(rows, 'mov', lambda ops: ops[1] == ('i', 1000))
        machine = machine_for(edit(rows, va, ops=(('r', tool.RAX, 4), ('i', 999))))
        self.assertEqual(tool.run_spot(machine, tool.SPOT[1], 7, 0, 0, flag=1), ('ok', 999))

    def test_spot_exponent_bit(self):
        rows = function_rows(tool.SPOT[1])
        va = first_va(rows, 'imul', lambda ops: ops[-1] == ('i', 100))
        machine = machine_for(edit(rows, va, ops=(('r', tool.RCX, 8), ('r', tool.RCX, 8), ('i', 1000))))
        self.assertNotEqual(tool.run_spot(machine, tool.SPOT[1], tool.MASK, 0, 2), ('ok', 100))

    def test_spot_reads_the_two_named_token_bytes(self):
        saved = tool.TOKEN_SZ_OFFSET
        tool.TOKEN_SZ_OFFSET = 0x4a
        try:
            with self.assertRaises(tool.Unmodelled):
                tool.run_spot(machine_for(function_rows(tool.SPOT[1])), tool.SPOT[1], 1, 0, 0)
        finally:
            tool.TOKEN_SZ_OFFSET = saved

    def test_floor_multiply(self):
        rows = function_rows(tool.FLOOR[0])
        window = tool.locate_window(rows)
        tail = tool.floor_tail(rows, window)
        store = next(r for r in rows if r[0] > tail['mul'] and r[1] == 'mov')
        machine = machine_for(edit(rows, store[0], ops=(store[2][0], ('r', tool.RDX, 8))))
        self.assertEqual(tool.run_floor(machine, tail, 1_234_567), 0)
        self.assertEqual(tool.run_floor(machine_for(rows), tail, 1_234_567), 1_234_500)

    def test_a_removed_multiply_stops_the_evaluator(self):
        rows = function_rows(tool.FLOOR[0])
        tail = tool.floor_tail(rows, tool.locate_window(rows))
        machine = machine_for(edit(rows, tail['mul'], mnemonic='nop', ops=()))
        with self.assertRaises(tool.Unmodelled):
            tool.run_floor(machine, tail, 1_234_567)

    def test_rounding_increment(self):
        rows = tool.read_rows(state()['binary'], tool.ROUNDING_ENTRY, tool.ROUNDING_STOP + 8)
        va = first_va(rows, 'inc')
        machine = machine_for(edit(rows, va, mnemonic='dec'))
        self.assertEqual(tool.run_rounding(machine, 1000, 10, True), 990)
        self.assertEqual(tool.run_rounding(machine_for(rows), 1000, 10, True), 1010)


class Coverage(unittest.TestCase):
    def test_every_instruction_of_the_tick_functions_ran_or_is_listed(self):
        covered = state()['analysis']['result']['coverage']
        self.assertEqual(len(covered), 5)
        for row in covered.values():
            self.assertEqual(row['instructions'] - row['executed'], len(row['not_executed']))
            self.assertGreater(row['executed'], 90)


class CallSites(unittest.TestCase):
    def setUp(self):
        self.calls = state()['analysis']['calls']

    def test_counts(self):
        counts = state()['analysis']['result']['call_sites']
        self.assertEqual(counts['total'], 54)
        self.assertEqual(counts['classes'], {'FLOOR': 5, 'NEXT': 24, 'REM': 25})

    def test_status_words_at_the_pinned_sites(self):
        words = {row[0]: row[7] for row in self.calls}
        tick, tpsl = tool.STATUS_BASE, tool.STATUS_BASE + 9
        self.assertEqual(words[0x21f8158], [tpsl])
        self.assertEqual(words[0x21f82fa], [tick])
        self.assertEqual(words[0x26ec560], [tick])
        self.assertEqual(words[0x430dc8f], [tick])

    def test_classify_needs_the_returned_tick_as_divisor(self):
        rows = [(1, 'mov', (('r', tool.RCX, 8), ('r', tool.RAX, 8)), 2),
                (2, 'div', (('r', tool.RSI, 8),), 3)]
        with self.assertRaises(tool.EvidenceError):
            tool.classify(rows)

    def test_classify_refuses_a_tail_without_a_division(self):
        rows = [(1, 'mov', (('r', tool.RCX, 8), ('r', tool.RAX, 8)), 2), (2, 'ret', (), None)]
        with self.assertRaises(tool.EvidenceError):
            tool.classify(rows)

    def test_a_wrong_status_sentence_is_refused(self):
        saved = dict(tool.STATUS_TEXT)
        tool.STATUS_TEXT[9] = b'Price must be divisible by tick size.'
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.check_status_messages(state()['binary'], state()['img'])
        finally:
            tool.STATUS_TEXT.clear()
            tool.STATUS_TEXT.update(saved)

    def test_the_outer_tag_prints_the_status(self):
        got = tool.check_outer_tag(state()['binary'], state()['img'])
        self.assertEqual(got['tag'], '0xc4')


if __name__ == '__main__':
    unittest.main()
