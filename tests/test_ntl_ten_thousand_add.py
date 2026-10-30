"""Tests for tools/ntl_ten_thousand_add.py: the /10000 saturating totals of node #94."""

import filecmp
import random
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import ntl_ten_thousand_add as tool  # noqa: E402

BINARY = ROOT / tool.BINARY
SIGNED_HELPER = 0x2712a00
NEG_SIGNED_MULTIPLY = 0x2733e17
UNSIGNED_LEA = 0x2716e50
NEG_UNSIGNED_LEA = 0x270ff78
STATE = {}


def setUpModule():
    STATE['blob'] = tool.load_binary(BINARY)
    STATE['table'] = tool.fde_table(STATE['blob'])
    STATE['starts'] = [item[0] for item in STATE['table']]
    STATE['result'] = tool.analyse(BINARY)


def listing(va):
    return tool.disassemble(BINARY, *tool.enclosing(STATE['table'], STATE['starts'], va))


def site_for(lea):
    return next(site for site in STATE['result'][1] if site['lea'] == lea)


def site_for_multiply(multiply):
    return next(site for site in STATE['result'][1] if site['multiply'] == multiply and not site['reused'])


def mutate(rows, old, new, after=0, count=1):
    """Replace text in the first count rows at or after VA after that contain old."""
    changed, hits = [], 0
    for address, body, target in rows:
        if address >= after and old in body and hits < count:
            body = body.replace(old, new)
            hits += 1
        changed.append((address, body, target))
    if hits != count:
        raise AssertionError(f'mutation {old!r} applied {hits} times')
    return changed


class Division(unittest.TestCase):
    def test_bound_holds_for_each_shape(self):
        rows = tool.division_rows()
        self.assertEqual([row['shape'] for row in rows], ['signed', 'neg-signed', 'unsigned', 'neg-unsigned'])
        self.assertTrue(all(row['proved'] and row['delta'] == 432 for row in rows))

    def test_low_reciprocal_is_rejected(self):
        self.assertFalse(tool.proves_division(tool.MAGIC - 1, tool.SHIFT, tool.DIVISOR, tool.MASK))

    def test_high_reciprocal_is_rejected_and_really_fails(self):
        wrong = tool.MAGIC + 1
        self.assertFalse(tool.proves_division(wrong, tool.SHIFT, tool.DIVISOR, tool.MASK))
        x = tool.MASK - tool.MASK % tool.DIVISOR - 1
        self.assertNotEqual((x * wrong) >> 75, x // tool.DIVISOR)

    def test_bound_stops_at_its_own_limit(self):
        limit = (1 << 75) // 432
        self.assertFalse(tool.proves_division(tool.MAGIC, tool.SHIFT, tool.DIVISOR, limit + 1))

    def test_wrong_shift_is_rejected(self):
        self.assertFalse(tool.proves_division(tool.MAGIC, tool.SHIFT - 1, tool.DIVISOR, tool.MASK))

    def test_formula_agrees_with_integer_division(self):
        rng = random.Random(10000)
        values = [k * 10000 + d for k in (0, 1, 2, 922337203685477) for d in (-1, 0, 1)]
        values += [rng.randrange(1 << 64) for _ in range(20000)]
        for x in values:
            if x >= 0:
                self.assertEqual((x * tool.MAGIC) >> 75, x // 10000)

    def test_truncation_is_toward_zero(self):
        self.assertEqual(tool.trunc_div(-1, 10000), 0)
        self.assertEqual(tool.trunc_div(-9999, 10000), 0)
        self.assertEqual(tool.trunc_div(-10000, 10000), -1)
        self.assertEqual(tool.trunc_div(-10001, 10000), -1)
        self.assertEqual(tool.trunc_div(tool.IMIN, 10000), -922337203685477)
        self.assertEqual(tool.expected_delta('neg-signed', tool.IMIN), 922337203685477)
        self.assertEqual(tool.expected_delta('neg-unsigned', tool.MASK), -1844674407370955)


class Boundaries(unittest.TestCase):
    def test_digest_rejects_other_bytes(self):
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / 'bad'
            data = bytearray(STATE['blob'])
            data[0x1343c80] ^= 1
            path.write_bytes(data)
            with self.assertRaises(tool.EvidenceError):
                tool.load_binary(path)

    def test_address_outside_every_fde(self):
        for va in (0x10, tool.TEXT_VA - 1, tool.TEXT_VA + tool.TEXT_SIZE + 0x100000):
            with self.assertRaises(tool.EvidenceError):
                tool.enclosing(STATE['table'], STATE['starts'], va)

    def test_location_needs_a_relocation(self):
        with self.assertRaises(tool.EvidenceError):
            tool.read_location(STATE['blob'], tool.LOCATION + 1)

    def test_location_text(self):
        path, line, column = tool.read_location(STATE['blob'], tool.LOCATION)
        self.assertTrue(path.endswith(tool.LOCATION_SUFFIX))
        self.assertEqual((line, column), (665, 1))

    def test_helper_extent_comes_from_its_fde(self):
        self.assertEqual(tool.enclosing(STATE['table'], STATE['starts'], SIGNED_HELPER),
                         (SIGNED_HELPER, SIGNED_HELPER + 0xe4))


class Evidence(unittest.TestCase):
    def test_counts(self):
        evidence = STATE['result'][0]
        self.assertEqual(evidence['location_references'], 79)
        self.assertEqual(evidence['functions'], 33)
        self.assertEqual(sum(evidence['sites_by_shape_and_offset'].values()), 79)
        self.assertEqual(evidence['signed_division_byte_hits'], 30)
        self.assertEqual(evidence['signed_division_hits_outside_family'], [])
        self.assertEqual(evidence['distinct_multiplies']['signed'] + evidence['distinct_multiplies']['neg-signed'], 30)
        self.assertEqual(evidence['recorder']['target'], hex(tool.RECORDER))

    def test_every_helper_instruction_ran(self):
        for name, item in STATE['result'][0]['helpers'].items():
            self.assertEqual(item['instructions'], 66, name)
            self.assertEqual(item['instructions_run'], 66, name)
            self.assertEqual(item['calls'], 6, name)

    def test_only_two_fields_are_targets(self):
        self.assertEqual({site['offset'] for site in STATE['result'][1]}, {'0x10', '0x18'})

    def test_transfer_shares_one_quotient(self):
        sites = [s for s in STATE['result'][1] if s['multiply'] == 0x2714d86]
        debit = sorted(s['add'] for s in sites if s['kind'] == 'neg-unsigned')
        credit = sorted(s['add'] for s in sites if s['kind'] == 'unsigned')
        self.assertEqual(debit, [0x2714d9d, 0x2714db1])
        self.assertEqual(credit, [0x2714def, 0x2714e06])

    def test_output_is_deterministic(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            tool.write_outputs(first, *STATE['result'])
            tool.write_outputs(second, *tool.analyse(BINARY))
            names = sorted(path.name for path in Path(first).iterdir())
            self.assertEqual(names, ['add-sites.tsv', 'divide-proof.tsv', 'evidence.json', 'helper-runs.tsv'])
            match, mismatch, errors = filecmp.cmpfiles(first, second, names, shallow=False)
            self.assertEqual((sorted(match), mismatch, errors), (names, [], []))


class SiteControls(unittest.TestCase):
    """Each edit lands on an instruction the vectors reach and must break the site check."""

    def assert_broken(self, rows, site):
        with self.assertRaises((tool.EvidenceError, tool.Unmodelled)):
            tool.check_site(rows, site)

    def test_unedited_sites_pass(self):
        for site in (site_for(UNSIGNED_LEA), site_for(NEG_UNSIGNED_LEA), site_for_multiply(NEG_SIGNED_MULTIPLY)):
            self.assertGreater(tool.check_site(listing(site['lea']), site), 0)

    def test_unsigned_shift(self):
        site = site_for(UNSIGNED_LEA)
        self.assert_broken(mutate(listing(site['lea']), ',0xb', ',0xa', site['multiply']), site)

    def test_unsigned_ceiling_is_not_saturation(self):
        site = site_for(UNSIGNED_LEA)
        rows = mutate(listing(site['lea']), '0x7fffffffffffffff', '0x7ffffffffffffffe', site['lea'])
        self.assert_broken(rows, site)

    def test_overflow_branch_sense(self):
        site = site_for(UNSIGNED_LEA)
        self.assert_broken(mutate(listing(site['lea']), 'jo ', 'jno ', site['add']), site)

    def test_missing_negation(self):
        site = site_for(NEG_UNSIGNED_LEA)
        rows = mutate(listing(site['lea']), 'neg rdx', 'nop', site['multiply'])
        self.assert_broken(rows, site)

    def test_saturation_constant(self):
        site = site_for(NEG_UNSIGNED_LEA)
        rows = mutate(listing(site['lea']), '0x8000000000000000', '0x8000000000000001', site['lea'] - 0x10)
        self.assert_broken(rows, site)

    def test_saturation_selector(self):
        site = site_for(NEG_UNSIGNED_LEA)
        self.assert_broken(mutate(listing(site['lea']), 'cmovo', 'cmovno', site['lea']), site)

    def test_missing_recorder(self):
        site = site_for(NEG_UNSIGNED_LEA)
        rows = [(a, 'nop' if a > site['lea'] and b.startswith('call QWORD') else b, t)
                for a, b, t in listing(site['lea'])]
        self.assert_broken(rows, site)

    def test_recorder_with_another_location(self):
        site = site_for(NEG_UNSIGNED_LEA)
        rows = [(a, b, 0x5713f98 if a == site['lea'] else t) for a, b, t in listing(site['lea'])]
        self.assert_broken(rows, site)

    def test_negated_reciprocal_sign_term(self):
        site = site_for_multiply(NEG_SIGNED_MULTIPLY)
        self.assert_broken(mutate(listing(site['lea']), 'shr rax,0x3f', 'shr rax,0x3e', site['multiply']), site)

    def test_sign_of_the_reciprocal_matters(self):
        site = dict(site_for_multiply(NEG_SIGNED_MULTIPLY))
        site['magic'] = tool.MAGIC
        self.assert_broken(listing(site['lea']), site)

    def test_store_moved_to_another_field(self):
        site = dict(site_for(UNSIGNED_LEA))
        site['offset'] = '0x18'
        self.assert_broken(listing(site['lea']), site)

    def test_unmodelled_instruction_stops(self):
        site = site_for(UNSIGNED_LEA)
        self.assert_broken(mutate(listing(site['lea']), 'add rax,r13', 'adc rax,r13', site['multiply']), site)


class StaticControls(unittest.TestCase):
    def lea_index(self, rows, lea):
        return next(k for k, row in enumerate(rows) if row[0] == lea)

    def test_foreign_multiplier_is_rejected(self):
        rows = mutate(listing(UNSIGNED_LEA), hex(tool.MAGIC), '0x346dc5d63886594c')
        with self.assertRaises(tool.EvidenceError):
            tool.describe_site(rows, self.lea_index(rows, UNSIGNED_LEA))

    def test_rewritten_delta_is_rejected(self):
        site = site_for(UNSIGNED_LEA)
        rows = listing(site['lea'])
        k = next(i for i, row in enumerate(rows) if row[0] == site['add'])
        rows[k - 1] = (rows[k - 1][0], f'mov {site["delta"]},r9', 0)
        with self.assertRaises(tool.EvidenceError):
            tool.describe_site(rows, self.lea_index(rows, UNSIGNED_LEA))

    def test_delta_across_a_call_is_rejected(self):
        rows = [(1, 'mul rcx', 0), (2, 'shr rdx,0xb', 0), (3, 'call 1234', 0), (4, 'add rax,rdx', 0)]
        with self.assertRaises(tool.EvidenceError):
            tool.delta_chain(rows, 0, 3, 'rdx')

    def test_undefined_delta_is_rejected(self):
        rows = [(1, 'mul rcx', 0), (2, 'nop', 0), (3, 'add rax,r9', 0)]
        with self.assertRaises(tool.EvidenceError):
            tool.delta_chain(rows, 0, 2, 'r9')

    def test_multiplier_clobbered_by_a_call(self):
        rows = [(1, f'movabs rcx,{tool.MAGIC:#x}', 0), (2, 'call 1234', 0), (3, 'mul rcx', 0)]
        self.assertIsNone(tool.magic_is_loaded(rows, 2, 'rcx'))
        self.assertEqual(tool.magic_is_loaded(rows[:1] + rows[2:], 1, 'rcx'), tool.MAGIC)


class HelperControls(unittest.TestCase):
    def test_second_value_selects_and_defaults(self):
        rows = listing(SIGNED_HELPER)
        got = tool.run_helper(rows, SIGNED_HELPER, 30000, 50000, 1, 0, 0)
        self.assertEqual((got['first_total'], got['second_total'], got['records']), (3, 5, 0))
        got = tool.run_helper(rows, SIGNED_HELPER, 30000, 50000, 0, 0, 0)
        self.assertEqual((got['first_total'], got['second_total'], got['records']), (3, 3, 0))

    def test_only_bit_zero_selects(self):
        got = tool.run_helper(listing(SIGNED_HELPER), SIGNED_HELPER, 30000, 50000, 0xfe, 0, 0)
        self.assertEqual(got['second_total'], 3)

    def test_small_magnitudes_vanish(self):
        got = tool.run_helper(listing(SIGNED_HELPER), SIGNED_HELPER, -9999, 9999, 1, 7, 7)
        self.assertEqual((got['first_total'], got['second_total']), (7, 7))

    def test_both_totals_saturate_and_record(self):
        got = tool.run_helper(listing(SIGNED_HELPER), SIGNED_HELPER, 10000, -10000, 1, tool.IMAX, tool.IMIN)
        self.assertEqual((got['first_total'], got['second_total'], got['records']), (tool.IMAX, tool.IMIN, 2))

    def test_wrong_lookup_target_stops(self):
        rows = mutate(listing(SIGNED_HELPER), 'call 1f849b0', 'call 47d7ca0')
        with self.assertRaises(tool.Unmodelled):
            tool.run_helper(rows, SIGNED_HELPER, 1, 1, 0, 0, 0)

    def test_strict_mode_rejects_unset_memory(self):
        rows = mutate(listing(SIGNED_HELPER), 'QWORD PTR [rbx+0x18]', 'QWORD PTR [rbx+0x20]')
        with self.assertRaises(tool.Unmodelled):
            tool.run_helper(rows, SIGNED_HELPER, 1, 1, 0, 0, 0)

    def test_broken_helper_fails_its_check(self):
        rows = mutate(listing(SIGNED_HELPER), 'cmovne r15,r14', 'cmove r15,r14')
        with self.assertRaises((tool.EvidenceError, tool.Unmodelled)):
            tool.check_helper(rows, SIGNED_HELPER)


if __name__ == '__main__':
    unittest.main()
