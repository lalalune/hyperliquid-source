import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import re007_margin_identifier_115 as T  # noqa: E402

PACKET = ROOT / 'research/work-items/RE-007-margin-mode-identifier-115'
_STATE = {}


def state():
    if not _STATE:
        data = T.TARGET.read_bytes()
        image = T.Image(data)
        bound = {}
        for entry, family, form in T.BODIES:
            stubs, rec, roles, rows, vrows = T.bind_stubs(image, entry, family, form)
            bound[entry] = (family, form, stubs, rec, roles, rows, T.gather_it_pool(rows, roles))
        _STATE.update(data=data, image=image, bound=bound)
    return _STATE


def run(entry, case):
    s = state()
    family, form, stubs, rec, roles, rows, it_pool = s['bound'][entry]
    got, ev, steps = T.run_case(s['image'], entry, form, stubs, rec, case)
    want, wev = T.recon(case, family)
    return got, ev, want, T.fix_it_pool(wev, it_pool)


class IdentityTest(unittest.TestCase):
    def test_digest_and_fde_starts(self):
        s = state()
        self.assertEqual(T.SHA115, 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301')
        by_start = T.fde_index(s['image'])
        for entry, _, _ in T.BODIES:
            self.assertIn(entry, by_start)
        self.assertEqual([by_start[e]['end'] - e for e, _, _ in T.BODIES], [1002, 1002, 1002, 873, 873])

    def test_roles_follow_call_order(self):
        for entry, (family, form, stubs, rec, roles, rows, it_pool) in state()['bound'].items():
            self.assertEqual(tuple(roles), T.ROLE_ORDER)
            self.assertEqual(len(set(roles.values())), 8)
            self.assertEqual(roles['visit_bytes'], T.VISITORS[(family, form)])

    def test_jump_table_arms(self):
        s = state()
        for entry, (family, form, stubs, rec, roles, rows, it_pool) in s['bound'].items():
            table, entries, default = T.jump_table(s['image'], rows)
            arms = T.check_arms(entries, default)
            self.assertEqual(sorted(arms), sorted(T.ARMS.values()))
            self.assertEqual([t for t, _ in entries], list(range(1, 16)))
            targets = dict(entries)
            for tag in (2, 3, 5, 6, 7, 8, 9, 10, 11):
                self.assertEqual(targets[tag], default)

    def test_name_words_are_the_three_names(self):
        s = state()
        words = {}
        for entry, (family, form, stubs, rec, roles, rows, it_pool) in s['bound'].items():
            for va, size, target, raw in T.name_literals(s['image'], rows):
                words[target] = raw
        self.assertEqual(words[0x5fe8ed], b'norm')
        self.assertEqual(words[0x5fe8f1], b'al')
        self.assertEqual(words[0x5feb14], b'noCr')
        self.assertEqual(words[0x5feb17], b'ross')
        self.assertEqual(words[0x5feb1b], b'strictIs')
        self.assertEqual(words[0x5feb21], b'Isolated')

    def test_pool_constants_are_per_family(self):
        pools = {}
        for entry, (family, form, stubs, rec, roles, rows, it_pool) in state()['bound'].items():
            pools.setdefault(family, set()).add(it_pool)
        self.assertEqual(pools, {1: {0x6429d28}, 2: {0x6470fb8}, 3: {0x64af090}})


class BehaviourTest(unittest.TestCase):
    def check_all(self, case):
        for entry, _, _ in T.BODIES:
            got, ev, want, wev = run(entry, case)
            self.assertEqual((got, ev), (want, wev), '0x%x %s' % (entry, case.label()))
        return got, ev

    def test_small_integers_are_variant_indexes(self):
        for v in (0, 1, 2):
            self.assertEqual(self.check_all(T.Case('int8', 1, value=v))[0], ('ok', v))
            self.assertEqual(self.check_all(T.Case('int64', 4, value=v))[0], ('ok', v))

    def test_integer_three_and_above_is_invalid_value(self):
        got, ev = self.check_all(T.Case('int8', 1, value=3))
        self.assertEqual(got, ('err', 'invalid_value'))
        self.assertEqual(ev[0], ('iv', 1, 3))
        got, ev = self.check_all(T.Case('int64', 4, value=0x100000000))
        self.assertEqual(ev[0], ('iv', 1, 0x100000000))

    def test_u8_reads_only_the_low_byte_of_the_slot(self):
        # the byte arm reads byte +1; an int64 value 0x100 has a zero low byte yet is still invalid
        self.assertEqual(self.check_all(T.Case('int64', 4, value=0x100))[0], ('err', 'invalid_value'))

    def test_exact_names_in_every_text_arm(self):
        for arm, tag in (('str', 13), ('string', 12), ('bytes', 15), ('bytebuf', 14)):
            for k, name in enumerate(T.NAMES):
                self.assertEqual(self.check_all(T.Case(arm, tag, data=name))[0], ('ok', k))

    def test_unknown_text_reports_the_bytes_and_the_pool(self):
        for entry, family, form in T.BODIES:
            got, ev, want, wev = run(entry, T.Case('str', 13, data=b'normaL'))
            self.assertEqual(got, ('err', 'unknown_variant'))
            self.assertEqual(ev[0], ('uv', b'normaL', T.VARIANT_POOLS[family], 3))

    def test_invalid_utf8_bytes_take_the_lossy_copy_and_free_it(self):
        for entry, family, form in T.BODIES:
            got, ev, want, wev = run(entry, T.Case('bytes', 15, data=b'norm\xffl'))
            kinds = [e[0] for e in ev]
            self.assertEqual(kinds[:3], ['lossy', 'uv', 'free'])
            self.assertEqual(ev[1][1], 'norm�l'.encode('utf-8'))
            self.assertEqual(ev[2][1], T.OWNED_BASE)

    def test_valid_utf8_bytes_are_not_copied(self):
        for entry, family, form in T.BODIES:
            got, ev, want, wev = run(entry, T.Case('bytes', 15, data=b'plain'))
            self.assertEqual([e[0] for e in ev][:2], ['lossy', 'uv'])
            self.assertNotIn('free', [e[0] for e in ev])

    def test_owned_buffers_are_freed_only_when_capacity_is_nonzero(self):
        for arm, tag in (('string', 12), ('bytebuf', 14)):
            _, ev = self.check_all(T.Case(arm, tag, data=b'normal', cap=0))
            self.assertNotIn('free', [e[0] for e in ev])
            _, ev = self.check_all(T.Case(arm, tag, data=b'normal', cap=9))
            self.assertIn(('free', T.DATA_BASE, 9, 0), ev)
            self.assertNotIn(('drop', 'c1', tag), ev)

    def test_borrowed_text_arms_drop_the_identifier(self):
        for arm, tag in (('str', 13), ('bytes', 15), ('int8', 1), ('int64', 4)):
            _, ev = self.check_all(T.Case(arm, tag, data=b'normal', value=1))
            self.assertIn(('drop', 'c1', tag), ev)

    def test_other_tags_are_invalid_type_and_keep_the_identifier(self):
        for tag in T.OTHER_TAGS:
            got, ev = self.check_all(T.Case('other', tag))
            self.assertEqual(got, ('err', 'invalid_type'))
            self.assertEqual(ev[0][0], 'it')
            self.assertNotIn(('drop', 'c1', tag), ev)

    def test_value_content_is_dropped_on_error_unless_niche(self):
        _, ev = self.check_all(T.Case('str', 13, data=b'x', c2=T.NICHE_TAG))
        self.assertFalse([e for e in ev if e[:2] == ('drop', 'c2')])
        _, ev = self.check_all(T.Case('str', 13, data=b'x', c2=0x03))
        self.assertEqual(ev[-1], ('drop', 'c2', 3))
        _, ev = self.check_all(T.Case('str', 13, data=b'normal', c2=0x03))
        self.assertFalse([e for e in ev if e[:2] == ('drop', 'c2')])

    def test_every_tag_byte(self):
        for tag in range(256):
            arm = T.ARMS.get(tag, 'other')
            case = T.Case(arm, tag, value=1, data=b'noCross', cap=0)
            self.check_all(case)

    def test_case_list_is_stable(self):
        cases = T.case_list()
        self.assertEqual(len(cases), 3052)
        self.assertEqual(len({c.label() for c in cases}), len(cases))

    def test_sampled_case_set_matches_every_body(self):
        s = state()
        for entry, (family, form, stubs, rec, roles, rows, it_pool) in s['bound'].items():
            for case in T.case_list(11):
                got, ev, _ = T.run_case(s['image'], entry, form, stubs, rec, case)
                want, wev = T.recon(case, family)
                self.assertEqual((got, ev), (want, T.fix_it_pool(wev, it_pool)), case.label())


class NegativeControlTest(unittest.TestCase):
    def test_every_model_flaw_is_caught_by_the_case_set(self):
        s = state()
        entry = T.BODIES[0][0]
        family, form, stubs, rec, roles, rows, it_pool = s['bound'][entry]
        hit = {f: 0 for f in T.Flaws.ALL}
        for case in T.case_list(2):
            got, ev, _ = T.run_case(s['image'], entry, form, stubs, rec, case)
            for flaw in T.Flaws.ALL:
                want, wev = T.recon(case, family, frozenset([flaw]))
                if (got, ev) != (want, T.fix_it_pool(wev, it_pool)):
                    hit[flaw] += 1
        self.assertEqual([f for f, n in hit.items() if n == 0], [])

    def test_unflawed_model_is_not_flagged(self):
        s = state()
        entry = T.BODIES[3][0]
        family, form, stubs, rec, roles, rows, it_pool = s['bound'][entry]
        for case in T.case_list(17):
            got, ev, _ = T.run_case(s['image'], entry, form, stubs, rec, case)
            want, wev = T.recon(case, family, frozenset())
            self.assertEqual((got, ev), (want, T.fix_it_pool(wev, it_pool)))

    def test_damaged_bound_compare_is_caught(self):
        s = state()
        entry = T.BODIES[0][0]
        rows = s['bound'][entry][5]
        bound = next(r for r in rows if r.op == 'cmp' and r.ext == 'imm' and r.imm == 0xe and r.rm[0] == 'reg')
        pos = bound.va + bound.length - 1
        cases = T.case_list(13)
        self.assertIsNone(T.run_damage(s['data'], entry, 1, 'tagged', {}, cases))
        self.assertIsNotNone(T.run_damage(s['data'], entry, 1, 'tagged', {pos: 0x06}, cases))

    def test_damaged_jump_table_entry_is_caught(self):
        s = state()
        entry = T.BODIES[1][0]
        rows = s['bound'][entry][5]
        table, entries, default = T.jump_table(s['image'], rows)
        patch, pos = T.table_patches(table, entries, 13, 12)
        self.assertIsNotNone(T.run_damage(s['data'], entry, 2, 'tagged', patch, T.case_list(13)))

    def test_damaged_niche_compare_is_caught(self):
        s = state()
        entry = T.BODIES[4][0]
        rows = s['bound'][entry][5]
        niche = next(r for r in rows if r.op == 'cmp' and r.ext == 'imm' and r.imm == 0x16 and r.rm[0] == 'reg')
        found = T.run_damage(s['data'], entry, 2, 'result', {niche.va + niche.length - 1: 0x1e}, T.case_list(5))
        self.assertIsNotNone(found)

    def test_wrong_digest_is_rejected(self):
        with self.assertRaises(T.Reject):
            T.check_sha(s_data_with_flip())

    def test_non_fde_entry_is_rejected(self):
        with self.assertRaises((T.Reject, KeyError)):
            T.bind_stubs(state()['image'], 0x1fa4631, 1, 'tagged')

    def test_missing_stub_is_rejected(self):
        s = state()
        entry = T.BODIES[0][0]
        stubs, rec, roles, rows, _ = T.bind_stubs(s['image'], entry, 1, 'tagged')
        del stubs[roles['unknown_variant']]
        with self.assertRaises(T.Reject):
            T.run_case(s['image'], entry, 'tagged', stubs, rec, T.Case('str', 13, data=b'zzz'))

    def test_unexpected_drop_object_is_rejected(self):
        rec = T.Recorder('tagged', 0)
        with self.assertRaises(T.Reject):
            rec.drop(None, (0x1234, 0, 0, 0, 0))

    def test_role_count_mismatch_is_rejected(self):
        rows = state()['bound'][T.BODIES[0][0]][5]
        with self.assertRaises(T.Reject):
            T.body_roles(rows[:20])


def s_data_with_flip():
    data = bytearray(state()['data'])
    data[len(data) // 2] ^= 1
    return bytes(data)


class PacketTest(unittest.TestCase):
    def test_measure_json_agrees_with_summary(self):
        self.assertTrue(PACKET.exists())
        measure = json.loads((PACKET / 'measure.json').read_text())
        summary = json.loads((PACKET / 'summary.json').read_text())
        self.assertEqual(measure['cases'], summary['cases'])
        self.assertEqual(measure['negative_controls'], summary['negative_controls'])
        self.assertEqual(measure['negative_detected'], measure['negative_controls'])
        self.assertTrue(summary['reconstruction_matches_all'])


if __name__ == '__main__':
    unittest.main()
