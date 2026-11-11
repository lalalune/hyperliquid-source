import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import re007_borrow_lend_identifier_115 as T  # noqa: E402

PACKET = ROOT / 'research/work-items/RE-007-borrow-lend-identifier-115'
_STATE = {}


def state():
    if not _STATE:
        data = T.TARGET.read_bytes()
        image = T.Image(data)
        bound = {}
        for entry, family, form in T.BODIES:
            stubs, rec, roles, rows = T.bind_stubs(image, entry, family, form)
            bound[entry] = (family, form, stubs, rec, roles, rows, T.gather_it_pool(rows, roles))
        _STATE.update(data=data, image=image, bound=bound, cases=T.case_list())
    return _STATE


def run(entry, case, flaws=frozenset()):
    s = state()
    family, form, stubs, rec, roles, rows, it_pool = s['bound'][entry]
    got, ev, steps = T.run_case(s['image'], entry, form, stubs, rec, case)
    want, wev = T.recon(case, flaws)
    return (got, ev), (want, T.fix_it_pool(wev, it_pool))


class IdentityTest(unittest.TestCase):
    def test_digest_and_fde_starts(self):
        s = state()
        self.assertEqual(hashlib.sha256(s['data']).hexdigest(), T.SHA115)
        by_start = T.fde_index(s['image'])
        for entry, _, _ in T.BODIES:
            self.assertIn(entry, by_start)
        self.assertEqual([by_start[e]['end'] - e for e, _, _ in T.BODIES], [742, 742, 742, 591, 591])

    def test_roles_follow_call_order(self):
        for entry, (family, form, stubs, rec, roles, rows, it_pool) in state()['bound'].items():
            self.assertEqual(tuple(roles), T.ROLE_ORDER)
            self.assertEqual(len(set(roles.values())), 8)
            self.assertEqual((roles['visit_str'], roles['visit_bytes']), T.VISITORS[(family, form)])

    def test_jump_table_arms(self):
        s = state()
        for entry, (family, form, stubs, rec, roles, rows, it_pool) in s['bound'].items():
            table, entries, default = T.base.jump_table(s['image'], rows)
            arms = T.base.check_arms(entries, default)
            self.assertEqual(sorted(arms), sorted(T.ARMS.values()))
            self.assertEqual([t for t, _ in entries], list(range(1, 16)))
            targets = dict(entries)
            for tag in (2, 3, 5, 6, 7, 8, 9, 10, 11):
                self.assertEqual(targets[tag], default)

    def test_int_tables_are_identity(self):
        s = state()
        for entry, (family, form, stubs, rec, roles, rows, it_pool) in s['bound'].items():
            table, entries, default = T.base.jump_table(s['image'], rows)
            ints = T.int_tables(s['image'], rows, entries)
            self.assertEqual(sorted(ints), [1, 4])
            for tag, (itable, bound, ops, bad) in ints.items():
                self.assertEqual((bound, ops), (3, [0, 1, 2, 3]))

    def test_names_and_bound(self):
        self.assertEqual(T.NAMES, (b'borrow', b'supply', b'repay', b'withdraw'))
        self.assertEqual(T.OK_MAX, len(T.NAMES) - 1)


class ReconstructionTest(unittest.TestCase):
    def test_every_body_matches_on_a_sample(self):
        s = state()
        for entry in s['bound']:
            for case in s['cases'][::11]:
                got, want = run(entry, case)
                self.assertEqual(got, want, (hex(entry), case.label()))

    def test_integer_arms(self):
        for entry in state()['bound']:
            for arm, tag in (('int8', 1), ('int64', 4)):
                for v in (0, 1, 2, 3):
                    got, want = run(entry, T.Case(arm, tag, value=v))
                    self.assertEqual(got[0], ('ok', v))
                    self.assertEqual(got, want)
                for v in (4, 0xff, 1 << 40):
                    if arm == 'int8' and v > 0xff:
                        continue
                    got, want = run(entry, T.Case(arm, tag, value=v))
                    self.assertEqual(got[0], ('err', 'invalid_value'))
                    self.assertEqual(got[1][0], ('iv', 1, v))
                    self.assertEqual(got, want)

    def test_name_arms_use_the_right_visitor(self):
        for entry in state()['bound']:
            for arm, tag, kind in (('str', 13, 'vs'), ('string', 12, 'vs'), ('bytes', 15, 'vb'), ('bytebuf', 14, 'vb')):
                for k, name in enumerate(T.NAMES):
                    got, want = run(entry, T.Case(arm, tag, data=name))
                    self.assertEqual(got[0], ('ok', k))
                    self.assertEqual(got[1][0], (kind, name))
                    self.assertEqual(got, want)
                got, want = run(entry, T.Case(arm, tag, data=b'borrowx'))
                self.assertEqual(got[0], ('err', 'unknown_variant'))
                self.assertEqual(got, want)

    def test_owned_buffers_are_freed_once_and_not_dropped(self):
        for entry in state()['bound']:
            got, want = run(entry, T.Case('string', 12, data=b'repay', cap=9))
            self.assertEqual(got[1], [('vs', b'repay'), ('free', T.DATA_BASE, 9, 0)])
            got, want = run(entry, T.Case('bytebuf', 14, data=b'repay', cap=0))
            self.assertEqual(got[1], [('vb', b'repay')])
            got, want = run(entry, T.Case('bytes', 15, data=b'repay'))
            self.assertEqual(got[1], [('vb', b'repay'), ('drop', 'c1', 15)])

    def test_value_content_dropped_only_on_error(self):
        for entry in state()['bound']:
            got, want = run(entry, T.Case('str', 13, data=b'repay', c2=0x03))
            self.assertEqual(got[0], ('ok', 2))
            self.assertNotIn(('drop', 'c2', 3), got[1])
            got, want = run(entry, T.Case('str', 13, data=b'nope', c2=0x03))
            self.assertEqual(got[1][-1], ('drop', 'c2', 3))
            got, want = run(entry, T.Case('str', 13, data=b'nope', c2=T.NICHE_TAG))
            self.assertNotIn('c2', [e[1] for e in got[1] if e[0] == 'drop'])

    def test_other_tags_are_invalid_type(self):
        for entry in state()['bound']:
            for tag in T.OTHER_TAGS:
                got, want = run(entry, T.Case('other', tag))
                self.assertEqual(got[0], ('err', 'invalid_type'))
                self.assertEqual(got[1][0][:2], ('it', tag))
                self.assertEqual(got, want)


class NegativeControlTest(unittest.TestCase):
    def test_every_flaw_is_caught_on_every_body(self):
        s = state()
        for flaw in T.Flaws.ALL:
            for entry in s['bound']:
                seen = False
                for case in s['cases'][::5]:
                    got, want = run(entry, case, frozenset([flaw]))
                    if got != want:
                        seen = True
                        break
                self.assertTrue(seen, (flaw, hex(entry)))

    def test_damaged_bound_is_caught(self):
        s = state()
        entry, family, form = T.BODIES[3]
        _, _, _, _, roles, rows, _ = s['bound'][entry]
        site = next(r for r in rows if r.op == 'cmp' and r.ext == 'imm' and r.imm == 3)
        pos = site.va + site.length - 1
        found = T.run_damage(s['data'], entry, family, form, {pos: site.raw[-1] ^ 0x08}, T.control_subset(s['cases']))
        self.assertIsNotNone(found)

    def test_inverted_branch_is_caught(self):
        s = state()
        entry, family, form = T.BODIES[0]
        rows = s['bound'][entry][5]
        site = next(r for r in rows if r.op == 'ja')
        found = T.run_damage(s['data'], entry, family, form, {site.va: site.raw[0] ^ 1}, T.control_subset(s['cases']))
        self.assertIsNotNone(found)

    def test_undamaged_body_is_not_flagged(self):
        s = state()
        entry, family, form = T.BODIES[4]
        self.assertIsNone(T.run_damage(s['data'], entry, family, form, {}, T.control_subset(s['cases'])))

    def test_retargeted_table_entry_is_caught(self):
        s = state()
        entry, family, form = T.BODIES[1]
        rows = s['bound'][entry][5]
        table, entries, default = T.base.jump_table(s['image'], rows)
        new = (dict(entries)[12] - table) & 0xffffffff
        raw = new.to_bytes(4, 'little')
        pos = table + 4 * (15 - 1)
        found = T.run_damage(s['data'], entry, family, form, {pos + k: raw[k] for k in range(4)},
                             T.control_subset(s['cases']))
        self.assertIsNotNone(found)

    def test_wrong_digest_and_bad_entry(self):
        s = state()
        with self.assertRaises(T.Reject):
            T.check_sha(s['data'][:-1])
        with self.assertRaises(T.Reject):
            T.check_sha(b'\0' + s['data'][1:])
        with self.assertRaises((T.Reject, KeyError)):
            T.bind_stubs(s['image'], 0x1fb06e1, 1, 'tagged')
        with self.assertRaises(T.Reject):
            T.bind_stubs(s['image'], 0x1fb06e0, 2, 'tagged')

    def test_missing_stub_is_rejected(self):
        s = state()
        family, form, stubs, rec, roles, rows, it_pool = s['bound'][0x1fab480]
        broken = dict(stubs)
        del broken[roles['drop']]
        with self.assertRaises(T.Reject):
            T.run_case(s['image'], 0x1fab480, form, broken, rec, T.Case('int8', 1, value=1))


class PacketTest(unittest.TestCase):
    def test_summary_matches_the_packet(self):
        summary = json.loads((PACKET / 'summary.json').read_text())
        measure = json.loads((PACKET / 'measure.json').read_text())
        self.assertTrue(summary['reconstruction_matches_all'])
        self.assertEqual(summary['cases'], summary['matches'])
        self.assertEqual(measure['cases'], summary['cases'])
        self.assertEqual(measure['negative_controls'], measure['negative_detected'])
        self.assertEqual(summary['sha256'], T.SHA115)

    def test_case_count_is_reproducible(self):
        self.assertEqual(len(state()['cases']) * len(T.BODIES), json.loads((PACKET / 'summary.json').read_text())['cases'])


if __name__ == '__main__':
    unittest.main()
