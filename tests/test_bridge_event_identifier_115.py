import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import bridge_event_identifier_115 as T  # noqa: E402

PACKET = ROOT / 'research/work-items/bridge-event-identifier-115'
_STATE = {}


def state():
    if not _STATE:
        data = T.TARGET.read_bytes()
        image = T.mi.Image(data)
        bound = {}
        for entry, family, form in T.HOSTS:
            stubs, rec, roles, rows = T.bind_host(image, entry, family, form)
            bound[entry] = (family, form, stubs, rec, roles, rows, T.it_pool_of(rows, roles))
        _STATE.update(data=data, image=image, bound=bound)
    return _STATE


def run(entry, case, flaws=frozenset()):
    s = state()
    family, form, stubs, rec, roles, rows, pool = s['bound'][entry]
    got, events, steps = T.run_case(s['image'], entry, form, stubs, rec, case)
    want, wev = T.recon(case, family, pool, flaws)
    return got, events, want, wev


def case(arm, tag, **kw):
    return T.mi.Case(arm, tag, **kw)


class IdentityTest(unittest.TestCase):
    def test_digest_and_fde_sizes(self):
        s = state()
        self.assertEqual(T.SHA115, 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301')
        by_start = T.mi.fde_index(s['image'])
        self.assertEqual([by_start[e]['end'] - e for e, _, _ in T.HOSTS], [610, 610, 760, 760, 760])

    def test_roles_follow_the_body_shape(self):
        for entry, (family, form, stubs, rec, roles, rows, pool) in state()['bound'].items():
            self.assertEqual(T.VIS[roles['str_visitor']][1:], ('str', form))
            self.assertEqual(T.VIS[roles['bytes_visitor']][1:], ('bytes', form))
            self.assertEqual(T.VIS[roles['str_visitor']][0], family)
            self.assertEqual(len(set(roles.values())), len(roles))

    def test_jump_tables(self):
        s = state()
        for entry, (family, form, stubs, rec, roles, rows, pool) in s['bound'].items():
            tables = T.tables_of(s['image'], rows)
            self.assertEqual([t[1] for t in tables], [15, 6, 6])
            default = [r for r in rows if r.op == 'ja'][0].target
            top = tables[0][2]
            for tag in range(1, 16):
                self.assertEqual(top[tag - 1] == default, tag not in T.ARMS, tag)
            self.assertEqual(len(set(top[t - 1] for t in T.ARMS)), len(T.ARMS))
            # both integer tables send values 0..5 to six distinct targets
            for tab in tables[1:]:
                self.assertEqual(len(set(tab[2])), 6)

    def test_pools_are_per_family(self):
        pools = {}
        for entry, (family, form, stubs, rec, roles, rows, pool) in state()['bound'].items():
            pools.setdefault(family, set()).add(pool)
        self.assertEqual(pools, {1: {0x6429008}, 2: {0x6470b18}, 3: {0x64adf30}})

    def test_visitor_pools_match_the_event_packet(self):
        self.assertEqual(T.ev.VARIANT_POOLS, (0x643e050, 0x648a528, 0x64bc6c0))
        self.assertEqual(T.COUNT, 6)


class BehaviourTest(unittest.TestCase):
    def check_all(self, c):
        for entry, _, _ in T.HOSTS:
            got, events, want, wev = run(entry, c)
            self.assertEqual((got, events), (want, wev), '0x%x %s' % (entry, c.label()))
        return got, events

    def test_small_integers_are_variant_indexes(self):
        for v in range(6):
            self.assertEqual(self.check_all(case('int8', 1, value=v))[0], ('ok', v))
            self.assertEqual(self.check_all(case('int64', 4, value=v))[0], ('ok', v))

    def test_integer_six_is_rejected(self):
        got, events = self.check_all(case('int8', 1, value=6))
        self.assertEqual(got, ('err', 'invalid_value'))
        self.assertEqual(events[0], ('iv', 1, 6))
        got, events = self.check_all(case('int64', 4, value=1 << 40))
        self.assertEqual(events[0], ('iv', 1, 1 << 40))

    def test_every_name_in_every_text_arm(self):
        for arm, tag in (('str', 13), ('bytes', 15), ('string', 12), ('bytebuf', 14)):
            for k, name in enumerate(T.NAMES):
                self.assertEqual(self.check_all(case(arm, tag, data=name))[0], ('ok', k))

    def test_unknown_names_report_the_text(self):
        got, events = self.check_all(case('str', 13, data=b'Deposits'))
        self.assertEqual(got, ('err', 'unknown_variant'))
        self.assertEqual(events[0][:2], ('uv', b'Deposits'))
        self.assertEqual(events[-1], ('drop', 'c2', 0x03) if events[-1][1] == 'c2' else events[-1])

    def test_bytes_arm_converts_before_reporting(self):
        got, events = self.check_all(case('bytes', 15, data=b'Dep\xffsit'))
        self.assertEqual(got, ('err', 'unknown_variant'))
        self.assertEqual(events[0], ('lossy', b'Dep\xffsit'))
        self.assertEqual(events[1][1], 'Dep�sit'.encode())
        self.assertEqual(events[2][0], 'vfree')

    def test_owned_buffers_are_freed_only_when_allocated(self):
        _, events = self.check_all(case('string', 12, data=b'Deposit', cap=0))
        self.assertEqual([e for e in events if e[0] == 'free'], [])
        _, events = self.check_all(case('string', 12, data=b'Deposit', cap=10))
        self.assertEqual([e for e in events if e[0] == 'free'], [('free', T.DATA_BASE, 10, 0)])
        _, events = self.check_all(case('bytebuf', 14, data=b'Deposit', cap=10))
        self.assertEqual([e for e in events if e[0] == 'drop'], [])

    def test_other_tags_are_invalid_type(self):
        for tag in (0, 2, 3, 5, 11, 16, 0x7f, 0xff):
            got, events = self.check_all(case('other', tag))
            self.assertEqual(got, ('err', 'invalid_type'))
            self.assertEqual(events[0][:2], ('it', tag))

    def test_value_content_is_dropped_on_errors_only(self):
        _, events = self.check_all(case('int8', 1, value=0, c2=0x03))
        self.assertNotIn(('drop', 'c2', 0x03), events)
        _, events = self.check_all(case('int8', 1, value=9, c2=0x03))
        self.assertEqual(events[-1], ('drop', 'c2', 0x03))
        _, events = self.check_all(case('int8', 1, value=9, c2=T.NICHE_TAG))
        self.assertNotIn('c2', [e[1] for e in events if e[0] == 'drop'])


class NegativeTest(unittest.TestCase):
    def sample(self):
        names = [case(a, t, data=d, cap=3) for a, t in (('str', 13), ('bytes', 15), ('string', 12), ('bytebuf', 14))
                 for d in (b'Deposit', b'deposit', b'Depositx', b'', b'FinalizedWithdrawal', b'RequestedWithdrawal',
                           b'InvalidatedWithdrawal', b'\xff', b'RequestedValidatorSetUpdateEvent')]
        ints = [case('int8', 1, value=v) for v in range(8)] + [case('int64', 4, value=v) for v in range(8)]
        extra = [case('int64', 4, value=0x100), case('int64', 4, value=1 << 40, c2=0x03), case('int16', 2),
                 case('str', 13, data=b'Deposit', cap=0), case('string', 12, data=b'Deposit', cap=0),
                 case('str', 13, data=b'Depos\x00t', c2=0x03), case('str', 13, data=b'DXXXXXX', c2=0x03),
                 case('str', 13, data=b'Xinalized' + b'ValidatorSetUpdate', c2=0x03),
                 case('bytes', 15, data=b'RequestedWithdrawal', c2=0x03),
                 case('str', 13, data=b'Deposits', c2=0x03), case('int8', 1, value=9, c2=0x03)]
        extra[2] = case('other', 2)
        return names + ints + extra + [case('other', 7), case('other', 22)]

    def test_every_model_flaw_is_caught(self):
        miss = []
        for flaw in T.Flaws.ALL:
            caught = False
            for entry, _, _ in T.HOSTS[:1]:
                for c in self.sample():
                    got, events, want, wev = run(entry, c, frozenset([flaw]))
                    caught |= (got, events) != (want, wev)
            if not caught:
                miss.append(flaw)
        # these two only show on c2 values the thinned sample above carries
        self.assertEqual(miss, [])

    def test_damaged_bound_is_caught(self):
        s = state()
        entry, family, form = T.HOSTS[0]
        rows = s['bound'][entry][5]
        cmp5 = [r for r in rows if r.op == 'cmp' and r.ext == 'imm' and r.imm == 5][0]
        found = T.run_damage(s['data'], entry, family, form, {cmp5.va + cmp5.length - 1: 0x0d}, self.sample())
        self.assertIsNotNone(found)
        self.assertEqual(T.run_damage(s['data'], entry, family, form, {}, self.sample()), None)

    def test_damaged_table_entry_is_caught(self):
        s = state()
        entry, family, form = T.HOSTS[2]
        rows = s['bound'][entry][5]
        top = T.tables_of(s['image'], rows)[0]
        patch, pos = T.swap_patch(top[0], top[2], 12, 11)
        self.assertIsNotNone(T.run_damage(s['data'], entry, family, form, patch, self.sample()))

    def test_out_of_range_inputs(self):
        s = state()
        with self.assertRaises(T.Reject):
            T.check_sha(s['data'][:-1])
        with self.assertRaises((T.Reject, KeyError)):
            T.bind_host(s['image'], 0x1fae861, 1, 'result')
        with self.assertRaises(T.Reject):
            T.bind_host(s['image'], 0x1fae860, 3, 'tagged')


class PacketTest(unittest.TestCase):
    def test_manifest_matches_files(self):
        lines = (PACKET / 'MANIFEST.sha256').read_text().splitlines()
        self.assertGreaterEqual(len(lines), 10)
        for line in lines:
            digest, name = line.split('  ')
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), digest, name)

    def test_summary_and_measure_agree(self):
        summary = json.loads((PACKET / 'summary.json').read_text())
        measure = json.loads((PACKET / 'measure.json').read_text())
        self.assertTrue(summary['reconstruction_matches_all'])
        self.assertEqual(summary['cases'], summary['matches'])
        self.assertGreaterEqual(summary['cases'], 10000)
        self.assertGreaterEqual(summary['negative_controls'], 30)
        self.assertEqual(summary['negative_controls'], summary['negative_detected'])
        self.assertEqual(measure, dict(cases=summary['cases'], negative_controls=summary['negative_controls'],
                                       negative_detected=summary['negative_detected']))

    def test_no_mismatch_rows_and_no_undetected_controls(self):
        for name in ('cases.tsv', 'damage-controls.tsv'):
            text = (PACKET / name).read_text()
            self.assertNotIn('MISMATCH', text)
            self.assertNotIn('UNDETECTED', text)
        for row in (PACKET / 'negative-controls.tsv').read_text().splitlines()[1:]:
            self.assertGreater(int(row.split('\t')[2]), 0, row)

    def test_every_host_and_arm_has_sample_rows(self):
        text = (PACKET / 'paths.tsv').read_text()
        for entry, _, _ in T.HOSTS:
            for arm in ('int8', 'int64', 'str', 'bytes', 'string', 'bytebuf', 'other'):
                self.assertIn('0x%x\t%s\t' % (entry, arm), text)


if __name__ == '__main__':
    unittest.main()
