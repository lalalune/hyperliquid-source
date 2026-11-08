import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import fde_extents  # noqa: E402
import bridge_event_json_reader_115 as tool  # noqa: E402

ev = tool.ev
DATA = tool.TARGET.read_bytes()
IMAGE = tool.jr.PatchedImage(DATA)
VIMAGE = tool.EvPatched(DATA)
_, RECS, _ = fde_extents.fde_extents(DATA)
BY_START = {r['start']: r for r in RECS}
VISITORS = {va: tool.VisitorBinding(VIMAGE, va, BY_START[va]['end']) for va in (0x2864e60, 0x44466c0)}
COUNTER = [0]


def prepared():
    out = {}
    for spec in tool.BODIES:
        va, kind, vis_va = spec[0], spec[1], spec[3]
        rows = tool.jr.linear(IMAGE, va, BY_START[va]['end'])
        stubs, _ = tool.bind_reader(rows, spec, VISITORS[vis_va], VIMAGE, COUNTER)
        leas = [r.rm[4] for r in rows if r.op == 'lea' and r.rm[5]]
        out[va] = (kind, VISITORS[vis_va].pool, leas[0] if kind == 'value' else 0, stubs, rows, vis_va)
    return out


PREP = prepared()
VALUE_BODIES = (0x1e20b30, 0x3fb9fa0)
KEY_BODIES = (0x1dee070, 0x3f7bff0)


def outcome(va, buf, pos=0, image=IMAGE, spec=None, stubs=None):
    kind, pool, exp, st, _, _ = PREP[va]
    got, _ = tool.run_case(image, va, stubs or st, buf, pos)
    want = tool.recon(kind, buf, pos, pool, spec or tool.Spec(expected=exp))
    return got, want


class DecoderTests(unittest.TestCase):
    def test_target_digest(self):
        self.assertEqual(hashlib.sha256(DATA).hexdigest(), tool.SHA115)

    def test_nop_padding_is_decoded_as_a_fallthrough(self):
        ins = tool.jr.decode(IMAGE, 0x1e20b62)
        self.assertEqual((ins.op, ins.length, ins.target), ('jmp', 14, 0x1e20b70))

    def test_nop_with_register_operand_rejected(self):
        patched = tool.jr.PatchedImage(DATA, {0x1e20b6a: 0xc0})
        with self.assertRaises(tool.Reject):
            tool.jr.decode(patched, 0x1e20b62)

    def test_bodies_decode_to_the_fde_end(self):
        for va, kind, fam, vis, code, invalid, fin in tool.BODIES:
            rows = PREP[va][4]
            end = rows[-1].va + rows[-1].length
            self.assertLessEqual(end, BY_START[va]['end'])
            self.assertEqual(IMAGE.read(end, BY_START[va]['end'] - end), b'\xcc' * (BY_START[va]['end'] - end))

    def test_visitor_pools_are_the_two_families(self):
        self.assertEqual(VISITORS[0x2864e60].pool, ev.VARIANT_POOLS[0])
        self.assertEqual(VISITORS[0x44466c0].pool, ev.VARIANT_POOLS[1])


class ReaderTests(unittest.TestCase):
    def test_every_name_value_reader(self):
        for va in VALUE_BODIES:
            for k, name in enumerate(tool.NAMES):
                got, want = outcome(va, b'"' + name + b'"')
                self.assertEqual(got, want)
                self.assertEqual(got[0], k)
                self.assertEqual(got[1], tool.DATA_BASE)
                self.assertEqual(got[2], len(name) + 2)

    def test_every_name_key_reader_consumes_colon(self):
        for va in KEY_BODIES:
            for k, name in enumerate(tool.NAMES):
                got, want = outcome(va, b' "' + name + b'" \t:x')
                self.assertEqual(got, want)
                self.assertEqual(got[0], k)
                self.assertEqual(got[2], len(name) + 6)

    def test_unknown_name_calls_visitor_then_finisher(self):
        for va in VALUE_BODIES + KEY_BODIES:
            got, want = outcome(va, b'"Withdrawal":')
            self.assertEqual(got, want)
            self.assertEqual(got[0], tool.ERR_TAG)
            self.assertEqual([e[0] for e in got[4]], ['parse', 'unknown', 'finish'])
            self.assertEqual(got[4][1][2:], (PREP[va][1], 6))

    def test_value_reader_non_quote_reports_invalid_type(self):
        for va in VALUE_BODIES:
            got, want = outcome(va, b'7')
            self.assertEqual(got, want)
            self.assertEqual([e[0] for e in got[4]], ['invalid', 'finish'])
            self.assertEqual(got[4][0][1], PREP[va][2])

    def test_key_reader_brace_and_other_codes(self):
        for va in KEY_BODIES:
            self.assertEqual(outcome(va, b'}')[0][4], [('code', 0xa)])
            self.assertEqual(outcome(va, b'7')[0][4], [('code', 0x11)])
            self.assertEqual(outcome(va, b'')[0][4], [('code', 3)])
            self.assertEqual(outcome(va, b'"Deposit";')[0][4], [('parse', 0), ('code', 6)])

    def test_escapes_reach_the_visitor_through_the_owned_buffer(self):
        for va in VALUE_BODIES:
            got, want = outcome(va, b'"\\u0044eposit"')
            self.assertEqual(got, want)
            self.assertEqual(got[0], 0)

    def test_parse_error_is_not_finished_in_value_readers_but_in_key_readers(self):
        for va in VALUE_BODIES:
            got, _ = outcome(va, b'"Dep')
            self.assertEqual([e[0] for e in got[4]], ['parse'])
        for va in KEY_BODIES:
            got, _ = outcome(va, b'"Dep')
            self.assertEqual([e[0] for e in got[4]], ['parse', 'finish'])

    def test_start_positions_past_the_end(self):
        for va in VALUE_BODIES + KEY_BODIES:
            for pos in (2, 3, tool.base.MASK, 1 << 63):
                got, want = outcome(va, b'  ', pos)
                self.assertEqual(got, want)
                self.assertEqual(got[0], tool.ERR_TAG)

    def test_case_inputs_are_deterministic_and_large(self):
        a, b = tool.case_inputs('value'), tool.case_inputs('key')
        self.assertEqual(a, tool.case_inputs('value'))
        self.assertGreater(len(a), 5000)
        self.assertGreater(len(b), 6000)
        self.assertTrue(all(isinstance(x, bytes) and isinstance(p, int) for x, p in a + b))


class NegativeControlTests(unittest.TestCase):
    def test_wrong_classifiers_are_caught(self):
        wrong = (ev.wrong_prefix, ev.wrong_casefold, ev.wrong_swap, ev.wrong_alphabetical, ev.wrong_first4,
                 ev.wrong_last16, ev.wrong_length_only, ev.wrong_first_byte, ev.wrong_short_table)
        probes = [b'"' + n + b'"' for n in tool.NAMES] + [b'"deposit"', b'"Deposits"', b'"FinalizedWithdrawaL"',
                                                           b'"RequestedWithdrawaL"', b'"A"', b'"Finalized"', b'"XnvalidatedWithdrawal"',
                                                           b'"XinalizedValidatorSetUpdate"']
        for fn in wrong:
            hits = 0
            for va in VALUE_BODIES:
                for buf in probes:
                    got, want = outcome(va, buf, spec=tool.Spec(expected=PREP[va][2], classifier=fn))
                    hits += got != want
            self.assertGreater(hits, 0, fn.__name__)

    def test_wrong_reader_rules_are_caught(self):
        wrong = (dict(eof_value=3), dict(ws=frozenset((9, 10, 13))), dict(clear_scratch=False),
                 dict(finish_unknown=False), dict(consume_ws=False), dict(expected=1))
        for kw in wrong:
            hits = 0
            for va in VALUE_BODIES:
                for buf in (b'', b'  "Deposit"', b'"xyz"', b' ', b'7', b'"Deposit"'):
                    got, want = outcome(va, buf, spec=tool.Spec(**{'expected': PREP[va][2], **kw}))
                    hits += got != want
            self.assertGreater(hits, 0, str(kw))
        for kw in (dict(colon_code=5), dict(colon=0x3b), dict(skip_after_name=False), dict(brace_code=0x11)):
            hits = 0
            for va in KEY_BODIES:
                for buf in (b'"Deposit" :', b'"Deposit";', b'}', b'"Deposit"'):
                    got, want = outcome(va, buf, spec=tool.Spec(**kw))
                    hits += got != want
            self.assertGreater(hits, 0, str(kw))

    def test_reader_code_damage_is_caught(self):
        for va in VALUE_BODIES + KEY_BODIES:
            kind, pool, exp, stubs, rows, _ = PREP[va]
            sites = {label: (addr, new) for label, addr, new in tool.reader_damage_sites(rows)}
            self.assertIn('quote_compare', sites)
            for label in ('quote_compare', 'error_tag_store', 'code_store_immediate'):
                addr, new = sites[label]
                bad = tool.jr.PatchedImage(DATA, {addr: new})
                hits = 0
                for buf in (b'"Deposit"', b'"Deposit":', b'', b'7', b'"xyz"'):
                    try:
                        got, want = outcome(va, buf, image=bad)
                    except tool.Reject:
                        hits += 1
                        continue
                    hits += got != want
                self.assertGreater(hits, 0, (hex(va), label))

    def test_visitor_code_damage_is_caught(self):
        for va in VALUE_BODIES:
            kind, pool, exp, stubs, rows, vis_va = PREP[va]
            vb = VISITORS[vis_va]
            for label, addr, new in tool.visitor_damage_sites(vb.rows):
                bad_stubs = dict(stubs)
                bad_stubs[vis_va] = tool.make_visit_stub(vb, tool.EvPatched(DATA, {addr: new}), [0])
                hits = 0
                for name in tool.NAMES:
                    try:
                        got, want = outcome(va, b'"' + name + b'"', stubs=bad_stubs)
                    except tool.Reject:
                        hits += 1
                        continue
                    hits += got != want
                self.assertGreater(hits, 0, (hex(va), label))

    def test_mid_function_addresses_are_not_fde_starts(self):
        for bogus in (0x1e20b31, 0x1dee080, 0x3fb9fa1, 0x3f7c000):
            self.assertNotIn(bogus, BY_START)

    def test_wrong_input_binary_is_refused(self):
        with self.assertRaises(tool.Reject):
            tool.build(b'not the node')
        with self.assertRaises(tool.Reject):
            tool.build(DATA[:-1] + bytes([DATA[-1] ^ 1]))

    def test_unknown_spec_field_is_refused(self):
        with self.assertRaises(tool.Reject):
            tool.Spec(bogus=1)


class CensusTests(unittest.TestCase):
    def test_census_counts(self):
        rows = tool.visitor_call_census(DATA, RECS)
        self.assertEqual(len(rows), 33)
        self.assertEqual(len(set(r[2] for r in rows)), 12)
        for entry in tool.VISITOR_ENTRIES:
            self.assertTrue(any(r[1] == entry for r in rows), hex(entry))
        for spec in tool.BODIES:
            self.assertTrue(any(r[2] == spec[0] and r[1] == spec[3] for r in rows))

    def test_census_is_sorted_and_inside_hosts(self):
        rows = tool.visitor_call_census(DATA, RECS)
        self.assertEqual([r[0] for r in rows], sorted(r[0] for r in rows))
        for site, tgt, host, size, lsda in rows:
            self.assertTrue(host <= site < host + size)


class EvidenceTests(unittest.TestCase):
    def test_committed_evidence_matches_regeneration(self):
        folder = ROOT / 'research/work-items/bridge-event-json-readers-115'
        result = tool.build(DATA)
        text = tool.render(result)
        for name, body in text.items():
            self.assertEqual((folder / name).read_text(encoding='ascii'), body, name)
        s = result['summary']
        self.assertEqual(s['case_matches'], s['cases'])
        self.assertEqual(s['negative_detected'], s['negative_controls'])
        self.assertGreaterEqual(s['cases'], 10000)
        self.assertGreaterEqual(s['negative_controls'], 30)
        measure = json.loads((folder / 'measure.json').read_text())
        self.assertEqual(measure, dict(cases=s['cases'], negative_controls=s['negative_controls'],
                                       negative_detected=s['negative_detected']))
        manifest = (folder / 'MANIFEST.sha256').read_text().splitlines()
        names = sorted(p.name for p in folder.iterdir() if p.name != 'MANIFEST.sha256')
        self.assertEqual([m.split('  ')[1] for m in manifest], names)
        for line in manifest:
            digest, name = line.split('  ')
            self.assertEqual(hashlib.sha256((folder / name).read_bytes()).hexdigest(), digest)

    def test_main_writes_the_same_files_twice(self):
        with tempfile.TemporaryDirectory() as one:
            self.assertEqual(tool.main(['--out', one]), 0)
            folder = ROOT / 'research/work-items/bridge-event-json-readers-115'
            for p in sorted(Path(one).iterdir()):
                self.assertEqual(p.read_bytes(), (folder / p.name).read_bytes(), p.name)


if __name__ == '__main__':
    unittest.main()
