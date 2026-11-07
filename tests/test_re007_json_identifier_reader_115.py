import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import fde_extents  # noqa: E402
import re007_json_identifier_reader_115 as tool  # noqa: E402

DATA = tool.base.TARGET.read_bytes()
IMAGE = tool.PatchedImage(DATA)
_, RECS, _ = fde_extents.fde_extents(DATA)
BY_START = {r['start']: r for r in RECS}


def prepared():
    out = {}
    for va, kind, pool in tool.BODIES:
        rows = tool.linear(IMAGE, va, BY_START[va]['end'])
        stubs, _ = tool.bind_stubs(rows, kind, va)
        leas = [r.rm[4] for r in rows if r.op == 'lea' and r.rm[5]]
        out[va] = (kind, leas[0], leas[1] if kind == 'value' else 0, stubs, rows)
    return out


PREP = prepared()


def outcome(va, buf, pos=0, image=IMAGE, spec=None):
    kind, pool, exp, stubs, _ = PREP[va]
    got, _ = tool.run_case(image, va, stubs, kind, buf, pos)
    want = tool.recon(kind, buf, pos, pool, spec or tool.Spec(expected=exp))
    return got, want


class DecoderTests(unittest.TestCase):
    def test_target_digest(self):
        self.assertEqual(hashlib.sha256(DATA).hexdigest(), tool.SHA115)

    def test_neg_and_bt_decode(self):
        neg = tool.decode(IMAGE, 0x1e20215)
        self.assertEqual((neg.op, neg.size, neg.rm, neg.length), ('neg', 8, ('reg', 1), 3))
        bt = tool.decode(IMAGE, 0x1e20232)
        self.assertEqual((bt.op, bt.size, bt.reg, bt.rm, bt.length), ('bt', 8, 8, ('reg', 7), 4))

    def test_neg_flags(self):
        mc = tool.Machine(IMAGE, {})
        mc.regs[1] = 5
        self.assertEqual(tool.decode(IMAGE, 0x1e20215).op, 'neg')
        mc.setflags(0, 8)
        mc.put(('reg', 1), (-5) & tool.MASK, 8)
        self.assertEqual(mc.regs[1], tool.MASK - 4)

    def test_unmodelled_bt_form_rejected(self):
        patched = tool.PatchedImage(DATA, {0x1e20234: 0x00})  # modrm now mod=00
        with self.assertRaises(tool.Reject):
            tool.decode(patched, 0x1e20232)

    def test_bodies_are_fde_starts_with_expected_sizes(self):
        sizes = {va: BY_START[va]['end'] - va for va, _, _ in tool.BODIES}
        self.assertEqual(sizes, {0x1e201f0: 376, 0x3fba8b0: 376, 0x1def7c0: 487, 0x3f7fe90: 487})

    def test_mid_function_address_is_not_an_fde(self):
        self.assertNotIn(0x1e201f1, BY_START)
        self.assertNotIn(0x1e20200, BY_START)

    def test_wrong_digest_rejected(self):
        with self.assertRaises(tool.Reject):
            tool.build(DATA[:-1] + bytes([DATA[-1] ^ 1]))


class StringModelTests(unittest.TestCase):
    def test_plain_and_escapes(self):
        self.assertEqual(tool.json_str(b'abc"x', 0), ('ok', b'abc', 4, False))
        self.assertEqual(tool.json_str(b'a\\u0041\\n"', 0), ('ok', b'aA\n', 10, True))

    def test_errors(self):
        self.assertEqual(tool.json_str(b'abc', 0), ('err', 'eof', 3))
        self.assertEqual(tool.json_str(b'a\x01"', 0), ('err', 'ctrl', 1))
        self.assertEqual(tool.json_str(b'\\q"', 0), ('err', 'esc', 1))
        self.assertEqual(tool.json_str(b'\\u00zz"', 0), ('err', 'esc', 1))
        self.assertEqual(tool.json_str(b'\\u0100"', 0), ('err', 'unicode', 1))
        self.assertEqual(tool.json_str(b'\\', 0), ('err', 'eof', 1))


class ReaderTests(unittest.TestCase):
    def check(self, buf, pos=0):
        for va in PREP:
            got, want = outcome(va, buf, pos)
            self.assertEqual(got, want, (hex(va), buf, pos))
        return got

    def test_every_name_in_both_positions(self):
        for idx, name in enumerate(tool.NAMES):
            v = outcome(0x1e201f0, b' "' + name + b'"')[0]
            self.assertEqual((v[0], v[1], v[2]), (idx, tool.DATA_BASE, len(name) + 3))
            k = outcome(0x1def7c0, b'"' + name + b'" :')[0]
            self.assertEqual((k[0], k[1], k[2]), (idx, tool.DATA_BASE, len(name) + 4))
            self.check(b'"' + name + b'":')

    def test_key_requires_colon(self):
        got = outcome(0x1def7c0, b'"normal";')[0]
        self.assertEqual((got[0], got[1] & 0xff), (3, 6))
        got = outcome(0x3f7fe90, b'"normal"')[0]
        self.assertEqual((got[0], got[1] & 0xff), (3, 3))

    def test_eof_codes_differ_by_reader(self):
        self.assertEqual(outcome(0x1e201f0, b'')[0][1] & 0xff, 5)
        self.assertEqual(outcome(0x3fba8b0, b'  ')[0][1] & 0xff, 5)
        self.assertEqual(outcome(0x1def7c0, b'')[0][1] & 0xff, 3)
        self.assertEqual(outcome(0x3f7fe90, b' ')[0][1] & 0xff, 3)

    def test_key_reader_brace_and_other_codes(self):
        self.assertEqual(outcome(0x1def7c0, b'}')[0][1] & 0xff, 0xa)
        self.assertEqual(outcome(0x1def7c0, b'1')[0][1] & 0xff, 0x11)
        self.assertEqual(outcome(0x3f7fe90, b'\x0b"')[0][1] & 0xff, 0x11)

    def test_value_reader_invalid_type_uses_its_own_expected_pool(self):
        got = outcome(0x1e201f0, b'7')[0]
        self.assertEqual(got[4][0], ('invalid', 0x6424020))
        got = outcome(0x3fba8b0, b'7')[0]
        self.assertEqual(got[4][0], ('invalid', 0x647f218))

    def test_unknown_name_reports_the_text_and_pool(self):
        got = outcome(0x1e201f0, b'"Normal"')[0]
        self.assertEqual(got[4][1], ('unknown', b'Normal', 0x643e188, 3))
        got = outcome(0x3fba8b0, b'"x"')[0]
        self.assertEqual(got[4][1], ('unknown', b'x', 0x6475de0, 3))

    def test_parse_error_finish_differs(self):
        v = outcome(0x1e201f0, b'"abc')[0]
        self.assertEqual([e[0] for e in v[4]], ['parse'])
        k = outcome(0x1def7c0, b'"abc')[0]
        self.assertEqual([e[0] for e in k[4]], ['parse', 'finish'])

    def test_start_positions_and_range(self):
        for pos in (0, 1, 5, 20, tool.MASK, 1 << 63):
            self.check(b' "noCross" :', pos)

    def test_escaped_name_matches(self):
        self.assertEqual(outcome(0x1e201f0, b'"\\u006eormal"')[0][0], 0)
        self.assertEqual(outcome(0x1def7c0, b'"no\\/Cross":')[0][0], 3)

    def test_first_byte_sweep(self):
        for b in range(256):
            self.check(bytes([b]) + b'normal":')

    def test_whitespace_runs(self):
        for ws in (b'\t', b'\n', b'\r', b' ', b'\x0b', b'\x0c', b' \t\r\n', b'\x00 '):
            self.check(ws + b'"strictIsolated"' + ws + b':')

    def test_name_mutations(self):
        for n in tool.NAMES:
            for p in range(len(n)):
                for v in (0, 0x20, 0x7f, 0xff, n[p] ^ 1):
                    self.check(b'"' + n[:p] + bytes([v]) + n[p + 1:] + b'":')

    def test_scratch_word_cleared_only_on_string_path(self):
        self.assertEqual(outcome(0x1e201f0, b'"normal"')[0][3], 0)
        self.assertEqual(outcome(0x1e201f0, b'7')[0][3], tool.SENT)


class NegativeTests(unittest.TestCase):
    def mismatches(self, spec_kw, inputs):
        n = 0
        for va in PREP:
            exp = PREP[va][2]
            for buf, pos in inputs:
                got, want = outcome(va, buf, pos, spec=tool.Spec(**{'expected': exp, **spec_kw}))
                n += got != want
        return n

    def test_mutated_reconstructions_are_caught(self):
        inputs = [(b'"normal":', 0), (b'"noCross" :', 0), (b'"strictIsolated"', 0), (b' \x0b"normal":', 0),
                  (b'"x":', 0), (b'', 0), (b'}', 0), (b'"abc', 0), (b'"normal";', 0), (b'7', 0), (b'"normal"', 0),
                  (b'"Normal":', 0), (b'"normalx":', 0), (b'\t\r"normal" \t:', 0)]
        for kw in (dict(ws=frozenset((9, 10, 13, 32, 0x0b))), dict(ws=frozenset((9, 10, 32))), dict(classify='prefix'),
                   dict(classify='swap'), dict(classify='casefold'), dict(eof_value=3), dict(finish_unknown=False),
                   dict(clear_scratch=False), dict(brace_code=0x11), dict(colon_code=5), dict(skip_after_name=False),
                   dict(finish_parse_error_key=False), dict(colon=0x3b)):
            self.assertGreater(self.mismatches(kw, inputs), 0, kw)

    def test_unmutated_spec_has_no_mismatch_on_the_same_inputs(self):
        self.assertEqual(self.mismatches({}, [(b'"normal":', 0), (b'}', 0), (b'"x"', 0)]), 0)

    def test_unknown_spec_field_rejected(self):
        with self.assertRaises(tool.Reject):
            tool.Spec(nonsense=1)

    def test_damaged_code_bytes_are_caught(self):
        battery = [(b'"normal":', 0), (b'"noCross":', 0), (b'"strictIsolated":', 0), (b' \t"normal":', 0), (b'x', 0),
                   (b'"x":', 0), (b'', 0)]
        for va, (kind, pool, exp, stubs, rows) in PREP.items():
            for label, addr, new in tool.damage_sites(rows):
                if label.startswith('bound_guard'):
                    continue
                bad = tool.PatchedImage(DATA, {addr: new})
                hit = 0
                for buf, pos in battery + [(b' "normal":', 0), (b'"noCross"', 0)]:
                    try:
                        got, _ = tool.run_case(bad, va, stubs, kind, buf, pos)
                        hit += got != tool.recon(kind, buf, pos, pool, tool.Spec(expected=exp))
                    except tool.Reject:
                        hit += 1
                self.assertGreater(hit, 0, (hex(va), label))

    def test_bound_guard_damage_is_an_equivalent_mutant(self):
        for va, (kind, pool, exp, stubs, rows) in PREP.items():
            label, addr, new = tool.damage_sites(rows)[2]
            self.assertTrue(label.startswith('bound_guard'))
            bad = tool.PatchedImage(DATA, {addr: new})
            for b in range(256):
                buf = bytes([b]) + b'normal":'
                got, _ = tool.run_case(bad, va, stubs, kind, buf, 0)
                self.assertEqual(got, tool.recon(kind, buf, 0, pool, tool.Spec(expected=exp)))

    def test_unmodelled_callee_is_rejected(self):
        kind, pool, exp, stubs, rows = PREP[0x1e201f0]
        short = {k: v for k, v in stubs.items() if v is not tool.stub_unknown}
        with self.assertRaises(tool.Reject):
            tool.run_case(IMAGE, 0x1e201f0, short, kind, b'"x"', 0)

    def test_family_scan_finds_nine_bodies(self):
        rows, scanned = tool.family_scan(IMAGE, RECS)
        self.assertEqual([hex(r[0]) for r in rows],
                         ['0x1def7c0', '0x1e201f0', '0x1fa4630', '0x1fac540', '0x3945390', '0x394a4e0', '0x3f7fe90',
                          '0x3fba8b0', '0x567f110'])
        self.assertGreater(scanned, 50000)


class PacketTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = tool.build(DATA)
        cls.files = tool.render(cls.result)

    def test_every_case_matches_and_counts(self):
        s = self.result['summary']
        self.assertTrue(s['reconstruction_matches_all'])
        self.assertGreaterEqual(s['cases'], 10000)
        self.assertGreaterEqual(s['negative_controls'], 30)
        self.assertEqual(s['negative_detected'], s['negative_controls'])

    def test_measure_json_matches_summary(self):
        s = self.result['summary']
        self.assertEqual(json.loads(self.files['measure.json']),
                         dict(cases=s['cases'], negative_controls=s['negative_controls'],
                              negative_detected=s['negative_detected']))

    def test_case_sample_is_every_fourth_row(self):
        total = self.result['summary']['cases']
        self.assertLessEqual(len(self.result['cases']), total // 4 + 4)
        self.assertNotIn('MISMATCH', self.files['cases.tsv'])

    def test_no_paths_or_times_in_outputs(self):
        for name, text in self.files.items():
            for root in ('home', 'mnt', 'srv', 'tmp'):
                self.assertNotIn('/' + root + '/', text, name)

    def test_main_writes_the_same_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(tool.main(['--out', tmp]), 0)
            for name, text in self.files.items():
                self.assertEqual((Path(tmp) / name).read_bytes(), text.encode('ascii'), name)

    def test_damage_table_lists_equivalent_guard(self):
        guards = [r for r in self.result['damage'] if r[1].startswith('bound_guard')]
        self.assertEqual(len(guards), 4)
        self.assertTrue(all(r[5] == 0 for r in guards))


if __name__ == '__main__':
    unittest.main()
