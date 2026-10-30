import importlib.util
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('fees_schedule_cancel_gate', ROOT / 'tools' / 'fees_schedule_cancel_gate.py')
T = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = T
spec.loader.exec_module(T)

PACKET = ROOT / 'research' / 'work-items' / 'fees-schedule-cancel-gate-94'
DATA = (ROOT / T.BINARY).read_bytes()
GATE = 0x2721260


def one_vector(pack):
    noon = T.milli(2026, 300, 43200)
    ce, secs, frac = T.civil(noon)
    return [('one', dict(base=T.HEAVY, now_date=pack(ce), now_secs=secs, now_frac=frac, vals={}, ms=noon + 5001))]


class Base(unittest.TestCase):
    def setUpClass(cls):
        cls.result, cls.img, cls.lists, cls.rows = T.analyse(DATA)
        cls.fdes = T.Fdes(cls.img)
        cls.code, _, _ = T.load_code(cls.img, cls.fdes)

    setUpClass = classmethod(setUpClass)

    def run_one(self, chain='a', **kw):
        noon = T.milli(2026, 300, 43200)
        ce, secs, frac = T.civil(noon)
        args = dict(base=T.HEAVY, now_date=T.pack_date(self.img, self.code, ce), now_secs=secs, now_frac=frac, vals={})
        args.update(kw)
        s = T.scenario(**args)
        got = T.evaluate(self.img, self.code, chain, s)
        self.assertEqual(T.compare(s, got, T.model(s)), [])
        return got, noon


class Identity(Base):
    def test_digest_is_pinned(self):
        self.assertEqual(self.result['sha256'], T.SHA256)

    def test_wrong_digest_fails(self):
        with self.assertRaises(T.EvidenceError):
            T.check_digest(DATA[:-1] + bytes([DATA[-1] ^ 1]))

    def test_every_listed_function_is_an_fde_start_and_decoding_lands_on_its_end(self):
        for row in self.result['functions'].values():
            start, end = int(row['start'], 16), int(row['end'], 16)
            insns = T.decode_range(self.img, start, end)
            self.assertEqual(len(insns), row['instructions'])
            self.assertEqual(insns[-1].va + insns[-1].size, end)

    def test_inner_address_is_not_an_fde_start(self):
        with self.assertRaises(T.EvidenceError):
            T.fde_of(self.fdes, GATE + 1)

    def test_out_of_range_address_is_refused(self):
        with self.assertRaises(T.EvidenceError):
            self.img.read(0x7fffffff0000, 8)
        with self.assertRaises(T.EvidenceError):
            self.fdes.range_of(0x10)

    def test_decoder_refuses_an_unlisted_opcode(self):
        with self.assertRaises(T.EvidenceError):
            T.decode_one(b'\x06' + b'\x90' * 16, 0, 0x1000)

    def test_wrong_decode_length_is_refused(self):
        with self.assertRaises(T.EvidenceError):
            T.decode_range(self.img, GATE, GATE + 7 + 1)

    def test_packet_files_match_a_fresh_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            T.write(Path(tmp), self.result, self.img, self.lists, self.rows)
            names = sorted(p.name for p in Path(tmp).iterdir())
            self.assertEqual(names, ['evidence.json', 'instructions.tsv', 'reference-diff.tsv', 'vectors.tsv'])
            for name in names:
                self.assertEqual((Path(tmp) / name).read_bytes(), (PACKET / name).read_bytes(), name)


class Facts(Base):
    def test_summary(self):
        s = self.result['summary']
        self.assertEqual(s['mismatches'], 0)
        self.assertEqual(s['evaluations'], 3 * s['vectors'])
        self.assertEqual(s['gate_instructions'], 344)
        self.assertEqual(s['gate_instructions_not_executed'], 2)

    def test_copies_differ_only_in_listed_operands(self):
        d = self.result['copy_comparison_against_a']
        self.assertEqual(d['b']['field_offset_instructions'], 0)
        self.assertEqual(d['c']['field_offset_instructions'], 7)
        self.assertEqual(sorted(x[0] for x in d['c']['field_offset_differences']), ['0x39a8', '0x39b0', '0x5c0', '0x5c8'])

    def test_messages(self):
        arms = self.result['error_arms']
        self.assertIn('at least 5 seconds', arms['0x10c']['text'])
        self.assertEqual(arms['0x10d']['pieces'][0], 'Too many scheduled cancels triggered for the day. Limit is ')
        self.assertEqual(arms['0x10e']['immediates_64'], ['0x412e848000000000'])
        self.assertEqual(T.b2f(0x412e848000000000), 1000000.0)
        self.assertEqual(self.result['constants']['count_message_argument'], 10)

    def test_locations_keep_no_build_root(self):
        for row in self.result['locations'].values():
            self.assertTrue(row['path'].startswith(('l1/src/', 'src/index.crates.io')), row['path'])

    def test_evidence_has_no_at_sign(self):
        self.assertNotIn('\x40', json.dumps(self.result))

    def test_unreached_code_is_only_the_listed_block(self):
        self.assertEqual(self.result['evaluation']['not_executed'][hex(GATE)], {'instructions': 2, 'non_padding': 2})


class Behaviour(Base):
    def test_five_seconds_is_the_boundary(self):
        got, noon = self.run_one(ms=T.milli(2026, 300, 43200) + 5000)
        self.assertEqual(got['tag'], T.TAG_EARLY)
        got, _ = self.run_one(ms=noon + 5001)
        self.assertEqual(got['result'], T.RESULT_OK)

    def test_five_days_is_not_the_boundary(self):
        got, _ = self.run_one(ms=T.milli(2026, 300, 43200) + 6000)
        self.assertEqual(got['result'], T.RESULT_OK)

    def test_threshold(self):
        got, _ = self.run_one(base=(T.THRESHOLD - 1, 0), ms=0, flag=0)
        self.assertEqual(got['tag'], T.TAG_VOLUME)
        self.assertEqual(struct.unpack('<d', got['payload'])[0], 999999.99)
        got, _ = self.run_one(base=(T.THRESHOLD, 0), ms=0, flag=0)
        self.assertEqual(got['result'], T.RESULT_OK)

    def test_overflow_saturates_and_passes_the_gate(self):
        got, _ = self.run_one(dex=((T.U64, 0),), base=(1, 0), flag=0)
        self.assertEqual(got['result'], T.RESULT_OK)
        self.assertEqual([e[1] for e in got['log'] if e[0] == 'hook'], [T.SCALED_LOCATION])

    def test_count_limit_is_ten_and_the_gate_does_not_count(self):
        for count, status in ((9, T.RESULT_OK), (10, T.RESULT_ERR)):
            noon = T.milli(2026, 300, 43200)
            vals = {T.ME: (count, 0, 0, 0)}
            got, _ = self.run_one(tree=[T.ME], vals=vals, ms=noon + 60000)
            self.assertEqual(got['result'], status)
            self.assertEqual(dict(got['map'])[T.ME][0], count)

    def test_clear_keeps_the_entry(self):
        vals = {T.ME: (3, 77, 5, 6)}
        got, _ = self.run_one(tree=[T.ME], vals=vals, flag=0)
        self.assertEqual(dict(got['map'])[T.ME], (3, 0, 5, 6))

    def test_date_dword_decodes_to_the_expected_day(self):
        ce = T.ce_from_civil(2024, 366)
        self.assertEqual(T.date_ce(T.pack_date(self.img, self.code, ce)), ce)

    def test_civil_round_trip(self):
        for ce in (1, 365, 366, 719163, T.MAX_CE):
            y, o = T.civil_from_ce(ce)
            self.assertEqual(T.ce_from_civil(y, o), ce)

    def test_model_comparison_notices_a_wrong_tag(self):
        got, noon = self.run_one(ms=T.milli(2026, 300, 43200) + 5001)
        s = T.scenario(base=T.HEAVY, ms=noon + 5001, now_date=1, vals={})
        want = T.model(dict(s, now_date=T.pack_date(self.img, self.code, T.civil(noon)[0]), now_secs=43200))
        want['result'] = T.RESULT_ERR
        self.assertTrue(T.compare(s, got, want))


class Mutants(unittest.TestCase):
    """Each patch flips one condition in copy a; the vectors of that copy must notice it."""

    CAUGHT = {
        'threshold_jae_to_ja': {0x27213b4: 0x87},
        'seconds_setae_to_seta': {0x272156b: 0x97},
        'nanos_jb_to_jbe': {0x2721576: 0x86},
        'count_jbe_to_jb': {0x2721780: 0x72},
        'saturation_cmovb_flip': {0x2721341: 0x43},
        'raw_not_to_neg': {0x2721375: 0xdf},
        'clear_writes_one': {0x2721713: 0x01},
        'seconds_field_moved': {0x2721793: 0x10},
        'wrapper_seta_to_setae': {0x1e5fc5e: 0x93},
        'threshold_immediate': {0x27213af: 0x01},
        'five_to_six': {0x27214ef: 0x06},
        'raw_then_low_jb_flip': {0x2721412: 0x73},
        'count_immediate': {0x272177a: 0x0a},
        'divisor_constant': {0x20a966: 0x5a},
    }

    def test_all_are_caught(self):
        for name, patch in self.CAUGHT.items():
            with self.subTest(name), self.assertRaises((T.EvidenceError, T.Unmodelled, T.Panic)):
                T.analyse(DATA, patch, chains=('a',))

    def test_second_raw_saturation_needs_its_own_vector(self):
        # Vectors alone must see this flip; the copy comparison would catch it too and hide a gap.
        img = T.Image(DATA, {0x272136f: 0x43})
        code, _, _ = T.load_code(img, T.Fdes(img))
        noon = T.milli(2026, 300, 43200)
        ce, secs, frac = T.civil(noon)
        s = T.scenario(base=(0, 1), dex=((0, T.U64), (0, 2)), flag=0, vals={}, now_date=T.pack_date(img, code, ce),
                       now_secs=secs, now_frac=frac)
        self.assertTrue(T.compare(s, T.evaluate(img, code, 'a', s), T.model(s)))

    def test_unpatched_small_run_passes(self):
        result, *_ = T.analyse(DATA, None, vectors=one_vector, chains=('a',))
        self.assertEqual(result['summary']['evaluations'], 1)


if __name__ == '__main__':
    unittest.main()
