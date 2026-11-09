import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
spec = importlib.util.spec_from_file_location('open_order_threshold_115', ROOT / 'tools' / 'open_order_threshold_115.py')
T = importlib.util.module_from_spec(spec)
sys.modules['open_order_threshold_115'] = T
spec.loader.exec_module(T)

DATA = (ROOT / T.BINARY).read_bytes()
FDES = T.Fdes(DATA)
CTX = T.Context(DATA, FDES)
SAMPLE = 300


class Setup(unittest.TestCase):
    def test_digest_is_node_115(self):
        self.assertEqual(T.check_digest(DATA), 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301')

    def test_damaged_binary_is_refused(self):
        bad = bytearray(DATA)
        bad[1000] ^= 1
        with self.assertRaises(T.EvidenceError):
            T.check_digest(bytes(bad))

    def test_every_function_decodes_to_its_fde_end(self):
        for fn in [c['entry'] for c in T.COPIES] + list(T.HELPERS):
            lo, hi = CTX.ranges[fn]
            last = CTX.lists[fn][-1]
            self.assertEqual(last.va + last.size, hi, hex(fn))
            self.assertEqual(CTX.lists[fn][0].va, lo)

    def test_copy_sizes(self):
        self.assertEqual([len(CTX.lists[c['entry']]) for c in T.COPIES], [245, 245])
        self.assertEqual(CTX.ranges[0x5495210][1] - 0x5495210, 1121)
        self.assertEqual(CTX.ranges[0x5495680][1] - 0x5495680, 1121)

    def test_copies_differ_only_in_displacements(self):
        rows = T.copy_diff_rows(CTX)
        self.assertEqual(len(rows), 3)
        text = ' '.join(r[4] + ' ' + r[5] for r in rows)
        for needle in ('0x968', '0x14d8', '0x7d0', '0x1340', '0x7c8', '0x1338'):
            self.assertIn(needle, text)

    def test_predicate_lists_eight_addresses(self):
        self.assertEqual(len(CTX.addresses), 8)
        self.assertEqual(len(set(CTX.addresses)), 8)
        self.assertTrue(all(len(a) == 20 for a in CTX.addresses))

    def test_lazy_defaults_are_zero_words(self):
        for name, lz in CTX.lazies.items():
            self.assertTrue(all(w == 0 for _, w in lz['words']), name)

    def test_division_proof(self):
        proof = T.division_proof()
        self.assertTrue(proof['holds'])
        self.assertEqual(proof['odd_divisor'], 1953125)
        for x in (0, 1, T.CAP_STEP - 1, T.CAP_STEP, T.CAP_STEP + 1, 4001 * T.CAP_STEP, T.U64):
            self.assertEqual(((x >> 8) * T.MAGIC) >> T.MAGIC_SHIFT, x // T.CAP_STEP)


class Cases(unittest.TestCase):
    def test_machine_matches_model_on_a_sample(self):
        for ci, copy in enumerate(T.COPIES):
            for i, v in enumerate(T.vectors(CTX, ci, SAMPLE)):
                self.assertIsNone(T.mismatch(CTX, copy, v), (copy['name'], i))

    def test_vectors_are_deterministic(self):
        a = [repr(v) for v in T.vectors(CTX, 0, 40)]
        b = [repr(v) for v in T.vectors(CTX, 0, 40)]
        self.assertEqual(a, b)
        self.assertNotEqual(a, [repr(v) for v in T.vectors(CTX, 1, 40)])

    def test_sample_reaches_pass_reject_and_panic(self):
        heads = set()
        for ci in range(2):
            for v in T.vectors(CTX, ci, 400):
                heads.add(T.model(v, CTX)['head'])
        self.assertEqual(heads, {T.HEAD_PASS, T.HEAD_REJECT, 'panic'})

    def test_events_include_hashes_once_and_records(self):
        kinds = set()
        for v in T.vectors(CTX, 0, 1500):
            kinds.update(e[0] for e in T.model(v, CTX)['events'])
        self.assertEqual(kinds, {'hash', 'once', 'record'})

    def test_handmade_limit_edges(self):
        copy = T.COPIES[0]
        key = bytes(range(1, 21))
        base = dict(key=key, kind=0, obj_b8=0, obj_a0=0, ord_19=2, ord_31=0, hash=(0x2a << 57) | 5,
                    lazy=dict(count=False, book=False, second=False), count_bad=False, books=[],
                    second_entries=[])
        for count, head in ((999, T.HEAD_PASS), (1000, T.HEAD_REJECT), (1001, T.HEAD_REJECT)):
            v = dict(base, count_entries=[(key, {0x28: count})])
            self.assertEqual(T.evaluate(CTX, copy, v)['head'], head, count)
        scaled = dict(base, count_entries=[(key, {0x28: 5000})], second_entries=[(key, {0x40: 4001 * T.CAP_STEP, 0x48: 0})])
        self.assertEqual(T.evaluate(CTX, copy, scaled)['head'], T.HEAD_REJECT)
        scaled['count_entries'] = [(key, {0x28: 4999})]
        self.assertEqual(T.evaluate(CTX, copy, scaled)['head'], T.HEAD_PASS)
        exempt = dict(base, key=CTX.addresses[3], count_entries=[(CTX.addresses[3], {0x28: 9999})])
        self.assertEqual(T.evaluate(CTX, copy, exempt)['head'], T.HEAD_PASS)
        exempt['count_entries'] = [(CTX.addresses[3], {0x28: 10000})]
        self.assertEqual(T.evaluate(CTX, copy, exempt)['head'], T.HEAD_REJECT)


class Negative(unittest.TestCase):
    def vecs(self):
        return list(T.vectors(CTX, 0, 2500))

    def test_wrong_readings_are_caught(self):
        vecs = self.vecs()
        hot = []
        for name, change in T.WRONG_SPECS:
            if name in ('flagged bound 9999', 'step 5e8 plus one'):
                continue
            spec = dict(T.SPEC)
            spec.update(change)
            self.assertIsNotNone(T.killed_by(CTX, T.COPIES[0], vecs, None, hot, None, spec), name)

    def test_correct_reading_is_not_caught(self):
        self.assertIsNone(T.killed_by(CTX, T.COPIES[0], self.vecs()[:600], None, [], None, dict(T.SPEC)))

    def test_branch_flip_in_the_threshold_is_caught(self):
        vecs = self.vecs()
        code = CTX.code[0x5495210]
        for va in (0x54955c8, 0x5495282, 0x549528b, 0x54952b2):
            ins = code[va]
            self.assertTrue(ins.op[0] == 'j', hex(va))
            new = dict(code)
            new[va] = T.patched_insn(ins, T.flip_raw(ins))
            self.assertIsNotNone(T.killed_by(CTX, T.COPIES[0], vecs, new, []), hex(va))

    def test_constant_changes_are_caught(self):
        vecs = self.vecs()
        code = CTX.code[0x5495210]
        wanted = {0x3e8: 0, 0x2710: 0}
        for ins in CTX.lists[0x5495210]:
            got = T.imm_mutation(ins)
            if got and ins.va in (0x54955c1, 0x5495334):
                new = dict(code)
                new[ins.va] = T.patched_insn(ins, got[0])
                self.assertIsNotNone(T.killed_by(CTX, T.COPIES[0], vecs, new, []), hex(ins.va))
                wanted[0x3e8] += 1
        self.assertEqual(wanted[0x3e8], 2)

    def test_corrupted_predicate_address_is_caught(self):
        patched = T.Context(DATA, FDES, {0x454410: CTX.img.read(0x454410, 1)[0] ^ 0x5a})
        self.assertIsNotNone(T.killed_by(patched, T.COPIES[0], self.vecs(), None, [], CTX))

    def test_corrupted_sentinel_constant_is_caught(self):
        patched = T.Context(DATA, FDES, {0x453b70: CTX.img.read(0x453b70, 1)[0] ^ 0x5a})
        self.assertIsNotNone(T.killed_by(patched, T.COPIES[0], self.vecs(), None, [], CTX))

    def test_out_of_domain_inputs_are_refused(self):
        img = T.Image(DATA)
        with self.assertRaises(T.EvidenceError):
            FDES.range_of(0x5495211)
        with self.assertRaises(T.EvidenceError):
            T.decode_range(img, 0x5495210, 0x5495210 + 1120)
        with self.assertRaises(T.EvidenceError):
            img.read(0x10, 4)
        with self.assertRaises(T.EvidenceError):
            img.relative(0x64e71a9)

    def test_control_rows_report_a_survivor_honestly(self):
        rows = T.range_controls(DATA, FDES)
        self.assertTrue(all(hit for _, hit in rows))


if __name__ == '__main__':
    unittest.main()
