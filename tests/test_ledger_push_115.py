import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import ledger_push_115 as t  # noqa: E402

WORK = ROOT / 'research' / 'work-items' / 'fees-ledger-push-115'
_CACHE = {}


def loaded():
    if not _CACHE:
        data = (ROOT / t.BINARY).read_bytes()
        t.check_digest(data)
        img = t.Image(data)
        fdes = t.Fdes(img)
        code, extents = t.decode_subjects(img, fdes)
        _CACHE.update(data=data, img=img, fdes=fdes, code=code, extents=extents)
    return _CACHE


def first_cases(per_group):
    seen, out = {}, []
    for group, fn, c in t.case_stream():
        seen[group] = seen.get(group, 0) + 1
        if seen[group] <= per_group:
            out.append((group, fn, c))
    return out


def hand_case(shape, hash_, items_hashes, cap, growth=None, key=bytes(range(1, 21)), fail=()):
    table = t.RawTable(8)
    rows = []
    for k, h in enumerate(items_hashes):
        table.insert(h, k)
        rows.append(t.make_row(shape, bytes([k]) * shape['vsize'], h, bytes([0x40 + k]) * 20))
    return dict(table=table, growth=7 - len(items_hashes) if growth is None else growth, items=len(items_hashes),
                rows=rows, cap=cap, fail=fail, hash=hash_, key=key, value=bytes([0xa5]) * shape['vsize'],
                kind='vacant', nrows=len(items_hashes))


class Setup(unittest.TestCase):
    def setUp(self):
        self.s = loaded()


class DecoderTests(Setup):
    def test_digest_and_extents(self):
        self.assertEqual(hashlib.sha256(self.s['data']).hexdigest(), t.SHA256)
        for fn in t.SUBJECTS:
            lo, hi = self.s['extents'][fn]
            self.assertEqual(lo, fn)
            self.assertGreater(hi - lo, 150)

    def test_instruction_counts(self):
        counts = {fn: sum(1 for v in self.s['code'] if self.s['extents'][fn][0] <= v < self.s['extents'][fn][1])
                  for fn in t.SUBJECTS}
        self.assertEqual(counts, {t.S_PA: 253, t.S_PB: 265, t.S_EA: 40, t.S_EB: 37})

    def test_ud2_is_decoded_but_never_run(self):
        ins = t.decode_one(b'\x0f\x0b' + b'\x90' * 16, 0, 0x1000)
        self.assertEqual((ins.op, ins.size), ('ud2', 2))

    def test_unlisted_opcode_refused(self):
        with self.assertRaises(t.EvidenceError):
            t.decode_one(b'\x0f\x0a' + b'\x90' * 16, 0, 0x1000)

    def test_not_an_fde_start(self):
        with self.assertRaises(t.EvidenceError):
            t.decode_subjects_one(self.s['img'], self.s['fdes'], t.S_PA + 1)

    def test_bad_digest(self):
        with self.assertRaises(t.EvidenceError):
            t.check_digest(self.s['data'][:-1] + bytes([self.s['data'][-1] ^ 1]))


class ModelTests(unittest.TestCase):
    """Hand-computed answers, independent of the interpreter."""

    def test_bucket_arithmetic(self):
        self.assertEqual([t.full_cap(n) for n in (4, 8, 16, 32, 64)], [3, 7, 14, 28, 56])
        self.assertEqual([t.buckets_for(c) for c in (1, 3, 4, 7, 8, 14, 15, 29)], [4, 4, 8, 8, 16, 16, 32, 64])

    def test_push_into_empty_table(self):
        shape = t.SHAPE[t.S_PA]
        c = hand_case(shape, 0x2a << 57 | 5, [], 0)
        res = t.model_push(shape, c, [(0, shape['vsize'])])
        cap, rows, table, slot, h = res[1]
        self.assertEqual((res[0], cap, slot, len(rows)), ('ok', 1, 5, 1))
        self.assertEqual(table[1][5], 0x2a)
        self.assertEqual((table[3], table[4]), (6, 1))
        self.assertEqual(table[2][5], 0)

    def test_vector_growth_sequence(self):
        shape = t.SHAPE[t.S_PB]
        caps = []
        for n in range(0, 8):
            c = hand_case(shape, 1 << 57 | n, [1 << 57 | k for k in range(n)], n)
            caps.append(t.model_push(shape, c, [(0, shape['vsize'])])[1][0])
        self.assertEqual(caps, [1, 2, 4, 6, 8, 10, 12, 14])

    def test_full_budget_resizes_table(self):
        shape = t.SHAPE[t.S_PA]
        c = hand_case(shape, 3, [i for i in range(7)], 7, growth=0)
        res = t.model_push(shape, c, [(0, shape['vsize'])])
        self.assertEqual(res[1][2][0], 16)
        self.assertEqual(res[1][2][3], 14 - 8)

    def test_items_overflow_panics(self):
        shape = t.SHAPE[t.S_PA]
        c = hand_case(shape, 3, [], 0)
        c['items'] = t.U64
        self.assertEqual(t.model_push(shape, c, [(0, 0xe0)]), ('panic', t.LOC_ITEMS_OVERFLOW))

    def test_alloc_failure_paths(self):
        shape = t.SHAPE[t.S_PB]
        one = hand_case(shape, 3, [1, 2, 3], 3, fail=(1,))
        self.assertEqual(t.model_push(shape, one, [(0, 0x50)])[1][0], 4)
        both = hand_case(shape, 3, [1, 2, 3], 3, fail=(1, 2))
        self.assertEqual(t.model_push(shape, both, [(0, 0x50)]), ('panic', ('alloc', 4 * 0x70, 8)))
        exact = hand_case(shape, 3, [1], 1, fail=(1,))
        self.assertEqual(t.model_push(shape, exact, [(0, 0x50)]), ('panic', ('alloc', 2 * 0x70, 8)))

    def test_default_values(self):
        a, b = t.default_value(t.S_EA), t.default_value(t.S_EB)
        self.assertEqual((len(a), len(b)), (0xe0, 0x50))
        self.assertEqual(int.from_bytes(a[0x88:0x90], 'little'), 8)
        self.assertEqual(int.from_bytes(a[0xa8:0xb0], 'little'), 8)
        self.assertEqual(int.from_bytes(b[0x08:0x10], 'little'), 8)
        self.assertEqual(int.from_bytes(b[0x28:0x30], 'little'), 8)
        self.assertEqual(sum(a) + sum(b), 32)

    def test_occupied_bounds(self):
        c = dict(kind='occupied', index=4, nrows=4)
        self.assertEqual(t.model_entry(t.S_EA, c), ('panic', t.LOC_BOUNDS_ENTRY))
        self.assertEqual(t.model_entry(t.S_EB, dict(c, index=3)), ('ok', 3))


class InterpreterTests(Setup):
    def check(self, cases):
        for group, fn, c in cases:
            obs, _ = t.observe(self.s['img'], self.s['code'], fn, c)
            self.assertTrue(t.agree(fn, obs, t.expected(fn, c)), (group, obs[:2]))

    def test_first_vectors_match_model(self):
        self.check(first_cases(120))

    def test_hand_case_runs_on_bytes(self):
        for fn in (t.S_PA, t.S_PB):
            shape = t.SHAPE[fn]
            c = hand_case(shape, 0x2a << 57 | 5, [0x11 << 57 | 1, 0x12 << 57 | 2], 2)
            obs, _ = t.run_push(self.s['img'], self.s['code'], fn, c)
            self.assertEqual(obs[0], 'ok')
            self.assertEqual(obs[2][0], 4)
            self.assertEqual(obs[2][3], 5)

    def test_rehash_stub_is_reached(self):
        n = 0
        for _, fn, c in first_cases(400):
            if fn in t.SHAPE and c['growth'] == 0 and c['items'] != t.U64 and not c['fail']:
                _, m = t.observe(self.s['img'], self.s['code'], fn, c)
                n += m.rehash
        self.assertGreater(n, 5)

    def test_entry_vacant_arm_pushes_default_value(self):
        shape = t.SHAPE[t.S_PA]
        c = hand_case(shape, 0x33 << 57 | 6, [0x11 << 57 | 1], 4)
        obs, _ = t.run_entry(self.s['img'], self.s['code'], t.S_EA, c)
        self.assertEqual((obs[0], obs[2][3]), ('ok', 1))
        row = obs[2][1][1]
        self.assertEqual(int.from_bytes(row[0x88:0x90], 'little'), 8)


class NegativeTests(Setup):
    def test_every_wrong_model_is_caught(self):
        ctl = t.control_vectors()
        for name, fn, variant in t.wrong_models():
            caught = False
            for g, payload in ctl:
                if g != fn:
                    continue
                obs, _ = t.observe(self.s['img'], self.s['code'], g, payload)
                if not t.agree(g, obs, t.expected(g, payload, variant)):
                    caught = True
                    break
            self.assertTrue(caught, name)

    def test_byte_mutants_are_caught(self):
        ctl = [x for x in t.control_vectors()][::5]
        muts = t.mutant_list(self.s['code'], self.s['extents'])
        self.assertGreater(len(muts), 80)
        caught = 0
        for name, patch, va in muts[::6]:
            img = t.Image(self.s['data'], patch)
            fn = next(f for f, (lo, hi) in self.s['extents'].items() if lo <= next(iter(patch)) < hi)
            lo, hi = self.s['extents'][fn]
            try:
                fresh = t.decode_range(img, lo, hi)
            except t.EvidenceError:
                caught += 1
                continue
            c2 = {v: i for v, i in self.s['code'].items() if not lo <= v < hi}
            c2.update({i.va: i for i in fresh})
            if t.detects(img, c2, ctl, {fn} | {e for e, p in t.PUSH_OF.items() if p == fn}):
                caught += 1
        self.assertGreaterEqual(caught, len(muts[::6]) - 3)

    def test_patched_image_fails_selfcheck(self):
        for va, val in ((0x3ec8cbd, 0x38), (0x3ec8cdd, 2), (0x3ec7c6f, 0x60)):
            with self.assertRaises((t.EvidenceError, t.Unmodelled)):
                t.selfcheck(t.Image(self.s['data'], {va: val}), self.s['fdes'])

    def test_stale_rows_list_is_refused(self):
        with self.assertRaises(IndexError):
            t.stale_case()

    def test_bad_allocation_arguments_are_refused(self):
        shape = t.SHAPE[t.S_PA]
        m = t.new_machine(self.s['img'], self.s['code'], shape)
        m.regs[t.R['r8']], m.regs[t.R['r9']] = 4, 0x100
        with self.assertRaises(t.Unmodelled):
            m.stubs[t.FINISH_GROW]()


class EvidenceFiles(unittest.TestCase):
    def test_measure_and_manifest(self):
        if not WORK.exists():
            self.fail('work item folder missing')
        m = json.loads((WORK / 'measure.json').read_text())
        self.assertEqual(m['cases'], 10600)
        self.assertEqual(m['negative_controls'], m['negative_detected'])
        self.assertGreaterEqual(m['negative_controls'], 30)
        for line in (WORK / 'MANIFEST.sha256').read_text().splitlines():
            digest, name = line.split('  ')
            self.assertEqual(hashlib.sha256((WORK / name).read_bytes()).hexdigest(), digest, name)

    def test_evidence_matches_subjects(self):
        e = json.loads((WORK / 'evidence.json').read_text())
        self.assertEqual(e['sha256'], t.SHA256)
        self.assertEqual(e['vectors'], 10600)
        self.assertEqual(e['subjects']['push_a'], [hex(t.S_PA), '0x3ec8f88'])
        self.assertEqual(e['mutants']['detected'] + e['mutants']['survivors'], e['mutants']['listed'])


if __name__ == '__main__':
    unittest.main()
