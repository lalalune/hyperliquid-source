import csv
import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import fees_open_order_cap as T  # noqa: E402

FOLDER = ROOT / 'research/work-items/fees-open-order-cap-94'


class Base(unittest.TestCase):
    data = (ROOT / T.BINARY).read_bytes()
    fdes, ctx = T.build(data)
    vecs = T.vectors(ctx.addresses)
    flagged = frozenset(ctx.addresses)

    def vec(self, **kw):
        return T.vec(self.flagged, **kw)

    def patched(self, patches):
        return T.Context(self.data, self.fdes, patches)


class Digest(Base):
    def test_digest(self):
        self.assertEqual(T.check_digest(self.data), T.SHA256)

    def test_wrong_digest(self):
        with self.assertRaises(T.EvidenceError):
            T.check_digest(self.data[:-1] + bytes((self.data[-1] ^ 1,)))


class Decoder(Base):
    def test_every_copy_lands_on_its_fde_end(self):
        for c in T.COPIES:
            start, end = self.ctx.ranges[c['entry']]
            last = self.ctx.lists[c['entry']][-1]
            self.assertEqual(last.va + last.size, end)
            self.assertEqual(start, c['entry'])

    def test_short_range_fails(self):
        start, end = self.ctx.ranges[T.COPIES[0]['entry']]
        with self.assertRaises(T.EvidenceError):
            T.decode_range(self.ctx.img, start, end - 1)

    def test_unknown_function_fails(self):
        with self.assertRaises(T.EvidenceError):
            self.fdes.range_of(T.COPIES[0]['entry'] + 1)

    def test_address_outside_sections_fails(self):
        with self.assertRaises(T.EvidenceError):
            self.ctx.img.read(0x7000_0000_0000, 8)

    def test_bss_has_no_file_bytes(self):
        addr = self.ctx.img.sec['.bss'][0]
        with self.assertRaises(T.EvidenceError):
            self.ctx.img.read(addr + 16, 8)

    def test_gate_walk_stops_at_the_stop(self):
        for c in T.COPIES:
            gate = T.reachable(self.ctx.lists[c['entry']], self.ctx.code[c['entry']], c['stop'])
            self.assertNotIn(c['stop'], gate)
            self.assertIn(c['entry'], gate)

    def test_lookup_offsets_are_read_from_bytes(self):
        self.assertEqual(self.ctx.offsets[0x2755400], dict(items=0x758, ctrl=0x740, mask=0x748))
        self.assertEqual(self.ctx.offsets[0x46f2e60], dict(items=0x11d8, ctrl=0x11c0, mask=0x11c8))


class Constants(Base):
    def test_division_proof(self):
        self.assertTrue(T.division_proof()['holds'])

    def test_division_at_edges(self):
        for k in (0, 1, 2, 4000, 4001, 1 << 30, (1 << 64) // T.CAP_STEP):
            for d in (-1, 0, 1):
                x = k * T.CAP_STEP + d
                if 0 <= x <= T.U64:
                    self.assertEqual(((x >> 8) * T.MAGIC) >> T.MAGIC_SHIFT, x // T.CAP_STEP)

    def test_wrong_multiplier_is_seen(self):
        x = T.CAP_STEP
        self.assertNotEqual(((x >> 8) * (T.MAGIC - 1)) >> T.MAGIC_SHIFT, x // T.CAP_STEP)

    def test_text_of_the_reject_tag(self):
        self.assertEqual(T.too_many_text(self.ctx.img)[2], 'Too many open orders')

    def test_changed_display_arm_fails(self):
        arm = T.too_many_text(self.ctx.img)[0]
        with self.assertRaises(T.EvidenceError):
            T.too_many_text(T.Image(self.data, {arm: 0x90}))

    def test_address_list(self):
        self.assertEqual(len(self.ctx.addresses), 8)
        self.assertEqual(len(set(self.ctx.addresses)), 8)
        self.assertTrue(all(len(a) == 20 for a in self.ctx.addresses))

    def test_address_list_refuses_nonzero_upper_bytes(self):
        block = next(i for i in self.ctx.lists[T.FLAGGED] if i.op == 'pcmpeqb' and i.ops[0] == ('x', 1))
        img = T.Image(self.data, {block.ops[1][4] + 8: 1})
        with self.assertRaises(T.EvidenceError):
            T.address_table(self.ctx.lists[T.FLAGGED], img)

    def test_locations(self):
        self.assertEqual(T.location(self.ctx.img, T.LOC_SCALED)['file'], 'l1/src/scaled_vlm.rs')
        self.assertEqual(T.location(self.ctx.img, T.LOC_RAW)['line'], 17)

    def test_lazy_defaults_are_zero(self):
        for rows in self.ctx.default_words.values():
            self.assertTrue(all(val == 0 for _, val in rows))


class Model(Base):
    def outcome(self, **kw):
        return T.model(self.vec(**kw))[:2]

    def test_table(self):
        self.assertEqual(self.outcome(count=999, b19=0, b31=1), ('pass', None))
        self.assertEqual(self.outcome(count=1000, b19=0), ('reject', None))
        self.assertEqual(self.outcome(count=1000, b31=1), ('reject', None))
        self.assertEqual(self.outcome(count=1000), ('reject', 1000))
        self.assertEqual(self.outcome(count=1000, base=(T.CAP_STEP - 1, 0, 'direct')), ('reject', 1000))
        self.assertEqual(self.outcome(count=1000, base=(T.CAP_STEP, 0, 'direct')), ('pass', 1001))
        self.assertEqual(self.outcome(count=4999, base=(T.U64, 0, 'direct')), ('pass', 5000))
        self.assertEqual(self.outcome(count=5000, base=(T.U64, 0, 'direct')), ('reject', 5000))
        self.assertEqual(self.outcome(count=9999, user=self.ctx.addresses[0]), ('pass', 10000))
        self.assertEqual(self.outcome(count=10000, user=self.ctx.addresses[0]), ('reject', 10000))

    def test_recorder_routes(self):
        v = self.vec(count=1000, dex=((T.U64, 0, 'direct'),), base=(1, 0, 'direct'))
        self.assertIn(('record', T.LOC_SCALED), T.model(v)[3])
        v = self.vec(count=1000, dex=((T.U64, 0, 'direct'), (1, 0, 'direct')))
        self.assertIn(('record', T.LOC_DEX), T.model(v)[3])
        v = self.vec(count=1000, dex=((0, T.U64, 'direct'),), base=(0, 1, 'direct'))
        self.assertIn(('record', T.LOC_RAW), T.model(v)[3])


class Evaluate(Base):
    def test_sample_on_every_copy(self):
        for c in T.COPIES:
            for v in self.vecs[::29]:
                self.assertIsNone(T.mismatch(self.ctx, c, v))

    def test_reference_shape_gets_no_flagged_bound(self):
        user = bytes((1,)) + bytes(range(2, 20)) + bytes(1)
        for c in T.COPIES:
            v = self.vec(count=5000, user=user)
            self.assertIsNone(T.mismatch(self.ctx, c, v))
            self.assertEqual(T.evaluate(self.ctx, c, v)[0], 'reject')

    def test_low_bound_mutant(self):
        for c in T.COPIES:
            ins = next(i for i in self.ctx.lists[c['entry']] if i.op == 'cmp' and ('i', 0x3e8) in i.ops)
            ctx = self.patched({ins.va + ins.size - 4: 0xe9})
            self.assertIsNotNone(T.mismatch(ctx, c, self.vec(count=1000, b19=0)))

    def test_flagged_bound_mutant(self):
        c = T.COPIES[0]
        ins = next(i for i in self.ctx.lists[c['entry']] if i.op == 'mov' and ('i', 0x2710) in i.ops)
        ctx = self.patched({ins.va + ins.size - 4: 0x11})
        self.assertIsNotNone(T.mismatch(ctx, c, self.vec(count=10000, user=self.ctx.addresses[0])))

    def test_tag_mutant(self):
        c = T.COPIES[0]
        ins = next(i for i in self.ctx.lists[c['entry']] if i.op == 'mov' and ('i', 0xc3) in i.ops)
        ctx = self.patched({ins.va + ins.size - 2: 0xc2})
        self.assertIn('reject tag', T.mismatch(ctx, c, self.vec(count=1000)))

    def test_address_byte_mutant(self):
        c = T.COPIES[0]
        block = next(i for i in self.ctx.lists[T.FLAGGED] if i.op == 'pcmpeqb' and i.ops[0] == ('x', 0))
        ctx_img = T.Image(self.data, {block.ops[1][4]: 0})
        fresh = dict(self.ctx.__dict__)
        ctx = T.Context.__new__(T.Context)
        ctx.__dict__.update(fresh)
        ctx.img = ctx_img
        self.assertIsNotNone(T.mismatch(ctx, c, self.vec(count=9999, user=self.ctx.addresses[0])))

    def test_every_branch_flip_of_one_copy_on_a_small_set(self):
        c = T.COPIES[0]
        code = self.ctx.code[c['entry']]
        gate = T.reachable(self.ctx.lists[c['entry']], code, c['stop'])
        hot = []
        for va in sorted(gate):
            ins = code[va]
            if ins.op[0] == 'j' and ins.op not in ('jmp', 'jmpr'):
                new = dict(code)
                new[va] = T.patched_insn(ins, T.flip_raw(ins))
                self.assertIsNotNone(T.killed_by(self.ctx, c, self.vecs, new, hot), hex(va))

    def test_written_arena_is_caught(self):
        c = T.COPIES[0]
        code = dict(self.ctx.code[c['entry']])
        # turn the attempts store into a store one word further on
        ins = next(i for i in self.ctx.lists[c['entry']] if i.op == 'mov' and i.ops[0][0] == 'm' and i.ops[0][4] == 0x888)
        raw = bytearray(ins.raw)
        raw[-4] = 0x90
        code[ins.va] = T.patched_insn(ins, raw)
        self.assertIsNotNone(T.mismatch(self.ctx, c, self.vec(count=999), code))


class Committed(Base):
    def test_manifest(self):
        rows = (FOLDER / 'MANIFEST.sha256').read_text(encoding='ascii').splitlines()
        self.assertGreaterEqual(len(rows), 7)
        for row in rows:
            digest, name = row.split('  ')
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_vectors_file_is_the_model(self):
        with open(FOLDER / 'vectors.tsv', encoding='ascii', newline='') as f:
            rows = list(csv.reader(f, delimiter='\t'))
        self.assertEqual(len(rows) - 1, len(self.vecs))
        for n, v in enumerate(self.vecs):
            self.assertEqual(rows[n + 1], [str(x) for x in T.vector_row(n, v)])

    def test_evidence_counts(self):
        ev = json.loads((FOLDER / 'evidence.json').read_text(encoding='ascii'))
        self.assertEqual(ev['evaluations'], ev['vectors'] * ev['copies'])
        self.assertEqual(ev['mismatches'], 0)
        self.assertEqual(ev['mutants']['killed'], ev['mutants']['total'])
        self.assertEqual(ev['gate_insns'], ev['gate_insns_executed'])
        self.assertEqual(ev['target']['sha256'], T.SHA256)

    def test_no_external_program(self):
        text = (ROOT / 'tools/fees_open_order_cap.py').read_text(encoding='ascii')
        self.assertNotIn('subprocess', text)
        self.assertNotIn('objdump', text.replace('no objdump, readelf or other', ''))


if __name__ == '__main__':
    unittest.main()
