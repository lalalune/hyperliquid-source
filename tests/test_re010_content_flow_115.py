import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('re010_content_flow_115', ROOT / 'tools' / 're010_content_flow_115.py')
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)
EVIDENCE = ROOT / 'research' / 'work-items' / 'RE-010-content-flow-115'


class FlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.img = t.Image(t.Path(t.BINARY).read_bytes())
        cls.sets = t.load_sets(cls.img)
        cls.prim = t.Prim(cls.img)
        cls.eofs = [(s['vr'].eof, s['ext'].eof) for s in cls.sets]

    def machine(self, si=0):
        return t.Machine(self.img, self.sets[si], self.prim)

    def run_all(self, buf, peek=None, depth=0x400, **kw):
        out = []
        for si in range(3):
            got, want = t.run_case(self.machine(si), t.case(buf, peek, depth, **kw), self.eofs[si])
            self.assertTrue(t.same(got, want), (si, got, want))
            out.append(got)
        for o in out[1:]:   # the sets agree on everything the original defines (stale error bytes differ)
            self.assertEqual(o[0], out[0][0])
            if o[0] == 'ret':
                self.assertEqual(o[1][0], out[0][1][0])
                if o[1][0] == 'ok':
                    self.assertEqual(o[1], out[0][1])
                self.assertEqual(o[2:], out[0][2:])
        return out[0]

    def test_digest_and_extents(self):
        self.assertEqual(hashlib.sha256(self.img.data).hexdigest(), t.SHA256)
        for si, fns in enumerate(self.sets):
            for kind, fn in fns.items():
                self.assertEqual(fn.start, t.SETS[si][kind])
                self.assertEqual(fn.end - fn.start, t.KINDS[kind]['size'])
        self.assertEqual(self.prim.end - self.prim.start, t.PRIM_SIZE)

    def test_call_graph_is_closed_per_set(self):
        for fns in self.sets:
            rows = t.closure_rows(self.img, fns)
            self.assertEqual(len(rows), 7)
            self.assertEqual({(r[0], r[2], r[3]) for r in rows},
                             {('vr', 'map', 'map'), ('vr', 'seq', 'seq'), ('vr', 'ext', 'ext'), ('vr', 'prim', 'prim'),
                              ('map', 'read', 'vr'), ('seq', 'read', 'vr'), ('map', 'read', 'vr')} |
                             {('vr', 'prim', 'prim')})

    def test_mixed_sets_are_rejected(self):
        with self.assertRaises(t.Fault):
            t.Machine(self.img, dict(self.sets[0], map=self.sets[1]['map']), self.prim)
        with self.assertRaises(t.Fault):
            t.Machine(self.img, dict(self.sets[2], seq=self.sets[0]['seq']), self.prim)

    def test_nested_map_of_seq(self):
        got = self.run_all(b'\x82\xa1a\x92\x01\x02\xa1b\xc3')
        self.assertEqual(got[1], ('ok', ('map', 2, ((('str', b'a'), ('seq', 2, (('u8', 1), ('u8', 2)))),
                                                    (('str', b'b'), ('bool', 1))))))
        self.assertEqual([e for e in got[2] if e[0] == 'alloc'], [('alloc', 128), ('alloc', 64)])
        self.assertEqual(got[3][4], 0x400)

    def test_ext_is_a_boxed_two_element_seq(self):
        got = self.run_all(b'\xd5\xfe\x09\x08')
        self.assertEqual(got[1], ('ok', ('newtype', ('seq', 4, (('i8', 0xfe), ('bytes', b'\x09\x08'))))))
        self.assertEqual(got[2], (('grow', 0, 0, 32), ('alloc', 32)))

    def test_depth_budget(self):
        one = self.run_all(b'\x91\x01', None, 1)       # budget 1 -> 0 on entry: error value, no visitor call
        self.assertEqual(one[1][0], 'err')
        self.assertEqual(one[2], ())
        self.assertEqual(one[3][4], 0)
        zero = self.run_all(b'\x91\x01', None, 0)      # nothing left: panic
        self.assertEqual(zero[0], 'unwind:panic_sub:vr')
        self.assertEqual(self.run_all(b'\x91\x01', None, 2)[3][4], 2)                 # success restores
        self.assertEqual(self.run_all(b'\x91\x92\x01', None, 5)[3][4], 3)            # map/seq error keeps the nested spend
        self.assertEqual(self.run_all(b'\xd4\x01', None, 5)[3][4], 5)                # ext error restores

    def test_clamp_and_cleanup(self):
        got = self.run_all(b'\xdd\xff\xff\xff\xff\x01\x02')
        self.assertEqual(got[1][0], 'err')
        self.assertEqual(got[2], (('alloc', 0x100000), ('drop', ('u8', 1)), ('drop', ('u8', 2)), ('free', 0x100000)))
        got = self.run_all(b'\xdf\xff\xff\xff\xff\x01')
        self.assertEqual(got[2][0], ('alloc', 0x100000))

    def test_failed_allocation_unwinds(self):
        got = self.run_all(b'\x91\x01', None, 5, fail_alloc=0)
        self.assertEqual(got, ('unwind:alloc_error:seq', (('alloc', 32), ('alloc_error', 8, 32))))

    def test_utf8_fallback_and_truncation(self):
        self.assertEqual(self.run_all(b'\xa3\xff\xfe\x41')[1], ('ok', ('bytes', b'\xff\xfeA')))
        self.assertEqual(self.run_all(b'\xa3\x61\x62\x63')[1], ('ok', ('str', b'abc')))
        self.assertEqual(self.run_all(b'\xa3\x61')[3][:2], (1, 1))      # the prefix is consumed, the payload not
        self.assertEqual(self.run_all(b'\xcd\x01')[3][:2], (2, 0))        # a short number swallows the rest
        self.assertEqual(self.run_all(b'\xc1')[1][0], 'err')

    def test_model_matches_sample_of_every_set(self):
        for si in range(3):
            m = self.machine(si)
            for j, c in enumerate(t.cases(si)):
                if j % 37 == 0:
                    got, want = t.run_case(m, c, self.eofs[si])
                    self.assertTrue(t.same(got, want), (si, j))

    def test_wrong_models_are_caught(self):
        allc = list(t.cases(0))
        sample = [c for j, c in enumerate(allc) if j % 11 == 0] + allc[-2:]
        m = self.machine(0)
        ran = [(c, t.run_case(m, c, self.eofs[0])[0]) for c in sample]
        for v in t.VARIANTS:
            caught = any(not t.same(got, t.reconstructed(c, self.eofs[0], v)) for c, got in ran
                         if self._safe(c, v))
            self.assertTrue(caught or v in self.SLOW, v)

    SLOW = ()

    def _safe(self, c, v):
        try:
            t.reconstructed(c, self.eofs[0], v)
            return True
        except (IndexError, KeyError, ValueError, struct.error, OverflowError, TypeError):
            return False

    def test_image_mutants_are_caught(self):
        sample = [c for j, c in enumerate(t.cases(0)) if j % 9 == 0][:600]
        for kind, offs in t.IMAGE_MUTANTS:
            for off in offs[:3]:
                self.assertTrue(t.run_mutant(self.img, self.sets[0], self.prim, kind, off, sample, self.eofs[0]),
                                (kind, off))

    def test_range_controls(self):
        for name, ok in t.range_controls(self.img, self.sets, self.prim, self.eofs[0]):
            self.assertTrue(ok, name)

    def test_rng_is_stable(self):
        self.assertEqual(hashlib.sha256(b''.join(t.DOCS)).hexdigest(), t.DOC_DIGEST)

    def test_committed_evidence_agrees(self):
        s = json.loads((EVIDENCE / 'summary.json').read_text())
        mj = json.loads((EVIDENCE / 'measure.json').read_text())
        self.assertEqual(s['mismatches'], 0)
        self.assertEqual(s['sha256'], t.SHA256)
        self.assertEqual((mj['cases'], mj['negative_controls'], mj['negative_detected']),
                         (s['cases'], s['negative_controls'], s['negative_detected']))
        self.assertEqual(s['negative_controls'], s['negative_detected'])
        self.assertGreaterEqual(s['cases'], 10000)
        self.assertGreaterEqual(s['negative_controls'], 30)

    def test_fixext_lengths_and_ext_forms(self):
        for sz, marker in enumerate((0xd4, 0xd5, 0xd6, 0xd7, 0xd8)):
            data = bytes(range(1, 1 + (1 << sz)))
            got = self.run_all(bytes([marker, 0x05]) + data)
            self.assertEqual(got[1], ('ok', ('newtype', ('seq', 4, (('i8', 5), ('bytes', data))))))
        for head in (b'\xc7\x03', b'\xc8\x00\x03', b'\xc9\x00\x00\x00\x03'):
            got = self.run_all(head + b'\x80abc')
            self.assertEqual(got[1], ('ok', ('newtype', ('seq', 4, (('i8', 0x80), ('bytes', b'abc'))))))
        self.assertEqual(self.run_all(b'\xc9\x00\x00')[1][0], 'err')       # short length consumes the rest

    def test_map_value_error_drops_the_key_first(self):
        got = self.run_all(b'\x81\xa1k\xc1')
        self.assertEqual(got[1][0], 'err')
        self.assertEqual(got[2], (('alloc', 64), ('utf8', 1), ('drop', ('str', b'k')), ('free', 64)))
        got = self.run_all(b'\x82\x01\x02\x03\xc1')
        self.assertEqual(got[2], (('alloc', 128), ('drop', ('u8', 3)), ('drop', ('u8', 1)), ('drop', ('u8', 2)),
                                  ('free', 128)))

    def test_peeked_discriminant_is_consumed_once(self):
        got = self.run_all(b'\x01\x02', (0x90, 2))
        self.assertEqual(got[1], ('ok', ('seq', 2, (('u8', 1), ('u8', 2)))))
        self.assertEqual(got[3][2:4], (1, 2))     # flag back to none, the data byte stays

    def test_error_survives_every_enclosing_level(self):
        got = self.run_all(b'\x91\x91\x91\x91\xca\x01')
        self.assertEqual(got[1][0], 'err')
        self.assertEqual(sum(1 for e in got[2] if e[0] == 'alloc'), 4)
        self.assertEqual(sum(1 for e in got[2] if e[0] == 'free'), 4)
        self.assertEqual(got[3][4], 0x400 - 4)

    def test_every_marker_byte_is_decoded(self):
        for b in range(256):
            got = self.run_all(bytes([b]) + b'\x01\x02\x03\x04\x05\x06\x07\x08\x09')
            self.assertIn(got[0], ('ret',))

    def test_case_generator_is_deterministic(self):
        first = [c['buf'] for c in t.cases(0)][:300]
        again = [c['buf'] for c in t.cases(0)][:300]
        self.assertEqual(first, again)
        self.assertEqual(len(list(t.cases(1))), len(list(t.cases(0))))
        self.assertGreater(len(list(t.cases(0))), 6000)


if __name__ == '__main__':
    unittest.main()
