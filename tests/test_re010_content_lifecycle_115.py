import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
sys.setrecursionlimit(30000)
import re010_content_lifecycle_115 as t  # noqa: E402

PACKET = ROOT / 'research' / 'work-items' / 'RE-010-content-lifecycle-115'


class LifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = Path(t.BINARY).read_bytes()
        cls.img = t.Image(cls.data)
        cls.prog = t.Prog(cls.img)
        cls.w = t.World(cls.prog)
        cls.cases = t.all_cases()

    def run_case(self, c, copy=0):
        return t.real_run(self.w, c, copy), t.model_run(c, copy)

    def test_function_extents(self):
        for k, size in (('vr', 2074), ('map', 1191), ('seq', 666), ('ext', 727), ('drop', 445), ('drop_result', 73)):
            for copy in t.COPIES:
                fn = self.prog.fn(copy[k])
                self.assertEqual(fn.end - fn.start, size, k)
        self.assertEqual(self.prog.fn(t.UTF8).end - t.UTF8, 503)
        self.assertEqual(self.prog.fn(t.PRIM).end - t.PRIM, 665)

    def test_stratified_real_equals_model(self):
        for copy in (0, 1, 2):
            for c in self.cases[::37]:
                got, want = self.run_case(c, copy)
                self.assertEqual(got, want, (copy, c['label'], c['buf'][:20].hex()))

    def test_sequence_allocation_and_drop(self):
        got, want = self.run_case(t.case(b'\x92\x01\xa2hi', 'x'))
        self.assertEqual(got, want)
        self.assertEqual(got[1], ('ok', ('seq', 2, [('u8', 1), ('str', b'hi')])))
        self.assertEqual(got[2], (('alloc', 64),))
        self.assertEqual(got[4], (('free', 64),))
        self.assertEqual(got[5], 0)

    def test_ext_is_boxed_sequence(self):
        got, want = self.run_case(t.case(b'\xd4\xfe\x07', 'x'))
        self.assertEqual(got, want)
        self.assertEqual(got[1], ('ok', ('nt', ('seq', 4, [('i8', -2), ('bytes', b'\x07')]))))
        self.assertEqual(got[2], (('alloc', 128), ('alloc', 32)))
        self.assertEqual(got[4], (('free', 128), ('free', 32)))

    def test_map_drops_key_then_value(self):
        got, want = self.run_case(t.case(b'\x81\x91\x01\x91\x02', 'x'))
        self.assertEqual(got, want)
        self.assertEqual(got[4], (('free', 32), ('free', 32), ('free', 64)))

    def test_error_cleanup_frees_everything(self):
        got, want = self.run_case(t.case(b'\x92\x91\x01\x91', 'x'))
        self.assertEqual(got, want)
        self.assertEqual(got[1][0], 'err')
        self.assertEqual(got[2][-2:], (('free', 32), ('free', 64)))
        self.assertEqual(got[5], 0)

    def test_staged_key_dropped_when_value_fails(self):
        got, want = self.run_case(t.case(b'\x81\x91\x01\xc1', 'x'))
        self.assertEqual(got, want)
        self.assertEqual(got[1], ('err', 2, 0xc1))
        self.assertEqual(got[2][-2:], (('free', 32), ('free', 64)))

    def test_alloc_failure_unwinds_without_leak(self):
        for k in range(3):
            got, want = self.run_case(t.case(b'\x92\x91\x01\x92\x02\x03', 'x', fail=k))
            self.assertEqual(got, want)
            self.assertEqual(got[0], 'escape')
            self.assertEqual(got[5], 0)
            self.assertIn(('alloc_error',), got[2])

    def test_depth_budget(self):
        got, want = self.run_case(t.case(b'\x91\x91\x91\x01', 'x', depth=3))
        self.assertEqual(got, want)
        self.assertEqual(got[1], ('err', 8, None))
        self.assertEqual(got[3][3], 0)
        got, want = self.run_case(t.case(b'\x91\x01', 'x', depth=0))
        self.assertEqual(got, want)
        self.assertEqual((got[0], got[2]), ('escape', (('panic_sub',),)))

    def test_depth_restored_only_on_success_and_ext(self):
        ok, _ = self.run_case(t.case(b'\x92\x91\x01\x01', 'x', depth=9))
        self.assertEqual(ok[3][3], 9)
        err, _ = self.run_case(t.case(b'\x91\x91', 'x', depth=9))
        self.assertEqual(err[3][3], 7)
        ext, _ = self.run_case(t.case(b'\xd4\x01', 'x', depth=9))
        self.assertEqual(ext[3][3], 9)

    def test_invalid_utf8_becomes_bytes(self):
        got, want = self.run_case(t.case(b'\xa2\xc3\x28', 'x'))
        self.assertEqual(got, want)
        self.assertEqual(got[1], ('ok', ('bytes', b'\xc3\x28')))

    def test_huge_declared_length_is_clamped(self):
        got, want = self.run_case(t.case(b'\xdd\xff\xff\xff\xff\x01', 'x'))
        self.assertEqual(got, want)
        self.assertEqual(got[2], (('alloc', 0x8000 * 32), ('free', 0x8000 * 32)))

    def test_from_utf8_matches_reference(self):
        for i, raw in enumerate(t.utf8_cases()):
            self.assertEqual(t.utf8_real(self.w, raw), t.utf8_model(raw), raw.hex())
            try:
                raw.decode('utf-8')
                self.assertIsNone(t.utf8_check(raw))
            except UnicodeDecodeError as e:
                self.assertEqual(t.utf8_check(raw)[0], e.start)

    def test_model_variants_are_detected(self):
        sample = t.mutation_sample()
        real = [t.real_run(self.w, c, 0) for c in sample]
        for v in t.VARIANTS:
            self.assertTrue(any(t.model_run(c, 0, v) != r for c, r in zip(sample, real)), v)

    def test_image_mutants_are_detected(self):
        sample = t.mutation_sample()
        exp = [t.model_run(c, 0) for c in sample]
        for f, off in t.IMAGE_MUTANTS[::5]:
            ins = self.prog.cache[f + off] if f + off in self.prog.cache else self.prog.fn(f) and self.prog.cache[f + off]
            w = t.World(t.Prog(t.flip_jcc(self.img, ins.va, ins)))
            self.assertTrue(any(t.real_run(w, c, 0) != e for c, e in zip(sample, exp)), (hex(f), off))

    def test_unmutated_image_is_not_flagged(self):
        sample = t.mutation_sample()[:60]
        self.assertTrue(all(t.real_run(self.w, c, 0) == t.model_run(c, 0) for c in sample))

    def test_range_controls_reject(self):
        for name, ok in t.range_controls(self.img, self.data):
            self.assertTrue(ok, name)

    def test_digest_is_enforced(self):
        bad = bytearray(self.data)
        bad[1000] ^= 0x40
        with self.assertRaises(ValueError):
            t.Image(bytes(bad))

    def test_committed_evidence_is_consistent(self):
        summary = json.loads((PACKET / 'summary.json').read_text())
        measure = json.loads((PACKET / 'measure.json').read_text())
        self.assertEqual(summary['sha256'], t.SHA256)
        self.assertEqual(summary['mismatches'], 0)
        self.assertEqual(summary['negative_controls'], summary['negative_detected'])
        self.assertGreaterEqual(summary['cases'], 10000)
        self.assertGreaterEqual(summary['negative_controls'], 30)
        for k in ('cases', 'negative_controls', 'negative_detected'):
            self.assertEqual(summary[k], measure[k])
        for line in (PACKET / 'MANIFEST.sha256').read_text().splitlines():
            digest, name = line.split('  ')
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), digest, name)


if __name__ == '__main__':
    unittest.main()
