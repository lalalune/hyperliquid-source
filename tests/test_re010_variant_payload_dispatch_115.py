import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import re010_variant_payload_dispatch_115 as t  # noqa: E402

FOLDER = ROOT / 'research' / 'work-items' / 'RE-010-variant-payload-dispatch-115'
DATA = t.BINARY.read_bytes()
IMG = t.Image(DATA)
SPEC = t.parse_spec(t.SPEC)
FNS = {row[0]: t.Fn(IMG, row) for row in t.FUNCS}


def compare(fn, cases, spec=SPEC, variant=None, img=IMG):
    m = t.Machine(img, fn)
    bad = 0
    for case in cases:
        got = t.run_machine(m, case)
        bad += got != t.reconstructed(spec, (fn.label, fn.start, 0, fn.frame, fn.ident, fn.n, fn.err), case, variant)
    return bad


class Static(unittest.TestCase):
    def test_digest_is_checked(self):
        bad = bytearray(DATA[:4096])
        with self.assertRaises(ValueError):
            t.Image(bytes(bad))

    def test_functions_and_tables(self):
        want = {'F18': (0x5f8978, 18), 'F18R': (0x5f8898, 18), 'E114A': (0x5f8f88, 114), 'E114B': (0x5f9150, 114)}
        for label, fn in FNS.items():
            self.assertEqual((fn.table_va, fn.n), want[label])
            self.assertEqual(len(fn.arms), fn.n)
            self.assertTrue(all(a in fn.cache for a in fn.arms))
            self.assertEqual(len(SPEC[label]), fn.n)

    def test_wrong_fde_size_is_rejected(self):
        row = list(t.FUNCS[0])
        row[2] += 1
        with self.assertRaises(t.Fault):
            t.Fn(IMG, tuple(row))

    def test_wrong_frame_is_rejected(self):
        row = list(t.FUNCS[2])
        row[3] = 0x28
        with self.assertRaises(t.Fault):
            t.Fn(IMG, tuple(row))

    def test_marker_decomposition(self):
        self.assertEqual(t.decompose_marker(0x05), (0x00, 0x05))
        self.assertEqual(t.decompose_marker(0x8f), (0x80, 0x0f))
        self.assertEqual(t.decompose_marker(0x93), (0x90, 0x03))
        self.assertEqual(t.decompose_marker(0xbf), (0xa0, 0x1f))
        self.assertEqual(t.decompose_marker(0xcc), (0xcc, 0x0c))
        self.assertEqual(t.decompose_marker(0xf0), (0xe0, 0xf0))

    def test_spec_order_is_checked(self):
        with self.assertRaises(ValueError):
            t.parse_spec('F18 1 | * ; 18bf310~sp+8~-~-~-~- ; E')


class Behaviour(unittest.TestCase):
    def test_f18_and_f18r_all_cases_match_with_full_coverage(self):
        for label in ('F18', 'F18R'):
            fn = FNS[label]
            cases = t.build_cases(SPEC, fn)
            rows, bad, cover, edges = t.compare(SPEC, IMG, fn, cases)
            self.assertEqual(bad, 0, label)
            self.assertEqual(cover & set(fn.cache), set(fn.cache), label)
            conds = [i.va for i in fn.insns if i.op == 'j']
            self.assertTrue(all((v, True) in edges and (v, False) in edges for v in conds), label)

    def test_e114_sampled_cases_match(self):
        for label in ('E114A', 'E114B'):
            fn = FNS[label]
            cases = t.build_cases(SPEC, fn)[::9]
            self.assertGreater(len(cases), 300)
            self.assertEqual(compare(fn, cases), 0, label)

    def test_wrong_models_are_caught(self):
        fn = FNS['F18R']
        cases = t.build_cases(SPEC, fn)
        for variant in t.MODEL_VARIANTS:
            self.assertGreater(compare(fn, cases, variant=variant), 0, variant)

    def test_wrong_spec_lines_are_caught(self):
        for label, name, old, new in t.SPEC_EDITS:
            self.assertEqual(t.SPEC.count(old), 1, name)
            fn = FNS[label]
            mspec = t.parse_spec(t.SPEC.replace(old, new))
            self.assertGreater(compare(fn, t.build_cases(SPEC, fn), spec=mspec), 0, name)

    def test_corrupted_image_is_caught(self):
        fn = FNS['F18']
        mut = bytearray(DATA)
        a, b = IMG.off(fn.table_va), IMG.off(fn.table_va + 4)
        mut[a:a + 4], mut[b:b + 4] = mut[b:b + 4], mut[a:a + 4]
        mimg = t.Image(bytes(mut), check=False)
        mfn = t.Fn(mimg, t.FUNCS[0])
        self.assertGreater(compare(mfn, t.build_cases(SPEC, fn), img=mimg), 0)
        mut = bytearray(DATA)
        disc = [i for i in fn.insns if i.op == 'mov' and i.b and i.b[0] == 'i' and i.b[1] == 0xd][0]
        mut[IMG.off(disc.va + disc.size - 4)] ^= 1
        mimg = t.Image(bytes(mut), check=False)
        self.assertGreater(compare(t.Fn(mimg, t.FUNCS[0]), t.build_cases(SPEC, fn), img=mimg), 0)


class Evidence(unittest.TestCase):
    def test_manifest_and_summary(self):
        lines = (FOLDER / 'MANIFEST.sha256').read_text().split('\n')
        rows = [ln.split('  ') for ln in lines if ln]
        self.assertEqual(sorted(r[1] for r in rows),
                         sorted(p.name for p in FOLDER.iterdir() if p.name != 'MANIFEST.sha256'))
        for digest, name in rows:
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)
        s = json.loads((FOLDER / 'summary.json').read_text())
        self.assertEqual(s['binary_sha256'], t.SHA256)
        self.assertEqual(s['mismatches'], 0)
        self.assertEqual(s['functions']['F18']['cases'], len(t.build_cases(SPEC, FNS['F18'])))
        self.assertEqual(s['image_mutants']['survived'], 0)
        self.assertEqual(s['model_mutants']['killed'], s['model_mutants']['total'])


if __name__ == '__main__':
    unittest.main()
