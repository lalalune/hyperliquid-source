import hashlib
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools' / 're010_content_map_seq_visitors_115.py'
PACKET = ROOT / 'research' / 'work-items' / 'RE-010-content-map-seq-visitors-115'

spec = importlib.util.spec_from_file_location('re010_content_map_seq_visitors_115', TOOL)
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)

DATA = t.BINARY.read_bytes()
IMG = t.Image(DATA)
FNS = t.load_fns(IMG)
BASE = {k: t.base_cases(k, huge=False) for k in t.KINDS}


class ContentVisitorTest(unittest.TestCase):
    def test_digest_is_checked(self):
        bad = bytearray(DATA[:4096])
        with self.assertRaises(ValueError):
            t.Image(bytes(bad))

    def test_copies_share_layout_and_roles(self):
        for kind, fl in FNS.items():
            anchor = fl[0]
            for f in fl:
                self.assertEqual(f.end - f.start, t.KINDS[kind]['size'])
                self.assertEqual(len(f.insns), len(anchor.insns))
                self.assertEqual(sorted(set(f.role.values())), sorted(set(anchor.role.values())))
            self.assertEqual(len({f.targets['read'] for f in fl}), 3)

    def test_not_a_function_start_is_rejected(self):
        with self.assertRaises(t.Fault):
            t.Fn(IMG, 'map', t.KINDS['map']['funcs'][0] + 1)
        with self.assertRaises(t.Fault):
            t.Fn(IMG, 'map', t.KINDS['seq']['funcs'][0])
        with self.assertRaises(t.Fault):
            t.Fn(IMG, 'seq', t.KINDS['map']['funcs'][1], FNS['seq'][0])

    def test_every_copy_matches_the_reconstruction(self):
        for kind, fl in FNS.items():
            sample = BASE[kind][::3] + t.throw_cases(IMG, fl[0], BASE[kind][::41])
            for f in fl:
                bad, insns, _ = t.compare(IMG, f, sample)
                self.assertEqual(bad, [], hex(f.start))
                self.assertGreater(len(insns), 120)

    def test_wrong_models_are_rejected(self):
        for kind, vs in (('map', ('map_niche_is_entry', 'map_err_keeps_key', 'cleanup_reverse', 'pad_zero')),
                         ('seq', ('clamp_half', 'seq_niche_stops', 'no_free_on_err', 'ok_tag_swapped'))):
            sample = BASE[kind] + t.throw_cases(IMG, FNS[kind][0], BASE[kind][::29])
            for v in vs:
                bad, _, _ = t.compare(IMG, FNS[kind][0], sample, v)
                self.assertTrue(bad, v)

    def test_corrupted_images_are_rejected(self):
        for kind in t.KINDS:
            sample = BASE[kind] + t.throw_cases(IMG, FNS[kind][0], BASE[kind][::7])
            for m in t.IMAGE_MUTANTS[kind][::4]:
                self.assertGreater(t.run_mutant(IMG, FNS[kind][0], m, sample), 0, m[3])

    def test_evidence_rows_regenerate(self):
        rows = (PACKET / 'cases.tsv').read_text().splitlines()[1:]
        for kind, fl in FNS.items():
            m = t.Machine(IMG, fl[0])
            mine = [r for r in rows if r.startswith(kind + '\t')]
            for n in range(0, 200, 13):
                c = BASE[kind][n]
                r = m.run(c)
                want = '\t'.join([kind, str(n)] + t.case_row(c) +
                                 [r[0], r[1], t.calls_text(r[2]), r[3], ','.join(r[4]) or '-'])
                self.assertEqual(mine[n], want)

    def test_manifest(self):
        for line in (PACKET / 'MANIFEST.sha256').read_text().splitlines():
            h, name = line.split('  ', 1)
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), h, name)


if __name__ == '__main__':
    unittest.main()
