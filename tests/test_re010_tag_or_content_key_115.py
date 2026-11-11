import hashlib
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools' / 're010_tag_or_content_key_115.py'
PACKET = ROOT / 'research' / 'work-items' / 'RE-010-tag-or-content-key-115'

spec = importlib.util.spec_from_file_location('re010_tag_or_content_key_115', TOOL)
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)

DATA = t.BINARY.read_bytes()
IMG = t.Image(DATA)
ANCHOR = t.Fn(IMG, t.FUNCS[0])
FNS = [ANCHOR] + [t.Fn(IMG, s, ANCHOR) for s in t.FUNCS[1:]]
BASE = t.base_cases()


class KeyReaderTest(unittest.TestCase):
    def test_digest_is_checked(self):
        bad = bytearray(DATA[:4096])
        with self.assertRaises(ValueError):
            t.Image(bytes(bad))

    def test_copies_share_layout_and_roles(self):
        for f in FNS:
            self.assertEqual(f.end - f.start, t.SIZE)
            self.assertEqual(len(f.insns), len(ANCHOR.insns))
            self.assertEqual(sorted(set(f.role.values())), sorted(set(ANCHOR.role.values())))
            self.assertEqual(f.table_rows(IMG), ANCHOR.table_rows(IMG))

    def test_not_a_function_start_is_rejected(self):
        with self.assertRaises(t.Fault):
            t.Fn(IMG, t.FUNCS[0] + 1)
        with self.assertRaises(t.Fault):
            t.Fn(IMG, t.CALLERS[0], ANCHOR)

    def test_every_copy_matches_the_reconstruction(self):
        sample = BASE[::4] + t.throw_cases(IMG, ANCHOR, BASE[::97])
        for f in FNS:
            bad, insns, _ = t.compare(IMG, f, sample)
            self.assertEqual(bad, [], hex(f.start))
            self.assertGreater(len(insns), 500)

    def test_wrong_models_are_rejected(self):
        for v in ('depth_le1', 'str_err_is_str', 'fresh_data_full', 'no_consume_short_len', 'nil_is_unit'):
            bad, _, _ = t.compare(IMG, ANCHOR, BASE, v)
            self.assertTrue(bad, v)

    def test_corrupted_images_are_rejected(self):
        picks = [m for m in t.IMAGE_MUTANTS if m[0] in (0x1a7e22b, 0x1a7e3fc, 0x1a7e7a6) or m[1] == 'swap'][:5]
        self.assertEqual(len(picks), 5)
        for m in picks:
            self.assertGreater(t.run_mutant(IMG, ANCHOR, m, BASE), 0, m[3])

    def test_evidence_rows_regenerate(self):
        m = t.Machine(IMG, ANCHOR)
        rows = (PACKET / 'cases.tsv').read_text().splitlines()[1:]
        self.assertEqual(len(rows), len(BASE))
        for n in range(0, len(BASE), 37):
            c = BASE[n]
            r = m.run(c)
            want = '\t'.join([str(n)] + t.case_row(c) + [r[0], r[1], t.calls_text(r[2]), r[3]])
            self.assertEqual(rows[n], want)

    def test_manifest(self):
        for line in (PACKET / 'MANIFEST.sha256').read_text().splitlines():
            h, name = line.split('  ', 1)
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), h, name)


if __name__ == '__main__':
    unittest.main()
