import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import re010_tagged_content_visitor_115 as t  # noqa: E402

PACKET = ROOT / 'research' / 'work-items' / 'RE-010-tagged-content-visitor-115'


class TaggedContentVisitorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = t.BINARY.read_bytes()
        cls.img = t.Image(cls.data)
        cls.fns, cls.anchors = [], {}
        for row in t.FUNCS:
            f = t.Fn(cls.img, row, cls.anchors.get(row[0]))
            cls.anchors.setdefault(row[0], f)
            cls.fns.append(f)
        cls.cases = t.all_cases(huge=False)

    def test_digest_is_checked(self):
        bad = bytearray(self.data)
        bad[0x1000] ^= 1
        with self.assertRaises(ValueError):
            t.Image(bytes(bad))

    def test_copies_share_layout_and_call_sites(self):
        for f in self.fns:
            self.assertEqual(f.end - f.start, 1230 if f.form == 'map' else 294)
        m = self.anchors['map']
        self.assertEqual(len(m.sites), 15)
        self.assertEqual(m.site_of(m.start + 0xfd), (m.start + 0x45b, 0))     # key read -> drop the vec
        self.assertEqual(m.site_of(m.start + 0x16c), (m.start + 0x44c, 0))    # value read -> drop the key too
        self.assertEqual(m.site_of(m.start + 0x1bc), (m.start + 0x437, 0))    # grow -> drop the pending pair
        self.assertIsNone(m.site_of(m.start + 0x43))                          # allocation has no call site
        self.assertEqual(self.anchors['seq'].lsda, 0)

    def test_corrupted_copy_is_not_a_layout_copy(self):
        bad = bytearray(self.data)
        bad[self.img.off(0x3952ed0 + 0x21)] ^= 0x01    # cmp $0x4000 immediate in the second copy
        img = t.Image(bytes(bad), check=False)
        with self.assertRaises(t.Fault):
            t.Fn(img, t.FUNCS[1], t.Fn(img, t.FUNCS[0]))

    def test_wrong_display_formatter_is_rejected(self):
        row = t.FUNCS[1][:4] + (t.FUNCS[0][4],)
        with self.assertRaises(t.Fault):
            t.Fn(self.img, row)

    def test_all_copies_match_reconstruction(self):
        sample = self.cases[::3]
        for f in self.fns:
            bad, edges, insns = t.compare(self.img, f, sample)
            self.assertEqual(bad, [], hex(f.start))

    def test_outcome_kinds_reached(self):
        kinds = {t.reconstructed(c, c['form'])[0] for c in self.cases}
        self.assertEqual(kinds, {'ret', 'resume', 'escape', 'terminate', 'alloc_error', 'no_call_site'})

    def test_grow_after_cautious_capacity(self):
        ok, thrown, twice = t.huge_cases()
        f = self.anchors['map']
        m = t.Machine(self.img, f)
        got = m.run(ok)
        self.assertEqual(got, t.reconstructed(ok, 'map'))
        self.assertIn('grow', [c[0] for c in got[2]])
        self.assertEqual(int.from_bytes(bytes.fromhex(got[1])[0x28:0x30], 'little'), t.CAUTIOUS_CAP + 1)
        self.assertEqual(m.run(thrown), t.reconstructed(thrown, 'map'))
        self.assertEqual(m.run(twice)[0], 'terminate')

    def test_wrong_models_are_rejected(self):
        for v in t.MODEL_VARIANTS:
            hits = []
            for f in (self.anchors['map'], self.anchors['seq']):
                hits += t.compare(self.img, f, self.cases, v)[0]
            self.assertTrue(hits, v)

    def test_image_mutants_are_rejected(self):
        for f in (self.anchors['map'], self.anchors['seq']):
            sites = t.image_sites(f)
            picks = [s for s in sites if any(k in s[2] for k in (' 0x16', ' 0x17', ' 0x5c', ' 0x15', ' 0x4000', ' 0x9'))]
            self.assertTrue(picks)
            for s in picks:
                res = t.run_image_mutant(self.data, self.img, f, s, self.cases)
                self.assertNotEqual(res, 'survived', s[2])

    def test_packet_summary(self):
        s = json.loads((PACKET / 'summary.json').read_text())
        self.assertEqual(s['binary_sha256'], t.SHA256)
        self.assertEqual(s['mismatches'], 0)
        self.assertEqual(s['model_mutants'][0], s['model_mutants'][1])
        self.assertNotIn('survived', s['image_mutants'])


if __name__ == '__main__':
    unittest.main()
