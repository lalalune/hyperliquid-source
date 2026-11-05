import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import re010_action_type_matcher_115 as tm  # noqa: E402

PACKET = ROOT / 'research' / 'work-items' / 'RE-010-action-type-matcher-115'


class ActionTypeMatcherTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = tm.BINARY.read_bytes()
        cls.img = tm.Image(cls.data)
        cls.names = cls.img.variants(tm.COPIES[0][3])

    def machine(self, index=0, img=None):
        copy = tm.COPIES[index]
        return tm.Machine(img or self.img, copy, {})

    def test_digest_mismatch_rejected(self):
        bad = bytearray(self.data)
        bad[-1] ^= 1
        with self.assertRaises(ValueError):
            tm.Image(bytes(bad))

    def test_variants_slice(self):
        self.assertEqual(len(self.names), 92)
        self.assertEqual(self.names[0], b'noop')
        self.assertEqual(self.names[91], b'cDeposit2')
        self.assertEqual(self.img.variants(tm.COPIES[1][3]), self.names)

    def test_every_name_maps_to_its_index_in_both_copies(self):
        for c in range(len(tm.COPIES)):
            m = self.machine(c)
            for i, n in enumerate(self.names):
                self.assertEqual(m.run(n), ('ok', i))

    def test_negative_inputs_reach_unknown_variant(self):
        m = self.machine()
        for s in (b'', b'Noop', b'noopAction', b'cancel\0', b'ORDER', b'a' * 41, b'VoteGlobal', b'hip3Deploy'):
            self.assertEqual(m.run(s), ('unknown', None))
            self.assertEqual(m.calls, [('unknown_variant', tm.COPIES[0][4])])

    def test_bcmp_path_used_for_long_names(self):
        m = self.machine()
        long_names = [n for n in self.names if len(n) == 40]
        self.assertTrue(long_names)
        self.assertEqual(m.run(long_names[0])[0], 'ok')
        self.assertTrue(any(c[0] in ('bcmp', 'memcmp') for c in m.calls))

    def test_reconstruction_rejects_mutants(self):
        cases = tm.build_cases(self.names)
        m = self.machine()
        truth = [(s, m.run(s)) for _, s in cases[:400]] + [(s, m.run(s)) for _, s in cases[-60:]]
        for name, fn in tm.MUTANTS.items():
            with self.subTest(mutant=name):
                self.assertTrue(any(fn(s, self.names) != got for s, got in truth))
        self.assertTrue(all(tm.reconstructed_match(s, self.names) == got for s, got in truth))

    def test_corrupted_compare_constant_diverges(self):
        # Flip the last immediate byte of the `noop` dword compare.
        buf = bytearray(self.data)
        buf[self.img.off(0x2ba1b1a + 5)] ^= 0x01
        mut = tm.Image.__new__(tm.Image)
        mut.data, mut.secs, mut.by_name = bytes(buf), self.img.secs, self.img.by_name
        mut.relative, mut.symbolic = self.img.relative, self.img.symbolic
        self.assertEqual(self.machine(0, mut).run(b'noop'), ('unknown', None))

    def test_out_of_range_start_faults(self):
        # Entering at the `noop` arm skips the three pushes, so the epilogue pops past the frame.
        bad = ('X', 0x2ba1b1a, 0x2ba2bde, 0x644cc40, 0x17fbba0)
        with self.assertRaises(tm.Fault):
            tm.Machine(self.img, bad, {}).run(b'noop')
        with self.assertRaises(tm.Fault):
            tm.coverage_sweep(self.img, 0x2ba1af0, 0x2ba2bde + 1)

    def test_packet_files_regenerate_byte_identical(self):
        with tempfile.TemporaryDirectory() as tmp:
            summary = tm.generate(tmp)
            for c in summary['copies']:
                self.assertEqual(c['mismatches'], 0)
                self.assertEqual(c['unexecuted'], [])
                self.assertTrue(c['success_stores_one_to_one'])
            self.assertEqual(summary['mutants']['killed'], summary['mutants']['total'])
            self.assertEqual(summary['image_mutants']['killed'], summary['image_mutants']['total'])
            produced = sorted(p.name for p in Path(tmp).iterdir())
            committed = sorted(p.name for p in PACKET.iterdir() if p.name not in ('README.md', 'MANIFEST.sha256'))
            self.assertEqual(produced, committed)
            for name in produced:
                self.assertEqual((Path(tmp) / name).read_bytes(), (PACKET / name).read_bytes(), name)

    def test_summary_shape(self):
        s = json.loads((PACKET / 'summary.json').read_text())
        self.assertEqual(s['binary_sha256'], tm.SHA256)
        self.assertEqual([c['start'] for c in s['copies']], ['0x2ba1af0', '0x3662730'])


if __name__ == '__main__':
    unittest.main()
