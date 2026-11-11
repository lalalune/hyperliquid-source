import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import re010_action_msgpack_struct_any_115 as T  # noqa: E402

FOLDER = ROOT / 'research' / 'work-items' / 'RE-010-action-msgpack-struct-any-115'


class StructAnyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = T.BINARY.read_bytes()
        cls.img = T.Image(cls.data)
        cls.copies = [T.Copy(cls.img, label, start) for label, start in T.COPIES]
        for c in cls.copies:
            c.bind_consts(cls.copies[0])
        cls.cases = T.build_cases()

    def test_digest_is_checked(self):
        bad = bytearray(self.data)
        bad[0x1000] ^= 0xff
        with self.assertRaises(ValueError):
            T.Image(bytes(bad))

    def test_copies_share_one_shape(self):
        base = self.copies[0]
        self.assertEqual(len(base.insns), 531)
        for c in self.copies[1:]:
            self.assertEqual([T.shape(i) for i in c.insns], [T.shape(i) for i in base.insns])
            self.assertEqual([a - c.start for a in c.marker_arms], [a - base.start for a in base.marker_arms])
            self.assertEqual([a - c.start for a in c.ext_arms], [a - base.start for a in base.ext_arms])
        self.assertEqual(base.by_role['visit_map'], 0x1fb1750)
        self.assertEqual(base.by_role['visit_seq'], 0x1fb1d20)

    def test_marker_table_groups(self):
        base = self.copies[0]
        groups = {}
        for t, a in enumerate(base.marker_arms):
            groups.setdefault(a, []).append(t)
        any_arm = base.marker_arms[0xc0]
        self.assertEqual(set(groups[any_arm]), T.ANY_TAGS)
        self.assertEqual(len(groups), 17)
        self.assertEqual(len(groups[base.marker_arms[0x01]]), 188)  # non-Marker tags -> ud2

    def test_not_an_fde_start_is_rejected(self):
        with self.assertRaises(T.Fault):
            T.Copy(self.img, 'X', 0x1b38991)

    def test_sampled_cases_match_on_every_copy(self):
        sample = self.cases[::11]
        _, bad, _ = T.compare(self.img, self.copies, sample)
        self.assertEqual(bad, [])
        self.assertGreater(len(sample), 2000)

    def test_rare_rules_match(self):
        sample = [c for c in self.cases if c[0][:1] in (b'\x81', b'\x93', b'\xdd', b'\xd4', b'\xc7') and c[2] >= 0xfffe]
        _, bad, _ = T.compare(self.img, self.copies[:1], sample)
        self.assertEqual(bad, [])
        kinds = {T.reconstructed_any(*c)[0][0] for c in sample}
        self.assertTrue({'panic_add', 'length_mismatch', 'callee_err', 'callee_out'} <= kinds, kinds)

    def test_model_mutants_are_killed(self):
        want = [T.reconstructed_any(*c) for c in self.cases]
        for v in T.MODEL_MUTANTS:
            with self.subTest(variant=v):
                self.assertTrue(any(T.reconstructed_any(*c, variant=v) != w for c, w in zip(self.cases, want)))

    def test_image_mutants_change_outcomes(self):
        base = self.copies[0]
        firsts = (b'\xc4', b'\xc1', b'\xdc', b'\xc8')
        sample = [c for c in self.cases if c[1] is None and c[0][:1] in firsts][:600]
        self.assertEqual({c[0][:1] for c in sample}, set(firsts))
        rows, bad, _ = T.compare(self.img, [base], sample)
        self.assertEqual(bad, [])
        for va in (base.marker_va + 4 * 0xc1, base.marker_va + 4 * 0xc4, base.marker_va + 4 * 0xdc,
                   base.ext_va + 4 * (0xc8 - T.EXT_TABLE_LO)):
            with self.subTest(site=hex(va)):
                self.assertIsNotNone(T.run_mutant(self.data, self.img, base, va, sample, rows))

    def test_wrong_visitor_or_consts_are_detected(self):
        case = (b'\x81', None, 2, 0, (T.OK, 1, None))
        got = T.Machine(self.img, self.copies[0]).run(case)
        self.assertEqual(got, T.reconstructed_any(*case, consts=self.copies[0].consts))
        self.assertEqual(got[0], ('length_mismatch', 0))
        other = dict(self.copies[0].consts, static_eof=0x641ccb8)
        eof = (b'', None, 2, 0, (T.OK, None, None))
        self.assertNotEqual(T.Machine(self.img, self.copies[0]).run(eof), T.reconstructed_any(*eof, consts=other))

    def test_packet_manifest_and_summary(self):
        manifest = (FOLDER / 'MANIFEST.sha256').read_text().splitlines()
        names = set()
        for line in manifest:
            digest, name = line.split('  ', 1)
            names.add(name)
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)
        self.assertEqual(names, {p.name for p in FOLDER.iterdir() if p.name != 'MANIFEST.sha256'})
        summary = json.loads((FOLDER / 'summary.json').read_text())
        self.assertEqual(summary['binary_sha256'], T.SHA256)
        self.assertEqual(summary['mismatches'], 0)
        self.assertEqual(summary['cases'], len(self.cases))
        killed, total = summary['model_mutants_killed'].split('/')
        self.assertEqual(killed, total)


if __name__ == '__main__':
    unittest.main()
