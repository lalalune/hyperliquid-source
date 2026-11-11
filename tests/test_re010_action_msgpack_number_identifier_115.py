import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import re010_action_msgpack_number_identifier_115 as tool  # noqa: E402

PACKET = ROOT / 'research' / 'work-items' / 'RE-010-action-msgpack-number-identifier-115'


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = tool.BINARY.read_bytes()
        cls.img = tool.Image(cls.data)
        cls.copies = {c[0]: tool.Copy(cls.img, *c) for c in tool.COPIES}


class StaticFacts(Base):
    def test_digest_is_checked(self):
        bad = bytearray(self.data)
        bad[0x1000] ^= 1
        with self.assertRaises(ValueError):
            tool.Image(bytes(bad))

    def test_copies_share_one_shape(self):
        shapes = {lab: [tool.shape(i) for i in c.insns] for lab, c in self.copies.items()}
        self.assertEqual(len({tuple(s) for s in shapes.values()}), 1)
        self.assertEqual(len(self.copies['N2'].insns), 197)

    def test_variant_counts_and_identity_tables(self):
        got = {lab: c.n_variants for lab, c in self.copies.items()}
        self.assertEqual(got, {'N1': 79, 'N2': 92, 'N3': 16, 'N4': 114, 'N5': 18})
        for c in self.copies.values():
            self.assertEqual(c.index, list(range(c.n_variants)))
            self.assertEqual(c.expected_text, f'variant index 0 <= i < {c.n_variants}')
            self.assertEqual(c.eof_text, 'failed to fill whole buffer')

    def test_non_fde_start_is_rejected(self):
        with self.assertRaises(tool.Fault):
            tool.Copy(self.img, 'X', 0x33fc5f1, 0x64e3f30)

    def test_wrong_got_slot_is_rejected(self):
        with self.assertRaises(tool.Fault):
            tool.Copy(self.img, 'X', 0x33fc5f0, 0x64dff80)

    def test_cvtss2sd_bits_match_struct_for_ordinary_values(self):
        for b in (0x3f800000, 0xc0490fdb, 0x00000001, 0x007fffff, 0x7f7fffff, 0x80000000, 0x7f800000):
            want = struct.unpack('<Q', struct.pack('<d', struct.unpack('<f', struct.pack('<I', b))[0]))[0]
            self.assertEqual(tool.f32_to_f64_bits(b), want)
        self.assertEqual(tool.f32_to_f64_bits(0x7f800001), 0x7ff8000020000000)  # signalling NaN quieted


class Behaviour(Base):
    def run_n2(self, marker, data, inp, img=None, copy=None):
        m = tool.Machine(img or self.img, copy or self.copies['N2'])
        return m.run(marker, data, inp)

    def test_action_index_bounds(self):
        c = self.copies['N2']
        self.assertEqual(self.run_n2(0x00, 91, b''), (('ok', 91), 0))
        self.assertEqual(self.run_n2(0x00, 92, b''),
                         (('invalid_value', 'Unsigned', 92, 'variant_index_text'), 0))
        self.assertEqual(self.run_n2(0xcd, 0, b'\x00\x5b\x77'), (('ok', 0x5b), 2))
        self.assertEqual(self.run_n2(0xcf, 0, b'\x00' * 7 + b'\x5c'),
                         (('invalid_value', 'Unsigned', 0x5c, 'variant_index_text'), 8))
        self.assertEqual(self.run_n2(0xce, 0, b'\x01\x02'), (('eof', c.eof_err), 2))

    def test_type_errors(self):
        self.assertEqual(self.run_n2(0xe0, 0xff, b''), (('invalid_type', 'Signed', tool.MASK64, 'visitor'), 0))
        self.assertEqual(self.run_n2(0xd1, 0, b'\x80\x00'),
                         (('invalid_type', 'Signed', (-0x8000) & tool.MASK64, 'visitor'), 2))
        self.assertEqual(self.run_n2(0xc3, 0, b''), (('invalid_type', 'Bool', 1, 'visitor'), 0))
        self.assertEqual(self.run_n2(0xc0, 0, b''), (('invalid_type', 'Unit', None, 'visitor'), 0))
        self.assertEqual(self.run_n2(0xca, 0, b'\x3f\x80\x00\x00'),
                         (('invalid_type', 'Float', 0x3ff0000000000000, 'visitor'), 4))
        self.assertEqual(self.run_n2(0xc1, 0x33, b''), (('passthrough', 0xc1, 0x33), 0))
        self.assertEqual(self.run_n2(0x90, 0x05, b'\x01'), (('passthrough', 0x90, 0x05), 0))

    def test_reconstruction_matches_all_n2_cases(self):
        c = self.copies['N2']
        rows, bad, m = tool.compare(self.img, c, tool.build_cases(c.n_variants))
        self.assertEqual(bad, 0)
        self.assertGreater(len(rows), 1500)
        for body in c.funcs.values():
            self.assertTrue(all(i.va in m.covered for i in body))

    def test_wrong_reconstructions_are_caught(self):
        c = self.copies['N2']
        cases = tool.build_cases(c.n_variants)
        for model in tool.MODEL_MUTANTS:
            _, bad, _ = tool.compare(self.img, c, cases, model)
            self.assertGreater(bad, 0, model)

    def test_corrupted_bound_byte_is_rejected_statically(self):
        # bound + 1 makes the 93rd jump-table word an arm, and it is not one
        c = self.copies['N2']
        u64 = c.funcs[c.by_role['visit_u64']]
        bad = bytearray(self.data)
        bad[self.img.off(u64[1].va) + u64[1].size - 1] = 0x5c
        with self.assertRaises(tool.Fault):
            tool.Copy(tool.Image(bytes(bad), check=False), 'N2', 0x33fc5f0, 0x64e3f30)

    def test_corrupted_range_branch_is_caught_dynamically(self):
        c = self.copies['N2']
        ja = next(i for i in c.insns if i.op == 'j' and i.a == 7)
        bad = bytearray(self.data)
        bad[self.img.off(ja.va)] = 0x73  # ja -> jae: marker 0xe0 leaves the table
        mimg = tool.Image(bytes(bad), check=False)
        mc = tool.Copy(mimg, 'N2', 0x33fc5f0, 0x64e3f30)
        got = tool.Machine(mimg, mc).run(0xe0, 0x80, b'')
        self.assertEqual(got, (('passthrough', 0xe0, 0x80), 0))
        self.assertNotEqual(got, tool.reconstructed(0xe0, 0x80, b'', c.n_variants, c.eof_err))

    def test_unmapped_static_read_faults(self):
        with self.assertRaises(tool.Fault):
            self.img.read(0x10, 4)


class Regeneration(unittest.TestCase):
    def test_tool_reproduces_packet_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            s = tool.generate(d)
            self.assertEqual(s['total_mismatches'], 0)
            self.assertEqual(s['model_mutants_killed'], s['model_mutants_total'])
            self.assertEqual(s['image_mutants_killed'], s['image_mutants_total'])
            names = sorted(p.name for p in Path(d).iterdir())
            for name in names:
                self.assertEqual((Path(d) / name).read_bytes(), (PACKET / name).read_bytes(), name)
        manifest = {}
        for line in (PACKET / 'MANIFEST.sha256').read_text().splitlines():
            h, name = line.split('  ', 1)
            manifest[name] = h
        for name, h in manifest.items():
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), h, name)
        self.assertTrue(set(names) <= set(manifest))
        summary = json.loads((PACKET / 'summary.json').read_text())
        self.assertEqual(summary['binary_sha256'], tool.SHA256)


if __name__ == '__main__':
    unittest.main()
