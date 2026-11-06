"""Native target evidence and sub-vector-drain counterfactuals."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import subvec_drain_callees_static as subject
from elf_index import sections

PACKET = (Path(__file__).resolve().parents[1] / 'research' / 'work-items'
          / 'RE-015-node115-subvec-drain-callees')


class SubvecDrainCalleesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not subject.TARGET.is_file() or \
                subject.TARGET.stat().st_size != 105896032:
            raise unittest.SkipTest('materialized node115 required')
        cls.data = subject.TARGET.read_bytes()
        if hashlib.sha256(cls.data).hexdigest() != subject.SHA:
            raise ValueError('wrong node115 capture')
        cls.secs = sections(cls.data)
        cls.report = subject.analyze(cls.data)

    def offset(self, va):
        s = next(s for s in self.secs
                 if s['type'] != 8
                 and s['address'] <= va < s['address'] + s['size'])
        return s['offset'] + va - s['address']

    def mutate(self, va, value=None):
        b = bytearray(self.data)
        o = self.offset(va)
        b[o] = b[o] ^ 1 if value is None else value
        return b

    def test_analysis_shape(self):
        owners = {row['role'] for row in self.report['owners']}
        self.assertEqual(owners, {'vec_a_subvec_drain',
                                  'vec_a_subvec_drain_unwind',
                                  'reader_subvec_drain',
                                  'reader_subvec_drain_unwind'})
        self.assertEqual(self.report['target_sha256'], subject.SHA)
        self.assertEqual([row['bytes'] for row in self.report['owners']],
                         [235, 86, 235, 86])
        bindings = self.report['slot_bindings']
        self.assertEqual(bindings['dealloc']['addend'], '0x635de30')
        self.assertEqual(bindings['dealloc']['type'], 8)
        self.assertEqual(bindings['unwind_cleanup']['addend'],
                         '0x1680cab')

    def test_censuses(self):
        calls = self.report['direct_calls']
        self.assertEqual(len(calls['vec_a_subvec_drain']['sites']), 9)
        self.assertEqual(len(calls['reader_subvec_drain']['sites']), 9)
        self.assertEqual(calls['vec_a_subvec_drain_unwind']['sites'],
                         ['0x15386a3', '0x1538f92'])
        self.assertEqual(calls['reader_subvec_drain_unwind']['sites'],
                         ['0x474dc56', '0x474dda2'])
        self.assertIn('0x1538f28', calls['vec_a_subvec_drain']['sites'])
        self.assertIn('0x47487ed', calls['reader_subvec_drain']['sites'])
        owners = {r['site']: r['owner_fde']
                  for r in calls['reader_subvec_drain']['rows']}
        self.assertEqual(owners['0x47487ed'],
                         ['0x4748500', '0x4749aa9'])
        self.assertEqual(owners['0x474dd38'],
                         ['0x474dcd0', '0x474ddd2'])

    def test_header_census(self):
        headers = self.report['headers']
        for role in ('vec_a_subvec_drain', 'reader_subvec_drain'):
            self.assertEqual(headers[role]['rdi_displacements'],
                             ['0x10', '0x8'])
            self.assertEqual(headers[role]['cursor_loads'],
                             ['0x10', '0x18', '0x8'])
        for role in ('vec_a_subvec_drain_unwind',
                     'reader_subvec_drain_unwind'):
            self.assertEqual(headers[role]['rbx_displacements'],
                             ['0x8'])
            self.assertEqual(headers[role]['rbx_entry_loads'], 2)

    def test_clone_shapes(self):
        shapes = {row['a']: row for row in self.report['shapes']}
        normal = shapes['vec_a_subvec_drain']
        self.assertTrue(normal['masked_identical'])
        self.assertEqual(normal['instructions'], 72)
        diffs = normal['differences']
        self.assertEqual(len(diffs), 5)
        by_kind = {}
        for row in diffs:
            by_kind.setdefault(row['kind'], []).append(row)
        self.assertEqual(len(by_kind['ripdisp32']), 3)
        self.assertEqual(len(by_kind['rel32']), 2)
        for row in by_kind['ripdisp32']:
            self.assertEqual(row['a_target'], row['b_target'])
        self.assertEqual({row['a_target'] for row in by_kind['ripdisp32']},
                         {'0x64df4a0', '0x64df4c0'})
        self.assertEqual({(r['a_target'], r['b_target'])
                          for r in by_kind['rel32']},
                         {('0x1537b00', '0x474e0b0'),
                          ('0x63f0a50', '0x63f0a50')})
        unwind = shapes['vec_a_subvec_drain_unwind']
        self.assertTrue(unwind['masked_identical'])
        self.assertEqual(unwind['instructions'], 29)
        diffs = unwind['differences']
        self.assertEqual(len(diffs), 4)
        by_kind = {}
        for row in diffs:
            by_kind.setdefault(row['kind'], []).append(row)
        self.assertEqual(len(by_kind['ripdisp32']), 2)
        self.assertEqual(len(by_kind['rel32']), 2)
        self.assertEqual({(r['a_target'], r['b_target'])
                          for r in by_kind['rel32']},
                         {('0x153deb0', '0x474e8a0'),
                          ('0x63f0a50', '0x63f0a50')})

    def test_regeneration(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / 'packet'
            subject.generate(subject.TARGET, out)
            generated = {p.name: p.read_bytes() for p in out.iterdir()}
        committed = {p.name: p.read_bytes() for p in PACKET.iterdir()
                     if p.name not in ('README.md', 'MANIFEST.sha256')}
        self.assertEqual(set(generated), set(committed))
        for name, blob in generated.items():
            self.assertEqual(blob, committed[name], name)

    def test_dealloc_slot_mutation_rejected(self):
        b = bytearray(self.data)
        s = next(s for s in self.secs if s['name'] == '.rela.dyn')
        for off in range(s['offset'], s['offset'] + s['size'], 24):
            offset, _, _ = struct.unpack_from('<QQq', bytes(b), off)
            if offset == 0x64df4a0:
                b[off + 16] ^= 1
                break
        else:
            self.fail('dealloc relocation not found')
        with self.assertRaises(ValueError):
            subject.analyze(bytes(b))

    def test_a_count_disp_mutation_rejected(self):
        with self.assertRaises(ValueError):
            subject.analyze(bytes(self.mutate(0x153debb + 3, 0x11)))

    def test_b_cursor_seed_mutation_rejected(self):
        with self.assertRaises(ValueError):
            subject.analyze(bytes(self.mutate(0x474e8b8 + 3, 0x19)))

    def test_shape_divergence_rejected(self):
        # `xor ebx,ebx` in the reader drain only: the masked byte
        # streams must diverge even though no pin covers the site.
        with self.assertRaises(ValueError):
            subject.analyze(bytes(self.mutate(0x474e8bc + 1, 0xff)))

    def test_owner_body_mutation_rejected(self):
        with self.assertRaises(ValueError):
            subject.analyze(bytes(self.mutate(0x153df9a)))
        with self.assertRaises(ValueError):
            subject.analyze(bytes(self.mutate(0x15399e5)))
        with self.assertRaises(ValueError):
            subject.analyze(bytes(self.mutate(0x474e2c5)))


if __name__ == '__main__':
    unittest.main()
