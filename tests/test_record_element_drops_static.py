"""Native target evidence and record-element-drop counterfactuals."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import record_element_drops_static as subject
from elf_index import sections

PACKET = (Path(__file__).resolve().parents[1] / 'research' / 'work-items'
          / 'RE-015-node115-record-element-drops')


class RecordElementDropsTests(unittest.TestCase):
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
        self.assertEqual(owners, {'vec_a_element_drop',
                                  'reader_element_drop'})
        self.assertEqual(self.report['target_sha256'], subject.SHA)
        self.assertEqual([row['bytes'] for row in self.report['owners']],
                         [258, 258])
        bindings = self.report['slot_bindings']
        self.assertEqual(bindings['dealloc']['addend'], '0x635de30')
        self.assertEqual(bindings['dealloc']['type'], 8)
        self.assertEqual(bindings['unwind_cleanup']['addend'],
                         '0x1680cab')

    def test_censuses(self):
        calls = self.report['direct_calls']
        self.assertEqual(calls['vec_a_element_drop']['sites'],
                         ['0x15ac61d', '0x15ac73d'])
        self.assertEqual(calls['reader_element_drop']['sites'],
                         ['0x4740dfd', '0x4740e4d', '0x4747ded',
                          '0x4747f0d', '0x47481ed', '0x474823d',
                          '0x4749b6d', '0x4749d2c'])
        owners = {r['site']: r['owner_fde']
                  for r in calls['reader_element_drop']['rows']}
        self.assertEqual(owners['0x4749b6d'],
                         ['0x4749ab0', '0x4749d71'])
        self.assertEqual(owners['0x47481ed'],
                         ['0x47481c0', '0x474826c'])

    def test_field_census(self):
        fields = self.report['element_fields']
        for role in ('vec_a_element_drop', 'reader_element_drop'):
            self.assertEqual(fields[role]['rbx_displacements'],
                             ['0x18', '0x20', '0x30', '0x38', '0x8'])
            self.assertEqual(fields[role]['rdi_entry_loads'], 1)

    def test_clone_shape(self):
        shape = self.report['shape']
        self.assertTrue(shape['masked_identical'])
        self.assertEqual(shape['instructions'], 80)
        diffs = shape['differences']
        self.assertEqual(len(diffs), 9)
        by_kind = {}
        for row in diffs:
            by_kind.setdefault(row['kind'], []).append(row)
        self.assertEqual(len(by_kind['ripdisp32']), 6)
        self.assertEqual(len(by_kind['rel32']), 3)
        slots = {row['a_target'] for row in by_kind['ripdisp32']}
        self.assertEqual(slots, {'0x64df4a0', '0x64df4c0'})
        for row in by_kind['ripdisp32']:
            self.assertEqual(row['a_target'], row['b_target'])
        rel = {(row['a_target'], row['b_target'])
               for row in by_kind['rel32']}
        self.assertEqual(rel, {('0x153deb0', '0x474e8a0'),
                               ('0x1539990', '0x474e270'),
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

    def test_a_tagged_disp_mutation_rejected(self):
        with self.assertRaises(ValueError):
            subject.analyze(bytes(self.mutate(0x1538edf + 3, 0x31)))

    def test_b_subvec_shift_mutation_rejected(self):
        with self.assertRaises(ValueError):
            subject.analyze(bytes(self.mutate(0x474dd49 + 3, 0x05)))

    def test_shape_divergence_rejected(self):
        # `test rsi,rsi` in the reader drop only: the masked byte
        # streams must diverge even though no pin covers the site.
        with self.assertRaises(ValueError):
            subject.analyze(bytes(self.mutate(0x474dcde + 2, 0xff)))

    def test_owner_body_mutation_rejected(self):
        with self.assertRaises(ValueError):
            subject.analyze(bytes(self.mutate(0x1538fc1)))
        with self.assertRaises(ValueError):
            subject.analyze(bytes(self.mutate(0x474ddd1)))


if __name__ == '__main__':
    unittest.main()
