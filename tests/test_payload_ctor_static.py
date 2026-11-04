"""Native target evidence and payload-ctor counterfactuals."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import payload_ctor_static as subject
from elf_index import sections

PACKET = (Path(__file__).resolve().parents[1] / 'research' / 'work-items'
          / 'RE-015-node115-payload-constructor')


class PayloadCtorTests(unittest.TestCase):
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
        return bytes(b)

    def test_analysis_shape(self):
        owners = {row['role'] for row in self.report['owners']}
        self.assertEqual(owners, {'payload_ctor', 'arc_wrap_ctor'})
        boundaries = {row['role'] for row in self.report['boundaries']}
        self.assertEqual(boundaries, {
            'collect_from_vec_b', 'map_vec_a', 'map_nested_vec',
            'insert_into_head', 'small_sort', 'large_sort',
            'drop_vec_c_snapshot', 'build_vec_b_tail',
            'collection_drop', 'registrar'})
        self.assertEqual(self.report['target_sha256'], subject.SHA)
        owner = next(r for r in self.report['owners']
                     if r['role'] == 'payload_ctor')
        self.assertEqual(owner['start'], '0x4741180')
        self.assertEqual(owner['end'], '0x4741869')
        self.assertEqual(owner['bytes'], 1769)
        self.assertEqual(
            owner['sha256'],
            '8b5d5c27780fad807407377de2a30320bd15ad6a8902c960b9d0f5ccb4955e6a')
        wrap = next(r for r in self.report['owners']
                    if r['role'] == 'arc_wrap_ctor')
        self.assertEqual(
            wrap['sha256'],
            'fe91e95a97ff89e4df3823200e2973aeb23dd05dabf5737d48ce10a74798ef9c')

    def test_slot_bindings(self):
        bindings = self.report['slot_bindings']
        self.assertEqual(bindings['alloc']['addend'], '0x6355830')
        self.assertEqual(bindings['alloc_error']['addend'], '0x141e264')
        self.assertEqual(bindings['dealloc']['addend'], '0x635de30')
        self.assertEqual(bindings['large_sort']['addend'], '0x47483e0')
        self.assertEqual(bindings['arc_wrap']['addend'], '0x4742470')
        self.assertEqual(bindings['global_cell']['addend'], '0x64ffef8')
        self.assertEqual(bindings['static_table']['addend'], '0x450150')
        self.assertEqual(bindings['registrar']['addend'], '0x474f6a0')

    def test_census_and_block(self):
        census = self.report['direct_call_census']
        self.assertEqual(census['0x4741180'], ['0x474248e'])
        self.assertEqual(census['0x4742470'], [])
        self.assertEqual(
            self.report['static_block']['words_after_relocation'],
            ['0x450150', '0x0', '0x0', '0x0'])

    def test_layouts(self):
        src = self.report['source_layout']
        self.assertEqual(src['size'], '0x50')
        self.assertEqual(len(src['fields']), 10)
        pay = self.report['payload_layout']
        self.assertEqual(pay['size'], '0x68')
        self.assertEqual(len(pay['head_struct_S']), 8)

    def test_counterfactual_terminator(self):
        with self.assertRaises(ValueError):
            subject.analyze(self.mutate(0x47413b9))

    def test_counterfactual_out_store(self):
        with self.assertRaises(ValueError):
            subject.analyze(self.mutate(0x474167b))

    def test_counterfactual_ctor_call(self):
        with self.assertRaises(ValueError):
            subject.analyze(self.mutate(0x474248f))

    def test_counterfactual_len_c_gate(self):
        with self.assertRaises(ValueError):
            subject.analyze(self.mutate(0x474132b))

    def test_counterfactual_const_block(self):
        with self.assertRaises(ValueError):
            subject.analyze(self.mutate(0x47412f3))

    def test_generate_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / 'packet'
            subject.generate(subject.TARGET, out)
            got = json.loads((out / 'records.json').read_text())
            self.assertEqual(got['verdict'], self.report['verdict'])
            self.assertTrue((out / 'payload_ctor_objdump.txt').is_file())
            self.assertTrue((out / 'frames.txt').is_file())

    def test_committed_records_match(self):
        committed = PACKET / 'records.json'
        if not committed.is_file():
            raise unittest.SkipTest('packet not generated yet')
        got = json.loads(committed.read_text())
        self.assertEqual(got, self.report)


if __name__ == '__main__':
    unittest.main()
