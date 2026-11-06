"""Native target evidence and insert-helper counterfactuals."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import insert_helper_static as subject
from elf_index import sections

PACKET = (Path(__file__).resolve().parents[1] / 'research' / 'work-items'
          / 'RE-015-node115-insert-helper')


class InsertHelperTests(unittest.TestCase):
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
        self.assertEqual(owners, {'insert_helper'})
        boundaries = {row['role'] for row in self.report['boundaries']}
        self.assertEqual(boundaries, {
            'payload_ctor', 'searcher_next', 'map_insert',
            'record_drop', 'vec_grow', 'cleanup_drop'})
        self.assertEqual(self.report['target_sha256'], subject.SHA)
        owner = self.report['owners'][0]
        self.assertEqual(owner['start'], '0x4741960')
        self.assertEqual(owner['end'], '0x4742124')
        self.assertEqual(owner['bytes'], 1988)
        self.assertEqual(
            owner['sha256'],
            '19ab10dcba77aea7e558737bddc7bace985b7d49bc254b69d731e23bb805136d')
        ctor = next(r for r in self.report['boundaries']
                    if r['role'] == 'payload_ctor')
        self.assertEqual(
            ctor['sha256'],
            '8b5d5c27780fad807407377de2a30320bd15ad6a8902c960b9d0f5ccb4955e6a')

    def test_slot_bindings(self):
        bindings = self.report['slot_bindings']
        self.assertEqual(bindings['searcher_build']['addend'], '0x167ff90')
        self.assertEqual(bindings['slice_error']['addend'], '0x16806c0')
        self.assertEqual(bindings['alloc']['addend'], '0x6355830')
        self.assertEqual(bindings['dealloc']['addend'], '0x635de30')
        self.assertEqual(bindings['alloc_error']['addend'], '0x141e264')
        self.assertEqual(bindings['bcmp']['name'], 'bcmp')
        self.assertEqual(bindings['memcpy']['name'], 'memcpy')

    def test_census_block_and_hash(self):
        census = self.report['direct_call_census']
        self.assertEqual(census['0x4741960'],
                         ['0x47414e0', '0x4741ccf', '0x4741e86'])
        self.assertEqual(
            self.report['static_block']['words_after_relocation'],
            ['0x450150', '0x0', '0x0', '0x0'])
        self.assertEqual(self.report['needle']['bytes'], '::')
        self.assertEqual(self.report['empty_head_hash'],
                         '0xaf64724c8602eb6e')

    def test_layouts(self):
        reads = self.report['s_fields_read']
        self.assertEqual(len(reads), 6)
        self.assertEqual(reads[-1]['offset'], '0x38')
        self.assertEqual(len(self.report['phases']), 6)
        self.assertIn('r9', self.report['call_args'])

    def test_counterfactual_fnv_basis(self):
        with self.assertRaises(ValueError):
            subject.analyze(self.mutate(0x4741a55))

    def test_counterfactual_result_tag(self):
        with self.assertRaises(ValueError):
            subject.analyze(self.mutate(0x47419be))

    def test_counterfactual_self_call(self):
        with self.assertRaises(ValueError):
            subject.analyze(self.mutate(0x4741cd0))

    def test_counterfactual_insert_result(self):
        with self.assertRaises(ValueError):
            subject.analyze(self.mutate(0x4742031))

    def test_counterfactual_s38_dispatch(self):
        with self.assertRaises(ValueError):
            subject.analyze(self.mutate(0x4741a17))

    def test_generate_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / 'packet'
            subject.generate(subject.TARGET, out)
            got = json.loads((out / 'records.json').read_text())
            self.assertEqual(got['verdict'], self.report['verdict'])
            self.assertTrue((out / 'insert_helper_objdump.txt').is_file())
            self.assertTrue((out / 'frames.txt').is_file())

    def test_committed_records_match(self):
        committed = PACKET / 'records.json'
        if not committed.is_file():
            raise unittest.SkipTest('packet not generated yet')
        got = json.loads(committed.read_text())
        self.assertEqual(got, self.report)


if __name__ == '__main__':
    unittest.main()
