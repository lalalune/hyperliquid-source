"""Native target evidence and map-insert counterfactuals."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import map_insert_static as subject
from elf_index import sections

PACKET = (Path(__file__).resolve().parents[1] / 'research' / 'work-items'
          / 'RE-015-node115-map-insert')


class MapInsertTests(unittest.TestCase):
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
        self.assertEqual(owners, {'map_insert'})
        boundaries = {row['role'] for row in self.report['boundaries']}
        self.assertEqual(boundaries, {
            'insert_helper', 'grow_reserve', 'record_drop',
            'value_drop', 'next_body'})
        self.assertEqual(self.report['target_sha256'], subject.SHA)
        owner = self.report['owners'][0]
        self.assertEqual(owner['start'], '0x474b620')
        self.assertEqual(owner['end'], '0x474ba5d')
        self.assertEqual(owner['bytes'], 1085)
        self.assertEqual(
            owner['sha256'],
            'f6d9ca4362a1a81c592c33e5e75d6522a738b71a143b4c6b9bcb0b1739cd6658')
        grow = next(r for r in self.report['boundaries']
                    if r['role'] == 'grow_reserve')
        self.assertEqual(
            grow['sha256'],
            'dddec9130ff0171ebc861ae72351d0e4d846e76cbbd9811c5bed5d56d0ac4a67')

    def test_slot_bindings(self):
        bindings = self.report['slot_bindings']
        self.assertEqual(bindings['bcmp']['name'], 'bcmp')
        self.assertEqual(bindings['dealloc']['addend'], '0x635de30')
        self.assertEqual(bindings['grow_fn']['addend'], '0x4742aa0')
        self.assertEqual(bindings['unwind_tail']['addend'], '0x1680cab')

    def test_census_and_hash(self):
        census = self.report['direct_call_census']
        self.assertEqual(census['0x474b620'], ['0x4742025'])
        self.assertEqual(census['0x474ac30'], ['0x474ba36'])
        self.assertEqual(self.report['empty_key_hash'],
                         '0xaf64724c8602eb6e')

    def test_layouts(self):
        fields = self.report['map_fields']
        self.assertEqual(len(fields), 4)
        self.assertEqual(fields[-1]['offset'], '0x18')
        bucket = self.report['bucket_layout']
        self.assertEqual(bucket['size'], '0x58')
        self.assertEqual(bucket['value']['offset'], '0x18')
        self.assertEqual(len(bucket['key_record']), 3)
        self.assertEqual(len(self.report['result_variants']), 2)
        self.assertEqual(len(self.report['phases']), 6)
        self.assertIn('rcx', self.report['call_args'])

    def test_counterfactual_fnv_basis(self):
        with self.assertRaises(ValueError):
            subject.analyze(self.mutate(0x474b651))

    def test_counterfactual_growth_cmp(self):
        with self.assertRaises(ValueError):
            subject.analyze(self.mutate(0x474b73a))

    def test_counterfactual_tag6_store(self):
        with self.assertRaises(ValueError):
            subject.analyze(self.mutate(0x474b9d5))

    def test_counterfactual_bcmp_call(self):
        with self.assertRaises(ValueError):
            subject.analyze(self.mutate(0x474b7ec))

    def test_counterfactual_ctrl_store(self):
        with self.assertRaises(ValueError):
            subject.analyze(self.mutate(0x474b956))

    def test_generate_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / 'packet'
            subject.generate(subject.TARGET, out)
            got = json.loads((out / 'records.json').read_text())
            self.assertEqual(got['verdict'], self.report['verdict'])
            self.assertTrue((out / 'map_insert_objdump.txt').is_file())
            self.assertTrue((out / 'frames.txt').is_file())

    def test_committed_records_match(self):
        committed = PACKET / 'records.json'
        if not committed.is_file():
            raise unittest.SkipTest('packet not generated yet')
        got = json.loads(committed.read_text())
        self.assertEqual(got, self.report)


if __name__ == '__main__':
    unittest.main()
