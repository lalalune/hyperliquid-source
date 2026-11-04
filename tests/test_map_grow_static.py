"""Native target evidence and map-grow counterfactuals."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import map_grow_static as subject
from elf_index import sections

PACKET = (Path(__file__).resolve().parents[1] / 'research' / 'work-items'
          / 'RE-015-node115-map-grow')


class MapGrowTests(unittest.TestCase):
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
        self.assertEqual(owners, {'map_grow'})
        boundaries = {row['role'] for row in self.report['boundaries']}
        self.assertEqual(boundaries, {
            'prev_body', 'record_drop', 'next_body', 'map_insert'})
        self.assertEqual(self.report['target_sha256'], subject.SHA)
        owner = self.report['owners'][0]
        self.assertEqual(owner['start'], '0x4742aa0')
        self.assertEqual(owner['end'], '0x4743347')
        self.assertEqual(owner['bytes'], 2215)
        self.assertEqual(
            owner['sha256'],
            'dddec9130ff0171ebc861ae72351d0e4d846e76cbbd9811c5bed5d56d0ac4a67')
        nxt = next(r for r in self.report['boundaries']
                   if r['role'] == 'next_body')
        self.assertEqual(
            nxt['sha256'],
            'bc09ee782d62721d2cbc93cc2e52d6f447caebbf7ef36da19f5ae89cfef84ae4')

    def test_slot_bindings(self):
        bindings = self.report['slot_bindings']
        self.assertEqual(bindings['alloc']['addend'], '0x6355830')
        self.assertEqual(bindings['alloc_error']['addend'],
                         '0x141e251')
        self.assertEqual(bindings['dealloc']['addend'], '0x635de30')
        self.assertEqual(bindings['memmove']['name'], 'memmove')
        self.assertEqual(bindings['memset']['name'], 'memset')
        self.assertEqual(bindings['panic_fmt']['addend'],
                         '0x1680e80')
        self.assertEqual(bindings['grow_fn']['addend'], '0x4742aa0')

    def test_census_and_models(self):
        self.assertEqual(self.report['direct_call_census'],
                         {'0x4742aa0': []})
        self.assertEqual(self.report['slot_call_census'],
                         {'0x64eaf78': ['0x474ba06']})
        self.assertEqual(self.report['empty_key_hash'],
                         '0xaf64724c8602eb6e')
        self.assertEqual(self.report['panic_message']['text'],
                         'Hash table capacity overflow')
        cap = self.report['capacity_model']['capacity_of_buckets']
        self.assertEqual(cap['16'], 14)
        self.assertEqual(cap['128'], 112)
        buckets = self.report['capacity_model'][
            'buckets_for_requested']
        self.assertEqual(buckets['15'], 32)
        self.assertEqual(buckets['113'], 256)
        self.assertEqual(subject.capacity(8), 7)
        self.assertEqual(subject.buckets_for(28), 32)
        self.assertEqual(subject.buckets_for(29), 64)

    def test_layouts(self):
        self.assertEqual(len(self.report['map_rewrites']), 3)
        self.assertEqual(len(self.report['phases']), 9)
        self.assertIn('rdx', self.report['call_args'])
        self.assertIn('overwritten', self.report['third_argument'])

    def test_counterfactual_items_load(self):
        with self.assertRaises(ValueError):
            subject.analyze(self.mutate(0x4742ab3))

    def test_counterfactual_div7_magic(self):
        with self.assertRaises(ValueError):
            subject.analyze(self.mutate(0x4742b65))

    def test_counterfactual_install_mask(self):
        with self.assertRaises(ValueError):
            subject.analyze(self.mutate(0x47432c8))

    def test_counterfactual_alloc_call(self):
        with self.assertRaises(ValueError):
            subject.analyze(self.mutate(0x4742bf3))

    def test_counterfactual_ctrl_store_new(self):
        with self.assertRaises(ValueError):
            subject.analyze(self.mutate(0x4742de5))

    def test_generate_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / 'packet'
            subject.generate(subject.TARGET, out)
            got = json.loads((out / 'records.json').read_text())
            self.assertEqual(got['verdict'], self.report['verdict'])
            self.assertTrue((out / 'map_grow_objdump.txt').is_file())
            self.assertTrue((out / 'frames.txt').is_file())

    def test_committed_records_match(self):
        committed = PACKET / 'records.json'
        if not committed.is_file():
            raise unittest.SkipTest('packet not generated yet')
        got = json.loads(committed.read_text())
        self.assertEqual(got, self.report)


if __name__ == '__main__':
    unittest.main()
