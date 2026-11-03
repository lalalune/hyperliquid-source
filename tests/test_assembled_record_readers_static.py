"""Native target evidence and assembled-record-reader counterfactuals."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import assembled_record_readers_static as subject
from elf_index import sections

PACKET = (Path(__file__).resolve().parents[1] / 'research' / 'work-items'
          / 'RE-015-node115-assembled-record-readers')


class AssembledRecordReadersTests(unittest.TestCase):
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
        self.assertEqual(owners, {'large_consumer', 'exit_reader',
                                  'pair_drop', 'tagged_destroy_a',
                                  'tagged_destroy_b', 'map1_drain_helper'})
        self.assertEqual(self.report['target_sha256'], subject.SHA)
        bindings = self.report['slot_bindings']
        self.assertEqual(bindings['exit_reader']['addend'], '0x4749ab0')
        self.assertEqual(bindings['merge_delegate']['addend'], '0x4748500')
        self.assertEqual(bindings['entry_vec_grow']['addend'], '0x474e490')
        self.assertEqual(bindings['vec40_grow_a']['addend'], '0x474e420')
        self.assertEqual(bindings['vec40_grow_b']['addend'], '0x474e420')
        self.assertEqual(bindings['assert_entry']['addend'], '0x1680c30')
        self.assertEqual(bindings['memcpy']['symbol'], 'memcpy')

    def test_censuses(self):
        sites = self.report['consumer_call_sites']
        self.assertEqual(sites['pair_drop'],
                         ['0x15a5e14', '0x15a5eb2', '0x15a60d9',
                          '0x15a64d4'])
        self.assertEqual(sites['tagged_destroy_a'],
                         ['0x15a5dfa', '0x15a5e4c'])
        self.assertEqual(sites['tagged_destroy_b'],
                         ['0x15a6186', '0x15a61a3'])
        self.assertEqual(sites['map1_drain_helper'], ['0x15a569e'])
        self.assertEqual(sites['drain_iterator'],
                         ['0x15a5580', '0x15a6459', '0x15a64b5'])
        calls = self.report['direct_calls']
        self.assertEqual(calls['transform_gate']['sites'],
                         ['0x4748742', '0x4748dae'])

    def test_stack_census(self):
        stacks = self.report['stack_census']
        for slot in ('0x1d0', '0x1e8', '0x1f0', '0x1f8', '0x208',
                     '0x210', '0x218', '0x220', '0x240', '0x250',
                     '0x260', '0x268'):
            drain = [r for r in stacks[slot] if r['region'] == 'drain']
            self.assertEqual(drain, [], slot)
        tail = [r['site'] for r in stacks['0x240']
                if int(r['site'], 16) >= 0x15a58f2]
        self.assertEqual(tail, ['0x15a591a', '0x15a64cc'])

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

    def test_exit_slot_mutation_rejected(self):
        b = bytearray(self.data)
        s = next(s for s in self.secs if s['name'] == '.rela.dyn')
        for off in range(s['offset'], s['offset'] + s['size'], 24):
            offset, _, _ = struct.unpack_from('<QQq', bytes(b), off)
            if offset == 0x64e1480:
                b[off + 16] ^= 1
                break
        else:
            self.fail('exit reader relocation not found')
        with self.assertRaises(ValueError):
            subject.analyze(bytes(b))

    def test_disc_cmp_mutation_rejected(self):
        with self.assertRaises(ValueError):
            subject.analyze(bytes(self.mutate(0x15a5930 + 4, 7)))

    def test_pair_drop_step_mutation_rejected(self):
        with self.assertRaises(ValueError):
            subject.analyze(bytes(self.mutate(0x15ac616 + 3, 0x41)))

    def test_tagged_size_mutation_rejected(self):
        with self.assertRaises(ValueError):
            subject.analyze(bytes(self.mutate(0x158bef8 + 3, 0x10)))

    def test_map1_child_mutation_rejected(self):
        with self.assertRaises(ValueError):
            subject.analyze(bytes(self.mutate(0x149e643 + 3, 0x21)))

    def test_delegate_sentinel_mutation_rejected(self):
        with self.assertRaises(ValueError):
            subject.analyze(bytes(self.mutate(0x474868f + 9, 0x81)))

    def test_owner_body_mutation_rejected(self):
        with self.assertRaises(ValueError):
            subject.analyze(bytes(self.mutate(0x4749d70)))


if __name__ == '__main__':
    unittest.main()
