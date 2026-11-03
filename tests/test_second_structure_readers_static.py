"""Native target evidence and second-structure-reader counterfactuals."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import second_structure_readers_static as subject
from elf_index import sections

PACKET = (Path(__file__).resolve().parents[1] / 'research' / 'work-items'
          / 'RE-015-node115-second-structure-readers')


class SecondStructureReadersTests(unittest.TestCase):
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
        self.assertEqual(owners, {'large_consumer', 'entry_take',
                                  'second_tree_drop',
                                  'second_tree_iterator',
                                  'payload_drop_30', 'payload_drop_70',
                                  'second_record_drop'})
        self.assertEqual(self.report['target_sha256'], subject.SHA)
        desc = self.report['descriptors']
        self.assertEqual(desc['0x63ffbf8']['size'], '0x30')
        self.assertEqual(desc['0x63ffbf8']['drop'], '0x15ac880')
        self.assertEqual(desc['0x63ffc70']['size'], '0x70')
        self.assertEqual(desc['0x63ffc70']['drop'], '0x15acde0')
        self.assertEqual(desc['0x63ffbd0']['size'], '0x30')
        self.assertEqual(desc['0x63ffbd0']['drop'], '0x15ac780')
        self.assertEqual(desc['0x63ffb48']['kind'], 'panic_location')
        self.assertEqual(desc['0x63ffb48']['path_len'], '0x16')
        bindings = self.report['slot_bindings']
        self.assertEqual(bindings['write']['addend'], '0x1680500')
        self.assertEqual(bindings['close']['symbol'], 'close')
        self.assertEqual(bindings['memmove']['symbol'], 'memmove')
        self.assertEqual(bindings['panic']['addend'], '0x1680c10')

    def test_censuses(self):
        calls = self.report['direct_calls']
        self.assertEqual(calls['second_tree_drop']['sites'],
                         ['0x15a54fc', '0x15a63cc'])
        self.assertEqual(calls['entry_take']['sites'],
                         ['0x15a4d6f', '0x15a4e5f'])
        self.assertEqual(calls['payload_drop_30']['sites'], [])
        self.assertEqual(calls['payload_drop_70']['sites'], ['0x15a6234'])
        self.assertEqual(calls['second_record_drop']['sites'],
                         ['0x15a62ce', '0x15a63a4', '0x15a63bc'])
        self.assertEqual(calls['tree_insert']['sites'], ['0x15a4c88'])
        rip = self.report['rip_references']
        self.assertEqual(
            [c['instruction'] for c in rip['0x63ffbf8']['rip_candidates']],
            ['0x15a4730'])
        self.assertEqual(
            [c['instruction'] for c in rip['0x63ffc70']['rip_candidates']],
            ['0x15a4b8f'])
        self.assertEqual(
            [c['instruction'] for c in rip['0x63ffbd0']['rip_candidates']],
            ['0x15a46d8', '0x15a4932'])
        for row in rip.values():
            self.assertEqual(row['imm64_sites'], [])

    def test_stack_census(self):
        stacks = self.report['stack_census']
        self.assertEqual([r['site'] for r in stacks['handle']['0x1d8']],
                         ['0x15a44f8'])
        self.assertEqual([r['site'] for r in stacks['handle']['0x1c8']],
                         ['0x15a44ec'])
        stores = [r['site'] for r in stacks['handle']['0x1b8']
                  if r['kind'] == 'store_or_test']
        self.assertEqual(stores, ['0x15a44e0', '0x15a4bec'])
        vec = stacks['collect_vector']
        for slot, first in (('0x90', '0x15a4f79'), ('0x98', '0x15a4f81'),
                            ('0xa0', '0x15a5031')):
            post = [r for r in vec[slot] if r['region'] == 'postloop']
            self.assertEqual(post[0]['site'], first)
            self.assertEqual(post[0]['kind'], 'store_or_test')
            loads = [r['site'] for r in post if r['kind'] == 'load']
            self.assertTrue(all(int(s, 16) >= 0x15a505b for s in loads))

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

    def test_descriptor_size_mutation_rejected(self):
        with self.assertRaises(ValueError):
            subject.analyze(bytes(self.mutate(subject.TAG_A + 8)))

    def test_descriptor_drop_mutation_rejected(self):
        b = bytearray(self.data)
        s = next(s for s in self.secs if s['name'] == '.rela.dyn')
        for off in range(s['offset'], s['offset'] + s['size'], 24):
            offset, _, _ = struct.unpack_from('<QQq', bytes(b), off)
            if offset == subject.TAG_B:
                b[off + 16] ^= 1
                break
        else:
            self.fail('tag B relocation not found')
        with self.assertRaises(ValueError):
            subject.analyze(bytes(b))

    def test_take_size_dec_mutation_rejected(self):
        with self.assertRaises(ValueError):
            subject.analyze(bytes(self.mutate(0x156edf1)))

    def test_overwrite_store_mutation_rejected(self):
        with self.assertRaises(ValueError):
            subject.analyze(bytes(self.mutate(0x15a4f79)))

    def test_tree_drop_call_mutation_rejected(self):
        with self.assertRaises(ValueError):
            subject.analyze(bytes(self.mutate(0x15a54fc + 1)))

    def test_init_word_mutation_rejected(self):
        with self.assertRaises(ValueError):
            subject.analyze(bytes(self.mutate(0x15a44f8 + 8, 3)))

    def test_owner_body_mutation_rejected(self):
        with self.assertRaises(ValueError):
            subject.analyze(bytes(self.mutate(0x15acfa0)))


if __name__ == '__main__':
    unittest.main()
