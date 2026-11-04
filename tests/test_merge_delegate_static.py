"""Native target evidence and merge-delegate counterfactuals."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import merge_delegate_static as subject
from elf_index import sections

PACKET = (Path(__file__).resolve().parents[1] / 'research' / 'work-items'
          / 'RE-015-node115-merge-delegate')


class MergeDelegateTests(unittest.TestCase):
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
        self.assertEqual(owners, {'merge_delegate', 'transform_gate',
                                  'exit_reader', 'hash_fn', 'set_init'})
        self.assertEqual(self.report['target_sha256'], subject.SHA)
        bindings = self.report['slot_bindings']
        self.assertEqual(bindings['merge_delegate']['addend'], '0x4748500')
        self.assertEqual(bindings['exit_reader']['addend'], '0x4749ab0')
        self.assertEqual(bindings['entry_vec_grow']['addend'], '0x474e490')
        self.assertEqual(bindings['vec40_grow_a']['addend'], '0x474e420')
        self.assertEqual(bindings['vec40_grow_b']['addend'], '0x474e420')
        self.assertEqual(bindings['vec18_grow']['addend'], '0x5c8b150')
        self.assertEqual(bindings['set_init']['addend'], '0x4743990')
        self.assertEqual(bindings['alloc']['addend'], '0x6355830')
        self.assertEqual(bindings['dealloc']['addend'], '0x635de30')
        self.assertEqual(bindings['assert_entry']['addend'], '0x1680c30')
        self.assertEqual(bindings['memcpy']['symbol'], 'memcpy')
        self.assertEqual(bindings['memcmp_bcmp']['symbol'], 'bcmp')

    def test_censuses(self):
        calls = self.report['direct_calls']
        self.assertEqual(calls['merge_delegate']['sites'], [])
        self.assertEqual(calls['transform_gate']['sites'],
                         ['0x4748742', '0x4748dae'])
        self.assertEqual(calls['exit_reader']['sites'], [])
        slots = self.report['slot_calls']
        self.assertEqual(slots['merge_delegate_slot']['sites'], ['0x4749ac9'])
        self.assertEqual(slots['exit_reader_slot']['sites'], ['0x15a592a'])
        self.assertEqual(slots['set_init_slot']['sites'], ['0x474bc91'])

    def test_descriptor_template(self):
        template = self.report['descriptor_template']
        self.assertEqual(template['0x64950f8']['reloc_addend'], '0x450150')
        self.assertEqual(template['0x6495118']['reloc_addend'], '0x4354fc')
        self.assertEqual(template['0x6495100']['file_qword'], '0x0')
        self.assertEqual(template['0x6495108']['file_qword'], '0x0')
        self.assertEqual(template['template_base_control_prefix'][:32],
                         'ff' * 16)

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

    def test_delegate_slot_mutation_rejected(self):
        b = bytearray(self.data)
        s = next(s for s in self.secs if s['name'] == '.rela.dyn')
        for off in range(s['offset'], s['offset'] + s['size'], 24):
            offset, _, _ = struct.unpack_from('<QQq', b, off)
            if offset == 0x64eafd8:
                b[off + 16] ^= 1
                break
        else:
            self.fail('delegate relocation not found')
        with self.assertRaises(ValueError):
            subject.analyze(bytes(b))

    def test_gate_call_mutation_rejected(self):
        with self.assertRaises(ValueError):
            subject.analyze(bytes(self.mutate(0x4748742 + 1, 0x1a)))

    def test_vec_a_sentinel_mutation_rejected(self):
        with self.assertRaises(ValueError):
            subject.analyze(bytes(self.mutate(0x474868f + 9, 0x81)))

    def test_loop1_sentinel_mutation_rejected(self):
        with self.assertRaises(ValueError):
            subject.analyze(bytes(self.mutate(0x474893e + 9, 0x81)))

    def test_temp_count_mutation_rejected(self):
        with self.assertRaises(ValueError):
            subject.analyze(bytes(self.mutate(0x47494d6 + 3, 0x61)))

    def test_scan_entry_mutation_rejected(self):
        with self.assertRaises(ValueError):
            subject.analyze(bytes(self.mutate(0x4748e10 + 2, 0xec)))

    def test_gate_init_call_mutation_rejected(self):
        with self.assertRaises(ValueError):
            subject.analyze(bytes(self.mutate(0x474bc91 + 2, 0xf2)))

    def test_owner_body_mutation_rejected(self):
        with self.assertRaises(ValueError):
            subject.analyze(bytes(self.mutate(0x4749d70)))

    def test_descriptor_reloc_mutation_rejected(self):
        b = bytearray(self.data)
        s = next(s for s in self.secs if s['name'] == '.rela.dyn')
        for off in range(s['offset'], s['offset'] + s['size'], 24):
            offset, _, _ = struct.unpack_from('<QQq', b, off)
            if offset == 0x64950f8:
                b[off + 16] ^= 1
                break
        else:
            self.fail('descriptor relocation not found')
        with self.assertRaises(ValueError):
            subject.analyze(bytes(b))


if __name__ == '__main__':
    unittest.main()
