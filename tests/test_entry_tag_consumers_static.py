"""Native target evidence and entry-tag-consumer counterfactuals."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import entry_tag_consumers_static as subject
from elf_index import sections

PACKET = (Path(__file__).resolve().parents[1] / 'research' / 'work-items'
          / 'RE-015-node115-entry-tag-consumers')


class EntryTagConsumersTests(unittest.TestCase):
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
        self.assertEqual(owners, {
            'exit_consumer', 'sole_caller_wrapper', 'entry_vec_drop',
            'unwrap_failed', 'panic_helper', 'registrar',
            'arc_wrap_ctor'})
        boundaries = {row['role'] for row in self.report['boundaries']}
        self.assertEqual(boundaries, {
            'exit_reader', 'err_debug_fmt', 'payload_ctor',
            'registrar_lookup', 'registrar_key', 'err_fmt_dispatch',
            'str_fmt'})
        self.assertEqual(self.report['target_sha256'], subject.SHA)
        owner = next(r for r in self.report['owners']
                     if r['role'] == 'exit_consumer')
        self.assertEqual(owner['start'], '0x15a3b90')
        self.assertEqual(owner['end'], '0x15a6509')
        self.assertEqual(owner['bytes'], 10617)
        self.assertEqual(
            owner['sha256'],
            '7995f7af57e2be27ca6ed1e307d9bcce9d6140f72b0ff0cf0804d7f09'
            'e5505fb')
        reader = next(r for r in self.report['boundaries']
                      if r['role'] == 'exit_reader')
        self.assertEqual(
            reader['sha256'],
            '6f4caa139b97d81e99776e8cf0f570c906c02c5133d755baec41104d'
            '77e9b0bb')

    def test_slot_bindings(self):
        bindings = self.report['slot_bindings']
        self.assertEqual(bindings['exit_reader']['addend'], '0x4749ab0')
        self.assertEqual(bindings['unwrap_failed']['addend'],
                         '0x1680c30')
        self.assertEqual(bindings['panic_entry']['addend'], '0x1680e80')
        self.assertEqual(bindings['registrar']['addend'], '0x474f6a0')
        self.assertEqual(bindings['arc_wrap']['addend'], '0x4742470')
        self.assertEqual(bindings['dealloc']['addend'], '0x635de30')
        self.assertEqual(bindings['global_cell']['addend'], '0x64ffef8')

    def test_err_facts(self):
        vt = self.report['err_vtable']
        self.assertEqual(vt, {'address': '0x63ffe00',
                              'drop': '0x15ac470', 'size': 24,
                              'align': 8, 'debug_fmt': '0x15b4420'})
        msg = self.report['unwrap_message']
        self.assertEqual(msg['text'],
                         'called `Result::unwrap()` on an `Err` value')
        self.assertEqual(msg['length'], 43)
        loc = self.report['unwrap_location']
        self.assertEqual(loc['file'], 'base/src/log/handle.rs')
        self.assertEqual(loc['line'], 167)
        self.assertEqual(loc['column'], 60)
        sib = self.report['sibling_unwrap_vtables']
        self.assertEqual(sib['unwrap_site_b']['drop'], '0x15ab120')
        self.assertEqual(sib['unwrap_site_c']['debug_fmt'], '0x5ca5610')

    def test_call_census(self):
        census = self.report['direct_call_census']
        self.assertEqual(census['0x15a3b90'], ['0x15a6556'])
        self.assertEqual(census['0x15ac470'], ['0x15a6042'])
        self.assertEqual(census['0x15b4420'], [])
        dest = self.report['dest_slot_census']
        self.assertEqual(dest['access_sites'],
                         ['0x15a3ba1', '0x15a5940'])
        wrap = self.report['wrapper_census']
        self.assertEqual(wrap['slot_calls']['0x15a6596'], '0x64e1488')
        self.assertEqual(wrap['slot_calls']['0x15a663f'], '0x64df6a0')

    def test_tag_consumption_verdict(self):
        tags = self.report['tag_consumption']
        self.assertFalse(tags['per_tag_dispatch_found'])
        self.assertEqual(len(self.report['destination_chain']), 6)
        self.assertIn('0x4741180',
                      self.report['destination_chain'][3])

    def test_counterfactual_discriminant(self):
        bad = self.mutate(0x15a5930 + 4, 0x07)
        with self.assertRaises(ValueError):
            subject.analyze(bytes(bad))

    def test_counterfactual_err_store(self):
        bad = self.mutate(0x4749b3a)
        with self.assertRaises(ValueError):
            subject.analyze(bytes(bad))

    def test_counterfactual_tag_gate(self):
        bad = self.mutate(0x15ac4a9)
        with self.assertRaises(ValueError):
            subject.analyze(bytes(bad))

    def test_counterfactual_dest_save(self):
        bad = self.mutate(0x15a3ba1)
        with self.assertRaises(ValueError):
            subject.analyze(bytes(bad))

    def test_counterfactual_registrar_forward(self):
        bad = self.mutate(0x474f6ad)
        with self.assertRaises(ValueError):
            subject.analyze(bytes(bad))

    def test_generate_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / 'packet'
            subject.generate(subject.TARGET, out)
            records = json.loads((out / 'records.json').read_text())
            self.assertEqual(records['target_sha256'], subject.SHA)
            self.assertFalse(
                records['tag_consumption']['per_tag_dispatch_found'])
            frames = (out / 'frames.txt').read_text()
            self.assertIn('pc=00000000015a3b90..00000000015a6509',
                          frames)
            self.assertIn('pc=000000000474f6a0..000000000474f7ff',
                          frames)
            for name, _, _, _ in subject.WINDOWS:
                self.assertTrue((out / name).is_file(), name)

    def test_packet_records_match(self):
        committed = json.loads((PACKET / 'records.json').read_text())
        self.assertEqual(committed, self.report)


if __name__ == '__main__':
    unittest.main()
