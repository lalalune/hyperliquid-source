"""Target-grounded counter commit order, full-body records and safety gates."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import bincode_size_state as subject

class BincodeSizeStateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=subject.cpu.TARGET.read_bytes()
        if len(cls.data)!=91774280 or hashlib.sha256(cls.data).hexdigest()!=subject.cpu.SHA256:
            raise ValueError('pinned target required')
        cls.image=subject.cpu.Image(cls.data)

    def test_freeze_keeps_all_owners_and_explicit_population(self):
        f=json.loads((subject.PACKET/'FREEZE.json').read_text())
        self.assertFalse(f['new_counter_api_exists'])
        self.assertEqual(f['rows'],137250)
        self.assertEqual(f['rows_per_owner'],[42750,47250,47250])
        self.assertEqual(f['distinct_logical_width_value_counter_states'],18000)
        for owner,site in zip(json.loads((subject.PACKET/'owners.json').read_text()),subject.SITES):
            a,b,_,_=site;raw=self.data[self.image.file_offset(a):self.image.file_offset(a)+b-a]
            self.assertEqual(self.image.fde_of(a),(a,b))
            self.assertEqual(raw.hex(),owner['raw_hex'])
            self.assertEqual(hashlib.sha256(raw).hexdigest(),owner['body_sha256'])
            self.assertEqual(sum(len(bytes.fromhex(i['bytes'])) for i in owner['instructions']),b-a)

    def test_frozen_smoke_rows_are_actual_instruction_states(self):
        rows=(subject.PACKET/'target-smoke.tsv').read_text().splitlines()
        self.assertEqual(len(rows),25)
        for row in rows:
            f=row.split('\t');actual,_=subject.evaluate(self.image,*map(int,f[:4]))
            self.assertEqual(actual,'\t'.join(f[4:]),row)
        for which in range(3):
            answer,_=subject.evaluate(self.image,which,251,subject.cpu.U64-1,255)
            self.assertEqual(answer,f'P\t{subject.cpu.U64}\t85')

    def test_actual_byte_controls_change_outcomes_and_full_body_bindings(self):
        for c in json.loads((subject.PACKET/'native-controls.json').read_text()):
            changed=bytearray(self.data);off=self.image.file_offset(int(c['va'],16))
            self.assertEqual(changed[off],c['old']);changed[off]=c['new']
            private=subject.cpu.Image(bytes(changed))
            self.assertEqual(subject.evaluate(self.image,*c['inputs'])[0],c['before'])
            self.assertEqual(subject.evaluate(private,*c['inputs'])[0],c['after'])
            self.assertNotEqual(c['before'],c['after'])
            a,b,_,_=subject.SITES[c['inputs'][0]];start=self.image.file_offset(a)
            self.assertNotEqual(self.data[start:start+b-a],changed[start:start+b-a])

    def test_selected_machine_rejects_calls_and_unqualified_memory(self):
        m=subject.Machine(self.image)
        with self.assertRaisesRegex(ValueError,'all calls forbidden'):m.call(0,0)
        with self.assertRaisesRegex(ValueError,'unqualified memory'):m.load(subject.cpu.INPUT+8,1)
        with self.assertRaisesRegex(ValueError,'unqualified memory'):m.store(subject.cpu.OUT+8,1,0)

    def test_bad_identity_stops_before_compilation_or_outputs(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);bad=root/'bad';bad.write_bytes(b'bad capture')
            with mock.patch.object(subprocess,'check_output',side_effect=AssertionError('compiler called')):
                with self.assertRaisesRegex(ValueError,'pinned node94 identity'):
                    subject.build(bad,root/'rustc',root/'out')
            self.assertFalse((root/'out').exists())
