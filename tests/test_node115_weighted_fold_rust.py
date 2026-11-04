"""Actual two-span fold, carry controls and explicit post-provider boundary."""
import os
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import node115_weighted_fold_rust as subject
@unittest.skipUnless(os.environ.get('HL_ALLOW_CAPTURED_INSTRUCTION_EVAL') == '1',
                     'captured instruction evaluation requires explicit authorization')
class WeightedFoldRustTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.result=subject.oracle()
    def test_frozen_population_and_full_static_bindings(self):
        f=json.loads((subject.PACKET/'FREEZE.json').read_text())
        self.assertFalse(f['production_source_exists']);self.assertEqual(f['helper_calls'],0)
        self.assertEqual(self.result['rows'],12804)
        self.assertEqual(subject.sha(self.result['inputs']),f['input_sha256'])
        self.assertEqual(subject.sha(self.result['expected']),f['expected_sha256'])
        self.assertEqual(self.result['record'],json.loads((subject.PACKET/'native-records.json').read_text()))
        self.assertEqual(self.result['selected_instructions'],json.loads((subject.PACKET/'selected-instructions.json').read_text()))
        self.assertEqual(len(self.result['selected_instructions']),37)
    def test_native_carry_factor_status_and_condition_controls(self):
        c=json.loads(json.dumps(self.result['controls']))
        self.assertEqual(c,json.loads((subject.PACKET/'native-controls.json').read_text()))
        self.assertEqual(len(c),4);self.assertTrue(all(x['before']!=x['after'] and x['binding_rejected'] for x in c))
    def test_smoke_rows_are_frozen_native_results(self):
        answers=dict(zip(self.result['inputs'].decode().splitlines(),self.result['expected'].decode().splitlines()))
        rows=(subject.PACKET/'target-smoke.tsv').read_text().splitlines();self.assertEqual(len(rows),14)
        self.assertEqual((subject.PACKET/'target-smoke.tsv').read_bytes(),(subject.COMPONENT/'target-smoke.tsv').read_bytes())
        for row in rows:
            f=row.split('\t');self.assertEqual(answers['\t'.join(f[:4])],f[4])
    def test_status_gate_follows_processing_and_memory_is_qualified(self):
        image=subject.Image(subject.native.TARGET.read_bytes())
        answer,trace=subject.evaluate(image,0,1,(1,),(2,))
        self.assertEqual(answer,'0');self.assertIn(0x422e2f0,trace)
        m=subject.Machine(image,1,1)
        with self.assertRaisesRegex(ValueError,'all calls forbidden'):m.call(0)
        with self.assertRaisesRegex(ValueError,'unqualified fold memory'):m.spill(subject.cpu.INPUT,0,8)
        with self.assertRaisesRegex(ValueError,'unqualified fold memory'):m.reload(0,subject.SECOND+32,1)
    def test_bad_capture_stops_before_compiler_or_outputs(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);bad=root/'bad';bad.write_bytes(b'bad capture')
            with mock.patch.object(subprocess,'check_output',side_effect=AssertionError('compiler called')):
                with self.assertRaisesRegex(ValueError,'pinned node115 identity'):subject.build(bad,root/'rustc',root/'out')
            self.assertFalse((root/'out').exists())
