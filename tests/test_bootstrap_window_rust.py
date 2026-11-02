"""Frozen native interval corpus and compiler admission; builds run explicitly."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import bootstrap_window_rust as subject


class BootstrapRustTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result=subject.oracle()

    def test_native_expected_corpus_is_frozen_before_production_source(self):
        freeze=json.loads((subject.PACKET/'FREEZE.json').read_text())
        self.assertFalse(freeze['production_source_exists'])
        self.assertTrue(freeze['unvalidated_draft_existed'])
        self.assertEqual((self.result['count'],self.result['distinct_inputs']),(106649,106649))
        self.assertEqual(subject.sha(self.result['inputs']),freeze['input_sha256'])
        self.assertEqual(subject.sha(self.result['expected']),freeze['expected_sha256'])
        self.assertEqual(self.result['record'],json.loads((subject.PACKET/'native-records.json').read_text()))

    def test_actual_native_immediate_edits_change_both_ordinary_and_saturated_windows(self):
        controls=json.loads(json.dumps(self.result['controls']))
        self.assertEqual(controls,json.loads((subject.PACKET/'native-controls.json').read_text()))
        self.assertEqual(controls[0]['after']['window'],[1,99])
        self.assertEqual(controls[1]['after']['window'][-1],subject.native.MASK-1)
        self.assertEqual(controls[2]['after']['window'][-1],0)
        self.assertTrue(all(row['before']!=row['after'] for row in controls))

    def test_changed_frozen_corpus_is_rejected_before_compiler(self):
        changed=dict(self.result,expected=b'wrong\n')
        with tempfile.TemporaryDirectory() as temp:
            out=Path(temp)/'new'
            with mock.patch.object(subject,'oracle',return_value=changed), \
                 mock.patch.object(subject.subprocess,'check_output',side_effect=AssertionError('compiler invoked')):
                with self.assertRaisesRegex(ValueError,'frozen expectations differ'):
                    subject.build(Path(temp)/'input',Path(temp)/'compiler',out)
            self.assertFalse(out.exists())
            with mock.patch.object(subject,'oracle',side_effect=AssertionError('target reopened')):
                with self.assertRaisesRegex(ValueError,'output must be new'):
                    subject.build(Path(temp)/'input',Path(temp)/'compiler',Path(temp))

    def test_unknown_target_instruction_and_out_of_domain_values_fail_closed(self):
        code=bytes.fromhex(subject.native.PATTERNS[subject.native.LOWER])
        with self.assertRaisesRegex(ValueError,'Unmodelled'):
            subject.native.lower(b'\x90'+code[1:],0,1)
        for current,target in [(-1,0),(0,1<<64),(True,1)]:
            with self.assertRaises(ValueError):
                subject.native.lower(code,current,target)
