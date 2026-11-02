"""Synthetic captured-arithmetic corpus, native controls and build admission."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import hash20_rust as subject


class Hash20RustTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected=subject.oracle()

    def test_frozen_expectations_precede_rust_and_regenerate(self):
        freeze=json.loads((subject.PACKET/'PRE-RUST-FREEZE.json').read_text())
        self.assertFalse(freeze['rust_source_exists'])
        self.assertEqual(freeze['input_sha256'],subject.sha(self.expected['inputs']))
        self.assertEqual(freeze['expected_sha256'],subject.sha(self.expected['expected']))
        self.assertEqual((subject.COMPONENT/'target-smoke.tsv').read_bytes(),self.expected['smoke'])
        self.assertEqual(json.loads((subject.PACKET/'native-records.json').read_text()),self.expected['record'])
        self.assertEqual((self.expected['count'],self.expected['distinct_inputs']),(20756,20676))

    def test_domains_are_fixed_twenty_bytes_and_explicit_public_seed_words(self):
        cases=subject.stimuli()
        self.assertTrue(all(len(message)==20 and len(seed)==2 for seed,message in cases))
        self.assertTrue(all(0<=word<=subject.native.MASK for seed,_ in cases for word in seed))
        self.assertEqual(len(cases[:20480]),4*20*256)
        self.assertTrue(self.expected['authorized_offline_Python_captured_arithmetic_interpreter'])

    def test_actual_rotations_and_constant_change_interpreted_hashes(self):
        controls=subject.target_controls()
        self.assertEqual(len(controls),3)
        for row in controls:
            self.assertEqual(row['expected'],'639e355ae68c0100')
            self.assertNotEqual(row['expected'],row['mutated'])
            self.assertTrue(row['authorized_offline_Python_instruction_evaluation'])
            self.assertFalse(row['native_capture_launched'])

    def test_wrong_identity_existing_output_and_changed_freeze_precede_compiler(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);bad=root/'bad';bad.write_bytes(b'not the node')
            with mock.patch.object(subject.subprocess,'check_output',side_effect=AssertionError('compiler ran')):
                with self.assertRaisesRegex(ValueError,'identity mismatch'):
                    subject.build(bad,root/'compiler',root/'new')
            self.assertFalse((root/'new').exists())
            with mock.patch.object(subject,'oracle',side_effect=AssertionError('target opened')):
                with self.assertRaisesRegex(ValueError,'must be new'):
                    subject.build(bad,root/'compiler',root)
            freeze=json.loads((subject.PACKET/'PRE-RUST-FREEZE.json').read_text())
            freeze['expected_sha256']='0'*64
            (root/'PRE-RUST-FREEZE.json').write_text(json.dumps(freeze))
            with mock.patch.object(subject,'PACKET',root),mock.patch.object(subject,'oracle',return_value=self.expected), \
                 mock.patch.object(subject.subprocess,'check_output',side_effect=AssertionError('compiler ran')):
                with self.assertRaisesRegex(ValueError,'corpus identity differs'):
                    subject.build(subject.TARGET,root/'compiler',root/'new')
            self.assertFalse((root/'new').exists())
