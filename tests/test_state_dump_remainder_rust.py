"""Target-backed oracle/fixture/CLI controls; actual Rust builds have their runner."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import state_dump_remainder_rust as rust


class ScalarRemainderOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected=rust.oracle()

    def test_fresh_target_equations_reproduce_Rust_corpus(self):
        rust.verify_fixture(self.expected)
        metadata=self.expected['metadata']
        self.assertEqual(metadata['case_count'],1906)
        self.assertEqual(metadata['fixture_sha256'],'0cfbef1de59d1bd8f2be84aece1b5a5a220a645bd1facbc223b6d023d7ac8903')
        self.assertEqual(metadata['whole_i64_algebra']['delta'],12928)
        selected=dict(self.expected['rows'])
        for value,wanted in ((-(1<<63),30592),(-86400,0),(-1,86399),(0,0),
                             (65536,65536),(86400,0),((1<<63)-1,55807)):
            self.assertEqual(selected[value],wanted)
        self.assertEqual(self.expected['record']['proof']['normal_return_conditions'][0],
                         'raw previous-helper status != excluded_status')

    def test_edited_or_empty_fixture_cannot_replace_fresh_oracle(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'target-vectors.tsv'
            for raw in (b'',self.expected['fixture'].replace(b'\t30592\n',b'\t0\n',1)):
                path.write_bytes(raw)
                with self.assertRaisesRegex(ValueError,'fixture differs'):
                    rust.verify_fixture(self.expected,path)
        # This is not a hash re-pin: the real target equations regenerate values.

    def test_actual_magic_shift_sign_mutations_change_values_before_rejection(self):
        controls=rust.target_controls(self.expected)
        self.assertEqual(len(controls),3)
        self.assertEqual(controls[0]['expected'],0)
        self.assertEqual(controls[0]['mutated_expression_result'],86400)
        for row in controls:
            self.assertTrue(row['semantic_difference'])
            self.assertNotEqual(row['expected'],row['mutated_expression_result'])
            self.assertFalse(row['captured_target_executed_or_modified'])

    def test_rejected_target_and_prior_output_precede_compiler_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);wrong=root/'wrong-node';wrong.write_bytes(b'\x7fELF'+bytes(60))
            output=root/'absent-report'
            with mock.patch.object(rust.subprocess,'check_output',side_effect=AssertionError('compiler must not run')):
                with self.assertRaisesRegex(ValueError,'Node94 identity mismatch'):
                    rust.build(wrong,root/'uninvoked-rustc',output)
            self.assertFalse(output.exists())
            output.mkdir();marker=output/'retained';marker.write_bytes(b'previous evidence\n')
            with mock.patch.object(rust,'oracle',side_effect=AssertionError('must not reopen input for existing output')):
                with self.assertRaisesRegex(ValueError,'directory must be new'):
                    rust.build(wrong,root/'uninvoked-rustc',output)
            self.assertEqual(marker.read_bytes(),b'previous evidence\n')
