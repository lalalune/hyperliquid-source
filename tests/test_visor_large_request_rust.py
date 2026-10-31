"""Native-bound interval and admission controls; actual Rust has a real build runner."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'tools'))
import visor_large_request_rust as rust


class VisorScalarClassOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected = rust.oracle()

    def test_fresh_native_partition_and_numeric_corpus(self):
        expected = self.expected
        rust.verify_fixtures(expected)
        self.assertEqual(len(expected['intervals']), 203)
        self.assertEqual(expected['intervals'][0], (4097, 5120, 29))
        self.assertEqual(expected['intervals'][-1], (0x6000000000000001, rust.UPPER, 231))
        self.assertEqual(expected['record']['proof']['constants']['class_bias'], -23)
        selected = dict(expected['rows'])
        for value, wanted in ((0, None), (4096, None), (4097, 29), (5120, 29),
                              (5121, 30), (8192, 32), (8193, 33),
                              (rust.UPPER, 231), (rust.UPPER+1, None), (rust.MAX64, None)):
            self.assertEqual(selected[value], wanted)
        self.assertEqual(expected['metadata']['case_count'], len(set(selected)))
        self.assertEqual(expected['metadata']['case_count'], 1876)
        self.assertEqual(expected['metadata']['fixture_sha256'],
                         '565c082a2d82e5ca7db3cc41fe20937aafb73c0479b740a089f022368ce01196')
        self.assertGreater(expected['metadata']['some_cases'], 1000)
        self.assertGreater(expected['metadata']['chosen_None_cases'], 256)
        self.assertIn('chosen numeric proof domain', expected['metadata']['None_meaning'])

    def test_retained_answer_edits_cannot_replace_fresh_native_oracle(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); vectors = root/'vectors.tsv'; native = root/'intervals.tsv'
            vectors.write_bytes(self.expected['fixture']); native.write_bytes(self.expected['interval_tsv'])
            rust.verify_fixtures(self.expected, vectors, native)
            for bad in (b'', self.expected['fixture'].replace(b'4097\t29\n', b'4097\t30\n', 1)):
                vectors.write_bytes(bad)
                with self.assertRaisesRegex(ValueError, 'vectors differ'):
                    rust.verify_fixtures(self.expected, vectors, native)
            vectors.write_bytes(self.expected['fixture'])
            native.write_bytes(self.expected['interval_tsv'].replace(b'4097\t5120\t29', b'4097\t5120\t30', 1))
            with self.assertRaisesRegex(ValueError, 'intervals differ'):
                rust.verify_fixtures(self.expected, vectors, native)

    def test_actual_raw_bias_and_request_guards_have_counterexamples(self):
        controls = rust.target_controls(self.expected)
        self.assertEqual(len(controls), 3)
        self.assertEqual(controls[0]['original_class'], 29)
        self.assertEqual(controls[0]['counterfactual_interval_class_or_outside'], 30)
        for row in controls:
            self.assertTrue(row['different'])
            self.assertFalse(row['captured_target_executed_or_modified'])
            self.assertTrue(row['admission_rejection'])

    def test_wrong_target_and_existing_output_precede_any_compiler_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); wrong = root/'wrong-visor'; wrong.write_bytes(b'\x7fELF'+bytes(60))
            report = root/'uncreated'
            with mock.patch.object(rust.subprocess, 'run', side_effect=AssertionError('compiler must not run')):
                with self.assertRaisesRegex(ValueError, 'visor input size differs'):
                    rust.build(wrong, root/'uninvoked-rustc', report)
            self.assertFalse(report.exists())
            report.mkdir(); marker = report/'retained'; marker.write_bytes(b'previous evidence\n')
            with mock.patch.object(rust, 'oracle', side_effect=AssertionError('must not open target for old output')):
                with self.assertRaisesRegex(ValueError, 'directory must be new'):
                    rust.build(wrong, root/'uninvoked-rustc', report)
            self.assertEqual(marker.read_bytes(), b'previous evidence\n')
