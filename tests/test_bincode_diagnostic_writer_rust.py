"""Fresh native-contract transcript/oracle controls; actual Rust builds are separate."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'tools'))
import bincode_diagnostic_writer_rust as rust


class DiagnosticWriterOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected = rust.oracle()

    def test_fresh_authenticated_contract_and_transcript_fixture(self):
        expected = self.expected
        rust.verify_fixture(expected)
        self.assertEqual(len(expected['cases']), 3023)
        self.assertEqual(rust.sha(expected['fixture']),
                         '0948969e5bd003de115a77092a50bc69c58622bf4025231cbd5d34be9ae64134')
        self.assertEqual(expected['metadata']['adapter_sha256'],
                         'd62080d0724a750e0162d6a0563c7a056ae76e2212fd48310f89bcf8809dfde4')
        self.assertEqual(expected['facts']['indentation']['bytes_hex'], '20202020')
        self.assertEqual(expected['record']['used_adapter_contract']['write_protocol']['flag_store']['order'],
                         'before payload callback')
        # Input-only production lines contain neither expected status nor request trace.
        self.assertNotIn(b'\t', expected['inputs'])
        self.assertEqual(len(expected['inputs'].splitlines()), len(expected['expected'].splitlines()))

    def test_independent_manual_flag_order_error_empty_and_byte_transcripts(self):
        examples = [
            ((b'', 255, (), (0, None)), 'c0000;0;255;0;'),
            ((b'\n', 0, (), (0, None)), 'c0000;0;1;1;0:0a:1:0:-'),
            ((b'    ', 0, (), (0, None)), 'c0000;0;0;1;0:20202020:0:0:-'),
            ((b'\n', 2, ((255, 128),), (0, None)), 'c0000;1;128;1;0:20202020:2:255:128'),
            ((b'a', 0, ((128, 255),), (0, None)), 'c0000;1;255;1;0:61:0:128:255'),
            ((b'a\nb', 128, ((0, 255), (0, 0), (0, 255)), (0, None)),
             'c0000;0;255;3;0:20202020:128:0:255,1:610a:1:0:0,2:62:0:0:255'),
            ((b'\n\n', 255, ((0, 0), (0, 0), (0, 128)), (0, None)),
             'c0000;0;128;3;0:20202020:255:0:0,1:0a:1:0:0,2:0a:1:0:128'),
            ((b'\x00\xff\x80\r', 0, (), (0, None)), 'c0000;0;0;1;0:00ff800d:0:0:-')]
        for case, wanted in examples:
            self.assertEqual(rust.transcript(0, case, self.expected['facts']), wanted)
        # Defaults make unexpected extra requests observable, not indexing panics.
        self.assertIn('|0:-', rust.stimulus_line(0, examples[0][0]))

    def test_edited_or_empty_expected_fixture_cannot_replace_fresh_native_relation(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'vectors.tsv'
            for raw in (b'', self.expected['fixture'].replace(b';0;', b';1;', 1)):
                path.write_bytes(raw)
                with self.assertRaisesRegex(ValueError, 'fixture differs'):
                    rust.verify_fixture(self.expected, path)

    def test_rejected_target_and_existing_output_precede_compiler_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); target = root/'wrong'; target.write_bytes(b'\x7fELF'+bytes(60))
            output = root/'uncreated'
            with mock.patch.object(rust.subprocess, 'run', side_effect=AssertionError('compiler must not run')):
                with self.assertRaisesRegex(ValueError, 'not authenticated node94'):
                    rust.build(target, root/'uninvoked-rustc', output)
            self.assertFalse(output.exists())
            output.mkdir(); marker = output/'retained'; marker.write_bytes(b'previous evidence\n')
            with mock.patch.object(rust, 'oracle', side_effect=AssertionError('no new input for existing output')):
                with self.assertRaisesRegex(ValueError, 'directory must be new'):
                    rust.build(target, root/'uninvoked-rustc', output)
            self.assertEqual(marker.read_bytes(), b'previous evidence\n')
