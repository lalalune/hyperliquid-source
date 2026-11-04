import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import packed_word_step115_rust as subject

RUSTC = os.environ.get('HYPERLIQUID_PACKED_WORD_RUSTC')


class PackedWordStepTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (subject.ROOT / subject.BINARY).read_bytes()
        cls.record = subject.native_record(cls.data)
        cls.params = cls.record['parameters']

    def test_actual_native_owners_and_state_offsets(self):
        owners = self.record['owners']
        self.assertEqual([(x['bytes'], x['instructions']) for x in owners], [(409, 101), (1402, 255)])
        self.assertEqual([self.params[k] for k in ('state_read_offset', 'state_init_offset', 'cas_offset')], [48] * 3)

    def test_corrupted_native_operand_is_rejected_below_identity(self):
        changed = bytearray(self.data)
        offset, _ = subject.native.read(self.data, 0x4770f85, 1)
        changed[offset] = 255
        self.assertNotEqual(subject.native.parameters(changed)['delta'], self.params['delta'])
        with self.assertRaises(ValueError):
            subject.native.analyze(changed)

    def test_capacity_boundary_and_retries_recheck_both_gates(self):
        self.assertEqual(subject.expected_init(self.params, (1 << 61) - 1), [1, (1 << 62) - 2])
        self.assertEqual(subject.expected_init(self.params, 1 << 61), [0])
        self.assertEqual(subject.expected_step(self.params, 4, (6,)), [2, 4, [[4, 6, 2, False], [6, 6, 4, True]]])
        self.assertEqual(subject.expected_step(self.params, 4, (6, 1)), [0, 1, [[4, 6, 2, False], [6, 1, 4, False]]])
        self.assertEqual(subject.expected_step(self.params, 4, (0,)), [1, 0, [[4, 0, 2, False]]])

    def test_captured_artifact_rejected_before_object_decode_or_compiler_dispatch(self):
        artifact = subject.ROOT / subject.BINARY
        with self.assertRaises(ValueError):
            subject.own_machine(artifact, 'step')
        with patch.object(subject.subprocess, 'run', side_effect=AssertionError('unexpected dispatch')):
            with self.assertRaisesRegex(ValueError, 'Captured artifact'):
                subject.verify(artifact, subject.ROOT / 'work/forbidden-permit')

    def test_retained_source_hashes_and_observed_case_counts(self):
        recorded = json.loads((subject.PACKET / 'rust-validation.json').read_bytes())
        self.assertEqual(recorded['native'], self.record)
        for name, digest in recorded['source_sha256'].items():
            self.assertEqual(hashlib.sha256((subject.CRATE / name).read_bytes()).hexdigest(), digest)
        self.assertEqual(hashlib.sha256(Path(subject.__file__).read_bytes()).hexdigest(), recorded['checker_sha256'])
        self.assertEqual((recorded['initialization_cases'], recorded['step_cases'], recorded['observed_failed_cas']), (1047, 10470, 6784))
        self.assertFalse(recorded['captured_executed'])

    @unittest.skipUnless(RUSTC, 'Explicit HYPERLIQUID_PACKED_WORD_RUSTC required')
    def test_actual_compiler_retry_transcripts_and_mutations(self):
        root = subject.ROOT / 'work/permit-rust-tests'
        root.mkdir(parents=True, exist_ok=True)
        out = Path(tempfile.mkdtemp(dir=root)) / 'comparison'
        actual = subject.verify(RUSTC, out)
        old = json.loads((subject.PACKET / 'rust-validation.json').read_bytes())
        for key in ('raw_comparisons_sha256', 'step_code_sha256', 'init_code_sha256',
                    'compiled_controls', 'native_operand_controls', 'mismatches'):
            self.assertEqual(actual[key], old[key], key)
        self.assertEqual(len(actual['compiled_controls']), 6)
        self.assertEqual(len(actual['native_operand_controls']), 4)


if __name__ == '__main__':
    unittest.main()
