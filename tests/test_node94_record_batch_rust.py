"""Target-grounded scalar oracle/corpus/protocol controls; no captured execution."""
import copy
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import node94_record_batch_rust as batch


class BatchScalarOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected = batch.oracle()

    def result(self, d, remaining, outputs=(0, 0, 0, 0), lower=0):
        values = ((lower + d) & batch.MASK, lower, *outputs,
                  *((o + r) & batch.MASK for o, r in zip(outputs, remaining)))
        return batch.scalar_value(self.expected['report'], values)

    def test_fresh_native_scalar_terms_reproduce_checked_in_vectors(self):
        batch.verify_fixture(self.expected)
        self.assertEqual(len(self.expected['values']), 3288)
        self.assertEqual(len(set(self.expected['values'])), 3288)
        self.assertEqual(batch.sha(self.expected['fixture']),
                         '424201675c7fed5e9b5b66115b29ecab7a3b1c9318d75f00a0dc8d05726d6885')
        self.assertEqual(self.expected['metadata']['target_sha256'], batch.static.DIGEST)
        self.assertEqual(self.expected['report']['candidate']['bytes'], 1269)
        self.assertEqual(self.expected['report']['cfg']['instructions'], 324)

    def test_each_lane_is_a_real_independent_limiter(self):
        for lane in range(4):
            remaining = [batch.MASK] * 4
            remaining[lane] = 10
            self.assertEqual(self.result(batch.MASK, remaining), (1, 5, 0), lane)
            remaining[lane] = 9
            self.assertEqual(self.result(batch.MASK, remaining), (0, 0, 1), lane)
        self.assertEqual(self.result(6, [batch.MASK] * 4), (0, 0, 1))
        self.assertEqual(self.result(7, [batch.MASK] * 4), (1, 5, 0))

    def test_modular_underflow_extremes_and_nonzero_stop_wrap(self):
        # Both input0<L and every end<output are intentionally raw modular inputs.
        result = batch.scalar_value(self.expected['report'], (0, 1, 1, 1, 1, 1, 0, 0, 0, 0))
        self.assertEqual(result, (1844674407370955161, 9223372036854775806, 0))
        self.assertEqual(self.result(7, [10] * 4, [batch.MASK - 4] * 4), (1, 0, 0))
        self.assertEqual(self.result(0, [batch.MASK] * 4, [batch.MASK] * 4),
                         (0, batch.MASK, 1))

    def test_expected_scalar_dag_refuses_unbound_memory_and_wrong_word_domain(self):
        changed = copy.deepcopy(self.expected['report'])
        quotient = changed['terms'][changed['quotient_term']]
        quotient.update(op='load', args=[changed['quotient_term'] - 1])
        with self.assertRaisesRegex(ValueError, 'Unbound or non-scalar'):
            batch.scalar_value(changed, (7, 0, 0, 0, 0, 0, 10, 10, 10, 10))
        for words in ((-1,) * 10, (batch.MASK + 1,) * 10, (0,) * 9):
            with self.assertRaisesRegex(ValueError, 'ten raw u64'):
                batch.scalar_value(self.expected['report'], words)

    def test_reciprocal_operand_edits_change_result_before_validation(self):
        controls = batch.target_controls(self.expected)
        self.assertEqual([r['name'] for r in controls], ['M7-minus-one', 'M10-minus-one'])
        for row in controls:
            self.assertEqual((row['original_quotient'], row['changed_quotient']), (1, 0))
            self.assertIn('source operands changed', row['rejection'])
            self.assertFalse(row['captured_target_modified_or_executed'])

    def test_empty_or_edited_fixture_cannot_supply_expected_results(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Path(temporary) / 'fixture.tsv'
            for raw in (b'', self.expected['fixture'].replace(b'\t0\t0\t1\n', b'\t1\t5\t0\n', 1)):
                self.assertNotEqual(raw, self.expected['fixture'])
                fixture.write_bytes(raw)
                with self.assertRaisesRegex(ValueError, 'Fixture differs'):
                    batch.verify_fixture(self.expected, fixture)

    def test_wrong_target_and_existing_output_fail_before_compiler(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            wrong = parent / 'wrong-node'
            wrong.write_bytes(b'\x7fELF' + bytes(60))
            output = parent / 'new-output'
            with mock.patch.object(batch.subprocess, 'check_output', side_effect=AssertionError('compiler must not run')):
                with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
                    batch.build(wrong, parent / 'unused-rustc', output)
            self.assertFalse(output.exists())
            output.mkdir()
            marker = output / 'retained'
            marker.write_bytes(b'prior evidence\n')
            with mock.patch.object(batch, 'oracle', side_effect=AssertionError('existing output must be checked first')):
                with self.assertRaisesRegex(ValueError, 'directory must be new'):
                    batch.build(wrong, parent / 'unused-rustc', output)
            self.assertEqual(marker.read_bytes(), b'prior evidence\n')
