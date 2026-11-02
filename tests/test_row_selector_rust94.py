"""Replay actual Rust output and attack its independent posthash comparator."""
import base64
import contextlib
import copy
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT/'research/work-items/RE-007-row-selector-rust-94'
SPEC = importlib.util.spec_from_file_location('row_selector_observed94', PACKET/'observed.py')
observed = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(observed)


class RowSelectorRust94(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report, cls.streams = observed.load()
        cls.recipe = observed.module('prepare_selector')

    def test_retained_real_output_and_distinct_denominators(self):
        actual = observed.audit(self.report, self.streams)
        self.assertEqual((actual['qualified_posthash_cases'], actual['chosen_policy_cases']), (894, 7))
        self.assertEqual((actual['posthash_observations'], actual['policy_observations']), (3576, 28))
        self.assertEqual((actual['native_normal_value_mutants'], actual['chosen_api_label_mutants']), (10, 3))
        self.assertEqual(actual['component_tests_by_opt'], {'0': 40, '3': 40})

    def test_exact_recorded_compiler_input_snapshot(self):
        self.assertTrue(observed.check_recorded_snapshot(self.report))

    def test_source_input_fixture_and_extra_file_corruption_controls(self):
        comparator = observed.module('compare_selector')
        with tempfile.TemporaryDirectory(prefix='selector-test-freeze-') as temporary:
            snapshot = Path(temporary)/'fixed'
            observed.extract_recorded_snapshot(snapshot, self.report)
            result = comparator.self_check(snapshot, self.report['freeze_sha256'])
            self.assertEqual(len(result['rejected_controls']), 14)
            self.assertIn('external-include-fixture', result['rejected_controls'])
            self.assertIn('extra-untracked-input', result['rejected_controls'])

    def test_changed_result_rejected_below_stream_identity(self):
        report, streams = copy.deepcopy(self.report), copy.deepcopy(self.streams)
        label = 'o0-r0-driver-run'
        raw = bytearray(base64.b64decode(streams[label]['stdout']))
        raw[17] ^= 1  # First case's late-state predicate; keep framing valid.
        streams[label]['stdout'] = base64.b64encode(raw).decode()
        digest = observed.sha(raw)
        next(c for c in report['commands'] if c['label'] == label)['stdout_sha256'] = digest
        report['builds'][0]['output_sha256'] = digest
        with self.assertRaisesRegex(ValueError, 'compiled baseline value mismatch'):
            observed.audit(report, streams)

    def test_non_distinguishing_mutant_rejected_below_stream_identity(self):
        report, streams = copy.deepcopy(self.report), copy.deepcopy(self.streams)
        control = report['native_relation_source_mutants'][0]
        rows = self.recipe.cases()
        raw = self.recipe.expected_bytes([rows[control['witness_id']]])
        label = control['name']+'-driver-run'
        streams[label]['stdout'] = base64.b64encode(raw).decode()
        digest = observed.sha(raw)
        next(c for c in report['commands'] if c['label'] == label)['stdout_sha256'] = digest
        control['output_sha256'] = digest
        with self.assertRaisesRegex(ValueError, 'mutant value distinction missing'):
            observed.audit(report, streams)

    def test_native_and_wrapper_metadata_remain_separate(self):
        native = self.recipe.cases()
        policies = self.recipe.policy_cases(len(native))
        self.assertTrue(all(c['scope'].startswith('conditional posthash') for c in native))
        self.assertTrue(all(c['expected']['choice'] == 'ApiError' for c in policies))
        self.assertEqual(self.report['frozen']['whole_lookup_native_hash_admissible_cases'], 0)
        record = observed.module('check_freeze')
        anchors, _ = record.load_frozen()
        data = (ROOT/'artifacts/node/94/hl-node').read_bytes()
        self.assertEqual(record.hashlib.sha256(data).hexdigest(), record.TARGET_SHA)
        record.structural(data, anchors)
        self.assertEqual(len(anchors['anchors']), 21)


if __name__ == '__main__':
    unittest.main()
