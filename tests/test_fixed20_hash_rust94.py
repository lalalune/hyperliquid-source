"""Native byte authentication and replay of real supplied-seed Rust comparisons."""
import base64
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT/'research/work-items/RE-007-fixed20-hash-rust-94'
SPEC = importlib.util.spec_from_file_location('fixed20_hash_observed94', PACKET/'observed.py')
observed = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(observed)


class Fixed20HashRust94(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report, cls.streams = observed.load()
        cls.temporary = tempfile.TemporaryDirectory(prefix='fixed20-test-inputs-')
        cls.snapshot = observed.extract_snapshot(Path(cls.temporary.name)/'fixed', cls.report)
        cls.recipe = observed.module(PACKET/'verify.py', 'fixed20_guarded_recipe')

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def audit(self, report=None, streams=None):
        return observed.audit(self.report if report is None else report,
                              self.streams if streams is None else streams, self.snapshot)

    def rewrite_output(self, report, streams, label, raw):
        streams[label]['stdout'] = base64.b64encode(raw).decode()
        next(c for c in report['commands'] if c['label'] == label)['stdout_sha256'] = observed.sha(raw)

    def test_actual_native_bytes_and_twenty_coordinate_controls(self):
        native = observed.module(PACKET/'native.py', 'fixed20_native_identity')
        raw, frozen = native.check()
        data = bytearray(raw)
        elf = native.Elf(data)
        self.assertEqual(len(frozen['controls']), 20)
        for control in frozen['controls']:
            mutation = control['planned_corruption']
            offset = elf.off(int(mutation['va'], 16))
            old = data[offset]
            self.assertEqual(old, int(mutation['old'], 16))
            data[offset] = int(mutation['new'], 16)
            with self.assertRaisesRegex(ValueError, 'native coordinate changed'):
                native.structural(data, frozen)
            data[offset] = old
        # These are coordinate/body identity controls, not arithmetic execution.
        offset = elf.off(0x399c8e4)
        data[offset] ^= 1
        with self.assertRaisesRegex(ValueError, 'body changed'):
            native.structural(data, frozen)

    def test_pre_source_hash_and_synthetic_table_expectations(self):
        rows, controls, stimulus, expected, comp_input, comp_expected = observed.expectations(self.snapshot)
        self.assertEqual((len(rows), len(controls)), (990, 13))
        self.assertEqual((len(stimulus), len(expected), len(comp_input), len(comp_expected)),
                         (39612, 11892, 1425612, 43572))
        self.assertEqual(rows[2]['expected'], 0x639e355ae68c0100)
        self.assertEqual(self.report['whole_lookup_admitted_vectors'], 0)

    def test_retained_compiled_outputs_and_distinct_control_classes(self):
        actual = self.audit()
        self.assertEqual((actual['hash_observations'], actual['composition_observations']), (3960, 7920))
        self.assertEqual((actual['normal_wrong_hash_mutants'], actual['normal_join_controls'],
                          actual['driver_framing_policy_controls']), (13, 1, 3))
        self.assertEqual(actual['component_tests_by_opt'], {'0': 41, '3': 41})

    def test_recorded_compiler_tree_and_selected_current_sources(self):
        self.recipe.authentic(self.snapshot, self.report['source_freeze_sha256'])
        self.assertTrue(observed.check_selected_sources(self.snapshot))
        self.assertIn('repo/src/node94-margin-risk/tests/hash20_vectors.rs', self.report['frozen']['manifest'])
        self.assertEqual((self.snapshot/'verify.py').read_bytes(), (PACKET/'verify.py').read_bytes())
        with tempfile.TemporaryDirectory(prefix='fixed20-pre-source-') as directory:
            context = self.recipe.extract_context(Path(directory)/'context')
            self.assertEqual(self.recipe.tree(context), self.recipe.tree(self.snapshot/'context'))
        for name in ['PRE-RUST-FREEZE.json', 'COMPOSITION-FREEZE.json']:
            self.assertEqual((PACKET/name).read_bytes(), (self.snapshot/'data'/name).read_bytes())

    def test_source_fixture_input_expected_and_extra_file_identity_controls(self):
        names = ['repo/src/node94-margin-risk/src/hash20.rs',
                 'repo/src/node94-margin-risk/tests/hash20_vectors.rs',
                 'data/input.bin', 'data/expected.bin']
        for name in names:
            path = self.snapshot/name
            raw = path.read_bytes()
            path.write_bytes(raw+b'\0')
            try:
                with self.assertRaisesRegex(ValueError, 'compiler/input snapshot changed'):
                    self.recipe.authentic(self.snapshot, self.report['source_freeze_sha256'])
            finally:
                path.write_bytes(raw)
        extra = self.snapshot/'repo/src/node94-margin-risk/src/untracked.rs'
        extra.write_text('// undeclared compiler input\n')
        try:
            with self.assertRaisesRegex(ValueError, 'compiler/input snapshot changed'):
                self.recipe.authentic(self.snapshot, self.report['source_freeze_sha256'])
        finally:
            extra.unlink()

    def test_changed_hash_rejected_below_stream_identity(self):
        report, streams = copy.deepcopy(self.report), copy.deepcopy(self.streams)
        label = 'o0-r0-hash-run'
        raw = bytearray(base64.b64decode(streams[label]['stdout']))
        raw[16] ^= 1  # Keep header, case ID and shape valid; alter only H.
        self.rewrite_output(report, streams, label, raw)
        report['profiles'][0]['hash']['output_sha256'] = observed.sha(raw)
        with self.assertRaisesRegex(ValueError, 'compiled hash normal value mismatch'):
            self.audit(report, streams)

    def test_non_distinguishing_math_mutant_rejected_below_stream_identity(self):
        report, streams = copy.deepcopy(self.report), copy.deepcopy(self.streams)
        control = report['source_mutants'][0]
        expected = (self.snapshot/'data/expected.bin').read_bytes()
        witness = control['witness']
        raw = expected[:8]+(1).to_bytes(4, 'little')+expected[12+12*witness:24+12*witness]
        label = control['name']+'-driver-run'
        self.rewrite_output(report, streams, label, raw)
        control['actual_sha256'] = observed.sha(raw)
        with self.assertRaisesRegex(ValueError, 'pre-source normal wrong-u64 witness'):
            self.audit(report, streams)

    def test_non_distinguishing_join_rejected_below_stream_identity(self):
        report, streams = copy.deepcopy(self.report), copy.deepcopy(self.streams)
        expected = (self.snapshot/'data/composition-expected.bin').read_bytes()
        raw = expected[:8]+(1).to_bytes(4, 'little')+expected[12+4*22:12+5*22]
        self.rewrite_output(report, streams, 'composition-wiring-run', raw)
        report['composition_wiring_control']['actual_sha256'] = observed.sha(raw)
        with self.assertRaisesRegex(ValueError, 'unchanged-H normal selection distinction'):
            self.audit(report, streams)

    def test_framing_partial_output_rejected_below_stream_identity(self):
        report, streams = copy.deepcopy(self.report), copy.deepcopy(self.streams)
        self.rewrite_output(report, streams, 'hash-trailing', b'K20OUT01')
        with self.assertRaisesRegex(ValueError, 'framing policy output/stimulus changed'):
            self.audit(report, streams)


if __name__ == '__main__':
    unittest.main()
