"""Target-grounded static relations; no target/callback instruction execution."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import bincode_diagnostic_field_static as field

PACKET = ROOT / 'research/work-items/RE-005-diagnostic-field-trace-94'
spec = importlib.util.spec_from_file_location('field_counterfactuals', PACKET / 'controls.py')
controls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(controls)
_DATA = None
_PROOF = None
_LEDGER = None


def data():
    global _DATA
    if _DATA is None:
        _DATA = field.TARGET.read_bytes()
    return _DATA


def proof():
    global _PROOF
    if _PROOF is None:
        _PROOF = field.analyze(data())[0]
    return _PROOF


def ledger():
    global _LEDGER
    if _LEDGER is None:
        _LEDGER = controls.run(data())
    return _LEDGER


class FieldContract(unittest.TestCase):
    def test_real_packet_rederives_exactly(self):
        self.assertEqual(json.loads(json.dumps(proof())), json.loads((PACKET / 'observed/records.json').read_text()))

    def test_prior_error_path_has_no_formatter_or_value_access_block(self):
        paths = [p for p in proof()['flat_paths'] if not p['guards'][0]['zero']]
        self.assertEqual(len(paths), 1)
        path = paths[0]
        self.assertEqual(path['blocks'], [field.BASE, field.COMMON])
        self.assertEqual(path['calls'], [])
        self.assertEqual(path['error_origin'], {'kind': 'constant', 'value': 1})
        self.assertEqual(path['ordered_state_stores'], [{'offset': 8, 'source': path['error_origin']},
                                                       {'offset': 9, 'constant': 1}])

    def test_each_writer_error_stops_before_later_calls(self):
        expected = list(field.CALL_ROLES)
        for stage, name in enumerate(['prefix_AL', 'name_AL', 'colon_AL']):
            candidates = [p for p in proof()['flat_paths'] if any(g['value'] == name and not g['zero'] for g in p['guards'])]
            self.assertEqual(len(candidates), 1, name)
            self.assertEqual(candidates[0]['calls'], expected[:stage + 1])
            self.assertEqual(candidates[0]['error_origin'], {'kind': 'constant', 'value': 1})

    def test_value_return_byte_is_not_a_writer_error_normalization(self):
        candidates = [p for p in proof()['flat_paths'] if field.CAPTURE in p['blocks']]
        self.assertEqual(len(candidates), 1)
        path = candidates[0]
        self.assertEqual(path['calls'], list(field.CALL_ROLES))
        self.assertEqual(path['error_origin'], {'kind': 'last_callback_AL', 'call_site': 0x1572009})
        self.assertNotIn('value_AL', [g['value'] for g in path['guards']])
        self.assertEqual(path['ordered_state_stores'][1], {'offset': 9, 'constant': 1})

    def test_prefix_and_colon_are_actual_pointer_length_slices(self):
        facts = proof()['operand_facts']
        self.assertEqual(facts['prefix_choices'], [{'H': 0, 'pointer': 0x252BFB, 'length': 3, 'bytes_hex': '207b20'},
                                                 {'H': 1, 'pointer': 0x252BEF, 'length': 2, 'bytes_hex': '2c20'}])
        self.assertEqual(facts['colon'], {'pointer': 0x252BFE, 'length': 2, 'bytes_hex': '3a20'})
        self.assertEqual(facts['prefix_cmov'], 'ne')
        self.assertEqual(facts['prefix_xor'], 3)

    def test_whole_cfg_inventory_does_not_promote_rendering_or_types(self):
        p = proof()
        self.assertEqual((p['native_instruction_rows'], len(p['cfg']['blocks']), len(p['cfg']['calls'])), (109, 14, 9))
        self.assertTrue(all(not set(path['blocks']) & field.PRETTY for path in p['flat_paths']))
        self.assertTrue(p['pretty_callback_state_contract_qualified_conditionally'])
        self.assertTrue(p['pretty_rendering_unqualified'])
        self.assertTrue(p['callback_alias_frame_preservation_conditions_required'])
        self.assertTrue(p['state_window_is_not_nominal_layout'])
        self.assertFalse(p['concrete_instruction_execution'])
        self.assertFalse(p['runtime_rendering_or_gate_claimed'])

    def test_actual_counterfactuals_preserve_shape_but_break_relations(self):
        result = ledger()
        expected = json.loads((PACKET / 'observed/counterfactuals.json').read_text())
        self.assertEqual(json.loads(json.dumps(result)), expected)
        self.assertEqual(len(result['counterfactuals']), 18)
        self.assertTrue(all(v['shape_equal_to_original'] and v['rejected_by_relation'] for v in result['counterfactuals']))
        self.assertTrue(all(v['span_sha256'] != result['original_span_sha256'] for v in result['counterfactuals']))

    def test_branch_retarget_changes_derived_order_with_equal_call_counts(self):
        row = next(v for v in ledger()['counterfactuals'] if v['name'] == 'prefix-error-continues')
        self.assertEqual(row['shape']['calls'], 9)
        self.assertEqual(row['shape']['rows'], 109)
        self.assertIn('short-circuit', row['rejected_by_relation'])
        self.assertTrue(row['changed_branch_edges'])
        self.assertTrue(any(len(calls) > 1 for calls in row['derived_call_sequences']))

    def test_result_and_store_mutations_are_operand_failures_not_count_guards(self):
        by_name = {r['name']: r for r in ledger()['counterfactuals']}
        for name, message in [('error-store-offset', 'error_store_offset'), ('field-present-store', 'field_store_value'),
                              ('value-result-source', 'capture_source_register_index')]:
            self.assertIn(message, by_name[name]['rejected_by_relation'])
            self.assertTrue(by_name[name]['changed_operand_facts'])

    def test_direct_ret_branch_does_not_invent_skipped_output_witnesses(self):
        body, read = controls.context(data())
        changed = bytearray(body)
        self.assertEqual(changed[0x1571FCA - field.BASE:0x1571FCC - field.BASE], bytes.fromhex('75a1'))
        changed[0x1571FCB - field.BASE] = 0xBA  # Actual JNE target becomes the existing RET.
        result, listing = field.extract_span(bytes(changed), read)
        self.assertEqual(result['native_instruction_rows'], 109)
        self.assertEqual(len(result['cfg']['calls']), 9)
        self.assertEqual(len(result['cfg']['branches']), 12)
        path = next(p for p in result['flat_paths']
                    if any(g['value'] == 'prefix_AL' and not g['zero'] for g in p['guards']))
        self.assertNotIn(field.COMMON, path['blocks'])
        self.assertEqual(path['ordered_state_stores'], [])
        self.assertNotEqual(path['return'], 'original state pointer')
        with self.assertRaisesRegex(field.ContractError, 'output witnesses'):
            field.prove_span(bytes(changed), read)

    def test_wrong_identity_and_truncation_do_not_start_native_proof(self):
        for value in [b'wrong', data()[:128]]:
            with self.assertRaisesRegex(field.ContractError, 'authenticated node94'):
                field.analyze(value)

    def test_existing_output_is_preserved_before_input_access(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / 'retained'
            output.mkdir()
            sentinel = output / 'sentinel'
            sentinel.write_bytes(b'preserve')
            with self.assertRaisesRegex(field.ContractError, 'Existing evidence'):
                field.generate(Path(folder) / 'missing-input', output)
            self.assertEqual(sentinel.read_bytes(), b'preserve')

    def test_actual_cli_success_and_wrong_input_output_boundary(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / 'actual'
            argv = [sys.executable, '-B', str(ROOT / 'tools/bincode_diagnostic_field_static.py'), '--output', str(output)]
            good = subprocess.run(argv, capture_output=True, env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
            self.assertEqual(good.returncode, 0, good.stderr.decode())
            self.assertEqual(json.loads((output / 'records.json').read_text()), json.loads(json.dumps(proof())))
            bad = Path(folder) / 'bad-input'
            bad.write_bytes(b'not node94')
            bad_output = Path(folder) / 'bad-output'
            wrong = subprocess.run(argv[:-1] + [str(bad_output), '--input', str(bad)], capture_output=True,
                                   env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
            self.assertNotEqual(wrong.returncode, 0)
            self.assertFalse(bad_output.exists())


if __name__ == '__main__':
    unittest.main()
