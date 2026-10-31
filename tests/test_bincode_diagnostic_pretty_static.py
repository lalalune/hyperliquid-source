"""Independent byte/interval expectations and actual native corruption controls."""
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
import bincode_diagnostic_adapter_static as adapter

PACKET = ROOT / 'research/work-items/RE-005-diagnostic-field-trace-94'
spec = importlib.util.spec_from_file_location('pretty_counterfactuals', PACKET / 'pretty_controls.py')
controls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(controls)
_DATA = _PROOF = _LEDGER = None


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


def static_cfg_path(graph, row_pcs, start, decisions):
    """Follow specified proof-domain edges, without evaluating instructions."""
    next_pc = dict(zip(row_pcs, row_pcs[1:]))
    pc, result = start, []
    while True:
        if pc in result:
            raise AssertionError('Unexpected cycle in a selected finite CFG path')
        result.append(pc)
        if pc in graph['returns']:
            return result
        branch = graph['branches'].get(pc)
        if branch:
            taken = True if branch['kind'] == 'jump' else decisions[pc]
            pc = branch['target'] if taken else branch['fallthrough']
        else:
            pc = next_pc[pc]


class PrettyAndAdapterContract(unittest.TestCase):
    def test_pair_boundaries_and_full_native_roles_are_target_bound(self):
        p = proof()
        a = p['used_adapter_contract']
        self.assertEqual(p['schema'], 're005-diagnostic-field-static/2')
        self.assertEqual(a['range'], ['0x157d000', '0x157d26e'])
        self.assertEqual(a['span_sha256'], 'd62080d0724a750e0162d6a0563c7a056ae76e2212fd48310f89bcf8809dfde4')
        self.assertEqual(a['unwind_metadata']['fde_va'], '0xcfb300')
        self.assertEqual(a['unwind_metadata']['cie_va'], '0xce1518')
        self.assertEqual(len(a['native_row_roles']), a['native_rows'])
        self.assertEqual(a['native_rows'], 176)
        self.assertEqual(a['cfg_edges']['calls'], [0x157D081, 0x157D23A])
        self.assertFalse(a['captured_or_emulated_execution'])
        self.assertFalse(p['runtime_rendering_or_gate_claimed'])

    def test_nine_pretty_routes_use_actual_ordered_output_witnesses(self):
        paths = proof()['pretty_contract']['normal_return_paths']
        self.assertEqual(len(paths), 9)
        for path in paths:
            self.assertEqual(path['return'], 'original state pointer')
            self.assertEqual(path['ordered_state_stores'],
                             [{'offset': 8, 'source': path['error_origin']}, {'offset': 9, 'constant': 1}])
            pcs = path['path_rows']
            self.assertLess(pcs.index(field.COMMON), pcs.index(0x1571F71))
            self.assertLess(pcs.index(0x1571F71), pcs.index(0x1571F75))
            self.assertLess(pcs.index(0x1571F75), pcs.index(0x1571F86))
            guards = {g['value']: g['zero'] for g in path['guards']}
            self.assertTrue(guards['entry_error'])
            self.assertFalse(guards['mode_bit'])

    def test_opening_error_does_not_create_or_use_local_adapter(self):
        paths = proof()['pretty_contract']['normal_return_paths']
        bad = next(p for p in paths if any(g['value'] == 'pretty_opening_AL' and not g['zero']
                                          for g in p['guards']))
        self.assertEqual(bad['calls'], [0x1572031])
        self.assertIn(0x157203A, bad['output_witness_pcs'])
        self.assertNotIn(0x1572045, bad['path_rows'])
        self.assertEqual(bad['error_origin'], {'kind': 'constant', 'value': 1})

    def test_pretty_value_failure_is_normalized_before_suffix(self):
        paths = proof()['pretty_contract']['normal_return_paths']
        bad = [p for p in paths if any(g['value'] == 'pretty_value_AL' and not g['zero']
                                      for g in p['guards'])]
        self.assertEqual(len(bad), 2)
        for path in bad:
            self.assertNotIn(0x15720CB, path['calls'])
            self.assertEqual(path['error_origin'], {'kind': 'constant', 'value': 1})
        flat = next(p for p in proof()['flat_paths'] if field.CAPTURE in p['blocks'])
        self.assertEqual(flat['error_origin'], {'kind': 'last_callback_AL', 'call_site': 0x1572009})

    def test_post_opening_samples_and_direct_call_frame_separation(self):
        p = proof()['pretty_contract']
        for path in p['normal_return_paths']:
            if 0x1572031 in path['calls'] and 0x1572049 in path['path_rows']:
                self.assertLess(path['path_rows'].index(0x1572031), path['path_rows'].index(0x1572049))
        f = p['direct_adapter_stack_separation']
        self.assertEqual(f['parent_N_relative_to_adapter_RBP'], 128 - 41)
        self.assertGreaterEqual(f['parent_N_relative_to_adapter_RBP'], f['return_slot_interval'][1])
        self.assertTrue(p['known_suffix_adapter_requires_local_metadata_preservation'])

    def test_borrow_certificate_covers_every_possible_incoming_borrow(self):
        a = proof()['used_adapter_contract']
        cases = a['certificates']['mask']['cases']
        self.assertEqual({(c['index'], c['incoming_borrow']) for c in cases},
                         {(0, 0)} | {(i, b) for i in range(1, 8) for b in [0, 1]})
        for case in cases:
            self.assertEqual(case['difference_byte'],
                             (case['constant_byte'] - case['incoming_borrow']) % 256)
            self.assertEqual(case['first_OR_high_bit'], 0)
            self.assertEqual(case['second_OR_high_bit'], 0)
        self.assertTrue(a['certificates']['mask']['false_positives_allowed'])

    def test_wide_skip_equation_cannot_skip_an_LF_at_any_word_byte(self):
        f = proof()['used_adapter_contract']['operand_facts']
        for fill in [0, 1, 9, 11, 127, 128, 255]:
            for index in range(16):
                value = bytearray([fill] * 16)
                value[index] = 10
                words = [int.from_bytes(value[:8], 'little'), int.from_bytes(value[8:], 'little')]
                self.assertFalse(adapter.wide_predicate(*words, f['C'], f['LFWORD'], f['HI']),
                                 (fill, index))

    def test_interval_partition_is_in_bounds_for_all_alignment_residues(self):
        f = proof()['used_adapter_contract']['operand_facts']
        width = -f['aligned_width_subtract']
        for n in [0, 1, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65]:
            for residue in range(8):
                segments = []
                if n <= f['small_threshold']:
                    segments = [(0, n)]
                else:
                    t = ((residue + f['alignment_addend']) & f['alignment_mask']) - residue
                    segments.append((0, t))
                    while t <= n - width:
                        first = t + 8 + f['first_word_displacement']
                        self.assertEqual(first, t)
                        self.assertLessEqual(t + width, n)
                        segments.extend([(first, first + 8), (t + 8, t + width)])
                        t += f['wide_skip_stride']
                    segments.append((t, n))
                cursor = 0
                for left, right in segments:
                    self.assertEqual(left, cursor)
                    self.assertLessEqual(left, right)
                    self.assertLessEqual(right, n)
                    cursor = right
                self.assertEqual(cursor, n)

    def test_changed_word_constants_have_real_false_negative_witnesses(self):
        read = controls.context(data())
        body = read(adapter.BASE, adapter.END - adapter.BASE)
        original = proof()['used_adapter_contract']['operand_facts']
        by_name = {r['name']: r for r in ledger()['counterfactuals']}
        for name in ['adapter-LFWORD', 'adapter-C-borrow', 'adapter-HI-low-bit']:
            row = by_name[name]
            value = bytes.fromhex(row['mathematical_counterexample']['input16_hex'])
            words = [int.from_bytes(value[:8], 'little'), int.from_bytes(value[8:], 'little')]
            self.assertIn(10, value)
            self.assertFalse(adapter.wide_predicate(*words, original['C'], original['LFWORD'], original['HI']))
            changed = bytearray(body)
            pos = int(row['va'], 16) - adapter.BASE
            changed[pos:pos + len(bytes.fromhex(row['after']))] = bytes.fromhex(row['after'])
            rows = adapter.native(bytes(changed))[0]
            facts = adapter.operand_facts(changed, rows, read)
            self.assertTrue(adapter.wide_predicate(*words, facts['C'], facts['LFWORD'], facts['HI']))

    def test_gap_and_overread_mutations_record_concrete_interval_failures(self):
        by_name = {r['name']: r for r in ledger()['counterfactuals']}
        w = by_name['adapter-wide-threshold']['mathematical_counterexample']
        self.assertTrue(w['changed_wide_guard'])
        self.assertGreater(w['read_interval'][1], w['remaining'])
        w = by_name['adapter-wide-stride']['mathematical_counterexample']
        self.assertLessEqual(w['gap'][0], w['LF_index'])
        self.assertLess(w['LF_index'], w['gap'][1])
        self.assertEqual(by_name['adapter-wide-first-load']['mathematical_counterexample']['unread_LF_index'], 0)

    def test_empty_input_cfg_has_no_flag_protocol_access_or_writer_call(self):
        a = proof()['used_adapter_contract']
        graph = a['cfg_edges']
        decisions = {0x157D0A5: False, 0x157D0AE: True, 0x157D0EA: False,
                     0x157D0EF: True, 0x157D214: True}
        path = static_cfg_path(graph, sorted(a['native_row_roles']), adapter.BASE, decisions)
        self.assertTrue({0x157D02F, 0x157D037, 0x157D03E} <= set(path))
        self.assertFalse({0x157D074, 0x157D081, 0x157D21D, 0x157D23A} & set(path))
        self.assertIn(0x157D259, path)

    def test_payload_flag_chain_and_physical_flag_conditions_remain_explicit(self):
        by_name = {r['name']: r for r in ledger()['counterfactuals']}
        self.assertIn('Continuation reload preserves payload TEST flags',
                      by_name['adapter-payload-flag-chain']['rejected_by_relation'])
        a = proof()['used_adapter_contract']
        self.assertEqual(a['write_protocol']['flag_store']['site'], '0x157d074')
        self.assertIn('before payload', a['write_protocol']['flag_store']['order'])
        self.assertTrue(any('frame/prologue' in c for c in a['conditions']))
        self.assertIn('post-prologue', a['write_protocol']['sampled_pointer_values'])
        self.assertIn(0x157D02F, a['native_row_roles'])
        self.assertEqual(a['operand_facts']['flag_pointer_offset'], 16)

    def test_pretty_direct_ret_mutation_does_not_invent_outputs(self):
        bad = next(r for r in ledger()['counterfactuals'] if r['name'] == 'pretty-value-error-direct-ret')
        self.assertEqual(bad['actual_skipped_outputs']['stores'], [])
        self.assertNotEqual(bad['actual_skipped_outputs']['return'], 'original state pointer')
        self.assertIn('output witnesses', bad['rejected_by_relation'])

    def test_all_forty_new_actual_mutations_reproduce_and_break_relations(self):
        expected = json.loads((PACKET / 'observed/pretty-counterfactuals.json').read_text())
        self.assertEqual(json.loads(json.dumps(ledger())), expected)
        self.assertEqual(len(ledger()['counterfactuals']), 40)
        self.assertTrue(all(r['shape_equal_to_original'] and r['rejected_by_relation']
                            for r in ledger()['counterfactuals']))

    def test_cli_exports_both_raw_spans_with_byte_bound_adapter_records(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / 'pair'
            run = subprocess.run([sys.executable, '-B', str(ROOT / 'tools/bincode_diagnostic_field_static.py'),
                                  '--output', str(output)], capture_output=True,
                                 env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
            self.assertEqual(run.returncode, 0, run.stderr.decode())
            self.assertEqual((output / 'adapter.objdump.txt').read_bytes(),
                             (PACKET / 'observed/adapter.objdump.txt').read_bytes())
            self.assertEqual(json.loads((output / 'records.json').read_text()),
                             json.loads(json.dumps(proof())))

    def test_final_tail_success_exits_before_old_emitted_cursor_is_reused(self):
        a = proof()['used_adapter_contract']
        path = static_cfg_path(a['cfg_edges'], sorted(a['native_row_roles']), 0x157D0A3,
                               {0x157D0A5: True})
        self.assertIn(0x157D259, path)
        self.assertNotIn(0x157D0AB, path)
        self.assertNotIn(0x157D0DC, path)
        self.assertNotIn(0x157D216, path)


if __name__ == '__main__':
    unittest.main()
