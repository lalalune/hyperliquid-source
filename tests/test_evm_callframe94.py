"""Static controls for the selected node #94 interpreter evidence."""
import csv
import json
from pathlib import Path
import tempfile
import unittest

from tools import evm_callframe94 as evidence


class CallFrameEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = evidence.TARGET.read_bytes()
        evidence.check_digest(cls.data)
        cls.secs, cls.index = evidence.unwind_index(cls.data)
        _, cls.fdes = evidence.eh_frame_records(cls.data, cls.secs)
        cls.relocs = evidence.relocation_map(cls.data, cls.secs)
        cls.work = evidence.ROOT / 'research/work-items/RE-021-interpreter-callframe-94'
        cls.constants = {
            'warm_or_cold_low': 100, 'warm_or_cold_high': 2600,
            'f1_value_cost': 9000, 'f1_value_new_cost': 34000,
            'f1_stipend': 2300, 'gas_cap_shift': 6,
            'memory_round_add': 31, 'memory_word_shift': 5,
            'memory_square_shift': 9, 'memory_linear_factor': 3,
            'empty_action_tag': 0x70, 'call_action_tag': 0x6c,
            'call_suspend_status': 0x20,
            'outcome_mode_success_offset': 0x1f0, 'outcome_mode_revert_offset': 0x1f0,
            'outcome_mode_other_offset': 0x1f0, 'outcome_push_zero': 0,
            'outcome_push_one': 1, 'outcome_push_two': 2,
        }
        cls.outcomes = (16, 6, 5, 101)

    def mutated(self, va, relative, value):
        data = bytearray(self.data)
        off = evidence.file_offset(self.secs, va, relative + 1, True) + relative
        data[off] = value
        return data

    def test_target_digest_and_invalid_hash(self):
        self.assertEqual(evidence.check_digest(self.data), evidence.SHA256)
        with self.assertRaises(ValueError):
            evidence.check_digest(self.data, '0' * 64)

    def test_bad_digest_is_rejected_before_output(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / 'result'
            with self.assertRaises(ValueError):
                evidence.generate(b'bad input', out)
            self.assertFalse(out.exists())

    def test_file_offsets_map_real_selected_code(self):
        off = evidence.file_offset(self.secs, 0x276d8e0, 1, True)
        self.assertEqual(self.data[off], 0x53)

    def test_file_mapping_rejects_nobits(self):
        sec = next(s for s in self.secs if s['name'] == '.bss')
        with self.assertRaises(ValueError):
            evidence.file_offset(self.secs, sec['address'], 1)

    def test_file_mapping_rejects_unmapped_and_bad_lengths(self):
        for va, length in ((0xffffffffffffffff, 1), (-1, 1), (0, 0), (1, -1)):
            with self.subTest(va=va, length=length), self.assertRaises(ValueError):
                evidence.file_offset(self.secs, va, length)

    def test_file_mapping_rejects_section_crossing(self):
        sec = next(s for s in self.secs if s['name'] == '.text')
        with self.assertRaises(ValueError):
            evidence.file_offset(self.secs, sec['address'] + sec['size'] - 1, 2, True)

    def test_file_mapping_rejects_ambiguous_section(self):
        sec = next(s for s in self.secs if s['name'] == '.text')
        with self.assertRaises(ValueError):
            evidence.file_offset(self.secs + [dict(sec)], 0x24ea6d0, 1, True)

    def test_selected_fdes_and_actual_body_hashes(self):
        rows, bodies, records, selected = evidence.digest_bodies(self.data, self.secs, self.fdes, self.index)
        self.assertEqual(len(rows), 11)
        self.assertEqual(sum(row[2] for row in rows), 10187)
        self.assertEqual(len(bodies), len(records))
        self.assertEqual(selected[0x24ea6d0]['end'], 0x24eac74)

    def test_missing_fde_is_rejected(self):
        altered = [f for f in self.fdes if f['start'] != 0x24ea6d0]
        with self.assertRaises(ValueError):
            evidence.digest_bodies(self.data, self.secs, altered, self.index)

    def test_duplicate_fde_is_rejected(self):
        selected = next(f for f in self.fdes if f['start'] == 0x24ea6d0)
        with self.assertRaises(ValueError):
            evidence.digest_bodies(self.data, self.secs, self.fdes + [selected], self.index)

    def test_wrong_fde_extent_is_rejected(self):
        altered = [dict(f, end=f['end'] + 1) if f['start'] == 0x24ea6d0 else f for f in self.fdes]
        with self.assertRaises(ValueError):
            evidence.digest_bodies(self.data, self.secs, altered, self.index)

    def test_changed_function_body_is_rejected(self):
        altered = self.mutated(0x24ea6d0, 0, 0x90)
        with self.assertRaises(ValueError):
            evidence.digest_bodies(altered, self.secs, self.fdes, self.index)

    def test_missing_relocation_is_rejected(self):
        altered = dict(self.relocs)
        del altered[0x56acf28]
        with self.assertRaises(ValueError):
            evidence.relative_record(altered, 0x56acf28, 0x24ea6d0)

    def test_relocation_kind_and_addend_are_checked(self):
        slot = 0x56acf28
        info, addend, off, raw = self.relocs[slot]
        for bad in ((info + 1, addend, off, raw), (info, addend + 1, off, raw)):
            altered = dict(self.relocs)
            altered[slot] = bad
            with self.assertRaises(ValueError):
                evidence.relative_record(altered, slot, addend)

    def test_selected_dispatch_slots_are_distinct(self):
        for opcode, (_, target, _, _, _) in evidence.VARIANTS.items():
            _, observed, _, _ = evidence.relative_record(self.relocs, evidence.TABLE + 8 * opcode, target)
            self.assertEqual(observed, target)
        self.assertEqual(len({row[1] for row in evidence.VARIANTS.values()}), 4)

    def test_recorded_constants_match_the_instruction_operands(self):
        with (self.work / 'constants.tsv').open(encoding='ascii', newline='') as f:
            actual = {row['label']: int(row['value']) for row in csv.DictReader(f, delimiter='\t')}
        for name, expected in self.constants.items():
            self.assertEqual(actual[name], expected)
        self.assertEqual((actual['underflow_status'], actual['gas_failure_status'],
                          actual['host_failure_status']), (0x5b, 0x50, 0x65))

    def test_fetch_loop_decodes_byte_index_and_stride(self):
        row = evidence.bytecode_dispatch(self.data, self.secs)
        self.assertEqual((row['program_pointer_offset'], row['slot_base_offset'], row['slot_stride']), (0x1d0, 8, 8))

    def test_changed_fetch_slot_scale_is_rejected(self):
        altered = self.mutated(0x279ef50, 29, 0x8d)
        with self.assertRaises(ValueError):
            evidence.bytecode_dispatch(altered, self.secs)

    def test_loop_state_resets_use_the_same_file_backed_literals(self):
        rows = evidence.loop_reset_literals(self.data, self.secs)
        self.assertEqual(len(rows), 3)
        self.assertEqual([r[3] for r in rows], ['0x3f0438', '0x3f0448', '0x3f0458'])
        self.assertEqual([r[5] for r in rows], ['00000000000000000100000000000000',
                                                '00000000000000000000000000000000',
                                                '08000000000000000000000000000000'])

    def test_changed_loop_reset_literal_reference_is_rejected(self):
        site = 0x279eff1
        off = evidence.file_offset(self.secs, site, 4, True) + 3
        altered = self.mutated(site, 3, self.data[off] ^ 1)
        with self.assertRaises(ValueError):
            evidence.loop_reset_literals(altered, self.secs)

    def test_callback_and_growth_slots(self):
        for slot, (_, target) in evidence.RELOCS.items():
            self.assertEqual(evidence.relative_record(self.relocs, slot, target)[1], target)

    def test_exception_table_binds_each_publication_landing(self):
        _, _, _, selected = evidence.digest_bodies(self.data, self.secs, self.fdes, self.index)
        rows = []
        for function in selected.values():
            found, _ = evidence.exception_table(self.data, self.secs, function)
            rows.extend(found)
        result = evidence.drop_landing_rows(self.data, self.secs, selected, rows)
        self.assertEqual(len(result), 4)
        self.assertEqual({int(r[6]) for r in result}, {0x6c})
        delegate = next(r for r in result if r[0] == '0x24ea6d0')
        self.assertEqual(delegate[1:4], ['0x24eabcb', '0x24eac0e', '0x24eac22'])

    def test_exception_header_corruption_is_rejected(self):
        function = next(f for f in self.fdes if f['start'] == 0x24ea6d0)
        altered = bytearray(self.data)
        pos = evidence.file_offset(self.secs, function['lsda'], 1)
        altered[pos] = 0
        with self.assertRaises(ValueError):
            evidence.exception_table(altered, self.secs, function)

    def test_bad_landing_record_is_rejected(self):
        _, _, _, selected = evidence.digest_bodies(self.data, self.secs, self.fdes, self.index)
        rows = []
        for function in selected.values():
            found, _ = evidence.exception_table(self.data, self.secs, function)
            rows.extend(found)
        changed = [list(row) for row in rows]
        for row in changed:
            if row[3] == '0x24eabcb':
                row[5] = '0x24eac0f'
        with self.assertRaises(ValueError):
            evidence.drop_landing_rows(self.data, self.secs, selected, changed)

    def test_changed_landing_publication_is_rejected(self):
        _, _, _, selected = evidence.digest_bodies(self.data, self.secs, self.fdes, self.index)
        rows = []
        for function in selected.values():
            found, _ = evidence.exception_table(self.data, self.secs, function)
            rows.extend(found)
        altered = self.mutated(0x24eac0e, 3, 0x90)
        with self.assertRaises(ValueError):
            evidence.drop_landing_rows(altered, self.secs, selected, rows)

    def test_indirect_call_checks_displacement(self):
        evidence.rip_slot(self.data, self.secs, 0x276dfe6, 0x5774df8)
        with self.assertRaises(ValueError):
            evidence.rip_slot(self.data, self.secs, 0x276dfe6, 0x5774df9)
        altered = self.mutated(0x276dfe6, 0, 0x90)
        with self.assertRaises(ValueError):
            evidence.rip_slot(altered, self.secs, 0x276dfe6, 0x5774df8)

    def test_signed_rel32_and_short_branch_targets(self):
        self.assertEqual(evidence.checked_branch(self.data, self.secs, 0x24ea978, 0x1ebec00)[0], 'call')
        self.assertEqual(evidence.checked_branch(self.data, self.secs, 0x279ef79, 0x279ef50)[0], 'jcc-4')
        self.assertEqual(evidence.checked_branch(self.data, self.secs, 0x279efbf, 0x279eff1)[0], 'jmp')

    def test_changed_branch_or_target_is_rejected(self):
        altered = self.mutated(0x24ea981, 0, 0x90)
        with self.assertRaises(ValueError):
            evidence.checked_branch(altered, self.secs, 0x24ea981, 0x24ea9e9)
        altered = self.mutated(0x24ea981, 1, 0)
        with self.assertRaises(ValueError):
            evidence.checked_branch(altered, self.secs, 0x24ea981, 0x24ea9e9)

    def test_each_call_family_failure_path_has_selected_branches(self):
        by_name = {name: (site, target) for name, site, target in evidence.TRANSFERS}
        for prefix in ('f1', 'f2', 'f4', 'fa'):
            for suffix in ('no-first-word', 'no-second-word', 'memory-failed',
                           'host-failed', 'base-gas-failed', 'old-action-drop'):
                site, target = by_name[prefix + '-' + suffix]
                evidence.checked_branch(self.data, self.secs, site, target)
        for name in ('f1-no-third-word', 'f2-no-third-word-wide',
                     'f2-no-third-word-narrow', 'f1-static-pass',
                     'f4-allocation-failed', 'fa-allocation-failed'):
            site, target = by_name[name]
            evidence.checked_branch(self.data, self.secs, site, target)

    def test_corrupted_callcode_and_static_failure_edges_are_rejected(self):
        for site, target in ((0x24f26b9, 0x24f26e2), (0x24e71a3, 0x24e71cc)):
            altered = self.mutated(site, 0, 0x90)
            with self.subTest(site=site), self.assertRaises(ValueError):
                evidence.checked_branch(altered, self.secs, site, target)

    def test_range_and_result_overflow_edges_are_checked(self):
        by_name = {name: (site, target) for name, site, target in evidence.TRANSFERS}
        for name in ('range-first-end-overflow', 'range-second-end-overflow',
                     'range-buffer-allocation-failed', 'range-second-growth-failed',
                     'outcome-copy-end-overflow-success', 'outcome-copy-end-overflow-revert',
                     'growth-cost-delta-underflow', 'growth-new-end-overflow'):
            site, target = by_name[name]
            evidence.checked_branch(self.data, self.secs, site, target)
            changed = self.mutated(site, 0, 0x90)
            with self.subTest(name=name), self.assertRaises(ValueError):
                evidence.checked_branch(changed, self.secs, site, target)

    def test_key_provenance_is_reverse_of_low_twenty_bytes(self):
        lanes = evidence.key_lanes(self.data, self.secs)
        self.assertEqual([row[1] for row in lanes], list(range(19, -1, -1)))
        self.assertEqual([int(row[-1], 16) for row in lanes], list(range(0x60, 0x74)))
        word = (9).to_bytes(32, 'little')
        self.assertEqual(bytes(word[row[1]] for row in lanes), bytes(19) + b'\x09')

    def test_key_all_low_bits_and_high_bits_are_distinct(self):
        lanes = evidence.key_lanes(self.data, self.secs)
        base = bytearray(32)
        base[0] = 9
        output = bytes(base[row[1]] for row in lanes)
        for bit in range(256):
            changed = bytearray(base)
            changed[bit // 8] ^= 1 << (bit % 8)
            result = bytes(changed[row[1]] for row in lanes)
            self.assertEqual(result == output, bit >= 160)

    def test_frame_copy_chunks_bind_the_four_variants(self):
        rows = evidence.frame_copy_rows(self.data, self.secs)
        self.assertEqual(len(rows), 14)
        copies = {(row[0], row[1], row[2], row[4], row[5]) for row in rows}
        self.assertIn(('0xf4', 'recipient', 16, '0x80', '0x74'), copies)
        self.assertIn(('0xf4', 'caller', 16, '0x94', '0x88'), copies)
        self.assertIn(('0xf2', 'recipient', 16, '0x80', '0x74'), copies)
        self.assertIn(('0xf2', 'caller', 16, '0x80', '0x88'), copies)
        self.assertIn(('0xf4', 'inherited-value', 16, '0x60', '0x8'), copies)
        self.assertIn(('0xf4', 'inherited-value', 16, '0x70', '0x18'), copies)

    def test_corrupted_frame_copy_source_and_destination_are_rejected(self):
        for site, relative in ((0x24eaa40, 3), (0x24eaa47, 4), (0x24eaa6b, 3), (0x24eaa73, 4)):
            off = evidence.file_offset(self.secs, site, relative + 1, True) + relative
            changed = self.mutated(site, relative, self.data[off] ^ 1)
            with self.subTest(site=site), self.assertRaises(ValueError):
                evidence.frame_copy_rows(changed, self.secs)

    def test_corrupt_key_load_is_rejected(self):
        altered = self.mutated(0x24ea72a, 4, 0)
        with self.assertRaises(ValueError):
            evidence.key_lanes(altered, self.secs)

    def test_corrupt_key_spill_is_rejected(self):
        altered = self.mutated(0x24ea725, 4, 0x1e)
        with self.assertRaises(ValueError):
            evidence.key_lanes(altered, self.secs)

    def test_corrupt_host_destination_is_rejected(self):
        altered = self.mutated(0x24ea8d3, 3, 0x43)
        with self.assertRaises(ValueError):
            evidence.key_lanes(altered, self.secs)

    def test_corrupt_frame_destination_is_rejected(self):
        altered = self.mutated(0x24eaaaa, 3, 0xa3)
        with self.assertRaises(ValueError):
            evidence.key_lanes(altered, self.secs)

    def test_corrupt_saved_register_load_is_rejected(self):
        altered = self.mutated(0x24ea7e2, 5, 0x12)
        with self.assertRaises(ValueError):
            evidence.key_lanes(altered, self.secs)

    def test_gas_exact_cost_and_one_below(self):
        self.assertEqual(evidence.gas_model(0xf4, 0, 0, 200, 0, self.constants), ('frame', 200, 0, 0))
        self.assertEqual(evidence.gas_model(0xf4, 0, 0, 199, 0, self.constants), ('gas-failed', 200, 199, None))

    def test_gas_cap_and_large_request(self):
        self.assertEqual(evidence.gas_model(0xf4, 0, 0, 264, 64, self.constants), ('frame', 200, 1, 63))
        self.assertEqual(evidence.gas_model(0xf4, 0, 0, 264, 1 << 64, self.constants), ('frame', 200, 1, 63))

    def test_gas_value_cost_and_stipend_by_variant(self):
        self.assertEqual(evidence.gas_model(0xf1, 0, 1, 9200, 0, self.constants), ('frame', 9200, 0, 2300))
        self.assertEqual(evidence.gas_model(0xf1, 0x10000, 1, 34200, 0, self.constants), ('frame', 34200, 0, 2300))
        self.assertEqual(evidence.gas_model(0xf2, 0x10000, 1, 9200, 0, self.constants), ('frame', 9200, 0, 2300))
        self.assertEqual(evidence.gas_model(0xf4, 0, 1, 200, 0, self.constants), ('frame', 200, 0, 0))

    def test_gas_host_error_and_cold_control(self):
        self.assertEqual(evidence.gas_model(0xfa, 2, 0, 50000, 5, self.constants), ('host-failed', None, 50000, None))
        self.assertEqual(evidence.gas_model(0xfa, 0x101, 0, 5200, 0, self.constants), ('frame', 5200, 0, 0))
        self.assertEqual(evidence.gas_model(0xfa, 0x200, 0, 100, 0, self.constants), ('frame', 100, 0, 0))

    def test_gas_model_rejects_bad_domain(self):
        for args in ((0, 0, 0, 0, 0), (0xf1, -1, 0, 0, 0), (0xf1, 0, 2, 0, 0),
                     (0xf1, 0, 0, -1, 0), (0xf1, 0, 0, 0, 1 << 256)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                evidence.gas_model(*args, self.constants)

    def test_memory_cost_against_integer_formula(self):
        for size in range(0, 8193):
            words = (size + 31) // 32
            self.assertEqual(evidence.memory_cost(size, self.constants), 3 * words + words * words // 512)

    def test_memory_cost_saturates_square_and_rounding(self):
        limit = (1 << 64) - 1
        words = limit >> 5
        self.assertEqual(evidence.memory_cost(limit, self.constants), 3 * words + (limit >> 9))
        with self.assertRaises(ValueError):
            evidence.memory_cost(limit + 1, self.constants)

    def test_memory_square_and_rounding_boundaries(self):
        limit = (1 << 64) - 1
        for size in ((1 << 37) - 33, (1 << 37) - 32, (1 << 37) - 31,
                     (1 << 37), (1 << 37) + 1, limit - 32, limit - 31, limit - 30, limit):
            words = min(limit, size + 31) // 32
            expected = 3 * words + min(limit, words * words) // 512
            self.assertEqual(evidence.memory_cost(size, self.constants), expected)

    def test_gas_cap_for_all_small_remainders(self):
        for remaining in range(8193):
            status, charge, parent, child = evidence.gas_model(
                0xfa, 0x200, 0, remaining + 100, (1 << 256) - 1, self.constants)
            self.assertEqual((status, charge), ('frame', 100))
            self.assertEqual(parent, remaining // 64)
            self.assertEqual(child, remaining - remaining // 64)

    def test_outcome_selected_statuses_in_both_modes(self):
        expected = {2: (1, 0, 'remaining-and-refund'), 0x10: (0, 1, 'remaining'),
                    0x53: (0, 2, 'none'), 0x60: (0, 2, 'none')}
        for status, (mode0, mode1, credit) in expected.items():
            self.assertEqual(evidence.outcome_model(status, 0, self.outcomes)[1:], (mode0, credit))
            self.assertEqual(evidence.outcome_model(status, 1, self.outcomes)[1:], (mode1, credit))
        self.assertEqual(evidence.outcome_model(0x65, 0, self.outcomes), ('fatal', None, 'none'))

    def test_outcome_mode_branches_and_changed_condition(self):
        selected = {name: (site, target) for name, site, target in evidence.TRANSFERS}
        for name in ('outcome-success-mode-zero', 'outcome-success-mode-nonzero',
                     'outcome-revert-mode-zero', 'outcome-other-mode-zero',
                     'outcome-two-to-push', 'outcome-zero-to-push'):
            site, target = selected[name]
            evidence.checked_branch(self.data, self.secs, site, target)
        site, target = selected['outcome-success-mode-zero']
        with self.assertRaises(ValueError):
            evidence.checked_branch(self.mutated(site, 1, 0), self.secs, site, target)

    def test_outcome_all_byte_inputs_obey_independent_partition(self):
        for status in range(256):
            expected = 'success-range' if status < 5 else ('revert-range' if 16 <= status < 22 else ('fatal' if status == 101 else 'other'))
            for flag in (0, 1):
                self.assertEqual(evidence.outcome_model(status, flag, self.outcomes)[0], expected)
        for args in ((-1, 0), (256, 0), (0, 2)):
            with self.assertRaises(ValueError):
                evidence.outcome_model(*args, self.outcomes)

    def test_generation_matches_committed_files(self):
        names = {'functions.tsv', 'variants.tsv', 'relocations.tsv', 'indirect-sites.tsv',
                 'control.tsv', 'windows.tsv', 'delegate-key-lanes.tsv', 'frame-copies.tsv',
                 'loop-reset-literals.tsv', 'constants.tsv',
                 'synthetic-outcomes.tsv', 'synthetic-gas.tsv', 'synthetic-memory.tsv',
                 'exception-sites.tsv', 'drop-landings.tsv', 'exception-headers.json',
                 'synthetic-addresses.tsv', 'dispatch.json', 'bodies.json', 'unwind.json', 'summary.json'}
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / 'regenerated'
            evidence.generate(self.data, out)
            self.assertEqual({p.name for p in out.iterdir()}, names)
            for name in sorted(names):
                with self.subTest(name=name):
                    self.assertEqual((out / name).read_bytes(), (self.work / name).read_bytes())

    def test_result_status_bounds_are_binary_derived(self):
        summary = json.loads((self.work / 'summary.json').read_text(encoding='ascii'))
        self.assertEqual(summary['outcome_status_bounds'], {'success_limit': 5, 'revert_base': 16, 'revert_width': 6, 'fatal': 101})
        with (self.work / 'delegate-key-lanes.tsv').open(encoding='ascii', newline='') as f:
            self.assertEqual(len(list(csv.DictReader(f, delimiter='\t'))), 20)


if __name__ == '__main__':
    unittest.main()
