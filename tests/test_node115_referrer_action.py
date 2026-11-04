"""Target-grounded controls for the selected node #115 referral-action path."""
import hashlib
import struct
import unittest

from tools import node115_referrer_action as re010


class PatchedBytes:
    """A tiny overlay for negative controls without copying the captured ELF."""
    def __init__(self, source, patches):
        self.source = source
        self.patches = dict(patches)

    def __len__(self):
        return len(self.source)

    def __getitem__(self, key):
        if isinstance(key, int):
            return self.patches.get(key, self.source[key])
        start, stop, step = key.indices(len(self.source))
        if step != 1:
            return self.source[key]
        original = self.source[start:stop]
        changes = [(pos - start, value) for pos, value in self.patches.items()
                   if start <= pos < stop]
        if not changes:
            return original
        result = bytearray(original)
        for pos, value in changes:
            result[pos] = value
        return bytes(result)


class ReferrerActionEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = re010.BINARY.read_bytes()
        cls.secs = re010.sections(cls.data)
        cls.files = re010.collect(cls.data)

    def mutate_va(self, address, new_value):
        off = re010.file_offset(self.secs, address, 1)
        return PatchedBytes(self.data, {off: new_value})

    def test_full_digest(self):
        self.assertEqual(re010.verify_digest(self.data), re010.SHA256)

    def test_wrong_digest_is_rejected(self):
        with self.assertRaises(ValueError):
            re010.verify_digest(b'not the captured node')

    def test_bad_elf_magic_is_rejected(self):
        with self.assertRaises(ValueError):
            re010.sections(b'\x00' * 64)

    def test_outside_file_backed_va_is_rejected(self):
        with self.assertRaises(ValueError):
            re010.file_offset(self.secs, (1 << 64) - 1, 8)

    def test_bss_is_not_treated_as_file_data(self):
        bss = next(s for s in self.secs if s['type'] == 8 and s['size'])
        fake = [dict(bss)]
        with self.assertRaises(ValueError):
            re010.file_offset(fake, bss['address'], 1)

    def test_overlapping_file_backed_sections_are_rejected(self):
        sec = {'address': 10, 'offset': 0, 'size': 10, 'type': 1}
        with self.assertRaises(ValueError):
            re010.file_offset([sec, dict(sec)], 12, 1)

    def test_empty_and_negative_ranges_are_rejected(self):
        for address, size in ((0, 0), (-1, 1), (0, -1)):
            with self.subTest(address=address, size=size), self.assertRaises(ValueError):
                re010.file_offset(self.secs, address, size)

    def test_selected_summary_and_files(self):
        import json
        summary = json.loads(self.files['summary.json'])
        self.assertEqual(summary['selected_functions'], 21)
        self.assertEqual(summary['selected_switch_entries'], 6)
        self.assertEqual(summary['selected_name_matcher_entries'], 3)
        self.assertEqual(summary['selected_relocations'], 5)
        self.assertEqual(summary['selected_calls'], 25)
        self.assertEqual(summary['arm_instruction_model_vectors'], 140)
        self.assertEqual(summary['registration_wrapper_vectors'], 6)
        self.assertEqual(summary['synthetic_parser_presence_vectors'], 341)
        self.assertEqual(summary['mode1_stubbed_instruction_vectors'], 18)
        self.assertEqual(summary['representation_guard_vectors'], 24)
        self.assertEqual(summary['parent_input_gate_vectors'], 9)
        self.assertEqual(summary['parent_admission_vectors'], 4)
        self.assertEqual(summary['vote_result_gate_vectors'], 8)
        self.assertEqual(summary['predicate_short_circuit_vectors'], 4)
        self.assertEqual(summary['target_sha256'], re010.SHA256)
        self.assertEqual(len(self.files), 21)

    def test_tag_bias_and_correlated_formatter_are_read_from_bytes(self):
        values, _ = re010.collect_constants(self.data, self.secs)
        self.assertEqual(values['parser_tag_map'], 0x37)
        self.assertEqual(values['parser_tag_sequence'], 0x37)
        self.assertEqual(values['clone_tag'], 0x37)
        self.assertEqual(values['parent_forwarded_tag'], 0x37)
        self.assertEqual(values['apply_bias'] + values['serializer_ordinal'], 0x37)

    def test_parent_input_tag_and_special_neighbors(self):
        route = re010.parent_input_gate
        self.assertEqual(route(self.data, self.secs, 0x37), 'vote-gate')
        self.assertEqual(route(self.data, self.secs, 0x1e), 'special')
        self.assertEqual(route(self.data, self.secs, 0x33), 'special')
        self.assertEqual(route(self.data, self.secs, 0x34), 'vote-gate')

    def test_parent_input_model_rejects_unmodelled_range(self):
        for tag in (0x13, 0x5d, -1, 1 << 64):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                re010.parent_input_gate(self.data, self.secs, tag)

    def test_parent_mutated_special_immediate_changes_route(self):
        off = re010.file_offset(self.secs, 0x2bf0247)
        altered = PatchedBytes(self.data, {off: 0x23})
        self.assertEqual(re010.parent_input_gate(self.data, self.secs, 0x37), 'vote-gate')
        self.assertEqual(re010.parent_input_gate(altered, self.secs, 0x37), 'special')

    def test_parent_input_rejects_corrupted_branch(self):
        off = re010.file_offset(self.secs, 0x2bf023f)
        with self.assertRaises(ValueError):
            re010.parent_input_gate(PatchedBytes(self.data, {off: 0x85}), self.secs, 0x37)

    def test_parent_admission_status_and_flag(self):
        gate = re010.parent_admission
        self.assertEqual(gate(self.data, self.secs, 0x1a2, 0), ('continue', None))
        self.assertEqual(gate(self.data, self.secs, 0, 1), ('continue', None))
        self.assertEqual(gate(self.data, self.secs, 0, 0), ('reject', 0x95))

    def test_parent_admission_mutated_success_changes_result(self):
        off = re010.file_offset(self.secs, 0x2bf01d7)
        altered = PatchedBytes(self.data, {off: 0xa3})
        self.assertEqual(re010.parent_admission(self.data, self.secs, 0x1a2, 0),
                         ('continue', None))
        self.assertEqual(re010.parent_admission(altered, self.secs, 0x1a2, 0),
                         ('reject', 0x95))

    def test_parent_admission_corrupted_failure_branch_rejected(self):
        off = re010.file_offset(self.secs, 0x2bf0210)
        with self.assertRaises(ValueError):
            re010.parent_admission(PatchedBytes(self.data, {off: 0x85}), self.secs, 0, 0)

    def test_vote_result_selected_conditions(self):
        gate = re010.vote_selected_gate
        self.assertEqual(gate(self.data, self.secs, 0, 1, 0x37), 'write-selected-tag')
        self.assertEqual(gate(self.data, self.secs, 1, 1, 0x37), 'continue-scan')
        self.assertEqual(gate(self.data, self.secs, 0, 0, 0x37), 'continue-scan')
        self.assertEqual(gate(self.data, self.secs, 0, 1, 0x86), 'continue-scan')

    def test_vote_result_mutated_marker_changes_route(self):
        off = re010.file_offset(self.secs, 0x28b179d)
        altered = PatchedBytes(self.data, {off: 0x37})
        self.assertEqual(re010.vote_selected_gate(self.data, self.secs, 0, 1, 0x37),
                         'write-selected-tag')
        self.assertEqual(re010.vote_selected_gate(altered, self.secs, 0, 1, 0x37),
                         'continue-scan')

    def test_vote_result_corrupt_predicate_branch_is_rejected(self):
        off = re010.file_offset(self.secs, 0x28b152d)
        with self.assertRaises(ValueError):
            re010.vote_selected_gate(PatchedBytes(self.data, {off: 0x85}),
                                     self.secs, 0, 1, 0x37)

    def test_vote_result_rejects_non_byte_flag(self):
        for flag in (-1, 256, True):
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                re010.vote_selected_gate(self.data, self.secs, flag, 1, 0x37)

    def test_two_stage_predicate_short_circuits(self):
        predicate = re010.predicate_short_circuit
        self.assertEqual(predicate(self.data, self.secs, 0, 1), 0)
        self.assertEqual(predicate(self.data, self.secs, 1, 0), 0)
        self.assertEqual(predicate(self.data, self.secs, 1, 1), 1)
        self.assertEqual(predicate(self.data, self.secs, 2, 255), 255)

    def test_two_stage_predicate_rejects_corrupt_jump(self):
        off = re010.file_offset(self.secs, 0x28a9c6f)
        with self.assertRaises(ValueError):
            re010.predicate_short_circuit(PatchedBytes(self.data, {off: 0x75}),
                                          self.secs, 0, 1)

    def test_two_stage_predicate_rejects_non_byte(self):
        with self.assertRaises(ValueError):
            re010.predicate_short_circuit(self.data, self.secs, 256, 1)

    def test_neighbor_names_do_not_alias_selected_ordinal(self):
        observed = []
        for key in b'JKL':
            result = re010.match_single_variant_name(self.data, self.secs, key, 0x287e450, 0x287ec7f)
            observed.append(result[-1])
        self.assertEqual(observed, [0x22, 0x23, 0x24])

    def test_name_matcher_rejects_out_of_range_bytes(self):
        for key in (0x40, 0x7b, 256, -1):
            with self.subTest(key=key), self.assertRaises(ValueError):
                re010.match_single_variant_name(self.data, self.secs, key, 0x287e450, 0x287ec7f)

    def test_name_matcher_rejects_modified_arm(self):
        off = re010.file_offset(self.secs, 0x287e950)
        patched = PatchedBytes(self.data, {off: 0x90})
        with self.assertRaises(ValueError):
            re010.match_single_variant_name(patched, self.secs, ord('K'), 0x287e450, 0x287ec7f)

    def test_table_selected_target(self):
        entry, raw, dest = re010.signed_table_target(
            self.data, self.secs, 0x5fc024, 35, 0x28cd7a0, 0x28d8ac4)
        self.assertEqual((entry, raw.hex(), dest), (0x5fc0b0, '5f252d02', 0x28ce583))

    def test_table_negative_index_is_rejected(self):
        with self.assertRaises(ValueError):
            re010.signed_table_target(self.data, self.secs, 0x5fc024, -1, 0x28cd7a0, 0x28d8ac4)

    def test_corrupted_table_entry_leaves_fde(self):
        slot = 0x5fc0b0
        off = re010.file_offset(self.secs, slot, 4)
        patched = PatchedBytes(self.data, {off + i: 0x7f for i in range(4)})
        with self.assertRaises(ValueError):
            re010.signed_table_target(patched, self.secs, 0x5fc024, 35, 0x28cd7a0, 0x28d8ac4)

    def test_corrupt_window_is_rejected(self):
        _, start, end, expected = next(row for row in re010.WINDOWS if row[0] == 'apply_variant')
        patched = self.mutate_va(start, self.data[re010.file_offset(self.secs, start)] ^ 1)
        with self.assertRaises(ValueError):
            re010.pinned_window(patched, self.secs, start, end, expected)

    def test_rel32_branch_targets(self):
        for address, raw_hex, target in re010.BRANCHES:
            raw = re010.read_va(self.data, self.secs, address, len(bytes.fromhex(raw_hex)))
            self.assertEqual(re010.check_branch(address, raw, raw_hex, target), target)

    def test_mutated_branch_is_rejected(self):
        address, raw_hex, target = re010.BRANCHES[10]
        raw = bytearray.fromhex(raw_hex)
        raw[-1] ^= 1
        with self.assertRaises(ValueError):
            re010.check_branch(address, raw, raw_hex, target)

    def test_truncated_branch_is_rejected(self):
        with self.assertRaises(ValueError):
            re010.decode_branch(0x100, b'\x0f\x84\x00')

    def test_rel32_call_target_and_corruption(self):
        self.assertEqual(re010.relative_call(self.data, self.secs, 0x3c1941c, 0x3ccb770)[0], 0xe8)
        off = re010.file_offset(self.secs, 0x3c1941c, 1)
        with self.assertRaises(ValueError):
            re010.relative_call(PatchedBytes(self.data, {off: 0x90}), self.secs, 0x3c1941c, 0x3ccb770)

    def test_static_relocation_target(self):
        sec = next(s for s in self.secs if s['name'] == '.rela.dyn')
        relocation = re010.read_rela(self.data, sec, {0x64e6a38})[0x64e6a38]
        self.assertEqual(relocation[:2], (8, 0x3c193d0))

    def test_copy_slot_names_dynamic_symbol(self):
        sec = next(s for s in self.secs if s['name'] == '.rela.dyn')
        info, addend, _ = re010.read_rela(self.data, sec, {0x64df508})[0x64df508]
        self.assertEqual((info & 0xffffffff, addend), (6, 0))
        self.assertEqual(re010.dynamic_symbol_name(self.data, self.secs, info >> 32), 'memcpy')

    def test_dynamic_symbol_index_and_name_range_controls(self):
        with self.assertRaises(ValueError):
            re010.dynamic_symbol_name(self.data, self.secs, 1000000)
        sym = next(s for s in self.secs if s['name'] == '.dynsym')
        offset = sym['offset'] + 24 * 7
        altered = PatchedBytes(self.data, {offset + i: 0xff for i in range(4)})
        with self.assertRaises(ValueError):
            re010.dynamic_symbol_name(altered, self.secs, 7)

    def test_duplicate_selected_relocation_is_rejected(self):
        record = struct.pack('<QQq', 0x100, 8, 0x200)
        section = {'type': 4, 'offset': 0, 'size': 48}
        with self.assertRaises(ValueError):
            re010.read_rela(record + record, section, {0x100})

    def test_missing_relocation_is_rejected(self):
        record = struct.pack('<QQq', 0x100, 8, 0x200)
        with self.assertRaises(ValueError):
            re010.read_rela(record, {'type': 4, 'offset': 0, 'size': 24}, {0x101})

    def test_truncated_relocation_is_rejected(self):
        with self.assertRaises(ValueError):
            re010.read_rela(bytes(23), {'type': 4, 'offset': 0, 'size': 24}, {0})

    def test_mutated_numeric_immediate_changes_machine_decision(self):
        limit = 0x0ccccccccccccccc
        # Decreasing the encoded bound by one must change the exact boundary.
        off = re010.file_offset(self.secs, 0x28ce5db)
        patched = PatchedBytes(self.data, {off: self.data[off] - 1})
        self.assertEqual(re010.instruction_arm(self.data, self.secs, 100, 1, limit - 1),
                         ('call', None, limit - 1))
        self.assertEqual(re010.instruction_arm(patched, self.secs, 100, 1, limit - 1),
                         ('number', 0x154, None))

    def test_mutated_length_immediate_changes_machine_decision(self):
        off = re010.file_offset(self.secs, 0x28ce5c1)
        patched = PatchedBytes(self.data, {off: 99})
        self.assertEqual(re010.instruction_arm(self.data, self.secs, 100, 0, 0)[0], 'call')
        self.assertEqual(re010.instruction_arm(patched, self.secs, 100, 0, 0)[0], 'length')

    def test_mutated_branch_opcode_is_rejected(self):
        off = re010.file_offset(self.secs, 0x28ce5c3)
        patched = PatchedBytes(self.data, {off: 0x82})
        with self.assertRaises(ValueError):
            re010.instruction_arm(patched, self.secs, 0, 0, 0)

    def test_mutated_field_offset_is_rejected(self):
        off = re010.file_offset(self.secs, 0x28ce586)
        patched = PatchedBytes(self.data, {off: 0xff})
        with self.assertRaises(ValueError):
            re010.instruction_arm(patched, self.secs, 0, 0, 0)

    def test_length_precedes_numeric_error(self):
        self.assertEqual(re010.instruction_arm(self.data, self.secs, 101, 1, re010.MAX_U64),
                         ('length', 0x158, None))

    def test_zero_option_does_not_forward_the_payload_word(self):
        self.assertEqual(re010.instruction_arm(self.data, self.secs, 100, 0, re010.MAX_U64),
                         ('call', None, 0))

    def test_numeric_threshold_equality_and_below(self):
        limit = 0x0ccccccccccccccc
        self.assertEqual(re010.instruction_arm(self.data, self.secs, 100, 1, limit),
                         ('number', 0x154, None))
        self.assertEqual(re010.instruction_arm(self.data, self.secs, 100, 1, limit - 1),
                         ('call', None, limit - 1))

    def test_registration_wrapper_length_and_fixed_arguments(self):
        gate = re010.registration_wrapper_gate
        self.assertEqual(gate(self.data, self.secs, 100), ('call', None, 0, 0))
        self.assertEqual(gate(self.data, self.secs, 101), ('reject', 0x158, None, None))

    def test_registration_wrapper_mutated_length_changes_result(self):
        off = re010.file_offset(self.secs, 0x285c742)
        altered = PatchedBytes(self.data, {off: 100})
        self.assertEqual(re010.registration_wrapper_gate(self.data, self.secs, 100)[0], 'call')
        self.assertEqual(re010.registration_wrapper_gate(altered, self.secs, 100)[0], 'reject')

    def test_invalid_word_domain_is_rejected(self):
        for value in (-1, 1 << 64, True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                re010.instruction_arm(self.data, self.secs, value, 0, 0)

    def test_map_presence_order_and_duplicate_controls(self):
        self.assertEqual(re010.selected_parser_model(('u',)), 'missing-c')
        self.assertEqual(re010.selected_parser_model(('c',)), 'missing-u')
        self.assertEqual(re010.selected_parser_model(('x', 'u', 'c')), 'tag-0x37')
        for field in ('c', 'n', 'u'):
            self.assertEqual(re010.selected_parser_model((field, field)), f'duplicate-{field}')

    def test_core_modes_have_different_gate_order(self):
        self.assertEqual(re010.selected_core_model(0, 101, False, 0, False, 'absent'), (0xa9, 'reject'))
        self.assertEqual(re010.selected_core_model(1, 101, False, 0, False, 'absent'), (0xa4, 'reject'))
        self.assertEqual(re010.selected_core_model(0, 100, True, 999_999, False, 'absent'), (0xa9, 'reject'))
        self.assertEqual(re010.selected_core_model(0, 100, True, 1_000_000, False, 'absent'), (0x1a2, 'insert'))

    def test_core_owner_and_conflict_branches(self):
        self.assertEqual(re010.selected_core_model(0, 10, True, 1_000_000, True, 'absent'), (0xa8, 'reject'))
        self.assertEqual(re010.selected_core_model(1, 10, False, 0, True, 'same'), (0x1a2, 'replace'))
        self.assertEqual(re010.selected_core_model(1, 10, False, 0, True, 'absent'), (0x1a2, 'replace'))
        self.assertEqual(re010.selected_core_model(1, 10, False, 0, True, 'other'), (0xa7, 'reject'))
        self.assertEqual(re010.selected_core_model(1, 10, False, 0, False, 'same'), (0xa7, 'reject'))

    def test_stubbed_mode1_compact_decisions(self):
        machine = re010.mode1_core_with_lookup_stubs
        for profile, owner, result in (
                (False, 'absent', (0x1a2, 'insert')),
                (False, 'same', (0xa7, 'reject')),
                (True, 'absent', (0x1a2, 'replace')),
                (True, 'same', (0x1a2, 'replace')),
                (True, 'other', (0xa7, 'reject'))):
            with self.subTest(profile=profile, owner=owner):
                self.assertEqual(machine(self.data, self.secs, 100, profile, owner), result)
        self.assertEqual(machine(self.data, self.secs, 101, True, 'other'), (0xa4, 'reject'))

    def test_stubbed_core_mutated_length_guard_changes_result(self):
        off = re010.file_offset(self.secs, 0x3c193ff)
        altered = PatchedBytes(self.data, {off: 99})
        observed = re010.mode1_core_with_lookup_stubs(self.data, self.secs, 100, False, 'absent')
        mutated = re010.mode1_core_with_lookup_stubs(altered, self.secs, 100, False, 'absent')
        self.assertEqual(observed, (0x1a2, 'insert'))
        self.assertEqual(mutated, (0xa4, 'reject'))

    def test_stubbed_core_rejects_corrupted_branch(self):
        off = re010.file_offset(self.secs, 0x3c1942a)
        with self.assertRaises(ValueError):
            re010.mode1_core_with_lookup_stubs(
                PatchedBytes(self.data, {off: 0x84}), self.secs, 0, True, 'other')

    def test_entry_representation_boundaries(self):
        sentinel = 1 << 63
        for role in ('profile', 'code'):
            with self.subTest(role=role):
                self.assertTrue(re010.entry_compacts(self.data, self.secs, role, sentinel, 31))
                self.assertFalse(re010.entry_compacts(self.data, self.secs, role, sentinel, 32))
                self.assertFalse(re010.entry_compacts(self.data, self.secs, role, sentinel - 1, 0))

    def test_mutated_entry_threshold_changes_decision(self):
        for role, va in (('profile', 0x3ccb7a0), ('code', 0x3cc9cbf)):
            with self.subTest(role=role):
                off = re010.file_offset(self.secs, va)
                altered = PatchedBytes(self.data, {off: 31})
                self.assertTrue(re010.entry_compacts(self.data, self.secs, role, 1 << 63, 31))
                self.assertFalse(re010.entry_compacts(altered, self.secs, role, 1 << 63, 31))

    def test_entry_representation_rejects_corrupted_branch(self):
        off = re010.file_offset(self.secs, 0x3ccb7aa)
        with self.assertRaises(ValueError):
            re010.entry_compacts(PatchedBytes(self.data, {off: 0x84}), self.secs,
                                 'profile', 1 << 63, 0)

    def test_saturated_sum_and_repeated_overflow(self):
        maximum = re010.MAX_U64
        self.assertEqual(re010.saturated_sum((maximum - 1, 2, 0, 1)), (maximum, 2))
        self.assertEqual(re010.saturated_sum((999_999, 1)), (1_000_000, 0))

    def test_model_rejects_invalid_state(self):
        with self.assertRaises(ValueError):
            re010.selected_core_model(2, 0, False, 0, False, 'absent')
        with self.assertRaises(ValueError):
            re010.selected_core_model(1, 0, False, 0, False, 'unknown')


if __name__ == '__main__':
    unittest.main()
