# SPDX-License-Identifier: MIT
"""Offline controls for the selected node #115 link-staking evidence."""
import hashlib
from pathlib import Path
import struct
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import link_staking_path_115 as path  # noqa: E402
from elf_index import sections  # noqa: E402


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = path.TARGET.read_bytes()
        cls.secs = sections(cls.data)
        cls.bundle = path.collect(cls.data)
        cls.functions, _, cls.switches, cls.edges, cls.relocs, _, cls.literals, constants, cls.summary = cls.bundle
        cls.constants = {row[0]: row[-1] for row in constants}

    def test_authenticated_target_and_summary(self):
        self.assertEqual(path.check_digest(self.data), path.DIGEST)
        self.assertEqual(self.summary['target_sha256'], path.DIGEST)
        self.assertEqual(len(self.functions), 16)
        self.assertEqual(len(self.edges), 107)
        self.assertEqual(self.summary['selected_dataflow_slices'], 31)
        self.assertEqual(self.summary['selected_indirect_sites'], 5)
        self.assertEqual(self.summary['selected_relocations'], 3)
        self.assertEqual(self.summary['switch_entries_per_table'], 92)

    def test_wrong_digest_rejected(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            path.check_digest(b'not the captured node')
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            path.collect(b'not an ELF')

    def test_function_ranges_have_indexed_fde_and_expected_digest(self):
        functions = {row[0]: row for row in self.functions}
        self.assertEqual(functions['action_dispatch'][1:3], (0x55f99b0, 0x55faa79))
        self.assertEqual(functions['action_wrapper'][1:3], (0x58c07d0, 0x58c08b8))
        self.assertEqual(functions['finalize_core'][1:3], (0x469fe90, 0x46a02ea))
        self.assertEqual(functions['relationship_upsert'][1:3], (0x3ce1080, 0x3ce15ad))
        for role, start, end, _, fde, _, _, length, digest in self.functions:
            self.assertGreater(fde, 0, role)
            self.assertEqual(length, end - start, role)
            self.assertEqual(hashlib.sha256(path.raw_at(self.data, self.secs, start, length)).hexdigest(), digest)

    def test_corrupt_function_bytes_fail_closed(self):
        role, start, end, _, _, _, _, length, digest = next(x for x in self.functions if x[0] == 'action_wrapper')
        raw = path.raw_at(self.data, self.secs, start, length)
        path.check_window(raw, digest)
        corrupt = bytearray(raw)
        corrupt[11] ^= 1
        with self.assertRaisesRegex(ValueError, 'window mismatch'):
            path.check_window(bytes(corrupt), digest)
        with self.assertRaises(ValueError):
            path.check_window(raw[:-1], digest)

    def test_dataflow_slices_are_file_backed_and_within_owner(self):
        rows = path.read_slices(self.data, self.secs)
        self.assertEqual(len(rows), 31)
        by_name = {row[0]: row for row in rows}
        selected = by_name['finalize_write_arguments']
        self.assertEqual(selected[2:4], (0x46a0241, 0x46a02c5))
        self.assertEqual(hashlib.sha256(bytes.fromhex(selected[-1])).hexdigest(), selected[-2])
        with self.assertRaisesRegex(ValueError, 'outside selected FDE'):
            path.read_slices(self.data, self.secs, [('bad', 'action_wrapper', 0x58c07cf, 0x58c07d1)])
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            path.read_slices(self.data, self.secs, [path.SLICES[0], path.SLICES[0]])

    def test_two_independent_switches_and_name(self):
        selected = self.switches[11]
        self.assertEqual(selected[:2], (11, 0x91))
        self.assertEqual(selected[5], 0x2bcca03)
        self.assertEqual(selected[9], 0x4e100cd)
        self.assertEqual(selected[13], 0x55f9efe)
        self.assertNotEqual(self.switches[10][13], selected[13])
        self.assertNotEqual(self.switches[12][13], selected[13])
        names = {row[0]: row[-1] for row in self.literals}
        self.assertEqual(names['formatter_name'], 'linkStakingUser')
        self.assertEqual(names['variant_label'], 'LinkStakingUser')
        self.assertEqual(self.constants['dispatcher_bias'], self.constants['formatter_bias'])

    def test_unsigned_tag_underflow_and_upper_domain(self):
        bias = self.constants['dispatcher_bias']
        fallback = self.constants['dispatcher_underflow_index']
        for tag, expected in ((0, 20), (0x85, 20), (0x86, 0), (0x91, 11), (0xe1, 91), (0xe2, 92)):
            with self.subTest(tag=tag):
                self.assertEqual(path.normalized_index(tag, bias, fallback), expected)
        for invalid in (-1, 1 << 64, 1.5, True):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                path.normalized_index(invalid, bias, fallback)

    def test_corrupt_switch_destination_and_count_rejected(self):
        sec = {'type': 1, 'address': 0x1000, 'offset': 0, 'size': 16}
        owner = {'start': 0x1020, 'end': 0x1030}
        data = struct.pack('<i', 0x20) + bytes(12)
        self.assertEqual(path.switch_targets(data, [sec], 0x1000, 1, owner)[0][-1], 0x1020)
        bad = struct.pack('<i', 0x40) + bytes(12)
        with self.assertRaisesRegex(ValueError, 'outside selected FDE'):
            path.switch_targets(bad, [sec], 0x1000, 1, owner)
        with self.assertRaises(ValueError):
            path.switch_targets(data, [sec], 0x1000, 0, owner)
        with self.assertRaises(ValueError):
            path.switch_targets(data, [sec], 0x1000, 5, owner)

    def test_direct_edges_include_both_paths_and_writes(self):
        found = {row[0]: (row[2], row[-1]) for row in self.edges}
        expected = {
            'parent_selector_call': (0x5536d3f, 0x4e10080),
            'parent_first_gate_call': (0x5536d8f, 0x5551140),
            'parent_second_gate_call': (0x5536dd6, 0x5551540),
            'parent_dispatch_call': (0x5536e14, 0x55f99b0),
            'dispatch_to_wrapper': (0x55f9f10, 0x58c07d0),
            'wrapper_zero_mode': (0x58c07df, 0x58c0871),
            'wrapper_to_prerequisite': (0x58c089a, 0x5611bd0),
            'request_write': (0x469fe49, 0x3ce1080),
            'final_first_write': (0x46a0288, 0x3ce1080),
            'final_second_write': (0x46a02b6, 0x3ce1080),
        }
        for label, pair in expected.items():
            self.assertEqual(found[label], pair, label)
        self.assertLess(found['final_first_write'][0], found['final_second_write'][0])

    def test_branch_opcode_displacement_and_truncation_controls(self):
        source, expected = 0x55f9f10, 0x58c07d0
        raw = path.raw_at(self.data, self.secs, source, 6)
        self.assertEqual(path.checked_edge(raw, source, 'call', expected)[0], expected)
        changed = bytearray(raw)
        changed[1] ^= 1
        with self.assertRaisesRegex(ValueError, 'destination mismatch'):
            path.checked_edge(bytes(changed), source, 'call', expected)
        changed[0] = 0xe9
        with self.assertRaisesRegex(ValueError, 'unsupported or corrupted'):
            path.checked_edge(bytes(changed), source, 'call', expected)
        with self.assertRaises(ValueError):
            path.checked_edge(raw[:3], source, 'call', expected)

    def test_selected_selector_empty_result_and_gate_routes(self):
        raw = path.raw_at(self.data, self.secs, 0x4e100cd, 21)
        self.assertEqual(raw, bytes.fromhex('48c747080000000048c747180000000066c707a201'))
        edge = {row[0]: row[-1] for row in self.edges}
        self.assertEqual(edge['gate_one_empty'], 0x5551505)
        self.assertEqual(edge['gate_two_empty'], 0x5551770)
        self.assertEqual(edge['gate_two_empty_success'], 0x55517d4)
        self.assertEqual(edge['iterator_empty_kind'], 0x51e4db2)
        self.assertEqual(path.raw_at(self.data, self.secs, 0x51e4db2, 8), bytes.fromhex('49c7450000000000'))

    def test_parent_preserves_child_and_actor_arguments(self):
        self.assertEqual(path.raw_at(self.data, self.secs, 0x5536bba, 4), bytes.fromhex('4c8b7b18'))
        self.assertEqual(path.raw_at(self.data, self.secs, 0x5536e0c, 8), bytes.fromhex('4d89f84c8b4c2428'))
        edge = {row[0]: row[-1] for row in self.edges}
        self.assertEqual(edge['parent_selector_failure'], 0x5536e1e)
        self.assertEqual(edge['parent_first_gate_failure'], 0x5536eab)
        self.assertEqual(edge['parent_second_gate_failure'], 0x5536f6d)

    def test_parent_key_selection_branches_are_distinct(self):
        edge = {row[0]: row[-1] for row in self.edges}
        self.assertEqual(edge['parent_primary_tree_empty'], 0x5536957)
        self.assertEqual(edge['parent_primary_compact_absent'], 0x5536957)
        self.assertEqual(edge['parent_alternate_empty'], 0x5536bba)
        self.assertEqual(edge['parent_alternate_single_match'], 0x5536b08)
        self.assertEqual(edge['parent_alternate_index_outside'], 0x5537025)
        self.assertEqual(edge['parent_secondary_tree_found'], 0x5536b77)
        c = self.constants
        self.assertEqual((c['parent_primary_container_offset'], c['parent_alternate_count_offset']), (0xa18, 0x3cb0))
        self.assertEqual((c['parent_alternate_value_offset'], c['parent_secondary_value_offset']), (0x1c, 0xa0))

    def test_wrapper_pair_order_is_anchored_to_target_instructions(self):
        # The machine copies payload then actor for zero mode, and actor then
        # payload for nonzero mode. The fields occupy two adjacent 20-byte slots.
        expected = (
            (0x58c0871, '8b4638894424100f1046280f290424'),
            (0x58c0880, '0f10020f114424148b421089442424'),
            (0x58c07fc, '0f10020f2904248b421089442410'),
            (0x58c07ec, '8b4638894424240f1046280f11442414'),
            (0x553679b, '4889542428'),
            (0x5536d7f, '488d542430'),
            (0x5536e0f, '4c8b4c2428'),
        )
        for va, hex_bytes in expected:
            raw = bytes.fromhex(hex_bytes)
            with self.subTest(va=hex(va)):
                self.assertEqual(path.raw_at(self.data, self.secs, va, len(raw)), raw)

    def test_state_write_staging_is_anchored_to_target_instructions(self):
        expected = (
            (0x469fe07, '488b4c24408b4110894424210f10010f11442411c644241000'
                        '488b4c24488b4110894424600f10010f29442450488dbc2493000000'
                        '488d542450488d4c24104c89eee8321264ff'),
            (0x46a0241, '488b4c2440488d59148b4110894424210f10010f11442411c644241001'
                        '8b4310898424b00000000f10030f298424a0000000488d7c2450'
                        '488d9424a0000000488d4c24104c89eee8f30d64ff8b431089442421'
                        '0f10030f11442411c644241002488d7c2450488d942480000000'
                        '488d4c24104c89eee8c50d64ff'),
            (0x3ce14aa, '498b4d0d4889480d410f1045000f1100488b4a0d49894d0d0f1002410f114500'),
            (0x45461fa, '4b8d04bf498d04c74903460849ff46180f10030f104b100f1053190f1150190f1148100f1100'),
        )
        for va, hex_bytes in expected:
            raw = bytes.fromhex(hex_bytes)
            with self.subTest(va=hex(va)):
                self.assertEqual(path.raw_at(self.data, self.secs, va, len(raw)), raw)

    def test_relative_and_external_relocations(self):
        reloc = {row[0]: row for row in self.relocs}
        self.assertEqual(reloc[0x64e7a80][2:5], (8, 0, 0x469fe90))
        self.assertEqual(reloc[0x64e7f20][2:5], (8, 0, 0x469fa60))
        self.assertEqual(reloc[0x64dfb50][2:6], (6, 12, 0, 'memcmp'))
        slot, raw = path.rip_target(self.data, self.secs, 0x58c0815, bytes.fromhex('ff15'))
        self.assertEqual(slot, 0x64e7a80)
        self.assertEqual(len(raw), 6)

    def test_duplicate_and_missing_relocation_rejected(self):
        row = (0x1000, 8, 0x2000, 0, bytes(24))
        self.assertEqual(len(path.resolve_slot_records([row], {0x1000})), 1)
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            path.resolve_slot_records([row, row], {0x1000})
        with self.assertRaisesRegex(ValueError, 'missing'):
            path.resolve_slot_records([row], {0x1000, 0x2000})

    def test_corrupt_relocation_addend_and_type_rejected(self):
        actual = [row for row in path.relocation_records(self.data, self.secs) if row[0] in path.SLOTS]
        self.assertEqual(len(actual), len(path.SLOTS))
        for field in (1, 2):
            altered = []
            for row in actual:
                if row[0] == 0x64e7a80:
                    row = list(row)
                    row[field] ^= 1
                    row = tuple(row)
                altered.append(row)
            with self.subTest(field=field), mock.patch.object(path, 'relocation_records', return_value=iter(altered)):
                with self.assertRaisesRegex(ValueError, 'unexpected relocation'):
                    path.make_relocations(self.data, self.secs)

    def test_corrupted_immediate_and_rip_pattern_rejected(self):
        sec = {'type': 1, 'address': 0x1000, 'offset': 0, 'size': 8}
        self.assertEqual(path.checked_immediate(bytes.fromhex('b914000000000000'), [sec], 0x1000, 'b9', 4), 20)
        with self.assertRaises(ValueError):
            path.checked_immediate(bytes.fromhex('b814000000000000'), [sec], 0x1000, 'b9', 4)
        with self.assertRaises(ValueError):
            path.rip_target(bytes.fromhex('fe15000000000000'), [sec], 0x1000, bytes.fromhex('ff15'))

    def test_corrupted_semantic_constant_is_rejected(self):
        for name in ('final_staking_error_word', 'request_success_word',
                     'selector_bias', 'wrapper_relationship_container_offset'):
            altered = self.constants.copy()
            altered[name] ^= 1
            with self.subTest(name=name), self.assertRaises(ValueError):
                path.validate_constants(altered)

    def test_file_mapping_rejects_nobits_ambiguity_and_crossing(self):
        a = {'type': 1, 'address': 0x1000, 'offset': 0x30, 'size': 8}
        b = {'type': 8, 'address': 0x2000, 'offset': 0, 'size': 8}
        self.assertEqual(path.file_offset([a, b], 0x1000, 8), 0x30)
        for va, size in ((0x2000, 1), (0x1007, 2), (0x1000, 0), (-1, 1)):
            with self.subTest(va=va, size=size), self.assertRaises(ValueError):
                path.file_offset([a, b], va, size)
        with self.assertRaisesRegex(ValueError, 'uniquely'):
            path.file_offset([a, dict(a)], 0x1000)

    def test_constants_and_distinct_normal_returns(self):
        c = self.constants
        self.assertEqual((c['inner_success_word'], c['relationship_error_word']), (0x1a2, 0x16f))
        self.assertEqual((c['outer_success_tag'], c['outer_failure_tag']), (0x0e, 0x0f))
        self.assertEqual((c['request_value_tag'], c['final_first_value_tag'], c['final_second_value_tag']), (0, 1, 2))
        self.assertEqual((c['tree_to_compact_below'], c['compact_to_tree_at_least']), (32, 64))
        self.assertEqual(c['tree_node_local_bound'], 11)
        self.assertEqual(c['tree_representation_sentinel'], 1 << 63)
        self.assertEqual(c['empty_tree_allocation_bytes'], 0x1d0)
        self.assertEqual(c['selector_success_word'], 0x1a2)
        self.assertEqual(c['gate_one_success_word'], 0x1a2)
        self.assertEqual(c['gate_two_success_word'], 0x1a2)
        self.assertEqual((c['request_success_word'], c['final_success_word']), (0x1a2, 0x1a2))
        self.assertEqual((c['final_pending_error_word'], c['final_staking_error_word']), (0x16f, 0x16f))
        self.assertEqual(c['stake_container_offset'], 0xfb0)
        self.assertEqual((c['wrapper_relationship_container_offset'], c['request_relationship_container_offset']), (0x40a0, 0x40a0))
        self.assertEqual(c['wrapper_zero_mode_value'], 0)
        self.assertEqual(c['parent_prior_reject_word'], 0x120)
        self.assertEqual(c['parent_failure_tag'], 0x0f)
        self.assertEqual((c['selector_empty_first'], c['selector_empty_second']), (0, 0))
        self.assertEqual((c['parent_child_pointer_offset'], c['selector_child_pointer_offset']), (0x18, 0x18))
        self.assertEqual(c['relationship_key_bytes'], 20)
        self.assertEqual(c['dispatch_payload_offset'] + c['wrapper_payload_key_offset'], 0x30)
        self.assertEqual(c['dispatch_payload_offset'] + c['wrapper_mode_payload_offset'], 0x45)
        self.assertEqual(c['relationship_value_tail_offset'] + 8, 21)
        self.assertEqual(c['compact_last_copy_offset'] + 16, 41)
        self.assertEqual(path.raw_at(self.data, self.secs, 0x58c07db, 4), bytes.fromhex('807e3d00'))


class TransitionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        data = path.TARGET.read_bytes()
        records = path.collect(data)[7]
        cls.c = {row[0]: row[-1] for row in records}
        cls.a = b'A' * 20  # synthetic staking key
        cls.b = b'B' * 20  # synthetic trading key
        cls.c_key = b'C' * 20

    def model(self, mode, actor, other, stake, state):
        original = state.copy()
        result, updated = path.model_transition(self.c, mode, actor, other, stake, state)
        self.assertEqual(state, original, 'the synthetic input must not be mutated')
        return result, updated

    def test_request_and_finalize_normal_sequence(self):
        result, pending = self.model(0, self.b, self.a, True, {})
        self.assertEqual(result, 'success')
        self.assertEqual(pending, {self.b: (0, self.a)})
        result, finalized = self.model(1, self.a, self.b, False, pending)
        self.assertEqual(result, 'success')
        self.assertEqual(finalized, {self.b: (1, self.a), self.a: (2, self.b)})

    def test_missing_stake_precedes_self_or_relationship_checks(self):
        state = {self.a: (2, self.b)}
        self.assertEqual(self.model(0, self.a, self.a, False, state), ('stake_missing', state))
        self.assertEqual(self.model(0, self.a, self.a, True, state), ('self_link', state))

    def test_request_duplicate_order_and_unchanged_failure(self):
        state = {self.a: (2, self.c_key), self.b: (1, self.c_key)}
        self.assertEqual(self.model(0, self.b, self.a, True, state), ('trading_linked', state))
        state = {self.a: (2, self.c_key)}
        self.assertEqual(self.model(0, self.b, self.a, True, state), ('staking_linked', state))

    def test_request_replaces_existing_zero_tag_record(self):
        state = {self.b: (0, self.c_key)}
        result, updated = self.model(0, self.b, self.a, True, state)
        self.assertEqual(result, 'success')
        self.assertEqual(updated[self.b], (0, self.a))
        self.assertNotEqual(updated, state)

    def test_finalize_requires_matching_zero_tag(self):
        for state in ({}, {self.b: (1, self.a)}, {self.b: (0, self.c_key)}):
            with self.subTest(state=state):
                self.assertEqual(self.model(1, self.a, self.b, True, state), ('pending_required', state))

    def test_finalize_checks_second_key_only_after_pending_match(self):
        state = {self.b: (0, self.a), self.a: (1, self.c_key)}
        self.assertEqual(self.model(7, self.a, self.b, False, state), ('staking_linked', state))
        wrong_pending = {self.b: (0, self.c_key), self.a: (1, self.c_key)}
        self.assertEqual(self.model(7, self.a, self.b, False, wrong_pending), ('pending_required', wrong_pending))

    def test_maximum_nonzero_mode_uses_finalize_path(self):
        state = {self.b: (0, self.a)}
        result, updated = self.model(255, self.a, self.b, False, state)
        self.assertEqual(result, 'success')
        self.assertEqual(updated, {self.b: (1, self.a), self.a: (2, self.b)})

    def test_bad_synthetic_input_rejected(self):
        for actor, state in ((b'short', {}), (self.a, {self.b: (0, b'short')}), (self.a, {self.b: (256, self.a)})):
            with self.subTest(actor=actor, state=state), self.assertRaises(ValueError):
                path.model_transition(self.c, 0, actor, self.a, True, state)
        for invalid in (-1, 256, True):
            with self.subTest(mode=invalid), self.assertRaises(ValueError):
                path.model_transition(self.c, invalid, self.a, self.b, True, {})


if __name__ == '__main__':
    unittest.main()
