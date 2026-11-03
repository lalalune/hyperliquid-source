# SPDX-License-Identifier: MIT
"""Target-bound and negative controls for the selected static evidence."""
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import re010_cvalidator_unregister_115 as evidence


def table(raw):
    return list(csv.DictReader(io.StringIO(raw.decode('utf-8')), delimiter='\t'))


class TargetEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # This must fail, not skip, when the pinned target is unavailable.
        cls.data = evidence.TARGET.read_bytes()
        cls.output = evidence.generate(cls.data)
        cls.secs = evidence.sections(cls.data)

    def test_target_digest_and_corruption(self):
        evidence.verify_digest(self.data)
        changed = bytearray(self.data)
        changed[0x3c3c480] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            evidence.verify_digest(changed)
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            evidence.verify_digest(self.data, '0' * 64)

    def test_selected_fdes_and_full_body_hashes(self):
        rows = {r['role']: r for r in table(self.output['functions.tsv'])}
        bodies = {r['role']: r for r in table(self.output['bodies.tsv'])}
        self.assertEqual(len(rows), 22)
        self.assertEqual(rows.keys(), bodies.keys())
        self.assertEqual(rows['state_dispatch']['start_va'], '0x3c3d480')
        self.assertEqual(rows['state_dispatch']['end_va_exclusive'], '0x3c3f412')
        self.assertEqual(rows['nested_clone']['start_va'], '0x5659f70')
        for name, row in rows.items():
            start = int(row['start_va'], 16)
            end = int(row['end_va_exclusive'], 16)
            raw = bytes.fromhex(bodies[name]['body_hex'])
            self.assertEqual(len(raw), end - start, name)
            self.assertEqual(raw, evidence.get_bytes(self.data, self.secs, start, len(raw)), name)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), row['sha256'], name)

    def test_other_arm_is_in_core_not_indexed_entry(self):
        _, entries = evidence.unwind_index(self.data)
        starts = {e['start'] for e in entries}
        self.assertIn(0x3c3d480, starts)
        self.assertNotIn(0x3c3d61d, starts)
        self.assertLess(0x3c3d480, 0x3c3d61d)
        self.assertLess(0x3c3d61d, 0x3c3f412)

    def test_direct_call_and_branch_bytes(self):
        branch = evidence.get_bytes(self.data, self.secs, 0x3c3d4e7, 6)
        self.assertEqual(branch.hex(), '0f8530010000')
        self.assertEqual(evidence.checked_transfer(branch, 0x3c3d4e7, 'jne', 0x3c3d61d), branch)
        call = evidence.get_bytes(self.data, self.secs, 0x3c3e77b, 5)
        self.assertEqual(evidence.decode_transfer(call, 0x3c3e77b)[:2], ('call', 0x3c36ba0))
        short = bytes.fromhex('75ea')
        self.assertEqual(evidence.decode_transfer(short, 0x1000)[:2], ('jne', 0xfec))

    def test_bad_transfer_bytes_fail_closed(self):
        raw = bytearray(bytes.fromhex('0f8530010000'))
        raw[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'transfer mismatch'):
            evidence.checked_transfer(raw, 0x3c3d4e7, 'jne', 0x3c3d61d)
        with self.assertRaisesRegex(ValueError, 'transfer mismatch'):
            evidence.checked_transfer(bytes.fromhex('0f8530010000'), 0x3c3d4e7, 'je', 0x3c3d61d)
        for invalid in (b'', b'\x0f\x85', b'\xe8\x00', b'\x90\x90'):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                evidence.decode_transfer(invalid, 0x1000)

    def test_fixed_immediate_rejects_changed_prefix_and_range(self):
        raw = bytes.fromhex('488b9810010000')
        section = [{'name': '.text', 'type': 1, 'address': 0x1000,
                    'offset': 0, 'size': len(raw)}]
        value, used = evidence.fixed_immediate(raw, section, 0x1000, '488b98', '<I')
        self.assertEqual((value, used), (0x110, raw))
        with self.assertRaisesRegex(ValueError, 'prefix mismatch'):
            evidence.fixed_immediate(b'\x90' + raw[1:], section, 0x1000, '488b98', '<I')
        with self.assertRaises(ValueError):
            evidence.fixed_immediate(raw, section, 0x1001, '488b98', '<I')

    def test_file_backing_and_nobits_are_enforced(self):
        text = next(s for s in self.secs if s['name'] == '.text')
        bss = next(s for s in self.secs if s['name'] == '.bss')
        self.assertEqual(evidence.va_offset(self.secs, text['address'], 1), text['offset'])
        with self.assertRaises(ValueError):
            evidence.va_offset(self.secs, bss['address'], 1)
        with self.assertRaises(ValueError):
            evidence.va_offset(self.secs, text['address'] + text['size'] - 1, 2)
        with self.assertRaises(ValueError):
            evidence.va_offset(self.secs, -1, 1)
        with self.assertRaises(ValueError):
            evidence.va_offset(self.secs, text['address'], 0)
        with self.assertRaises(ValueError):
            evidence.va_offset([text, dict(text)], text['address'], 1)

    def test_reference_lea_and_relocation(self):
        site = 0x574d5f6
        raw = evidence.get_bytes(self.data, self.secs, site, 7)
        self.assertEqual(evidence.rip_lea(raw, site, '488d15'), 0x64aff08)
        with self.assertRaises(ValueError):
            evidence.rip_lea(raw[:-1], site, '488d15')
        with self.assertRaises(ValueError):
            evidence.rip_lea(raw, site, '488d05')
        rows = {r['role']: r for r in table(self.output['relocations.tsv'])}
        self.assertEqual(rows['core_entry_slot']['addend'], '0x3c3d480')
        self.assertEqual(rows['visitor_description']['addend'], '0x9345ad')
        self.assertEqual(rows['comparison_slot']['symbol'], 'memcmp')
        self.assertEqual(rows['shift_slot']['symbol'], 'memmove')
        self.assertEqual(rows['tree_entry_allocate_slot']['addend'], '0x6355830')
        with self.assertRaises(ValueError):
            evidence.dynamic_symbol(self.data, self.secs, 1000000)

    def test_missing_or_duplicate_relocations_rejected(self):
        records = [struct.pack('<QQq', slot, kind, addend)
                   for _, slot, kind, addend, _ in evidence.RELOCATION_SLOTS]
        def fake_section(n):
            return [{'name': '.rela.dyn', 'type': 4, 'offset': 0, 'size': n * 24}]
        self.assertEqual(len(evidence.find_relocations(b''.join(records), fake_section(len(records)))), 9)
        with self.assertRaisesRegex(ValueError, 'absent'):
            evidence.find_relocations(b''.join(records[:-1]), fake_section(len(records) - 1))
        duplicate = b''.join(records + [records[0]])
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            evidence.find_relocations(duplicate, fake_section(len(records) + 1))
        with self.assertRaisesRegex(ValueError, 'misaligned'):
            evidence.find_relocations(b'\0', [{'name': '.rela.dyn', 'type': 4, 'offset': 0, 'size': 1}])

    def test_bad_dynamic_symbol_string_rejected(self):
        data = bytes(24) + b'bad'
        sections = [{'name': '.dynsym', 'type': 11, 'offset': 0, 'size': 24},
                    {'name': '.dynstr', 'type': 3, 'offset': 24, 'size': 3}]
        with self.assertRaisesRegex(ValueError, 'unterminated'):
            evidence.dynamic_symbol(data, sections, 0)
        with self.assertRaisesRegex(ValueError, 'outside'):
            evidence.dynamic_symbol(data, sections, 1)
        missing = [sections[0], dict(sections[1], type=8)]
        with self.assertRaisesRegex(ValueError, 'missing'):
            evidence.dynamic_symbol(data, missing, 0)

    def test_names_and_outer_tag_observations(self):
        names = {int(r['ordinal']): r['name'] for r in table(self.output['names.tsv'])}
        self.assertEqual(names, {0: 'register', 1: 'changeProfile', 2: 'unregister'})
        identity = {r['role']: r['literal'] for r in table(self.output['identity.tsv'])}
        self.assertEqual(identity['visitor_diagnostic'],
                         'struct variant VoteGlobalAction::CValidator with 2 elements')
        self.assertEqual(identity['nested_unregister_wire_name'], 'unregister')
        self.assertEqual(identity['nested_enum_type'], 'CValidatorAction')
        self.assertEqual(identity['outer_variant_wire_name'], 'O')
        self.assertEqual(identity['nested_field_wire_name'], 'a')
        self.assertEqual(identity['second_field_wire_name'], 'c')
        switches = table(self.output['outer-switch.tsv'])
        chosen = {r['owner']: r for r in switches if r['tag'] == '59'}
        self.assertEqual(chosen['outer_clone']['target_va'], '0x565a61c')
        self.assertEqual(chosen['outer_serializer']['target_va'], '0x53b455b')
        self.assertEqual(chosen['outer_clone']['index'], '39')

    def test_output_counts_and_closed_scope(self):
        counts = json.loads(self.output['summary.json'])
        self.assertEqual(counts['target_sha256'], evidence.DIGEST)
        self.assertEqual(counts['selected_fdes'], 22)
        self.assertEqual(counts['selected_windows'], 94)
        self.assertEqual(counts['selected_branches'], 81)
        self.assertEqual(counts['selected_direct_calls'], 32)
        self.assertEqual(counts['selected_relocations'], 9)
        self.assertEqual(counts['selected_immediates'], 43)
        self.assertEqual(counts['derived_operands'], 2)
        self.assertEqual(counts['identity_records'], 7)
        self.assertEqual(counts['niche_vectors'], 7)
        self.assertEqual(counts['decision_vectors'], 8)
        self.assertEqual(counts['compact_vectors'], 27)
        self.assertEqual(counts['transition_vectors'], 18)
        for key, filename in (('selected_windows', 'windows.tsv'),
                              ('selected_branches', 'branches.tsv'),
                              ('selected_direct_calls', 'calls.tsv')):
            self.assertEqual(counts[key], len(table(self.output[filename])))
        self.assertEqual(len(self.output), 16)

    def test_decoded_state_offsets_and_widths(self):
        rows = {r['label']: r['value'] for r in table(self.output['operands.tsv'])}
        self.assertEqual(rows['first_lookup_state_offset'], '0x110')
        self.assertEqual(rows['second_lookup_state_offset'], '0xd0')
        self.assertEqual(rows['third_remove_state_offset'], '0x288')
        self.assertEqual(rows['followup_first_state_offset'], '0x180')
        self.assertEqual(rows['followup_second_state_offset'], '0x1e8')
        self.assertEqual(rows['followup_last_collection_offset'], '0x48')
        self.assertEqual(rows['followup_compact_record_stride'], '0x38')
        self.assertEqual(rows['key_comparison_bytes'], '0x14')
        self.assertEqual(rows['second_lookup_stride'], '0x70')
        self.assertEqual(rows['visitor_missing_marker'], '0x86')
        self.assertEqual(rows['outer_first_payload_offset'], '0x8')
        self.assertEqual(rows['outer_second_payload_offset'], '0x70')
        self.assertEqual(rows['tree_entry_empty_node_size'], '0xe8')
        self.assertEqual(rows['tree_entry_node_slot_limit'], '0xb')
        self.assertEqual(rows['tree_entry_initial_node_count'], '0x0')
        self.assertEqual(rows['tree_insert_empty_node_size'], '0x248')
        self.assertEqual(rows['tree_insert_node_slot_limit'], '0xb')
        self.assertEqual(rows['tree_insert_initial_node_count'], '0x0')
        self.assertEqual(rows['compact_insert_record_stride'], '0x38')
        derived = {r['label']: r['value'] for r in table(self.output['derived-operands.tsv'])}
        self.assertEqual(derived['first_lookup_record_stride'], '0x40')
        self.assertEqual(derived['third_lookup_record_stride'], '0x30')

    def test_selected_followup_mutation_routes(self):
        calls = {r['label']: r for r in table(self.output['calls.tsv'])}
        self.assertEqual(calls['followup_compact_search']['target_va'], '0x455a9e0')
        self.assertEqual(calls['followup_compact_insert']['target_va'], '0x4548f00')
        self.assertEqual(calls['followup_tree_insert']['target_va'], '0x370d5e0')
        branches = {r['label']: r for r in table(self.output['branches.tsv'])}
        self.assertEqual(branches['followup_compact_bad_index']['target_va'], '0x3c37474')
        self.assertEqual(branches['visitor_empty_sequence']['target_va'], '0x574d5f2')
        self.assertEqual(branches['tree_entry_empty_root']['target_va'], '0x370bf3c')
        self.assertEqual(branches['tree_entry_allocation_failure']['target_va'], '0x370bfbc')
        self.assertEqual(branches['tree_entry_node_full']['target_va'], '0x370bfcc')

    def test_followup_compact_lookup_found_and_missing_encodings(self):
        self.assertEqual(evidence.get_bytes(self.data, self.secs, 0x455ab05, 5).hex(),
                         '31c04d89ee')
        self.assertEqual(evidence.get_bytes(self.data, self.secs, 0x455aafb, 5).hex(),
                         'b801000000')
        jump = evidence.get_bytes(self.data, self.secs, 0x455aaf0, 2)
        self.assertEqual(evidence.decode_transfer(jump, 0x455aaf0)[:2], ('je', 0x455ab05))

    def test_followup_insertion_updates_are_file_backed(self):
        self.assertEqual(evidence.get_bytes(self.data, self.secs, 0x4548fc2, 4).hex(),
                         '49ff4618')
        self.assertEqual(evidence.get_bytes(self.data, self.secs, 0x370d6db, 5).hex(),
                         '49ff442410')
        branches = {r['label']: r for r in table(self.output['branches.tsv'])}
        self.assertEqual(branches['followup_insert_bad_index']['target_va'], '0x4548ff0')
        self.assertEqual(branches['followup_tree_allocation_failure']['target_va'], '0x370d701')
        self.assertEqual(branches['followup_tree_node_full']['target_va'], '0x370d711')


class SyntheticModelTests(unittest.TestCase):
    def test_niche_sign_and_wrap_boundaries(self):
        cases = ((0, 0), (1, 0), (2**63 - 1, 0), (2**63, 1),
                 (2**63 + 1, 2), (2**63 + 2, 3), (2**64 - 1, 2**63))
        for word, result in cases:
            with self.subTest(word=word):
                self.assertEqual(evidence.classify_word(word), result)
        for invalid in (-1, 2**64, True, 1.5):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                evidence.classify_word(invalid)

    def test_clone_other_canonicalization(self):
        self.assertEqual(evidence.clone_other_word(2**63 + 1), 2**63 + 1)
        self.assertEqual(evidence.clone_other_word(2**64 - 1), 2**63 + 1)
        for invalid in (0, 2**63):
            with self.subTest(word=invalid), self.assertRaises(ValueError):
                evidence.clone_other_word(invalid)

    def test_early_result_precedence(self):
        f = evidence.removal_outcome
        self.assertEqual(f(True, True, False), ('first_nonzero', 0x144))
        self.assertEqual(f(True, True, True), ('first_nonzero', 0x144))
        self.assertEqual(f(False, True, False), ('profile_missing', 0x95))
        self.assertEqual(f(True, False, False), ('profile_missing', 0x95))
        self.assertEqual(f(True, False, True), ('remove_path', 0x1a2))
        with self.assertRaises(ValueError):
            f(1, False, False)

    def test_compact_removal_bounds_and_tie(self):
        f = evidence.compact_removal_model
        self.assertEqual(f(7, 6, 5, 0), ('prefix', 0, 4, 0))
        self.assertEqual(f(7, 6, 5, 2), ('prefix', 0, 4, 2))
        self.assertEqual(f(7, 6, 5, 3), ('suffix', 6, 4, 1))
        self.assertEqual(f(7, 6, 5, 5), ('out_of_range', 6, 5, 0))
        self.assertEqual(f(1, 0, 0, 0), ('out_of_range', 0, 0, 0))
        self.assertEqual(f(1, 0, 1, 0), ('prefix', 0, 0, 0))

    def test_invalid_compact_assumptions_rejected(self):
        f = evidence.compact_removal_model
        for args in ((0, 0, 0, 0), (7, 7, 0, 0), (7, 0, 8, 0),
                     (7, 0, 1, -1), (7, 0, 1, 2**64), (7, True, 1, 0)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                f(*args)

    def test_small_tree_threshold_and_sentinel(self):
        f = evidence.small_tree_conversion
        self.assertTrue(f(2**63, 31))
        self.assertFalse(f(2**63, 32))
        self.assertFalse(f(0, 31))
        for args in ((-1, 31), (2**64, 31), (2**63, -1), (2**63, True)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                f(*args)

    def test_followup_conversion_threshold_and_found_key(self):
        f = evidence.followup_representation_route
        self.assertEqual(f(0, 63, True), 'compact_route')
        self.assertEqual(f(0, 64, True), 'compact_conversion')
        self.assertEqual(f(0, 64, False), 'compact_route')
        self.assertEqual(f(2**63, 64, True), 'tree_route')
        for args in ((0, -1, True), (0, 2**64, True), (0, 64, 1)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                f(*args)


if __name__ == '__main__':
    unittest.main()
