"""Negative controls and boundary tests for node 94 role-cache evidence."""
import copy
import hashlib
import itertools
import math
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

from tools import config_role_cache94 as target


class RoleCacheEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = target.TARGET.read_bytes()
        cls.view = target.View(cls.data)
        cls.results = target.collect(cls.data)
        cls.constants = cls.results['summary']['constants']
        cls.decodes = {name: target.decode_body(cls.view.read(start, end - start), start)
                       for name, start, end, _ in target.FUNCTIONS}
        cls.mutable = bytearray(cls.data)
        cls.mview = target.View(cls.mutable)

    def flip(self, va):
        off = self.mview.offset(va)
        self.mutable[off] ^= 1
        self.addCleanup(self.restore, off)
        return off

    def restore(self, off):
        self.mutable[off] ^= 1

    def test_input_identity_is_checked_before_parsing(self):
        target.verify_identity(self.data)
        corrupted = bytearray(self.data)
        corrupted[0] ^= 1
        with mock.patch.object(target, 'sections', side_effect=AssertionError('parsed corrupt input')):
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                target.collect(corrupted)

    def test_truncated_input_is_rejected(self):
        with self.assertRaises(ValueError):
            target.verify_identity(self.data[:-1])

    def test_selected_ranges_and_complete_byte_cover(self):
        self.assertEqual(15, len(self.results['functions']))
        self.assertEqual(9038, self.results['summary']['selected_fde_bytes'])
        for name, start, end, digest in target.FUNCTIONS:
            with self.subTest(function=name):
                decoded = self.decodes[name]
                self.assertEqual(start, decoded[0]['va'])
                self.assertEqual(end, decoded[-1]['end'])
                body = b''.join(x['bytes'] for x in decoded)
                self.assertEqual(self.view.read(start, end - start), body)
                self.assertEqual(digest, hashlib.sha256(body).hexdigest())

    def test_changed_fde_range_is_rejected(self):
        old = list(target.FUNCTIONS)
        name, start, end, digest = old[0]
        old[0] = name, start, end + 1, digest
        with mock.patch.object(target, 'FUNCTIONS', tuple(old)):
            with self.assertRaisesRegex(ValueError, 'FDE'):
                target.collect(self.data)

    def test_duplicate_fde_is_rejected(self):
        cies, fdes = target.eh_frame_records(self.data, self.view.sections)
        selected = next(x for x in fdes if x['start'] == target.FUNCTIONS[0][1])
        with mock.patch.object(target, 'eh_frame_records', return_value=(cies, fdes + [selected])):
            with self.assertRaisesRegex(ValueError, 'FDE'):
                target.collect(self.data)

    def test_changed_instruction_is_rejected_after_identity_gate(self):
        self.flip(0x1f85359)
        with mock.patch.object(target, 'verify_identity', return_value=None):
            with self.assertRaisesRegex(ValueError, 'digest'):
                target.collect(self.mutable)

    def test_every_contract_rejects_single_byte_corruption(self):
        for label, va, expected in target.CONTRACTS:
            off = self.mview.offset(va)
            self.mutable[off] ^= 1
            try:
                with self.subTest(label=label), self.assertRaises(ValueError):
                    target.require(self.mview, label, va, bytes.fromhex(expected))
            finally:
                self.mutable[off] ^= 1

    def test_contract_collection_rejects_corrupt_instruction(self):
        self.flip(0x27d028b)
        with self.assertRaises(ValueError):
            target.collect_contracts(self.mview, self.decodes)

    def test_layout_operands_and_corrupt_displacement(self):
        fields = {r['label']: r['value'] for r in target.layout_rows(self.view, self.decodes)}
        self.assertEqual(0x4720, fields['first_map_pointer'])
        self.assertEqual(0x4738, fields['first_map_count'])
        self.assertEqual(0x18c0, fields['tree_root'])
        self.assertEqual(0x568, fields['cache_lock'])
        self.assertEqual(fields['cache_update_index'], fields['cache_peek_index'])
        self.assertEqual(0x570, fields['cache_update_index'])
        self.assertEqual(0x58, fields['cache_node_allocation_size'])
        self.assertEqual(0x10, fields['role_descriptor_variant_pointer'])
        self.assertEqual(0x18, fields['role_descriptor_variant_length'])
        self.flip(0x27cfed6)
        with self.assertRaises(ValueError):
            target.layout_rows(self.mview, self.decodes)

    def test_contract_rejects_duplicate_and_interior_instruction(self):
        with mock.patch.object(target, 'CONTRACTS', (target.CONTRACTS[0], target.CONTRACTS[0])):
            with self.assertRaisesRegex(ValueError, 'duplicate'):
                target.collect_contracts(self.view, self.decodes)
        va = 0x1f8535a
        with mock.patch.object(target, 'CONTRACTS', (('interior', va, self.view.read(va, 1).hex()),)):
            with self.assertRaisesRegex(ValueError, 'complete decoded'):
                target.collect_contracts(self.view, self.decodes)

    def test_branch_decoder_rejects_jump_into_operand(self):
        with self.assertRaisesRegex(ValueError, 'instruction'):
            target.decode_body(bytes.fromhex('7501b800000000c3'), 0x1000)
        accepted = target.decode_body(bytes.fromhex('7505b800000000c3'), 0x1000)
        self.assertEqual(0x1007, accepted[0]['target'])

    def test_decoder_rejects_truncated_unknown_and_prefix_flood(self):
        for raw in ('488b0500', '0fff', '66' * 9 + '90'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                target.decode_body(bytes.fromhex(raw), 0x1000)

    def test_all_selected_branch_targets_land_on_instructions(self):
        for function, body in self.decodes.items():
            starts = {row['va'] for row in body}
            start, end = body[0]['va'], body[-1]['end']
            for row in body:
                if row['kind'] in ('conditional', 'jump') and start <= row['target'] < end:
                    with self.subTest(function=function, va=hex(row['va'])):
                        self.assertIn(row['target'], starts)

    def test_selected_relocation_corruption_is_rejected(self):
        rows = target.selected_relocations(self.view, target.RELOCATIONS)
        off = int(rows[0x576e928]['record_file_offset'], 16)
        self.mutable[off + 16] ^= 1
        try:
            with self.assertRaisesRegex(ValueError, 'target mismatch'):
                target.selected_relocations(self.mview, target.RELOCATIONS)
        finally:
            self.mutable[off + 16] ^= 1

    def test_duplicate_relocation_is_rejected(self):
        rows = target.selected_relocations(self.view, target.RELOCATIONS)
        selected = int(rows[0x576e928]['record_file_offset'], 16)
        rela = next(x for x in self.view.sections if x['name'] == '.rela.dyn')
        other = next(off for off in range(rela['offset'], rela['offset'] + rela['size'], 24)
                     if struct.unpack_from('<Q', self.data, off)[0] not in target.RELOCATIONS)
        saved = self.mutable[other:other + 24]
        self.mutable[other:other + 24] = self.mutable[selected:selected + 24]
        try:
            with self.assertRaisesRegex(ValueError, 'duplicate'):
                target.selected_relocations(self.mview, target.RELOCATIONS)
        finally:
            self.mutable[other:other + 24] = saved

    def test_nobits_ambiguous_out_of_range_and_empty_views_rejected(self):
        view = target.View.__new__(target.View)
        view.data = bytes(16)
        view.sections = [{'name': 'section', 'type': 8, 'address': 0x1000,
                          'offset': 0, 'size': 8, 'flags': 2}]
        with self.assertRaises(ValueError):
            view.read(0x1000, 1)
        view.sections[0]['type'] = 1
        with self.assertRaises(ValueError):
            view.read(0x1007, 2)
        with self.assertRaises(ValueError):
            view.read(0x1000, 0)
        view.sections.append(dict(view.sections[0]))
        with self.assertRaises(ValueError):
            view.read(0x1000, 1)

    def test_bounded_handoff_and_pool_corruption_rejected(self):
        self.flip(0x27e537a)
        with self.assertRaises(ValueError):
            target.collect_context(self.mview)

    def test_label_requires_the_full_length_delimited_bytes(self):
        _, context = target.collect_context(self.view)
        relocs = target.selected_relocations(self.view, target.RELOCATIONS)
        records = target.collect_pools(self.view, relocs, context)
        self.assertEqual([20, 22, 9], [x['length'] for x in records])
        self.assertEqual('75', records[0]['after'])
        self.flip(0x3f3af2)
        with self.assertRaisesRegex(ValueError, 'bounded label'):
            target.collect_pools(self.mview, relocs, context)

    def test_threshold_corruption_rejected(self):
        self.flip(0x20aab8)
        with self.assertRaisesRegex(ValueError, 'threshold'):
            target.constants_from_bytes(self.mview, self.decodes)

    def test_five_role_outcomes_and_precedence(self):
        self.assertEqual((2, 3, 4, 1, 0), tuple(
            target.role_choice(hits, self.constants)[1] for hits in (
                (True, True, True, True), (False, True, True, True),
                (False, False, True, True), (False, False, False, True),
                (False, False, False, False))))
        for hits in itertools.product((False, True), repeat=4):
            source, result = target.role_choice(hits, self.constants)
            first = next((i for i, hit in enumerate(hits) if hit), None)
            expected = (2, 3, 4, 1)[first] if first is not None else 0
            self.assertEqual(expected, result, (hits, source))
        with self.assertRaises(ValueError):
            target.role_choice((True, False), self.constants)
        with self.assertRaises(ValueError):
            target.role_choice((1, False, False, False), self.constants)

    def test_writer_dispatch_and_descriptor_boundaries(self):
        descriptors = self.results['descriptors']
        self.assertEqual(['missing', 'user', 'agent', 'vault', 'subAccount'],
                         [target.writer_variant(i, descriptors) for i in range(5)])
        self.assertEqual([0, 1, 2, 3, 4], [r['ordinal'] for r in descriptors])
        self.assertEqual(['', '', '0x2a289cb', '', '0x2a28925'],
                         [r['payload_call'] for r in descriptors])
        self.assertEqual(['role', 'data', 'user', 'master'],
                         [r['text'] for r in self.results['writer_keys']])
        for invalid in (-1, 5, 255, True):
            with self.assertRaises(ValueError):
                target.writer_variant(invalid, descriptors)

    def test_role_selector_tags_match_writer_descriptor_ordinals(self):
        rows = self.results['descriptors']
        for hits, expected in (((True, False, False, False), 'agent'),
                               ((False, True, False, False), 'vault'),
                               ((False, False, True, False), 'subAccount'),
                               ((False, False, False, True), 'user'),
                               ((False, False, False, False), 'missing')):
            _, tag = target.role_choice(hits, self.constants)
            self.assertEqual(expected, target.writer_variant(tag, rows))
        self.assertEqual(5, self.constants['cache_miss_tag'])
        with self.assertRaises(ValueError):
            target.writer_variant(self.constants['cache_miss_tag'], rows)

    def test_writer_key_corruption_is_rejected(self):
        for va in (0x209d14, 0x20a08c, 0x209ebc, 0x41fb8e):
            off = self.mview.offset(va)
            self.mutable[off] ^= 1
            try:
                with self.subTest(va=hex(va)), self.assertRaises(ValueError):
                    target.writer_literals(self.mview, self.decodes)
            finally:
                self.mutable[off] ^= 1

    def test_nested_writer_branches_separate_error_from_finish(self):
        for name, failed, cleanup, finish, success in (
                ('agent_nested_writer', 0x2a28d7a, 0x2a28d88, 0x2a28dde, 0x2a28d8f),
                ('subaccount_nested_writer', 0x2a28c4a, 0x2a28c58, 0x2a28cae, 0x2a28c5f)):
            with self.subTest(function=name):
                body = self.decodes[name]
                self.assertTrue(target.reachable(body, failed, cleanup))
                self.assertFalse(target.reachable(body, failed, finish))
                self.assertTrue(target.reachable(body, success, finish))

    def test_role_field_passes_variant_and_checks_failure_path(self):
        body = self.decodes['role_field_helper']
        self.assertTrue(target.reachable(body, 0x29fbdf9, 0x29fbe1f))
        self.assertTrue(target.reachable(body, 0x29fbe1f, 0x29fbe5e))
        self.assertTrue(target.reachable(body, 0x29fbf22, 0x29fbdf1))
        self.assertFalse(target.reachable(body, 0x29fbf22, 0x29fbe5e))

    def test_corrupt_jump_table_and_descriptor_are_rejected(self):
        relocs = target.selected_relocations(self.view, target.RELOCATIONS)
        entry = self.mview.offset(0x41f33c, 4)
        saved = self.mutable[entry:entry + 4]
        self.mutable[entry:entry + 4] = bytes(4)
        try:
            with self.assertRaises(ValueError):
                target.role_descriptors(self.mview, self.decodes, relocs)
        finally:
            self.mutable[entry:entry + 4] = saved
        ordinal = self.mview.offset(0x56d5278, 8)
        self.mutable[ordinal] ^= 1
        try:
            with self.assertRaises(ValueError):
                target.role_descriptors(self.mview, self.decodes, relocs)
        finally:
            self.mutable[ordinal] ^= 1

    def test_key_comparison_distinguishes_each_byte_and_length(self):
        key = bytes(range(20))
        self.assertTrue(target.key_equal20(key, key, self.constants['key_bytes']))
        for index in range(20):
            other = bytearray(key)
            other[index] ^= 1
            with self.subTest(index=index):
                self.assertFalse(target.key_equal20(key, other, self.constants['key_bytes']))
        for other in (key[:-1], key + b'X'):
            with self.assertRaises(ValueError):
                target.key_equal20(key, other, self.constants['key_bytes'])

    def test_name_gate_boundaries_and_nan(self):
        selected = {13, 14, 18, 19, 20, 21, 31}
        for value in range(256):
            self.assertEqual(value in selected, target.gate_uses_second_state(value, 3.5, self.constants))
            self.assertFalse(target.gate_uses_second_state(value, 3.0, self.constants))
            self.assertFalse(target.gate_uses_second_state(value, math.nan, self.constants))
        self.assertFalse(target.gate_uses_second_state(32, math.inf, self.constants))
        self.assertTrue(target.gate_uses_second_state(31, math.inf, self.constants))
        for invalid in (-1, 256, True):
            with self.assertRaises(ValueError):
                target.gate_uses_second_state(invalid, 4.0, self.constants)

    def test_cache_replacement_allocation_and_reuse(self):
        a, b, c = (bytes([x]) * 20 for x in (1, 2, 3))
        self.assertEqual(('replace', [b, a]), target.cache_step([a, b], b, 2, 20))
        self.assertEqual(('allocate', [c, a, b]), target.cache_step([a, b], c, 3, 20))
        self.assertEqual(('reuse_tail', [c, a]), target.cache_step([a, b], c, 2, 20))
        for order, key, cap in (([a, a], b, 2), ([a], b[:-1], 2), ([a, b], c, 1), ([], a, 0)):
            with self.assertRaises(ValueError):
                target.cache_step(order, key, cap, 20)

    def test_removal_marker_boundary_and_checked_counter(self):
        maximum = (1 << 64) - 1
        self.assertEqual((0xff, 1, False), target.removal_marker(15, 0, self.constants))
        self.assertEqual((0x80, 0, False), target.removal_marker(16, 0, self.constants))
        self.assertEqual((None, maximum, True), target.removal_marker(15, maximum, self.constants))
        self.assertEqual((0x80, maximum, False), target.removal_marker(16, maximum, self.constants))
        for distance, count in ((-1, 0), (65536, 0), (0, -1), (0, maximum + 1)):
            with self.assertRaises(ValueError):
                target.removal_marker(distance, count, self.constants)

    def test_counter_saturates_at_unsigned_max(self):
        top = (1 << 64) - 1
        self.assertEqual(1, target.saturating_next(0))
        self.assertEqual(top, target.saturating_next(top - 1))
        self.assertEqual(top, target.saturating_next(top))
        for invalid in (-1, top + 1, True):
            with self.assertRaises(ValueError):
                target.saturating_next(invalid)

    def test_exception_table_rejects_changed_encoding(self):
        fde = next(x for x in self.results['functions'] if x['function'] == 'cache_update')
        lsda = int(fde['lsda_va'], 16)
        self.flip(lsda)
        with self.assertRaises(ValueError):
            target.parse_lsda(self.mview, int(fde['start_va'], 16), int(fde['end_va_exclusive'], 16), lsda)

    def test_exception_landing_must_match_selected_call(self):
        records = copy.deepcopy(self.results['lsda'])
        record = next(r for r in records if r['function_name'] == 'cache_update' and
                      int(r['start_va'], 16) <= 0x27d2ea1 < int(r['end_va'], 16))
        record['landing_va'] = '0x1'
        with self.assertRaisesRegex(ValueError, 'landing'):
            target.checked_failures(records)

    def test_cfg_controls_include_forbidden_reachability(self):
        rows = {r['proposition']: r['reachable'] for r in target.checked_flow(self.decodes)}
        self.assertEqual(1, rows['replacement_relinks'])
        self.assertEqual(0, rows['replacement_reaches_allocation'])
        self.assertEqual(0, rows['first_match_reaches_tree'])
        self.assertEqual(1, rows['update_landing_reaches_resume'])
        with self.assertRaises(ValueError):
            target.reachable(self.decodes['cache_lookup'], 0x1f854e2, 0x1f855f4)

    def test_regeneration_is_byte_identical(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            target.generate(self.data, base / 'one')
            target.generate(self.data, base / 'two')
            first = {p.name: p.read_bytes() for p in (base / 'one').iterdir()}
            second = {p.name: p.read_bytes() for p in (base / 'two').iterdir()}
            self.assertEqual(19, len(first))
            self.assertEqual(first, second)


if __name__ == '__main__':
    unittest.main()
