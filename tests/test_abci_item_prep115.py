"""Target-grounded controls for the RE-017 static evidence extractor."""
import csv
import hashlib
import io
import itertools
import json
import struct
import unittest
from unittest.mock import patch

from tools import abci_item_prep115 as item


class ItemPreparationEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = item.TARGET.read_bytes()
        cls.secs = item.sections(cls.data)
        cls.evidence = item.collect(cls.data)
        cls.summary = json.loads(cls.evidence['summary.json'])
        cls.joins = json.loads(cls.evidence['joins.json'])
        cls.functions = list(csv.DictReader(io.StringIO(cls.evidence['functions.tsv'].decode()), delimiter='\t'))
        cls.fields = list(csv.DictReader(io.StringIO(cls.evidence['fields.tsv'].decode()), delimiter='\t'))
        cls.transfers = list(csv.DictReader(io.StringIO(cls.evidence['transfers.tsv'].decode()), delimiter='\t'))

    @classmethod
    def tearDownClass(cls):
        del cls.data

    def fixture_frames(self):
        frames, header = [], []
        for row in self.functions:
            fde = {'start': int(row['start_va'], 16), 'end': int(row['end_va_exclusive'], 16),
                   'fde': int(row['fde_va'], 16), 'cie': int(row['cie_va'], 16),
                   'lsda': None if row['lsda_va'] == '-' else int(row['lsda_va'], 16)}
            frames.append(fde)
            header.append({'start': fde['start'], 'fde': fde['fde'], 'index': int(row['unwind_index'])})
        return frames, header

    def check_fake_frames(self, frames, header):
        with patch.object(item, 'unwind_index', return_value=(self.secs, header)), \
             patch.object(item, 'eh_frame_records', return_value=({}, frames)):
            return item.selected_fdes(self.data, self.secs)

    def test_target_digest_and_nonempty_selection(self):
        self.assertEqual(item.verify_digest(self.data), item.SHA256)
        self.assertEqual(self.summary['selected_fde_count'], 14)
        self.assertEqual(len(self.functions), 14)

    def test_bad_hash_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            item.verify_digest(b'not the authenticated ELF')

    def test_digest_is_computed_from_supplied_bytes(self):
        sample = b'mutable-fixture'
        digest = hashlib.sha256(sample).hexdigest()
        self.assertEqual(item.verify_digest(sample, digest), digest)
        with self.assertRaises(ValueError):
            item.verify_digest(sample + b'!', digest)

    def test_generated_files_are_exactly_the_documented_set(self):
        self.assertEqual(set(self.evidence), {
            'functions.tsv', 'fields.tsv', 'patterns.tsv', 'windows.tsv', 'transfers.tsv', 'locations.tsv',
            'relocations.tsv', 'buckets.tsv', 'tables.tsv', 'unwind.tsv', 'unwind-calls.tsv',
            'joins.json', 'summary.json'})

    def test_every_selected_body_fingerprint_has_a_corruption_control(self):
        for row in self.functions:
            with self.subTest(role=row['role']):
                body = bytearray.fromhex(row['raw_hex'])
                item.check_body(body, row['sha256'])
                body[len(body) // 2] ^= 1
                with self.assertRaises(ValueError):
                    item.check_body(body, row['sha256'])

    def test_each_operand_rejects_mutated_machine_bytes(self):
        for name, va, expected, offset, width, signed in item.FIELDS:
            with self.subTest(field=name):
                raw = bytearray(item.get_bytes(self.data, self.secs, va, len(bytes.fromhex(expected)), True))
                item.read_field(raw, expected, offset, width, signed)
                raw[-1] ^= 1
                with self.assertRaises(ValueError):
                    item.read_field(raw, expected, offset, width, signed)

    def test_operand_extraction_rejects_bad_ranges(self):
        with self.assertRaises(ValueError):
            item.read_field(b'\x90', '90', 1, 1)
        with self.assertRaises(ValueError):
            item.read_field(b'\x90', '90', 0, 0)

    def test_every_pointer_pattern_rejects_damage(self):
        for name, va, expected in item.PATTERNS:
            raw = bytearray(item.get_bytes(self.data, self.secs, va, len(bytes.fromhex(expected)), True))
            with self.subTest(pattern=name):
                item.check_pattern(raw, expected)
                raw[0] ^= 1
                with self.assertRaises(ValueError):
                    item.check_pattern(raw, expected)

    def test_every_selected_transfer_rejects_displacement_damage(self):
        for row in self.transfers:
            with self.subTest(site=row['site_va']):
                site = int(row['site_va'], 16)
                raw = bytearray.fromhex(row['raw_hex'])
                kind, _, target = item.decode_transfer(raw, site)
                self.assertEqual(kind, row['kind'])
                item.ensure_target(target, int(row['target_va_or_slot'], 16))
                raw[-1] ^= 1
                _, _, wrong = item.decode_transfer(raw, site)
                with self.assertRaises(ValueError):
                    item.ensure_target(wrong, target)

    def test_transfer_decoder_rejects_unknown_and_truncated_forms(self):
        for raw in (b'', b'\xe8', b'\x0f\x85\0', b'\x90\x90'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                item.decode_transfer(raw, 0x1000)

    def test_short_branch_uses_signed_relative_displacement(self):
        kind, raw, target = item.decode_transfer(b'\x75\xfc', 0x1000)
        self.assertEqual((kind, raw, target), ('branch', b'\x75\xfc', 0xffe))

    def test_fde_fixture_reconciles_header_and_bodies(self):
        frames, header = self.fixture_frames()
        self.assertEqual(len(self.check_fake_frames(frames, header)), 14)

    def test_fde_wrong_end_rejected(self):
        frames, header = self.fixture_frames()
        frames[0]['end'] += 1
        with self.assertRaises(ValueError):
            self.check_fake_frames(frames, header)

    def test_fde_wrong_header_pointer_rejected(self):
        frames, header = self.fixture_frames()
        header[0]['fde'] += 4
        with self.assertRaises(ValueError):
            self.check_fake_frames(frames, header)

    def test_fde_duplicate_header_rejected(self):
        frames, header = self.fixture_frames()
        header.append(dict(header[0]))
        with self.assertRaises(ValueError):
            self.check_fake_frames(frames, header)

    def test_overlapping_fde_rejected(self):
        frames, header = self.fixture_frames()
        frames.append({'start': frames[0]['start'] + 1, 'end': frames[0]['end'],
                       'fde': 0x123, 'cie': 0, 'lsda': None})
        with self.assertRaisesRegex(ValueError, 'overlap'):
            self.check_fake_frames(frames, header)

    def test_invalid_and_fileless_address_rejected(self):
        bss = item.section_named(self.secs, '.text')['address'] + (1 << 40)
        with self.assertRaises(ValueError):
            item.file_offset(self.data, self.secs, bss, 1)
        with self.assertRaises(ValueError):
            item.file_offset(self.data, self.secs, 0, 0)
        fileless = [dict(name='bss', type=8, flags=6, address=0x1000, offset=0, size=16)]
        with self.assertRaises(ValueError):
            item.file_offset(b'\0' * 16, fileless, 0x1000, 1)

    def test_ambiguous_mapping_rejected(self):
        sec = dict(name='x', type=1, flags=6, address=0x1000, offset=0, size=16)
        with self.assertRaises(ValueError):
            item.file_offset(b'\0' * 16, [sec, dict(sec)], 0x1000, 1)

    def test_mapping_does_not_extend_past_file(self):
        sec = dict(name='x', type=1, flags=6, address=0x1000, offset=3, size=16)
        with self.assertRaises(ValueError):
            item.file_offset(b'1234', [sec], 0x1000, 4)

    def test_nonexecutable_section_rejected_for_code(self):
        sec = dict(name='data', type=1, flags=2, address=0x1000, offset=0, size=8)
        with self.assertRaises(ValueError):
            item.file_offset(b'12345678', [sec], 0x1000, 2, executable=True)

    def test_missing_and_duplicate_named_section_rejected(self):
        with self.assertRaises(ValueError):
            item.section_named([], '.text')
        sec = dict(name='.text', type=1)
        with self.assertRaises(ValueError):
            item.section_named([sec, sec], '.text')

    def test_relocation_uniqueness_and_contents(self):
        raw = struct.pack('<QQq', 0x1000, 8, 0x2000)
        sec = dict(name='.rela.dyn', type=4, offset=0, size=len(raw))
        self.assertEqual(item.read_relocations(raw, [sec], {0x1000})[0x1000], (0, 8, 0, 0x2000))
        with self.assertRaises(ValueError):
            item.read_relocations(raw, [sec], {0x1001})
        sec['size'] *= 2
        with self.assertRaises(ValueError):
            item.read_relocations(raw + raw, [sec], {0x1000})

    def test_partial_relocation_rejected(self):
        sec = dict(name='.rela.dyn', type=4, offset=0, size=25)
        with self.assertRaises(ValueError):
            item.read_relocations(b'\0' * 25, [sec], {0x1000})

    def test_dynamic_symbol_name_and_invalid_index(self):
        raw = b'\0' * 24 + struct.pack('<IBBHQQ', 1, 0, 0, 0, 0, 0) + b'\0memcmp\0'
        secs = [dict(name='.dynsym', type=11, offset=0, size=48),
                dict(name='.dynstr', type=3, offset=48, size=8)]
        self.assertEqual(item.dynamic_symbol(raw, secs, 1), 'memcmp')
        with self.assertRaises(ValueError):
            item.dynamic_symbol(raw, secs, 2)

    def test_lsda_positive_and_nonzero_landing(self):
        data = bytes.fromhex('ffff010402030400')
        sec = dict(name='.gcc_except_table', type=1, flags=2, address=0x3000, offset=0, size=len(data))
        fde = dict(role='fixture', start=0x1000, end=0x1010, lsda=0x3000)
        rows = item.lsda_rows(data, [sec], fde)
        self.assertEqual([(r['start'], r['end'], r['landing'], r['action']) for r in rows],
                         [(0x1002, 0x1005, 0x1004, 0)])

    def test_lsda_rejects_bad_header_truncation_and_out_of_range(self):
        fde = dict(role='fixture', start=0x1000, end=0x1010, lsda=0x3000)
        for raw in (bytes.fromhex('00ff010402030400'), bytes.fromhex('ffff010902030400'),
                    bytes.fromhex('ffff010402200400'), bytes.fromhex('ffff010402031000')):
            sec = dict(name='.gcc_except_table', type=1, flags=2, address=0x3000, offset=0, size=len(raw))
            with self.subTest(raw=raw.hex()), self.assertRaises(ValueError):
                item.lsda_rows(raw, [sec], fde)

    def test_selected_location_records_have_distinct_release_specific_coordinates(self):
        rows = list(csv.DictReader(io.StringIO(self.evidence['locations.tsv'].decode()), delimiter='\t'))
        self.assertEqual([(r['line'], r['column'], r['path_suffix']) for r in rows],
                         [('123', '37', 'l1/src/abci/state.rs'), ('340', '21', 'l1/src/abci/state.rs')])
        self.assertNotEqual(rows[0]['location_va'], rows[1]['location_va'])

    def test_switch_entries_remain_in_their_selected_fdes(self):
        rows = list(csv.DictReader(io.StringIO(self.evidence['tables.tsv'].decode()), delimiter='\t'))
        self.assertEqual(sum(r['role'] == 'common_selector' for r in rows), 4)
        self.assertEqual(sum(r['role'] == 'value_selector' for r in rows), 21)
        self.assertEqual(rows[4]['target_va'], '0x4d90d93')
        self.assertEqual(rows[-1]['target_va'], '0x4d90d81')

    def test_key_offsets_are_joined_across_producer_and_consumer(self):
        j = self.joins
        self.assertEqual((j['prepared_parent_offset'], j['prepared_index_offset'], j['prepared_tag_offset']),
                         (0, 16, 32))
        self.assertEqual((j['prepared_key_first_offset'], j['prepared_key_last_word_offset']), (35, 51))
        self.assertEqual(j['consumer_key_first_offset'], j['prepared_key_first_offset'])
        self.assertEqual(j['consumer_key_last_word_offset'], j['prepared_key_last_word_offset'])

    def test_join_rejects_a_single_offset_change(self):
        vals = {r['name']: int(r['value_decimal']) for r in self.fields}
        item.make_joins(vals)
        vals['consumer_key_first'] += 1
        with self.assertRaises(ValueError):
            item.make_joins(vals)

    def test_join_rejects_wrong_bucket_pack_and_tag(self):
        vals = {r['name']: int(r['value_decimal']) for r in self.fields}
        for name in ('bucket_b_pack_stack', 'returned_stop_tag', 'merge_initial_mode', 'row_stride'):
            broken = dict(vals)
            broken[name] += 1
            with self.subTest(name=name), self.assertRaises(ValueError):
                item.make_joins(broken)

    def test_join_rejects_broken_state_cell_handoff(self):
        vals = {r['name']: int(r['value_decimal']) for r in self.fields}
        for name in ('engine_reload_stack', 'collect_cell_store', 'wrapper_address_load',
                     'outer_stack_argument', 'outer_mapper_argument', 'mapper_cell_store',
                     'append_cell_address_stack', 'append_cell_save_stack', 'worker_stack_argument'):
            broken = dict(vals)
            broken[name] += 1
            with self.subTest(name=name), self.assertRaises(ValueError):
                item.make_joins(broken)

    def test_context_counter_load_and_store_offsets_join(self):
        vals = {r['name']: int(r['value_decimal']) for r in self.fields}
        self.assertEqual((self.joins['context_first_saturating_counter_offset'],
                          self.joins['context_second_saturating_counter_offset']), (0x16b0, 0x16b8))
        self.assertEqual(self.joins['context_admission_key_offsets'], [0x48, 0x58])
        for name in ('context_first_counter_store', 'context_second_counter_load',
                     'context_admission_key_tail', 'context_admission_singleton',
                     'context_handler_input_tag', 'context_handler_result_tag'):
            broken = dict(vals)
            broken[name] += 1
            with self.subTest(name=name), self.assertRaises(ValueError):
                item.make_joins(broken)

    def test_bucket_decisions_and_priority(self):
        tag = self.joins['first_bucket_parent_tag']
        expected = [((tag, False, False), 0), ((tag, True, True), 0),
                    ((tag + 1, True, False), 2), ((tag + 1, True, True), 2),
                    ((tag + 1, False, True), 1), ((tag + 1, False, False), 3)]
        for (parent_tag, first, second), wanted in expected:
            with self.subTest(parent_tag=parent_tag, first=first, second=second):
                self.assertEqual(item.model_bucket(parent_tag, first, second, tag), wanted)

    def test_bucket_evidence_shows_distinct_test_and_merge_orders(self):
        rows = list(csv.DictReader(io.StringIO(self.evidence['buckets.tsv'].decode()), delimiter='\t'))
        self.assertEqual([r['bucket'] for r in rows], ['A', 'B', 'C', 'D'])
        self.assertEqual([int(r['evaluation_order']) for r in rows], [1, 3, 2, 4])
        self.assertEqual([int(r['merge_input_offset']) for r in rows], [8, 40, 72, 104])

    def test_bucket_copy_loop_sites_are_decoded_branch_targets(self):
        rows = list(csv.DictReader(io.StringIO(self.evidence['buckets.tsv'].decode()), delimiter='\t'))
        edges = {r['label']: r for r in self.transfers}
        for row, ordinal in zip(rows, ('first', 'second', 'third', 'fourth')):
            edge = edges[f'merge_{ordinal}_loop']
            self.assertEqual(row['copy_loop_va'], edge['target_va_or_slot'])
            self.assertLess(int(row['copy_loop_va'], 16), int(edge['site_va'], 16))

    def test_bucket_predicates_use_nonzero_byte_values(self):
        special = self.joins['first_bucket_parent_tag']
        for value in range(1, 256):
            self.assertEqual(item.model_bucket(special + 1, value, 1, special), 2)
            self.assertEqual(item.model_bucket(special + 1, 0, value, special), 1)

    def test_bucket_merge_changes_cross_group_order_but_is_stable_within_groups(self):
        special = self.joins['first_bucket_parent_tag']
        rows = [('c1', 0, 1, 1), ('d1', 0, 0, 0), ('b1', 0, 0, 1),
                ('a1', special, 1, 1), ('b2', 0, 0, 1), ('c2', 0, 1, 0)]
        self.assertEqual(item.model_order(rows, special), ['a1', 'b1', 'b2', 'c1', 'c2', 'd1'])
        self.assertNotEqual(item.model_order(rows, special), ['a1', 'c1', 'c2', 'b1', 'b2', 'd1'])

    def test_bucket_model_against_independent_rank_oracle(self):
        special = self.joins['first_bucket_parent_tag']
        types = [(special, 0, 0), (0, 0, 1), (0, 1, 0), (0, 0, 0)]
        for indices in itertools.product(range(4), repeat=4):
            rows = [(i, *types[k]) for i, k in enumerate(indices)]
            expected = [i for k in range(4) for i, actual in enumerate(indices) if actual == k]
            self.assertEqual(item.model_order(rows, special), expected)

    def test_all_twenty_key_bytes_matter(self):
        key = bytes(range(20))
        self.assertTrue(item.model_equal20(key, key))
        for i in range(20):
            for delta in range(1, 256):
                other = bytearray(key)
                other[i] ^= delta
                self.assertFalse(item.model_equal20(key, other), (i, delta))

    def test_simple_precheck_stores_three_copies_of_the_same_key(self):
        key = bytes(range(20))
        writes = item.model_three_key_writes(key, self.joins)
        self.assertEqual(writes, {0: b'\xa2\x01', 2: b'\0', 3: key, 23: key, 43: key})
        changed = bytearray(key)
        changed[-1] ^= 0xff
        changed_writes = item.model_three_key_writes(changed, self.joins)
        for offset in (3, 23, 43):
            self.assertNotEqual(writes[offset], changed_writes[offset])
        with self.assertRaises(ValueError):
            item.model_three_key_writes(bytes(19), self.joins)

    def test_empty_map_and_scan_success_model_fails_closed_on_changed_conditions(self):
        j = self.joins
        args = dict(parent_tag=j['first_bucket_parent_tag'], action_tag=j['prepared_tag'],
                    category=j['common_selector_threshold'],
                    map_marker=0, map_count=0, scan_marker=0, scan_count=0,
                    mode=j['mode_skip_value'], parent_option=0)
        key = bytes(range(20))
        self.assertEqual(item.model_simple_case(key, j, **args), item.model_three_key_writes(key, j))
        changes = {'parent_tag': j['first_bucket_parent_tag'] + 1, 'action_tag': j['stop_tag'],
                   'category': 1, 'map_marker': j['high_bit_sentinel'], 'map_count': 1,
                   'scan_marker': j['high_bit_sentinel'], 'scan_count': 1,
                   'mode': j['mode_skip_value'] - 1, 'parent_option': 1}
        for field, value in changes.items():
            broken = dict(args)
            broken[field] = value
            with self.subTest(field=field):
                self.assertIsNone(item.model_simple_case(key, j, **broken))

    def test_common_selector_boundaries_and_target(self):
        self.assertEqual([item.model_common_index(i) for i in range(6)], [0, 0, 1, 2, 3, 4])
        rows = list(csv.DictReader(io.StringIO(self.evidence['tables.tsv'].decode()), delimiter='\t'))
        common = [r for r in rows if r['role'] == 'common_selector']
        self.assertEqual(common[item.model_common_index(2)]['target_va'], '0x4d90a7a')
        with self.assertRaises(ValueError):
            item.model_common_index(256)

    def test_key_length_controls(self):
        with self.assertRaises(ValueError):
            item.model_equal20(bytes(19), bytes(20))
        with self.assertRaises(ValueError):
            item.model_equal20(bytes(20), bytes(21))

    def test_merge_count_boundary_without_allocating(self):
        maximum = self.joins['merge_allocation_max_count']
        stride = self.joins['prepared_row_stride']
        self.assertEqual(item.model_allocation_bytes(0, stride, maximum), 0)
        self.assertEqual(item.model_allocation_bytes(maximum, stride, maximum), maximum * stride)
        self.assertLessEqual(maximum * stride, (1 << 63) - 1)
        self.assertIsNone(item.model_allocation_bytes(maximum + 1, stride, maximum))
        with self.assertRaises(ValueError):
            item.model_allocation_bytes(-1, stride, maximum)

    def test_context_saturating_increment_boundaries(self):
        maximum = (1 << 64) - 1
        for value, wanted in ((0, 1), (maximum - 1, maximum), (maximum, maximum)):
            self.assertEqual(item.model_saturating_increment64(value), wanted)
        for invalid in (-1, maximum + 1):
            with self.assertRaises(ValueError):
                item.model_saturating_increment64(invalid)

    def test_stop_tag_is_not_the_prepare_tag(self):
        self.assertEqual((self.joins['prepared_tag'], self.joins['stop_tag']), (0x1a2, 0x1a3))
        self.assertNotEqual(self.joins['prepared_tag'], self.joins['stop_tag'])


if __name__ == '__main__':
    unittest.main()
