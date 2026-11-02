"""Corruption and boundary controls for the node 94 chain-field collector."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import config_chain_field94 as subject


class ChainFieldEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.TARGET.read_bytes()
        subject.verify_identity(cls.data)
        cls.image = subject.Image(cls.data)
        cls.result = subject.extract(cls.image)
        cls.names = cls.result['names']

    def changed(self, va, replacement):
        current = self.image.read(va, 1)[0]
        if replacement == current:
            raise AssertionError('control did not change a byte')
        return self.image.changed(va, replacement)

    def changed_bytes(self, va, replacement):
        altered = self.image
        for i, b in enumerate(replacement):
            altered = altered.changed(va + i, b)
        return altered

    def test_identity(self):
        subject.verify_identity(self.data)

    def test_corrupted_digest_is_rejected(self):
        with self.assertRaises(ValueError):
            subject.verify_identity(self.data, '0' * 64)

    def test_truncated_input_is_rejected(self):
        with self.assertRaises(ValueError):
            subject.verify_identity(self.data[:64])

    def test_selected_fdes_are_distinct_nonempty(self):
        records = self.result['functions']
        self.assertEqual(len(records), 13)
        self.assertEqual(len({r['start'] for r in records}), len(records))
        self.assertTrue(all(r['size'] == r['end'] - r['start'] > 0 for r in records))
        self.assertTrue(all(len(bytes.fromhex(r['bytes'])) == r['size'] for r in records))

    def test_address_outside_file_is_rejected(self):
        with self.assertRaises(ValueError):
            self.image.read(0xffffffffffffffff, 8)

    def test_zero_and_negative_ranges_are_rejected(self):
        for va, size in [(0, 0), (-1, 1), (1, -1)]:
            with self.subTest(va=va, size=size), self.assertRaises(ValueError):
                self.image.offset(va, size)

    def test_cross_section_range_is_rejected(self):
        section = next(s for s in self.image.sections if s['name'] == '.text')
        with self.assertRaises(ValueError):
            self.image.read(section['address'] + section['size'] - 1, 2)

    def test_nobits_is_not_file_backed(self):
        bss = next(s for s in self.image.sections if s['name'] == '.bss')
        with self.assertRaises(ValueError):
            self.image.read(bss['address'] + bss['size'] - 1, 1)

    def test_ambiguous_mapping_is_rejected(self):
        text = next(s for s in self.image.sections if s['name'] == '.text')
        ambiguous = subject.Image(self.data, section_rows=[text, dict(text)])
        with self.assertRaises(ValueError):
            ambiguous.read(text['address'], 1)

    def test_all_selected_window_corruptions_fail(self):
        for label, start, _, _ in subject.ANCHORS:
            with self.subTest(label=label):
                byte = self.image.read(start, 1)[0]
                with self.assertRaises(ValueError):
                    subject.validate_anchors(self.changed(start, byte ^ 1))

    def test_key_table_has_all_nine_distinct_fields(self):
        fields = self.result['fields']
        self.assertEqual([r['index'] for r in fields], list(range(9)))
        self.assertEqual([r['text'] for r in fields], [
            'signatureChainId', 'hyperliquidChain', 'destination', 'sourceDex',
            'destinationDex', 'token', 'amount', 'fromSubAccount', 'nonce'])

    def test_key_comparison_covers_entire_name(self):
        length, pieces, _ = subject.FIELD_PIECES[2]
        partial = pieces[:1]
        with self.assertRaises(ValueError):
            subject.join_pieces(self.image, length, partial)

    def test_overlapping_comparison_must_agree(self):
        length, pieces, _ = subject.FIELD_PIECES[2]
        altered = self.changed(0x1e71f7c, self.image.read(0x1e71f7c, 1)[0] ^ 1)
        with self.assertRaises(ValueError):
            subject.join_pieces(altered, length, pieces)

    def test_network_names_and_codes(self):
        self.assertEqual([(r['index'], r['text']) for r in self.names],
                         [(0, 'Local'), (1, 'Sandbox'), (2, 'Testnet'), (3, 'Mainnet')])
        self.assertEqual([r['encoded_hex'] for r in self.names],
                         ['a54c6f63616c', 'a753616e64626f78',
                          'a7546573746e6574', 'a74d61696e6e6574'])

    def test_two_matchers_reference_same_new_descriptor(self):
        refs = {r['label']: r['target'] for r in self.result['refs']}
        self.assertEqual(refs['network_descriptor_packed_error'], 0x56a0fc0)
        self.assertEqual(refs['network_descriptor_byte_error'], 0x56a0fc0)
        self.assertEqual(refs['field_descriptor_error'], refs['field_byte_descriptor_error'])
        self.assertEqual(refs['network_field_missing'], refs['network_field_duplicate'])

    def test_chain_key_byte_compares_match_descriptor(self):
        rows = self.result['field_checks']
        self.assertEqual([r['index'] for r in rows], list(range(16)))
        self.assertEqual(bytes.fromhex(''.join(r['value_hex'] for r in rows)), b'hyperliquidChain')
        self.assertEqual(rows[0]['branch_target'], 0x1e71d72)
        self.assertTrue(all(r['branch_target'] == 0x1e71dd9 for r in rows[1:]))

    def test_chain_key_byte_corruption_is_rejected(self):
        site = self.result['field_checks'][5]['site'] + 3
        changed = self.changed(site, self.image.read(site, 1)[0] ^ 1)
        with self.assertRaises(ValueError):
            subject.extract(changed)

    def test_field_numeric_domains_have_distinct_nine_entry_bound(self):
        for tag in (1, 4):
            for value in range(9):
                self.assertEqual(subject.classify_numeric(tag, value, self.result['fields']), value)
            for value in (9, 32, 255):
                self.assertIsNone(subject.classify_numeric(tag, value, self.result['fields']))

    def test_field_numeric_wrong_but_in_range_arm_is_rejected(self):
        table = [r for r in self.result['tables'] if r['table'] == 'field_numeric_byte']
        changed = self.changed_bytes(table[1]['slot'], bytes.fromhex(table[2]['raw']))
        with self.assertRaises(ValueError):
            subject.extract(changed)

    def test_iterator_advance_and_counter_sentinel(self):
        self.assertEqual([r['operand_hex'] for r in self.result['iterator']],
                         ['40', '28', 'ff', '', '40'])
        edges = {r['label']: r['target'] for r in self.result['edges']}
        self.assertEqual(edges['key_iterator_count_overflow'], 0x1ecdc55)

    def test_iterator_overflow_branch_corruption_is_rejected(self):
        changed = self.changed(0x1ecdb7f, 0x85)
        with self.assertRaises(ValueError):
            subject.extract(changed)

    def test_chain_value_input_routes_are_distinct(self):
        edges = {r['label']: r['target'] for r in self.result['edges']}
        self.assertEqual(edges['chain_input_tag_12'], edges['chain_input_tag_13'])
        self.assertEqual(edges['chain_input_empty_sequence'], edges['chain_input_empty_first'])
        self.assertNotEqual(edges['chain_input_tag_other'], edges['chain_input_extra_element'])

    def test_action_entry_and_record_name_are_elf_backed(self):
        self.assertEqual([r['text'] for r in self.result['action_entries']],
                         ['type', 'internally tagged enum Action', 'SendAssetAction'])
        self.assertEqual(self.result['action_index'], 69)
        self.assertEqual([r['value'] for r in self.result['action_route']],
                         [0x88, 0xb9, 0xcc, 0x8000000000000000, 0xf0, 9])

    def test_action_name_corruption_is_rejected(self):
        name_va = self.result['action_entries'][2]['va']
        changed = self.changed(name_va, ord('X'))
        with self.assertRaises(ValueError):
            subject.extract(changed)

    def test_action_dispatch_slot_corruption_is_rejected(self):
        entry = next(r for r in self.result['tables'] if r['table'] == 'action_selected')
        old = self.image.read(entry['slot'], 1)[0]
        changed = self.changed(entry['slot'], old ^ 1)
        with self.assertRaises(ValueError):
            subject.extract(changed)

    def test_action_allocation_branch_corruption_is_rejected(self):
        changed = self.changed(0x2882f46, 0x85)
        with self.assertRaises(ValueError):
            subject.extract(changed)

    def test_record_container_markers_come_from_code(self):
        self.assertEqual(self.result['mode_markers'], [
            {'mode_byte': 0, 'marker_hex': '9a'}, {'mode_byte': 1, 'marker_hex': '8a'}])

    def test_descriptor_reference_corruption_fails(self):
        site = 0x22edbdc + 3
        old = self.image.read(site, 1)[0]
        altered = self.changed(site, old ^ 1)
        with self.assertRaises(ValueError):
            subject.extract(altered)

    def test_packed_matcher_exact_names(self):
        for row in self.names:
            with self.subTest(name=row['text']):
                self.assertEqual(subject.classify_network(row['text'].encode(), self.names), row['index'])

    def test_each_one_byte_mutation_is_rejected_by_model(self):
        for row in self.names:
            text = row['text'].encode('ascii')
            for i in range(len(text)):
                mutant = text[:i] + bytes([text[i] ^ 1]) + text[i + 1:]
                with self.subTest(name=row['text'], position=i):
                    self.assertIsNone(subject.classify_network(mutant, self.names))

    def test_length_and_case_are_not_normalized_by_model(self):
        for row in self.names:
            raw = row['text'].encode('ascii')
            for mutant in [raw.lower(), raw + b' ', b' ' + raw, raw + b'\x00', raw[:-1]]:
                with self.subTest(name=row['text'], mutant=mutant):
                    self.assertIsNone(subject.classify_network(mutant, self.names))

    def test_aws_name_default_is_not_a_network_spelling(self):
        self.assertIsNone(subject.classify_network(b'NvTestnet', self.names))
        self.assertEqual(self.result['missing_sentinel'], 4)

    def test_numeric_internal_tags_boundaries(self):
        for tag in (1, 4):
            for value in range(4):
                self.assertEqual(subject.classify_numeric(tag, value, self.names), value)
            for value in (4, 31, 32, 75, 76, 255):
                self.assertIsNone(subject.classify_numeric(tag, value, self.names))

    def test_numeric_internal_tag_domain_is_explicit(self):
        for tag, value in [(2, 0), (1, 256), (4, -1), (4, 1 << 64)]:
            with self.subTest(tag=tag, value=value), self.assertRaises(ValueError):
                subject.classify_numeric(tag, value, self.names)

    def test_missing_value_text_is_length_delimited(self):
        diag = self.result['diagnostic']
        self.assertEqual(bytes.fromhex(diag['hex']),
                         b'MapAccess::next_value called before next_key')
        self.assertEqual(diag['length'], len(bytes.fromhex(diag['hex'])))

    def test_network_and_record_offsets_agree(self):
        self.assertEqual(self.result['record_chain_offset'], 0xb8)

    def test_duplicate_branch_direction_corruption_fails(self):
        altered = self.changed(0x20dccdc, 0x84)
        with self.assertRaises(ValueError):
            subject.validate_anchors(altered)

    def test_record_field_offset_corruption_fails(self):
        altered = self.changed(0x20de00a, 0xb9)
        with self.assertRaises(ValueError):
            subject.validate_anchors(altered)

    def test_writer_marker_corruption_fails(self):
        altered = self.changed(0x22e618e + 3, 0xa6)
        with self.assertRaises(ValueError):
            subject.validate_anchors(altered)

    def test_branch_displacement_corruption_fails(self):
        old = self.image.read(0x20dccdd, 1)[0]
        altered = self.changed(0x20dccdd, old ^ 1)
        with self.assertRaises(ValueError):
            subject.extract(altered)

    def test_out_of_range_jump_table_is_rejected(self):
        tables = [r for r in self.result['tables'] if r['table'] == 'network_writer']
        altered = self.changed_bytes(tables[0]['slot'], bytes.fromhex('ffffff7f'))
        with self.assertRaises(ValueError):
            subject.extract(altered)

    def test_in_range_wrong_jump_table_is_rejected(self):
        tables = [r for r in self.result['tables'] if r['table'] == 'network_writer']
        altered = self.changed_bytes(tables[0]['slot'], bytes.fromhex(tables[1]['raw']))
        with self.assertRaises(ValueError):
            subject.extract(altered)

    def test_wrong_network_literal_is_rejected(self):
        va = self.names[0]['string_va']
        altered = self.changed(va, ord('X'))
        with self.assertRaises(ValueError):
            subject.extract(altered)

    def test_wrong_descriptor_relocation_is_rejected(self):
        rela = next(s for s in self.image.sections if s['name'] == '.rela.dyn')
        file_offset = self.names[0]['relocation_offset']
        addend_va = rela['address'] + file_offset - rela['offset'] + 16
        old = self.image.read(addend_va, 1)[0]
        altered = self.changed(addend_va, old ^ 1)
        with self.assertRaises(ValueError):
            subject.extract(altered)

    def test_wrong_relocation_type_is_rejected(self):
        rela = next(s for s in self.image.sections if s['name'] == '.rela.dyn')
        file_offset = self.names[0]['relocation_offset']
        info_va = rela['address'] + file_offset - rela['offset'] + 8
        altered = self.changed(info_va, 7)
        with self.assertRaises(ValueError):
            subject.relocation_map(altered, {self.names[0]['slot']})

    def test_missing_relocation_is_rejected(self):
        with self.assertRaises(ValueError):
            subject.relocation_map(self.image, {0})

    def test_bad_template_is_rejected(self):
        va = 0x1df8f3
        length = self.image.read(va, 1)[0]
        altered = self.changed(va + length + 1, 0xc1)
        with self.assertRaises(ValueError):
            subject.template(altered, va)

    def test_exact_capacity_needs_no_grow_in_model(self):
        for row in self.names:
            self.assertEqual(subject.growth_trace(row['length'] + 1, row['length']),
                             ['write_prefix', 'write_payload'])

    def test_payload_failure_occurs_after_prefix_in_model(self):
        self.assertEqual(subject.growth_trace(1, 7, fail='payload'),
                         ['write_prefix', 'grow_payload'])

    def test_prefix_failure_precedes_writes_in_model(self):
        self.assertEqual(subject.growth_trace(0, 7, fail='prefix'), ['grow_prefix'])

    def test_grow_can_be_needed_twice_in_model(self):
        self.assertEqual(subject.growth_trace(0, 7, grown_spare=1),
                         ['grow_prefix', 'write_prefix', 'grow_payload', 'write_payload'])

    def test_invalid_buffer_models_are_rejected(self):
        for args in [(-1, 7), (0, 0), (0, 7)]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                subject.growth_trace(*args)

    def test_transfer_must_be_supported(self):
        with self.assertRaises(ValueError):
            subject.transfer(self.image, 0x22e6164)


if __name__ == '__main__':
    unittest.main()
