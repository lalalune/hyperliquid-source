"""Negative and boundary controls for the node 94 configuration-field packet."""
import copy
import csv
import io
import json
from pathlib import Path
import struct
import unittest

from tools import config_name_field94 as study

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-015-config-name-field-94'


def rows(payload):
    return list(csv.DictReader(io.StringIO(payload.decode('utf-8')), delimiter='\t'))


class ConfigFieldTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = study.Image((ROOT / 'artifacts/node/94/hl-node').read_bytes())
        cls.outputs = study.collect(cls.image)
        cls.summary = json.loads(cls.outputs['evidence.json'])

    def reject_patch(self, address, replacement):
        with self.assertRaises(study.EvidenceError):
            study.collect(self.image.with_patch(address, replacement))

    def test_digest_rejects_other_input(self):
        with self.assertRaises(study.EvidenceError):
            study.verify_digest(b'not the captured node')

    def test_all_generated_files_match_retained_bytes(self):
        self.assertEqual(len(self.outputs), 9)
        for name, content in self.outputs.items():
            with self.subTest(name=name):
                self.assertEqual((PACKET / name).read_bytes(), content)

    def test_selected_function_map(self):
        selected = rows(self.outputs['functions.tsv'])
        self.assertEqual(len(selected), 12)
        self.assertEqual({int(r['start'], 16) for r in selected}, set(study.ENTRIES))
        self.assertTrue(all(int(r['end'], 16) > int(r['start'], 16) for r in selected))

    def test_component_path_and_return_links(self):
        by_name = {r['label']: r for r in rows(self.outputs['calls.tsv'])}
        edges = {
            'initializer_to_selector': '0x144b150',
            'selector_to_document': '0x149e710',
            'document_to_object': '0x14baf90',
            'object_to_visitor': '0x14a2870',
            'visitor_optional_map_boundary': '0x1441d10',
            'visitor_unknown_collector': '0x14889f0',
            'selector_to_binary_marker': '0x13bd490',
            'binary_marker_to_visitor': '0x13abf40',
            'binary_visitor_counted_key': '0x13c75e0',
            'binary_visitor_validated_key': '0x13c75e0',
            'binary_visitor_optional_field': '0x13aa6e0',
            'binary_optional_value_boundary': '0x13bec50',
            'binary_unknown_collector_boundary': '0x14886d0',
        }
        for label, target in edges.items():
            with self.subTest(label=label):
                self.assertEqual(by_name[label]['target'], target)
        self.assertEqual(by_name['visitor_publish_copy_slot']['symbol'], 'memcpy')
        self.assertEqual(by_name['binary_publish_copy_slot']['symbol'], 'memcpy')

    def test_path_template_and_relations(self):
        template = self.summary['template']
        self.assertEqual(template['va'], '0x1dd405')
        self.assertEqual(template['literal'], '/api_secrets.json')
        self.assertEqual(template['bytes'], 'c0112f6170695f736563726574732e6a736f6e00')
        refs = {r['slot']: r['relative_addend'] for r in self.summary['relocation_context']}
        self.assertEqual(refs['0x576e928'], '0x577b288')
        self.assertEqual(refs['0x577a898'], '0x13d28e0')
        self.assertEqual(refs['0x5668488'], '0x2180ff')
        self.assertEqual(self.summary['initializer'], {'display_callback': '0x13da090',
                         'configuration_field_offset': 24, 'default_output_offset': 32,
                         'default_word': 0})

    def test_whitespace_boundaries(self):
        self.assertEqual(self.summary['document_whitespace']['accepted_bytes'], [9, 10, 13, 32])
        for byte in (0, 8, 11, 12, 14, 31, 33, 255):
            self.assertNotIn(byte, self.summary['document_whitespace']['accepted_bytes'])

    def test_field_discriminants_are_not_aws_discriminants(self):
        mapping = rows(self.outputs['field-dispatch.tsv'])
        self.assertEqual(len(mapping), 24)
        self.assertEqual([int(r['field_tag'], 16) for r in mapping], list(range(22, 46)))
        bkeys = mapping[22]
        self.assertEqual((bkeys['literal'], bkeys['field_tag'], bkeys['value_target']),
                         ('b_keys', '0x2c', '0x1441d10'))
        self.assertEqual((mapping[23]['literal'], mapping[23]['field_tag']), ('cg_key', '0x2d'))
        self.assertEqual(self.summary['discriminator_context']['name'], 'NvTestnet')
        self.assertNotEqual(int(bkeys['field_tag'], 16), 32)

    def test_json_special_tag_prechecks(self):
        self.assertEqual(self.summary['json_special_tags'], [
            {'tag': '0x2e', 'branch': '0x14a2ade', 'target': '0x14a6013'},
            {'tag': '0x2f', 'branch': '0x14a2b16', 'target': '0x14a600c'}])
        self.reject_patch(0x14a2add, b'\x2f')
        self.reject_patch(0x14a2b15, b'\x2e')

    def test_binary_field_predicates_match_diagnostic_routes(self):
        binary = rows(self.outputs['binary-field-paths.tsv'])
        dispatch = rows(self.outputs['field-dispatch.tsv'])
        self.assertEqual([(r['name'], r['tag']) for r in binary],
                         [(r['literal'], r['field_tag']) for r in dispatch])
        self.assertEqual(len(binary), 24)
        self.assertEqual(self.summary['binary_field_classifier']['failure_paths'], 357)
        self.assertEqual((self.summary['binary_field_classifier']['length_minimum'],
                          self.summary['binary_field_classifier']['length_maximum']), (6, 33))
        for r in binary:
            expected = bytes.fromhex(r['tag'][2:])
            self.assertEqual(len(expected), 1)
            self.assertEqual(len(r['name'].encode()), int(r['length']))

    def test_binary_predicate_negative_inputs(self):
        binary = rows(self.outputs['binary-field-paths.tsv'])
        def accepts(row, candidate):
            if len(candidate) != int(row['length']):
                return False
            for condition in row['comparisons'].split(','):
                _, offset, value, relation = condition.split(':')
                equal = candidate[int(offset)] == int(value, 16)
                if equal != (relation == 'eq'):
                    return False
            return True
        def accepted_tags(candidate):
            return [r['tag'] for r in binary if accepts(r, candidate)]
        for row in binary:
            name = row['name'].encode('ascii')
            self.assertEqual(accepted_tags(name), [row['tag']])
        for name in (b'b_key', b'b_keyx', b'B_keys', b'b_keys_', b'b_key\x00',
                     b'cg_keY', b'NvTestnet', b'', b'X' * 34):
            self.assertEqual(accepted_tags(name), [], name)

    def test_both_json_key_probes(self):
        probes = rows(self.outputs['json-field-probes.tsv'])
        binary = rows(self.outputs['binary-field-paths.tsv'])
        self.assertEqual(len(probes), 68)
        for classifier, fallback in (('borrowed', '0xd'), ('owned', '0xc')):
            selected = [r for r in probes if r['classifier'] == classifier]
            self.assertEqual([r['tag'] for r in selected if r['case'] == 'known'],
                             [r['tag'] for r in binary])
            self.assertTrue(all(r['tag'] == fallback for r in selected if r['case'] == 'negative'))
        self.assertEqual(self.summary['json_key_probes'], {'classifiers': 2,
                         'known_inputs_per_classifier': 24, 'negative_inputs_per_classifier': 10,
                         'single_byte_mutations_per_classifier': 371,
                         'known_bcmp_paths': 2, 'bcmp_symbol': 'bcmp'})

    def test_each_json_key_single_byte_mutation(self):
        binary = rows(self.outputs['binary-field-paths.tsv'])
        known = {r['name'].encode('ascii'): int(r['tag'], 16) for r in binary}
        for owned, entry, fallback in ((False, 0x13c71c0, 13), (True, 0x13c84c0, 12)):
            fde = self.image.fde(entry)
            for name in known:
                for i in range(len(name)):
                    altered = name[:i] + bytes([name[i] ^ 1]) + name[i + 1:]
                    result = study.json_key_probe(self.image, altered, fde, owned)
                    self.assertEqual(result['tag'], known.get(altered, fallback), altered)

    def test_binary_selected_option_and_duplicate_route(self):
        result = self.summary['binary_selected_field']
        self.assertEqual(result, {'dispatch_table': '0x20faa0', 'dispatch_index': 22,
                                  'dispatch_slot': '0x20faf8', 'arm': '0x13ad678',
                                  'duplicate_arm': '0x13b1863', 'duplicate_name_va': '0x21693d',
                                  'null_marker': '0xc0', 'option_reader': '0x13aa6e0',
                                  'value_boundary': '0x13bec50'})
        branches = {r['label']: r for r in rows(self.outputs['branches.tsv'])}
        self.assertEqual(branches['binary_option_cached_null']['target'], '0x13aa77f')
        self.assertEqual(branches['binary_option_end_of_input']['target'], '0x13aa730')
        self.assertEqual(branches['binary_selected_value_error']['target'], '0x13b097f')
        self.assertEqual(branches['binary_collector_failure']['target'], '0x13ae3f0')
        self.assertEqual(self.image.read(0x13aa77f, 6), bytes.fromhex('0f57c00f1103'))
        self.assertEqual(self.image.read(0x13ada2c, 12)[-4:], struct.pack('<I', 0))

    def test_two_classifiers_six_byte_boundaries(self):
        variants = rows(self.outputs['key-matchers.tsv'])
        self.assertEqual(len(variants), 2)
        for result in variants:
            self.assertEqual((result['first_name'], result['first_tag']), ('b_keys', '0x2c'))
            self.assertEqual((result['second_name'], result['second_tag']), ('cg_key', '0x2d'))
            known = {result['first_name'].encode(), result['second_name'].encode()}
            for key in known:
                for i in range(len(key)):
                    altered = key[:i] + bytes([key[i] ^ 1]) + key[i + 1:]
                    self.assertNotIn(altered, known)
            for key in (b'b_key', b'b_keys_', b'B_keys', b'b_key\x00', b'cg_key\x00'):
                self.assertNotIn(key, known)

    def test_absent_field_and_duplicate_guards(self):
        self.assertEqual(self.image.read(0x14a28f2, 12)[-4:], struct.pack('<I', 2))
        self.assertEqual(self.image.read(0x14a33ed, 8)[-1], 2)
        self.assertEqual(self.image.read(0x14a4d51, 12)[-4:], struct.pack('<I', 0))
        self.assertEqual(self.image.read(0x13d2a7c, 8)[-4:], struct.pack('<I', 0))
        self.assertEqual(self.summary['duplicate_template']['prefix'], 'duplicate field `')
        self.assertEqual(self.summary['json_selected_field'], {'field_tag': '0x2c',
                         'slot_offset': '0x610', 'unset_sentinel': 2,
                         'default_word': 0, 'value_boundary': '0x1441d10'})

    def test_path_selector_two_predicates_have_distinct_results(self):
        branches = {r['label']: r for r in rows(self.outputs['branches.tsv'])}
        self.assertEqual(branches['selector_path_predicate_false']['target'], '0x144b1b8')
        self.assertEqual(branches['selector_transformed_predicate_false']['target'], '0x144b1e1')
        self.assertEqual(self.image.read(0x144b1b8, 6), bytes.fromhex('41bd02000000'))
        self.assertEqual(self.image.read(0x144b640, 7), bytes.fromhex('48c70303000000'))
        self.assertEqual(self.summary['path_selector'], {'predicate_slot': '0x576e9e8',
                         'predicate': '0x144a710', 'transformer': '0x144a600',
                         'initial_false_tag': 2, 'error_tag': 3})

    def test_unknown_field_record_boundary(self):
        context = self.summary['discriminator_context']
        self.assertEqual(context['fallback_arm'], '0x14a2e1e')
        self.assertEqual(context['unknown_record_stride'], 64)
        branches = {r['label']: r for r in rows(self.outputs['branches.tsv'])}
        self.assertEqual(branches['unknown_collector_skip_tag']['target'], '0x1488a40')
        self.assertEqual(branches['unknown_collector_non_error']['target'], '0x14a544f')

    def test_different_non_file_backed_ranges_fail(self):
        sec = {'type': 1, 'flags': 2, 'address': 0x1000, 'size': 8, 'offset': 4}
        self.assertEqual(study.file_offset([sec], 0x1002, 2, 32), 6)
        no_bytes = dict(sec, type=8)
        for address, size, sections in [(-1, 1, [sec]), (0x1008, 1, [sec]),
                                        (0x1000, 0, [sec]), (0x1000, 1, [no_bytes]),
                                        (0x1000, 1, [sec, dict(sec)]),
                                        (0x1007, 2, [sec])]:
            with self.subTest(address=address, size=size):
                with self.assertRaises(study.EvidenceError):
                    study.file_offset(sections, address, size, 32)

    def test_non_executable_fde_rejected(self):
        changed = copy.copy(self.image)
        changed.secs = [dict(s, flags=s['flags'] & ~4) if s['name'] == '.text' else s
                        for s in self.image.secs]
        with self.assertRaises(study.EvidenceError):
            study.collect(changed)

    def test_ambiguous_fde_rejected(self):
        changed = copy.copy(self.image)
        changed.fdes = self.image.fdes + [dict(self.image.fde(0x14a2870))]
        with self.assertRaises(study.EvidenceError):
            study.collect(changed)

    def test_changed_key_comparison_rejected(self):
        self.reject_patch(0x13c71e2, b'X')

    def test_changed_owned_classifier_result_rejected(self):
        self.reject_patch(0x13c8923, b'\x2d')

    def test_changed_length_dispatch_rejected(self):
        self.reject_patch(0x216a40, struct.pack('<i', 0))

    def test_changed_root_branch_rejected(self):
        self.reject_patch(0x149e7af, b'\x72')

    def test_changed_second_path_predicate_rejected(self):
        self.reject_patch(0x144b19f, b'\x75')
        self.reject_patch(0x144b643, b'\x04')

    def test_changed_binary_field_byte_rejected(self):
        self.reject_patch(0x13c7656, b'X')

    def test_changed_borrowed_json_predicate_rejected(self):
        self.reject_patch(0x13c7304, b'X')
        self.reject_patch(0x2037f0, b'X')
        self.reject_patch(0x216d44, b'X')

    def test_changed_owned_json_predicate_rejected(self):
        self.reject_patch(0x13c8600, b'X')

    def test_unsupported_borrowed_json_opcode_rejected(self):
        self.reject_patch(0x13c7302, b'\x49')

    def test_unsupported_owned_json_opcode_rejected(self):
        self.reject_patch(0x13c85fe, b'\x49')

    def test_changed_binary_success_tag_rejected(self):
        self.reject_patch(0x13c764b, b'\x2d')

    def test_changed_binary_branch_rejected(self):
        self.reject_patch(0x13c7608, b'\x85')

    def test_changed_binary_length_table_rejected(self):
        self.reject_patch(0x216ab0, struct.pack('<i', 0x7fffffff))

    def test_changed_binary_failure_sentinel_rejected(self):
        self.reject_patch(0x13c84a6, b'\x0e')

    def test_changed_binary_selected_dispatch_rejected(self):
        self.reject_patch(0x20faf8, struct.pack('<i', 0x7fffffff))

    def test_changed_binary_duplicate_name_rejected(self):
        self.reject_patch(0x21693d, b'X')

    def test_changed_binary_null_or_failure_rejected(self):
        self.reject_patch(0x13aa6f5, b'\xc1')
        self.reject_patch(0x13aa73f, b'\x49')

    def test_changed_binary_option_call_rejected(self):
        self.reject_patch(0x13ad696, b'\x00')

    def test_changed_binary_default_rejected(self):
        self.reject_patch(0x13ada34, b'\x01')

    def test_changed_binary_publication_rejected(self):
        self.reject_patch(0x13ae0e8, b'\x21')

    def test_changed_duplicate_guard_rejected(self):
        self.reject_patch(0x14a33f5, b'\x0e')

    def test_changed_duplicate_diagnostic_rejected(self):
        self.reject_patch(0x21bc5d, b'c')

    def test_changed_other_field_diagnostic_rejected(self):
        self.reject_patch(0x21bb16, b'X')

    def test_invalid_field_arm_rejected(self):
        self.reject_patch(0x21b834, struct.pack('<i', 0x7fffffff))

    def test_duplicate_field_arm_rejected(self):
        self.reject_patch(0x21b834, self.image.read(0x21b838, 4))

    def test_changed_colon_branch_rejected(self):
        self.reject_patch(0x14a3428, b'\x0e')

    def test_changed_map_call_rejected(self):
        self.reject_patch(0x14a4036, b'\x00')

    def test_changed_unknown_record_stride_rejected(self):
        self.reject_patch(0x14a35cc, b'\x05')

    def test_changed_unknown_collection_error_rejected(self):
        self.reject_patch(0x1488b71, b'\x48')

    def test_changed_suffix_or_name_slice_rejected(self):
        self.reject_patch(0x1dd407, b'X')
        self.reject_patch(0x2180ff, b'X')
        self.reject_patch(0x5668490, struct.pack('<Q', 10))

    def test_removed_or_retargeted_relocation_rejected(self):
        for slot in (0x576e928, 0x577a898, 0x5668488, 0x576dfe0):
            with self.subTest(slot=slot):
                changed = copy.copy(self.image)
                changed.relas = dict(self.image.relas)
                changed.relas.pop(slot)
                with self.assertRaises(study.EvidenceError):
                    study.collect(changed)
        changed = copy.copy(self.image)
        changed.relas = dict(self.image.relas)
        changed.relas[0x576e928] = (8, 0)
        with self.assertRaises(study.EvidenceError):
            study.collect(changed)

    def test_changed_duplicate_template_rejected(self):
        self.reject_patch(0x1e0fd6, b'X')

    def test_branch_decoder_rejects_truncated_or_wrong_form(self):
        with self.assertRaises(study.EvidenceError):
            study.branch(self.image, 'invalid', 0x149e7af, '72')
        with self.assertRaises(study.EvidenceError):
            study.rel32(self.image, 0x14a4035, 'e9')


if __name__ == '__main__':
    unittest.main()
