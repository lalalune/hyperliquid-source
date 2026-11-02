"""Independent boundary and corruption controls for the static RE-006 packet."""
import csv
import io
import json
from pathlib import Path
import struct
import unittest

from tools import untriggered_tree_delete94 as subject


class UntriggeredTreeDeletionEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Missing input is a failure, not a skipped test.
        cls.data = subject.TARGET.read_bytes()
        subject.authenticate(cls.data)
        cls.sections, cls.fdes = subject.input_fdes(cls.data)
        cls.outputs = subject.make_outputs(cls.data)

    def rows(self, name):
        return list(csv.DictReader(io.StringIO(self.outputs[name].decode()), delimiter='\t'))

    def test_authenticated_input_and_single_byte_corruption(self):
        self.assertEqual(subject.authenticate(self.data), subject.TARGET_SHA256)
        damaged = bytearray(self.data)
        pos = subject.va_offset(self.sections, 0x49454c0, 1, True)
        damaged[pos] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            subject.authenticate(damaged)

    def test_sections_do_not_map_nobits_or_cross_boundaries(self):
        text = next(s for s in self.sections if s['name'] == '.text')
        first, end = text['address'], text['address'] + text['size']
        self.assertEqual(subject.va_offset(self.sections, first, 1, True), text['offset'])
        self.assertEqual(subject.va_offset(self.sections, end - 1, 1, True),
                         text['offset'] + text['size'] - 1)
        with self.assertRaises(ValueError):
            subject.va_offset(self.sections, end - 1, 2, True)
        with self.assertRaises(ValueError):
            subject.va_offset(self.sections, first, 0, True)
        synthetic = [{'name': 'empty', 'type': 8, 'flags': 6,
                      'address': 0x1000, 'offset': 0, 'size': 16}]
        with self.assertRaises(ValueError):
            subject.va_offset(synthetic, 0x1000, 1, True)
        synthetic.append(dict(synthetic[0], name='backed', type=1))
        self.assertEqual(subject.va_offset(synthetic, 0x1000, 1, True), 0)
        synthetic.append(dict(synthetic[-1], name='ambiguous'))
        with self.assertRaises(ValueError):
            subject.va_offset(synthetic, 0x1000, 1, True)

    def test_fde_extents_and_selected_calls(self):
        expected = {
            0x49454a0: 0x4945813, 0x2866870: 0x2866be3, 0x28660a0: 0x2866413,
            0x42b66c0: 0x42b699a, 0x1b22a90: 0x1b22d6a,
            0x429f690: 0x42a0340, 0x1b17160: 0x1b17e10,
            0x42788d0: 0x4278c17, 0x1af72d0: 0x1af7617,
            0x427ecd0: 0x427f08e, 0x1afcfe0: 0x1afd39e,
        }
        self.assertEqual({start: row['end'] for start, row in self.fdes.items()}, expected)
        calls = {int(row['site_va'], 16): int(row['target_va'], 16)
                 for row in self.rows('calls.tsv')}
        self.assertEqual(len(calls), 18)
        for site, target in {
            0x42f8954: 0x49454a0, 0x26de5a4: 0x2866870, 0x26df5fa: 0x28660a0,
            0x4945562: 0x42b66c0, 0x42b68ee: 0x429f690,
            0x42b67e5: 0x429f690, 0x429fcb4: 0x42788d0,
            0x429fcd4: 0x427ecd0, 0x1b17d75: 0x1af72d0,
        }.items():
            self.assertEqual(calls[site], target)

    def test_direct_call_signed_displacement_and_invalid_opcode(self):
        self.assertEqual(subject.decode_rel32(bytes.fromhex('e8fbffffff'), 0x1000), 0x1000)
        self.assertEqual(subject.decode_rel32(bytes.fromhex('e810000000'), 0x1000), 0x1015)
        for raw in (b'\xe9\0\0\0\0', b'\xe8\0\0\0', b''):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                subject.decode_rel32(raw, 0x1000)

    def test_short_and_near_branch_decoding_and_corruption(self):
        self.assertEqual(subject.decode_branch(bytes.fromhex('74fe'), 0x1000)[:3],
                         ('je', 0x1002, 0x1000))
        self.assertEqual(subject.decode_branch(bytes.fromhex('0f87f2040000'), 0x429f803)[:3],
                         ('ja', 0x429f809, 0x429fcfb))
        for raw in (b'\x90', b'\x0f\x87\x01', b'\xeb\x00', b''):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                subject.decode_branch(raw, 0x1000)
        branch_rows = self.rows('branches.tsv')
        self.assertEqual(len(branch_rows), 94)
        for row in branch_rows:
            with self.subTest(site=row['site_va']):
                self.assertEqual(subject.decode_branch(bytes.fromhex(row['raw_hex']),
                                                       int(row['site_va'], 16))[2],
                                 int(row['taken_va'], 16))

    def test_fixed_windows_detect_altered_bytes(self):
        label, _, hex_bytes = next(x for x in subject.WINDOWS if x[0] == 'leaf_value_shift_and_threshold')
        original = bytes.fromhex(hex_bytes)
        fake = [{'name': 'window', 'type': 1, 'flags': 6, 'address': 0x3000,
                 'offset': 0, 'size': len(original)}]
        self.assertEqual(subject.expect_bytes(original, fake, 0x3000, hex_bytes), original)
        corrupt = bytearray(original)
        corrupt[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'signature mismatch'):
            subject.expect_bytes(corrupt, fake, 0x3000, hex_bytes)
        self.assertEqual(label, 'leaf_value_shift_and_threshold')

    def test_normalization_detects_code_and_opcode_changes(self):
        def body(start):
            record = self.fdes[start]
            return subject.read_va(self.data, self.sections, start, record['end'] - start, True)
        a, b = body(0x49454a0), body(0x2866870)
        masks = subject.MASKS['remove']
        self.assertNotEqual(a, b)
        self.assertEqual(subject.normalize(a, masks), subject.normalize(b, masks))
        changed = bytearray(a)
        changed[0] ^= 1
        self.assertNotEqual(subject.normalize(changed, masks), subject.normalize(a, masks))
        changed = bytearray(a)
        changed[masks[0][0] - 1] ^= 1
        with self.assertRaisesRegex(ValueError, 'opcode mismatch'):
            subject.normalize(changed, masks)
        with self.assertRaisesRegex(ValueError, 'overlapping'):
            subject.normalize(a, (masks[0], masks[0]))
        with self.assertRaisesRegex(ValueError, 'outside function'):
            subject.normalize(a, ((len(a) - 1, 'e8'),))

    def test_masked_operands_can_still_change_call_targets(self):
        fde = self.fdes[0x49454a0]
        body = subject.read_va(self.data, self.sections, fde['start'], fde['end'] - fde['start'], True)
        offset = subject.MASKS['remove'][0][0]
        changed = bytearray(body)
        changed[offset] ^= 1
        self.assertEqual(subject.normalize(body, subject.MASKS['remove']),
                         subject.normalize(changed, subject.MASKS['remove']))
        site = fde['start'] + offset - 1
        self.assertNotEqual(subject.decode_rel32(body[offset - 1:offset + 4], site),
                            subject.decode_rel32(changed[offset - 1:offset + 4], site))

    def test_leaf_shift_boundaries_are_checked_model_only(self):
        constants = {r['label']: int(r['value_decimal']) for r in self.rows('constants.tsv')}
        stride = constants['node_value_stride']
        projected = {r['label']: r for r in self.rows('boundary-cases.tsv')}
        self.assertEqual((projected['merge_below_limit']['left'], projected['merge_below_limit']['predicate_true']), ('11', 'False'))
        self.assertEqual((projected['merge_at_limit']['left'], projected['merge_at_limit']['predicate_true']), ('12', 'True'))
        self.assertEqual((projected['donor_short_by_one']['predicate_true'], projected['donor_exact']['predicate_true']), ('True', 'False'))
        self.assertEqual((projected['wrapper_full_tag_high_bits']['predicate_true'],
                          projected['caller_low_tag_high_bits']['predicate_true']), ('False', 'True'))
        self.assertEqual((stride, constants['leaf_small_count_limit'],
                          constants['merge_exclusive_limit']), (0xb8, 4, 12))
        regions = {r['label']: r for r in self.rows('layout-capacity.tsv')}
        self.assertEqual((constants['node_key_stride'], constants['node_edge_stride']), (8, 8))
        self.assertEqual([regions[n]['whole_strides'] for n in ('key_region', 'value_region', 'internal_edge_region')],
                         ['11', '11', '12'])
        # Arithmetic implied by the pinned key/value shift instructions. These
        # are model fixtures; they do not execute or emulate the target.
        for count, index, expected in ((1, 0, (0, 0)), (5, 0, (32, 736)),
                                       (5, 2, (16, 368)), (11, 10, (0, 0)),
                                       (11, 0, (80, 1840))):
            with self.subTest(count=count, index=index):
                self.assertEqual(subject.leaf_shift_lengths(count, index, stride), expected)
        for count, index in ((0, 0), (1, -1), (1, 1), (65536, 0)):
            with self.subTest(count=count, index=index), self.assertRaises(ValueError):
                subject.leaf_shift_lengths(count, index, stride)

    def test_guard_and_store_order_around_failure_paths(self):
        # These are independently selected machine-byte checks, not execution
        # or a claim about what a surrounding unwind retains.
        signatures = {
            0x427891a: '664489b34a080000',  # left donor count store
            0x4278927: '664189874a080000',  # right destination count store
            0x4278a39: '488954c808',        # parent key replacement
            0x427ed16: '664189864a080000',  # left destination count store
            0x427ed1e: '6641898f4a080000',  # right donor count store
            0x427ed9e: '488954c808',        # parent key replacement
            0x4945619: '49ff4e10',          # tree header count decrement
        }
        for address, encoded in signatures.items():
            with self.subTest(address=hex(address)):
                self.assertEqual(subject.expect_bytes(self.data, self.sections, address, encoded).hex(), encoded)
        branches = {int(r['site_va'], 16): r for r in self.rows('branches.tsv')}
        for capacity, donor, store, parent_store, height in (
            (0x42788f5, 0x427890f, 0x427891a, 0x4278a39, 0x4278a97),
            (0x427ecf5, 0x427ed10, 0x427ed16, 0x427ed9e, 0x427ee8d),
        ):
            self.assertLess(capacity, donor)
            self.assertLess(donor, store)
            self.assertLess(store, parent_store)
            self.assertLess(parent_store, height)
            self.assertEqual((branches[capacity]['condition'], branches[donor]['condition'],
                              branches[height]['condition']), ('jae', 'jb', 'je'))
        self.assertLess(0x4945619, 0x494563a)
        self.assertEqual(branches[0x494563a]['taken_va'], '0x49457c7')

    def test_diagnostics_and_dynamic_symbols(self):
        diag = {r['label']: r for r in self.rows('diagnostics.tsv')}
        self.assertEqual(len(diag), 10)
        self.assertEqual(json.loads(diag['collapse_height_zero']['message_json']),
                         'assertion failed: self.height > 0')
        self.assertEqual(json.loads(diag['left_rotation_source']['message_json']),
                         'assertion failed: old_left_len >= count')
        self.assertEqual((diag['left_rotation_capacity']['line'],
                          diag['right_rotation_capacity']['line']), ('1537', '1600'))
        self.assertTrue(all(not r['path_suffix'].startswith('/') for r in diag.values()))
        failures = {r['label']: r for r in self.rows('failure-edges.tsv')}
        self.assertEqual(failures['null_root_after_collapse']['slot_va'], '0x576e470')
        self.assertEqual(failures['empty_internal_first']['argument_word_hex'], '0x7b')
        self.assertEqual(failures['empty_internal_first']['call_va'], failures['empty_internal_upward']['call_va'])
        locations = {r['location_va']: r for r in self.rows('failure-locations.tsv')}
        self.assertEqual((locations['0x571c480']['line'], locations['0x571c480']['column']), ('1360', '31'))
        self.assertEqual((locations['0x5733f08']['line'], locations['0x5733f08']['column']), ('614', '42'))
        got = {r['slot_va']: r for r in self.rows('relocations.tsv')}
        self.assertEqual(got['0x576dfe0']['symbol_name'], 'memcpy')
        self.assertEqual(got['0x576e0e0']['symbol_name'], 'memmove')
        self.assertEqual((got['0x576e010']['type'], got['0x576e010']['addend']), ('8', '0x54c8cb0'))
        self.assertEqual(json.loads(diag['left_rotation_height_mismatch']['message_json']),
                         json.loads(diag['right_rotation_height_mismatch']['message_json']))

    def test_relocation_missing_duplicate_and_name_bounds_fail(self):
        relsec = {'name': '.rela.dyn', 'type': 4, 'flags': 2, 'address': 0,
                  'offset': 0, 'size': 24}
        raw = struct.pack('<QQq', 0x1000, 8, 0x2000)
        self.assertEqual(subject.relocation_records(raw, [relsec], {0x1000})[0x1000], (8, 0, 0x2000))
        with self.assertRaisesRegex(ValueError, 'missing'):
            subject.relocation_records(raw, [relsec], {0x1008})
        duplicated = dict(relsec, size=48)
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            subject.relocation_records(raw + raw, [duplicated], {0x1000})
        with self.assertRaisesRegex(ValueError, 'unsupported'):
            subject.relocation_records(raw, [dict(relsec, size=23)], {0x1000})
        symsec = {'name': '.dynsym', 'type': 11, 'flags': 2, 'address': 0,
                  'offset': 0, 'size': 24}
        strsec = {'name': '.dynstr', 'type': 3, 'flags': 2, 'address': 0,
                  'offset': 24, 'size': 1}
        with self.assertRaisesRegex(ValueError, 'name outside'):
            subject.symbol_name(struct.pack('<I', 1) + bytes(21), [symsec, strsec], 0)
        with self.assertRaisesRegex(ValueError, 'index outside'):
            subject.symbol_name(bytes(25), [symsec, strsec], 1)

    def test_generated_evidence_matches_packet_byte_for_byte(self):
        directory = subject.ROOT / 'research/work-items/RE-006-untriggered-tree-delete-94'
        self.assertEqual(len(self.outputs), 13)
        for name, content in self.outputs.items():
            with self.subTest(name=name):
                self.assertEqual((directory / name).read_bytes(), content)
        summary = json.loads(self.outputs['evidence.json'])
        self.assertEqual((summary['function_count'], summary['family_count'],
                          summary['recorded_call_count'], summary['recorded_diagnostic_count']),
                         (11, 5, 18, 10))
        self.assertEqual((summary['anchored_window_count'], summary['recorded_branch_count'],
                          summary['boundary_projection_count'], summary['layout_projection_count'],
                          summary['additional_failure_edge_count']), (41, 94, 10, 3, 3))
        self.assertEqual(summary['selected_copy_pair_comparison'],
                         {'selected_peer_pairs': 6, 'raw_equal': 0,
                          'masked_only': 6, 'unmatched_outside_mask': 0})


if __name__ == '__main__':
    unittest.main()
