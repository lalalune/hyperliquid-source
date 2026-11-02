"""Focused static controls for the node 94 grouped preimage study."""

import contextlib
import mmap
import struct
import unittest

from tools import abci_root_groups94 as study


class GroupedRootInputs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = study.TARGET.open('rb')
        cls.data = mmap.mmap(cls.source.fileno(), 0, access=mmap.ACCESS_COPY)
        cls.image = study.Image(cls.data)
        cls.result = study.analyse(cls.image)

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.source.close()

    @contextlib.contextmanager
    def patched(self, va, new):
        pos = self.image.off(va, len(new))
        old = self.data[pos:pos + len(new)]
        self.data[pos:pos + len(new)] = new
        try:
            yield
        finally:
            self.data[pos:pos + len(new)] = old

    def test_artifact_digest_rejected_before_elf_parsing(self):
        old = self.data[0]
        try:
            self.data[0] ^= 1
            with self.assertRaisesRegex(ValueError, 'artifact digest mismatch'):
                study.Image(self.data)
        finally:
            self.data[0] = old

    def test_selected_body_mutation_is_rejected(self):
        with self.patched(0x1e5ede9, b'\x90'):
            with self.assertRaisesRegex(ValueError, 'selected body digest mismatch'):
                study.Image(self.data, check_digest=False)

    def test_selected_fde_range_mutation_is_rejected(self):
        frame = self.image.frames[0x1e5ed40]['fde']
        with self.patched(frame + 12, struct.pack('<I', 1)):
            with self.assertRaises(ValueError):
                study.Image(self.data, check_digest=False)

    def test_fde_extent_and_body_inventory(self):
        rows = self.result['function_extents']
        self.assertEqual(len(rows), 14)
        for row in rows:
            start = int(row['start'], 16)
            end, expected = study.SELECTED[start]
            self.assertEqual(int(row['end_exclusive'], 16), end)
            self.assertEqual(row['byte_count'], end - start)
            self.assertEqual(row['body_sha256'], expected)

    def test_capture_offsets_have_expected_order(self):
        groups = self.result['capture_groups']['low']
        self.assertEqual(tuple(int(row['state_offset'], 16) for row in groups['39']),
                         (0x3980, 0xb90, 0xba0, 0x3ac8, 0x8b8, 0x38f8,
                          0x3ac9, 0x31a8, 0x32e8, 0x3328, 0x3908, 0x7a0,
                          0x3938, 0x3ab0, 0x3aca, 0x3a48))
        self.assertEqual([len(groups[str(n)]) for n in (38, 39, 40)], [15, 16, 8])

    def test_capture_displacement_corruption_is_rejected(self):
        va = int(self.result['capture_groups']['low']['39'][1]['capture_va'], 16)
        with self.patched(va + 3, struct.pack('<I', 0xb91)):
            with self.assertRaisesRegex(ValueError, 'state capture mismatch'):
                study.capture_groups(self.image)

    def test_fat_pointer_relocation_type_corruption_is_rejected(self):
        slot = 0x56bda38 + 39 * 0x20 + 0x18
        old = self.image.relocations[slot]
        try:
            self.image.relocations[slot] = (7, old[1], old[2], old[3])
            with self.assertRaisesRegex(ValueError, 'expected RELATIVE relocation'):
                study.context_links(self.image)
        finally:
            self.image.relocations[slot] = old

    def test_relocation_actual_addend_corruption_is_rejected(self):
        slot = 0x56bda38 + 39 * 0x20 + 0x18
        entry = self.image.relocations[slot]
        pos = entry[3] + 16
        original = self.data[pos:pos + 8]
        try:
            self.data[pos:pos + 8] = struct.pack('<q', 0)
            altered = study.Image(self.data, check_digest=False)
            with self.assertRaises(ValueError):
                study.context_links(altered)
        finally:
            self.data[pos:pos + 8] = original

    def test_shared_capture_displacements_have_independent_witnesses(self):
        for source, expected in (('secondary', 0xb90), ('primary', 0x1610)):
            capture = self.result['capture_groups'][source]['39'][1]
            self.assertEqual(int(capture['state_offset'], 16), expected)
            va = int(capture['capture_va'], 16)
            with self.patched(va + 3, struct.pack('<I', expected + 1)):
                with self.assertRaisesRegex(ValueError, 'state capture mismatch'):
                    study.capture_groups(self.image, source)

    def test_every_capture_displacement_has_a_negative_control(self):
        count = 0
        for source, groups in self.result['capture_groups'].items():
            for rows in groups.values():
                for row in rows:
                    va = int(row['capture_va'], 16) + 3
                    new = bytes([self.image.read(va, 1)[0] ^ 1])
                    with self.subTest(source=source, va=hex(va)):
                        with self.patched(va, new):
                            with self.assertRaisesRegex(ValueError, 'state capture mismatch'):
                                study.capture_groups(self.image, source)
                    count += 1
        self.assertEqual(count, 117)

    def test_field_offsets_have_explicit_builder_sources(self):
        rows = self.result['fields']
        self.assertEqual(len(rows), 78)
        self.assertEqual({r['state_offset_basis'] for r in rows},
                         {'low_builder_capture', 'secondary_builder_capture'})
        for group, length in ((38, 15), (39, 16), (40, 8)):
            for lane in ('low', 'shared'):
                selected = [r for r in rows if r['group'] == group and r['lane'] == lane]
                self.assertEqual([r['index'] for r in selected], list(range(length)))
                self.assertEqual([int(r['box_offset'], 16) for r in selected],
                                 [i * 8 for i in range(length)])
                if lane == 'shared':
                    self.assertTrue(all(int(r['primary_state_offset'], 16) ==
                                        int(r['state_offset'], 16) + 0xa80 for r in selected))
                else:
                    self.assertTrue(all(r['primary_state_offset'] == '' for r in selected))

    def test_three_builders_bind_their_boxes_to_the_correct_tables(self):
        links = self.result['prior_context_links']
        self.assertEqual(len(links), 9)
        self.assertEqual({r['builder'] for r in links}, {'low', 'primary', 'secondary'})
        for row in links:
            table_base = 0x56bda38 if row['builder'] == 'low' else 0x57446e8
            self.assertEqual(int(row['vtable'], 16), table_base + row['group'] * 0x20)

    def test_prior_closure_error_exits_reject_corruption(self):
        rows = self.result['prior_closure_outcomes']
        self.assertEqual(len(rows), 6)
        for row in rows:
            self.assertEqual(row['branch']['condition'], 'not_equal')
            self.assertEqual(row['diagnostic'], 'called `Result::unwrap()` on an `Err` value')
            va = int(row['branch']['va'], 16) + 2
            corrupt = bytes([self.image.read(va, 1)[0] ^ 1])
            with self.subTest(group=row['group'], lane=row['lane']):
                with self.patched(va, corrupt):
                    with self.assertRaisesRegex(ValueError, 'prior closure result branch changed'):
                        study.prior_closure_outcomes(self.image)
                for name in ('writer_init', 'success_setup', 'failure_entry', 'failure_setup'):
                    target = int(row[name]['va'], 16)
                    changed = bytes([self.image.read(target, 1)[0] ^ 1])
                    with self.patched(target, changed):
                        with self.assertRaisesRegex(ValueError, 'instruction window mismatch'):
                            study.prior_closure_outcomes(self.image)
                target = int(row['diagnostic_va'], 16)
                with self.patched(target, b'X'):
                    with self.assertRaisesRegex(ValueError, 'closure diagnostic bytes changed'):
                        study.prior_closure_outcomes(self.image)

    def test_builder_register_flow_and_negative_controls(self):
        groups = {s: study.capture_groups(self.image, s) for s in ('low', 'secondary', 'primary')}
        flows = study.prior_builder_flow(self.image, groups)
        self.assertEqual(len(flows), 3)
        for flow in flows:
            self.assertGreater(flow['instruction_counts']['memory_store'], 0)
            self.assertEqual([g['size_argument'] for g in flow['capture_gaps']], [0x80, 0x40])
            source = flow['builder']
            with self.subTest(source=source):
                with self.patched(int(flow['begin'], 16), b'\x90'):
                    with self.assertRaisesRegex(ValueError, 'unrecognized prior builder flow instruction'):
                        study.prior_builder_flow(self.image, groups)
                gap = flow['capture_gaps'][0]
                with self.patched(int(gap['begin'], 16) + 1, b'\x81'):
                    with self.assertRaisesRegex(ValueError, 'prior allocation setup changed'):
                        study.prior_builder_flow(self.image, groups)
                branch = int(gap['null_branch']['va'], 16)
                with self.patched(branch + 1, b'\x85'):
                    with self.assertRaisesRegex(ValueError, 'prior allocation failure branch changed'):
                        study.prior_builder_flow(self.image, groups)
                changed = bytes([self.image.read(branch + 2, 1)[0] ^ 1])
                with self.patched(branch + 2, changed):
                    with self.assertRaisesRegex(ValueError, 'prior allocation failure branch changed'):
                        study.prior_builder_flow(self.image, groups)
                alias = int(flow['capture_aliases'][0]['va'], 16)
                with self.patched(alias, b'\x90'):
                    with self.assertRaisesRegex(ValueError, 'instruction window mismatch'):
                        study.prior_builder_flow(self.image, groups)

    def test_freeze_pointer_and_callee(self):
        rows = [r for r in self.result['fields'] if r['group'] == 39 and r['index'] == 1]
        self.assertEqual([(r['lane'], r['state_offset'], r['callee']) for r in rows],
                         [('low', '0xb90', '0x1e0fcc0'),
                          ('shared', '0xb90', '0x43f69d0')])
        low = [r for r in self.result['branches']
               if r['role'] == 'freeze_tag_not_one' and r['lane'] == 'low'][0]
        self.assertEqual((low['condition'], low['fallthrough'], low['target']),
                         ('not_equal', '0x1e0fcf6', '0x1e0fdc9'))

    def test_prior_loader_copy_and_clear_offsets_agree(self):
        row = self.result['prior_loader_dataflow']
        self.assertEqual((row['copy_base_stack_offset'], row['copy_size'],
                          row['clear_stack_offset'], row['clear_offset_in_copy']),
                         ('0x68', '0x3ae8', '0xbf8', '0xb90'))
        with self.patched(0x3272813, b'\xf9'):
            with self.assertRaisesRegex(ValueError, 'instruction window mismatch'):
                study.prior_loader_dataflow(self.image)

    def test_all_six_array_openers(self):
        openers = self.result['openers']
        self.assertEqual([(r['group'], r['lane'], r['length']) for r in openers],
                         [(38, 'low', 15), (38, 'shared', 15),
                          (39, 'low', 16), (39, 'shared', 16),
                          (40, 'low', 8), (40, 'shared', 8)])

    def test_all_six_parent_sentinels_and_corruptions(self):
        rows = self.result['sentinels']
        self.assertEqual(len(rows), 6)
        for row in rows:
            self.assertEqual(row['value'], '0x8000000000000004')
            va = int(row['va'], 16) + 2
            with self.subTest(va=hex(va)):
                with self.patched(va, b'\x05'):
                    with self.assertRaisesRegex(ValueError, 'instruction window mismatch'):
                        study.analyse(self.image)

    def test_enum_mapping_both_lanes(self):
        for lane in ('low', 'shared'):
            rows = [r for r in self.result['enum_cases'] if r['group'] == 38 and r['lane'] == lane]
            self.assertEqual([(r['tag'], r['text']) for r in rows],
                             [(0, 'Local'), (1, 'Sandbox'), (2, 'Testnet'), (3, 'Mainnet')])
            rows = [r for r in self.result['enum_cases'] if r['group'] == 40 and r['lane'] == lane]
            self.assertEqual([(r['tag'], r['text']) for r in rows],
                             [(0, 'disabled'), (1, 'reduceOnly'), ('other', 'enabled')])

    def test_enum_relative_table_corruption_is_rejected(self):
        rows = [r for r in self.result['enum_cases'] if r['group'] == 38]
        self.assertEqual(len(rows), 8)
        for row in rows:
            va = int(row['table_entry'], 16)
            with self.subTest(lane=row['lane'], tag=row['tag']):
                with self.patched(va, struct.pack('<i', 0)):
                    with self.assertRaisesRegex(ValueError, 'enum arm outside selected FDE'):
                        study.enums(self.image)

    def test_conditional_branch_kinds_and_destination(self):
        tests = ((0x1e5da3d, 'equal', '0x1e5dbba'),
                 (0x1e5db82, 'not_equal', '0x1e5dc28'),
                 (0x1e5dc5c, 'not_equal', '0x1e5dcbb'),
                 (0x1e5dd53, 'equal', '0x1e5ddd1'))
        for va, condition, target in tests:
            with self.subTest(va=hex(va)):
                row = study.decode_branch(self.image, va)
                self.assertEqual((row['condition'], row['target']), (condition, target))

    def test_nonbranch_opcode_is_rejected(self):
        with self.patched(0x1e5da3d, b'\x90'):
            with self.assertRaisesRegex(ValueError, 'unexpected conditional branch'):
                study.decode_branch(self.image, 0x1e5da3d)

    def test_regular_error_joins(self):
        regular = [r for r in self.result['fields'] if 'failure_target' in r]
        self.assertEqual(len(regular), 58)
        for group, expected in ((38, {'low': '0x1e5e709', 'shared': '0x4447049'}),
                                (39, {'low': '0x1e5efb4', 'shared': '0x4446814'})):
            for lane in ('low', 'shared'):
                self.assertEqual({r['failure_target'] for r in regular
                                  if r['group'] == group and r['lane'] == lane}, {expected[lane]})
        self.assertEqual(len(self.result['error_copies']), 6)

    def test_every_regular_error_branch_rejects_opcode_and_displacement_mutations(self):
        regular = [r for r in self.result['fields'] if 'failure_target' in r]
        count = 0
        for row in regular:
            va = int(row['branch_va'], 16)
            offset = 2 if self.image.read(va, 1) == b'\x0f' else 1
            corrupt_displacement = bytes([self.image.read(va + offset, 1)[0] ^ 1])
            captures = self.result['capture_groups']['low'][str(row['group'])]
            with self.subTest(group=row['group'], lane=row['lane'], index=row['index']):
                with self.patched(va, b'\x90'):
                    with self.assertRaises(ValueError):
                        study.regular_fields(self.image, row['group'], row['lane'], captures)
                with self.patched(va + offset, corrupt_displacement):
                    with self.assertRaisesRegex(ValueError, 'failure join changed'):
                        study.regular_fields(self.image, row['group'], row['lane'], captures)
            count += 1
        self.assertEqual(count, 58)

    def test_helper_evidence_and_calls(self):
        rows = self.result['selected_helper_decisions']
        self.assertEqual(len(rows), 2)
        for row, target in zip(rows, ('0x25ac0d0', '0x4aeca50')):
            self.assertEqual(len(row['windows']), 12)
            self.assertEqual({r['target'] for r in row['calls']
                              if r['kind'] in ('option_u64', 'u64')}, {target})

    def test_helper_result_windows_and_mutations(self):
        count = 0
        for helper in self.result['selected_helper_decisions']:
            self.assertEqual(len(helper['terminal_windows']), 9)
            for row in helper['terminal_windows']:
                if row['role'].endswith('allocation_error'):
                    self.assertIn('0300000026000000', row['bytes'])
                va = int(row['va'], 16)
                corrupt = bytes([self.image.read(va, 1)[0] ^ 1])
                with self.subTest(lane=helper['lane'], role=row['role']):
                    with self.patched(va, corrupt):
                        with self.assertRaisesRegex(ValueError, 'instruction window mismatch'):
                            study.analyse(self.image)
                count += 1
        self.assertEqual(count, 18)

    def test_keyed_serializer_names_captured_fields(self):
        names = {(r['group'], r['index']): r['key'] for r in self.result['named_field_context']}
        self.assertEqual(names[(39, 0)], 'max_order_distance_from_anchor')
        self.assertEqual(names[(39, 1)], 'scheduled_freeze_height')
        self.assertEqual(names[(39, 2)], 'simulate_crash_height')
        self.assertEqual(names[(39, 3)], 'spot_disabled')
        self.assertEqual(names[(39, 6)], 'evm_enabled')
        self.assertEqual(names[(39, 14)], 'hip3_no_cross')
        self.assertEqual(names[(40, 1)], 'dex_abstraction_enabled')
        self.assertEqual(names[(38, 3)], 'post_only_until_height')
        self.assertEqual(names[(39, 5)], 'begin_block_logic_guard')
        self.assertEqual(names[(39, 8)], 'perp_deploy_gas_auction')
        self.assertEqual(names[(40, 7)], 'pmn')
        self.assertEqual(len(names), 27)

    def test_key_literal_corruption_is_rejected(self):
        for row in self.result['named_field_context']:
            va = int(row['key_va'], 16)
            changed = bytes([self.image.read(va, 1)[0] ^ 0x20])
            with self.subTest(key=row['key']):
                with self.patched(va, changed):
                    with self.assertRaisesRegex(ValueError, 'key bytes changed'):
                        study.named_field_context(self.image)

    def test_helper_instruction_corruption_is_rejected(self):
        with self.patched(0x1e0fced, b'\x90'):
            with self.assertRaisesRegex(ValueError, 'instruction window mismatch'):
                study.analyse(self.image)

    def test_fresh_prefix_boundaries_and_nil(self):
        prefix = bytes.fromhex('dc0010cb0000000000000000')
        for value, encoded in ((0, '00'), (42, '2a'), (127, '7f'),
                               (128, 'cc80'), (255, 'ccff'),
                               (256, 'cd0100'), (65535, 'cdffff')):
            with self.subTest(value=value):
                self.assertEqual(study.group39_prefix(0, 1, value), prefix + bytes.fromhex(encoded))
        self.assertEqual(study.group39_prefix(0, 0, 42), prefix + b'\xc0')
        self.assertEqual(study.group39_prefix(0, 2, 42), prefix + b'\xc0')
        self.assertEqual(study.group39_prefix(0x3ff0000000000000, 1, 42).hex(),
                         'dc0010cb3ff00000000000002a')

    def test_prefix_model_rejects_values_outside_its_proved_range(self):
        for value in (-1, 65536, True):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    study.small_u64_messagepack(value)
        for bits, tag in ((-1, 1), (1 << 64, 1), (0, -1), (0, 1 << 32)):
            with self.subTest(bits=bits, tag=tag):
                with self.assertRaises(ValueError):
                    study.group39_prefix(bits, tag, 0)

    def test_virtual_address_must_be_unique_file_backed_allocated_interval(self):
        self.assertEqual(study.file_offset([{'type': 1, 'flags': 2, 'address': 100,
                                             'size': 4, 'offset': 12}], 102, 2), 14)
        for sections, va, size in (([], 0, 1),
                                   ([{'type': 8, 'flags': 2, 'address': 100, 'size': 4, 'offset': 12}], 100, 1),
                                   ([{'type': 1, 'flags': 0, 'address': 100, 'size': 4, 'offset': 12}], 100, 1),
                                   ([{'type': 1, 'flags': 2, 'address': 100, 'size': 4, 'offset': 12}], 103, 2),
                                   ([{'type': 1, 'flags': 2, 'address': 100, 'size': 4, 'offset': 12}] * 2, 100, 1),
                                   ([], -1, 1), ([], 0, 0)):
            with self.subTest(va=va, size=size, sections=sections):
                with self.assertRaises(ValueError):
                    study.file_offset(sections, va, size)

    def test_synthetic_cases_are_not_target_execution(self):
        rows = self.result['synthetic_group39_prefixes']
        self.assertEqual(len(rows), 9)
        self.assertEqual(rows[0]['prefix_hex'], 'dc0010cb0000000000000000c0')
        self.assertEqual(rows[-2]['prefix_hex'], 'dc0010cb3ff0000000000000cdffff')


if __name__ == '__main__':
    unittest.main()
