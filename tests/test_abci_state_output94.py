"""Target-grounded and negative controls for the node 94 output-path packet."""
from contextlib import contextmanager
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import abci_state_output94 as packet
from tools.elf_index import sections


class AbciStateOutput94Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # The artifact is required: absence is an error, never a skipped test.
        cls.data = bytearray(packet.TARGET.read_bytes())
        cls.secs = sections(cls.data)
        cls.result = packet.analyze(cls.data)
        cls.branches = {row['label']: row for row in cls.result['branches']}
        cls.edges = {row['label']: row for row in cls.result['edges']}

    @contextmanager
    def changed(self, va, replacement):
        _, off = packet.file_mapping(self.secs, va, len(replacement))
        old = self.data[off:off + len(replacement)]
        self.data[off:off + len(replacement)] = replacement
        try:
            yield
        finally:
            self.data[off:off + len(replacement)] = old

    def test_target_identity_and_selected_extents(self):
        self.assertEqual(packet.authenticate(self.data),
                         '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f')
        functions = {int(row['start'], 16): row for row in self.result['functions']}
        self.assertEqual(len(functions), 22)
        self.assertEqual(functions[0x2519180]['end_exclusive'], '0x2519329')
        self.assertEqual(functions[0x23367a0]['end_exclusive'], '0x2336b49')
        self.assertNotIn(0x22ae8a0, functions)
        self.assertNotIn(0x28c66b0, functions)
        self.assertNotIn(0x28cb9f0, functions)
        self.assertTrue(all(row['section'] == '.text' for row in functions.values()))

    def test_loaded_value_and_output_edges(self):
        wanted = {
            'converted_records_from_boundary': ('0x28c697d', '0x2519180'),
            'map_update_from_boundary': ('0x28c6adb', '0x2862490'),
            'sink_from_boundary': ('0x28c6bd8', '0x28cb9f0'),
            'adapter_from_boundary': ('0x28cbb65', '0x25dd540'),
            'collect_entries': ('0x25dd5aa', '0x2566730'),
            'write_entries': ('0x25dd5b8', '0x1e37f00'),
            'write_entry': ('0x1e380ee', '0x1df07d0'),
            'write_entry_value': ('0x1df0853', '0x28c7b10'),
            'write_sentinel_side_map': ('0x28c7b46', '0x1e562a0'),
            'write_side_map': ('0x28c7be8', '0x1e562a0'),
            'write_untriggered': ('0x28c7c29', '0x1e4a950'),
            'write_converted_record': ('0x1e4aa49', '0x28c7770'),
            'tag_one_order': ('0x28c778a', '0x23367a0'),
            'tag_zero_order': ('0x1e0e776', '0x23367a0'),
            'children_element': ('0x1e3bb79', '0x23367a0'),
            'text_adapter_from_boundary': ('0x28cbdfb', '0x25e7da0'),
            'text_collect_entries': ('0x25e7e07', '0x2566730'),
            'text_write_entries': ('0x25e7e12', '0x290ea20'),
            'text_write_side_map': ('0x290eed1', '0x2399b40'),
            'text_write_untriggered': ('0x290ef3b', '0x294c110'),
            'text_tag_nonzero_order': ('0x294c1a7', '0x2336310'),
            'text_tag_zero_order': ('0x294c450', '0x2336310'),
            'text_children_tail': ('0x23d2064', '0x2967f60'),
            'text_children_order': ('0x29680ff', '0x2336310'),
        }
        for label, expected in wanted.items():
            with self.subTest(label=label):
                self.assertEqual((self.edges[label]['site'], self.edges[label]['target']), expected)
        # The earlier inventory owns this handoff; do not count it as a new edge.
        self.assertNotIn('0x22aec2e', {row['site'] for row in self.result['edges']})

    def test_conditional_paths_and_failures(self):
        expected = {
            'boundary_no_height': ('je', '0x28c6bef'),
            'boundary_non_two_kind': ('jne', '0x28c66f6'),
            'boundary_convert_flag_zero': ('je', '0x28c69e0'),
            'boundary_mul_fits': ('jno', '0x28c6816'),
            'boundary_mul_overflow': ('jo', '0x28c6d25'),
            'boundary_add_overflow': ('jb', '0x28c6d34'),
            'boundary_sink_no_height': ('je', '0x28cbae0'),
            'boundary_null_path': ('je', '0x28cbee8'),
            'boundary_predicate_zero': ('je', '0x28cbd9b'),
            'boundary_writer_failure': ('jne', '0x28cbf0a'),
            'record_flag_nonzero': ('jne', '0x2519260'),
            'record_allocation_failure': ('je', '0x25192f7'),
            'map_allocation_failure': ('je', '0x2862819'),
            'map_node_capacity_failure': ('jae', '0x286282b'),
            'sequence_header_error': ('jne', '0x1e3802e'),
            'sequence_entry_error': ('jne', '0x1e37fe0'),
            'record_tag_not_one': ('jne', '0x28c7794'),
            'children_element_error': ('jne', '0x1e3bd4f'),
            'order_cloid_error': ('jne', '0x2336b12'),
            'boundary_text_writer_error': ('jne', '0x28cbf4e'),
            'text_outer_empty': ('je', '0x290f557'),
            'text_container_regular': ('jno', '0x290ee30'),
            'text_record_nonzero': ('jne', '0x294c1a0'),
            'text_direct_order_error': ('jne', '0x294c63f'),
            'text_pair_order_error': ('jne', '0x294c63f'),
            'text_children_element_error': ('jne', '0x2968198'),
        }
        for label, pair in expected.items():
            with self.subTest(label=label):
                row = self.branches[label]
                self.assertEqual((row['condition'], row['taken_target']), pair)
        self.assertEqual(len(self.branches), len(packet.BRANCHES))
        self.assertGreaterEqual(len(self.branches), 80)

    def test_named_fields_in_machine_order(self):
        expected = ('coin', 'side', 'limitPx', 'sz', 'oid', 'timestamp',
                    'triggerCondition', 'isTrigger', 'triggerPx', 'children',
                    'isPositionTpsl', 'reduceOnly', 'orderType', 'origSz', 'tif', 'cloid')
        fields = self.result['fields']
        self.assertEqual(tuple(f['name'] for f in fields), expected)
        text_fields = self.result['text_fields']
        self.assertEqual(tuple(f['name'] for f in text_fields), expected)
        self.assertEqual([f['name_va'] for f in text_fields], [f['name_va'] for f in fields])
        self.assertEqual(text_fields[9]['lea_va'], '0x23d2058')
        self.assertEqual(text_fields[9]['call_va'], '0x233659a')
        self.assertEqual([f['ordinal'] for f in fields], list(range(1, 17)))
        self.assertEqual(fields[9]['lea_va'], '0x23d4acf')  # children adapter
        self.assertEqual(fields[9]['call_va'], '0x2336a03')
        self.assertEqual(fields[-1]['call_va'], '0x2336b01')
        self.assertEqual(len({f['name_va'] for f in fields}), 16)

    def test_order_source_offsets_and_operand_corruption(self):
        layout = self.result['field_layout']
        by_name = {}
        for row in layout:
            by_name.setdefault(row['field'], []).append(row['order_offset'])
        self.assertEqual(len(layout), 19)
        self.assertEqual(by_name['coin'], ['0x8', '0x10'])
        self.assertEqual(by_name['side'], ['0x90'])
        self.assertEqual(by_name['triggerCondition'], ['0x20', '0x28'])
        self.assertEqual(by_name['children'], ['0x30'])
        self.assertEqual(by_name['orderType'], ['0x50', '0x58'])
        self.assertEqual(by_name['cloid'], ['0x94'])
        with self.changed(0x23368b6, b'\x61'):
            with self.assertRaisesRegex(ValueError, 'wrong source offset'):
                packet.source_operand(self.data, self.secs, 0x23368b1,
                                      bytes.fromhex('f2410f1046'), 1, 0x60)
        with self.changed(0x23368b1, b'\x90'):
            with self.assertRaisesRegex(ValueError, 'unexpected source operand'):
                packet.source_operand(self.data, self.secs, 0x23368b1,
                                      bytes.fromhex('f2410f1046'), 1, 0x60)

    def test_reordered_text_fields_are_rejected(self):
        reordered = list(packet.TEXT_FIELD_SPECS)
        reordered[0], reordered[1] = reordered[1], reordered[0]
        with patch.object(packet, 'TEXT_FIELD_SPECS', reordered):
            with self.assertRaisesRegex(ValueError, 'binary/text field order mismatch'):
                packet.analyze(self.data, check_digest=False)
        binary_reordered = list(packet.FIELD_SPECS)
        binary_reordered[0], binary_reordered[1] = binary_reordered[1], binary_reordered[0]
        with patch.object(packet, 'FIELD_SPECS', binary_reordered):
            with self.assertRaisesRegex(ValueError, 'binary field calls not in instruction order'):
                packet.analyze(self.data, check_digest=False)

    def test_converter_and_serializer_controls(self):
        self.assertEqual(self.result['source_layout'], {
            'base_offset': '0x5c0', 'count_offset': '0x5c8',
            'group_stride': '0x2f0', 'loop_stride': '0x2f0',
        })
        layout = self.result['record_layout']
        self.assertEqual(layout, {
            'input_stride': 192, 'output_stride': 200,
            'zero_flag_tag': 1, 'zero_flag_source_offset': 24,
            'zero_flag_defined_copy': 168, 'zero_flag_other_stored_bytes': 24,
            'nonzero_flag_tag': 0, 'nonzero_flag_defined_copy': 192,
            'serializer_control_word_bytes': '00040001',
            'serializer_following_byte': 0,
        })
        labels = {row['role']: row['text'] for row in self.result['binary_labels']}
        self.assertEqual(labels['side_zero'], 'B')
        self.assertEqual(labels['side_one'], 'A')
        self.assertEqual(labels['sentinel_side_map'], 'SideMap')
        self.assertEqual(labels['book_orders'], 'book_orders')
        self.assertEqual(labels['untriggered_orders'], 'untriggered_orders')
        syntax = {row['role']: row['stored_bytes'] for row in self.result['text_syntax']}
        self.assertEqual(syntax['array_open'], '5b')
        self.assertEqual(syntax['object_close'], '7d')
        self.assertEqual(syntax['comma_newline'], '2c0a')

    def test_source_arithmetic_boundaries(self):
        arithmetic = self.result['arithmetic']
        self.assertEqual(arithmetic, {
            'multiplier': 10000, 'operand_offset': '0x30', 'operand_bits': 64,
            'maximum_operand_without_product_overflow': 1844674407370955,
        })
        factor = arithmetic['multiplier']
        limit = arithmetic['maximum_operand_without_product_overflow']
        maximum = (1 << 64) - 1
        self.assertEqual(packet.checked_product_sum(factor, limit, 0),
                         ('ok', factor * limit))
        self.assertEqual(packet.checked_product_sum(factor, limit + 1, 0),
                         ('multiply_overflow', None))
        remaining = maximum - factor * limit
        self.assertEqual(packet.checked_product_sum(factor, limit, remaining),
                         ('ok', maximum))
        self.assertEqual(packet.checked_product_sum(factor, limit, remaining + 1),
                         ('add_overflow', None))
        for invalid in (-1, 1 << 64, True):
            with self.assertRaises(ValueError):
                packet.checked_product_sum(factor, invalid, 0)
        with self.changed(0x28c6808, b'\x11'):
            with self.assertRaisesRegex(ValueError, 'boundary window changed'):
                packet.analyze(self.data, check_digest=False)

    def test_variant_controls_include_malformed_tag(self):
        instructions = {v['mode']: v for v in self.result['discriminants']}
        self.assertEqual((instructions['binary']['bytes'], instructions['binary']['width_bytes']),
                         ('833e01', 4))
        self.assertEqual((instructions['text']['bytes'], instructions['text']['width_bytes']),
                         ('803800', 1))
        self.assertEqual(packet.variant_routes(0),
                         {'binary_direct_order': False, 'text_direct_order': False})
        self.assertEqual(packet.variant_routes(1),
                         {'binary_direct_order': True, 'text_direct_order': True})
        # A synthetic malformed tag exposes the different branch comparisons.
        self.assertEqual(packet.variant_routes(2),
                         {'binary_direct_order': False, 'text_direct_order': True})
        for invalid in (-1, 1 << 64, True):
            with self.assertRaises(ValueError):
                packet.variant_routes(invalid)

    def test_missing_or_corrupt_identity_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            out = Path(root) / 'evidence'
            out.mkdir()
            marker = out / 'unchanged'
            marker.write_bytes(b'control')
            with self.changed(0x2519180, b'\x00'):
                with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
                    packet.authenticate(self.data)
                with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
                    packet.produce(out, self.data)
            self.assertEqual(marker.read_bytes(), b'control')
            self.assertEqual({p.name for p in out.iterdir()}, {'unchanged'})
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            packet.authenticate(self.data, '0' * 64)

    def test_selected_function_tampering_rejected_even_without_digest(self):
        original = packet.read_va(self.data, self.secs, 0x2519180, 1)
        with self.changed(0x2519180, bytes([original[0] ^ 1])):
            with self.assertRaisesRegex(ValueError, 'extent hash mismatch'):
                packet.analyze(self.data, check_digest=False)

    def test_boundary_tampering_rejected_even_without_digest(self):
        original = packet.read_va(self.data, self.secs, 0x22aec15, 1)
        with self.changed(0x22aec15, bytes([original[0] ^ 1])):
            with self.assertRaisesRegex(ValueError, 'boundary window changed'):
                packet.analyze(self.data, check_digest=False)

    def test_order_literal_tampering_rejected_even_without_digest(self):
        name = int(self.result['fields'][0]['name_va'], 16)
        with self.changed(name, b'X'):
            with self.assertRaisesRegex(ValueError, 'field name mismatch'):
                packet.analyze(self.data, check_digest=False)

    def test_fde_range_tampering_rejected_even_without_digest(self):
        row = next(row for row in self.result['functions'] if row['start'] == '0x2519180')
        range_va = int(row['fde'], 16) + 12
        original = packet.read_va(self.data, self.secs, range_va, 1)
        with self.changed(range_va, bytes([original[0] ^ 1])):
            with self.assertRaisesRegex(ValueError, 'FDE extent or header mismatch'):
                packet.analyze(self.data, check_digest=False)

    def test_branch_and_call_corruption_controls(self):
        va = 0x251929e
        self.assertEqual(packet.branch(self.data, self.secs, va, 'jne', 0x2519260)[:2],
                         ('jne', 0x2519260))
        with self.changed(va, b'\x74'):
            with self.assertRaisesRegex(ValueError, 'wrong conditional branch'):
                packet.branch(self.data, self.secs, va, 'jne', 0x2519260)
        with self.changed(va + 1, b'\x00'):
            with self.assertRaisesRegex(ValueError, 'wrong conditional branch'):
                packet.branch(self.data, self.secs, va, 'jne', 0x2519260)
        call = 0x28c697d
        with self.changed(call, b'\x90'):
            with self.assertRaisesRegex(ValueError, 'unexpected relative encoding'):
                packet.direct_call(self.data, self.secs, call, 0x2519180)
        with self.changed(call + 1, b'\x00'):
            with self.assertRaisesRegex(ValueError, 'wrong call target'):
                packet.direct_call(self.data, self.secs, call, 0x2519180)

    def test_all_selected_branches_reject_instruction_corruption(self):
        checked = 0
        for label, va, kind, target in packet.BRANCHES:
            with self.subTest(branch=label):
                _, _, raw = packet.branch(self.data, self.secs, va, kind, target)
                with self.changed(va, b'\x90'):
                    with self.assertRaises(ValueError):
                        packet.branch(self.data, self.secs, va, kind, target)
                with self.changed(va + len(raw) - 1, bytes([raw[-1] ^ 1])):
                    with self.assertRaises(ValueError):
                        packet.branch(self.data, self.secs, va, kind, target)
                checked += 2
        self.assertEqual(checked, 2 * len(packet.BRANCHES))

    def test_all_selected_transfers_reject_instruction_corruption(self):
        checked = 0
        for transfers, decoder in ((packet.EDGES, packet.direct_call),
                                   (packet.TAIL_EDGES, packet.direct_jump)):
            for label, va, target in transfers:
                with self.subTest(transfer=label):
                    _, raw = decoder(self.data, self.secs, va, target)
                    with self.changed(va, b'\x90'):
                        with self.assertRaises(ValueError):
                            decoder(self.data, self.secs, va, target)
                    with self.changed(va + 1, bytes([raw[1] ^ 1])):
                        with self.assertRaises(ValueError):
                            decoder(self.data, self.secs, va, target)
                    checked += 2
        self.assertEqual(checked, 2 * (len(packet.EDGES) + len(packet.TAIL_EDGES)))

    def test_mapping_rejects_nobits_crossing_nonexec_and_ambiguity(self):
        base = {'type': 1, 'flags': 6, 'address': 0x1000, 'offset': 0x20, 'size': 16}
        nobits = dict(base, type=8)
        self.assertEqual(packet.file_mapping([base], 0x1003, 3, executable=True)[1], 0x23)
        for secs, va, size, executable in (
            ([nobits], 0x1000, 1, False),
            ([base], 0xfff, 1, False),
            ([base], 0x100f, 2, False),
            ([base], 0x1000, 0, False),
            ([dict(base, flags=2)], 0x1000, 1, True),
            ([base, dict(base)], 0x1000, 1, True),
        ):
            with self.subTest(secs=secs, va=va, size=size):
                with self.assertRaises(ValueError):
                    packet.file_mapping(secs, va, size, executable=executable)
        with self.assertRaisesRegex(ValueError, 'exceeds input'):
            packet.read_va(b'abc', [base], 0x1000, 1)

    def test_output_is_stable_and_has_only_documented_generated_files(self):
        with tempfile.TemporaryDirectory() as root:
            first, second = Path(root) / 'one', Path(root) / 'two'
            packet.produce(first, self.data)
            packet.produce(second, self.data)
            names = {'functions.tsv', 'extents.tsv', 'windows.tsv', 'edges.tsv', 'branches.tsv',
                     'fields.tsv', 'field-layout.tsv', 'text-fields.tsv', 'summary.json'}
            self.assertEqual({p.name for p in first.iterdir()}, names)
            self.assertEqual({p.name for p in second.iterdir()}, names)
            for name in sorted(names):
                with self.subTest(name=name):
                    self.assertEqual((first / name).read_bytes(), (second / name).read_bytes())


if __name__ == '__main__':
    unittest.main()
