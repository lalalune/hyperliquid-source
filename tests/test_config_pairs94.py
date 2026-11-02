"""Offline controls for the node 94 binary pair-map evidence."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools import config_pairs94 as packet


class OverlayView(packet.View):
    """Change selected reads without changing the captured input."""
    def __init__(self, data, section_rows, edits):
        super().__init__(data, section_rows)
        self.edits = edits

    def read(self, va, size):
        raw = bytearray(super().read(va, size))
        for start, replacement in self.edits:
            lo = max(va, start)
            hi = min(va + size, start + len(replacement))
            if lo < hi:
                raw[lo - va:hi - va] = replacement[lo - start:hi - start]
        return bytes(raw)


class PairPathEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = packet.TARGET.read_bytes()
        cls.result = packet.collect(cls.data)
        cls.view = cls.result['view']
        cls.fdes = cls.result['fdes']
        cls.instructions = cls.result['instructions']
        cls.by_site = {r['site']: r for r in cls.instructions}
        cls.by_label = {r[0]: r for r in cls.result['witnesses']}

    def overlay(self, *edits):
        return OverlayView(self.data, self.view.sections, edits)

    def test_target_identity(self):
        self.assertEqual(len(self.data), 91774280)
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), packet.DIGEST)
        packet.verify_identity(self.data)

    def test_short_target_rejected(self):
        with self.assertRaises(packet.EvidenceError):
            packet.verify_identity(self.data[:-1])

    def test_same_size_corrupt_target_rejected(self):
        damaged = bytes([self.data[0] ^ 1]) + self.data[1:]
        with self.assertRaises(packet.EvidenceError):
            packet.verify_identity(damaged)

    def test_actual_fdes_and_bytes_are_not_next_index_windows(self):
        found = {row['role']: row for row in self.fdes}
        self.assertEqual(found['binary_field_map']['end'], 0x13c171a)
        self.assertEqual(found['insert_or_replace']['end'], 0x14cc311)
        self.assertEqual(found['split_insert']['end'], 0x13a456e)
        self.assertEqual(found['drain_map']['end'], 0x14cd9f1)
        self.assertEqual(found['map_value_type_error']['end'], 0x14d4cda)
        self.assertEqual(sum(row['end'] - row['start'] for row in self.fdes), 13121)

    def test_duplicate_fde_is_rejected(self):
        original = packet.eh_frame_records(self.data, self.view.sections)
        duplicate = original[1] + [dict(self.fdes[0])]
        with mock.patch.object(packet, 'eh_frame_records', return_value=(original[0], duplicate)):
            with self.assertRaises(packet.EvidenceError):
                packet.selected_fdes(self.view)

    def test_file_backed_ranges(self):
        row = {'type': 1, 'flags': 2, 'address': 0x1000, 'size': 4, 'offset': 1, 'name': 'data'}
        view = packet.View(b'abcde', [row])
        self.assertEqual(view.read(0x1001, 2), b'cd')
        for address, size in ((0xfff, 1), (0x1003, 2), (0x1000, 0), (-1, 1), (2**64 - 1, 2)):
            with self.subTest(address=address, size=size):
                with self.assertRaises(packet.EvidenceError):
                    view.read(address, size)

    def test_nobits_and_ambiguous_sections_are_rejected(self):
        original = {'type': 1, 'flags': 2, 'address': 0x1000, 'size': 4, 'offset': 0, 'name': 'a'}
        no_data = dict(original, type=8)
        for rows in ([no_data], [original, dict(original, name='b')]):
            with self.subTest(rows=rows):
                with self.assertRaises(packet.EvidenceError):
                    packet.View(b'abcd', rows).read(0x1000, 1)

    def test_truncated_and_unrecognized_instruction_are_rejected(self):
        for data in (b'\x48', b'\xe8\x00\x00', b'\x0f\xff\xc0'):
            with self.subTest(data=data):
                with self.assertRaises(packet.EvidenceError):
                    packet.decode_instruction(data)

    def test_branch_into_an_operand_is_rejected(self):
        fde = next(x for x in self.fdes if x['role'] == 'binary_field_map')
        altered = self.overlay((0x13c0b9b, b'\x01'))
        with self.assertRaises(packet.EvidenceError):
            packet.decode_body(altered, fde)

    def test_selected_witness_corruption_rejected(self):
        altered = self.overlay((0x13c0b99, b'\x03'))
        with self.assertRaises(packet.EvidenceError):
            packet.witnesses(altered, self.instructions)

    def test_relocation_target_corruption_rejected(self):
        rows = list(self.result['relocs'])
        index = next(i for i, row in enumerate(rows) if row[0] == 0x576eb70)
        row = list(rows[index]); row[4] ^= 8; rows[index] = tuple(row)
        with self.assertRaises(packet.EvidenceError):
            packet.validate_relocations(rows)

    def test_relocation_symbol_corruption_rejected(self):
        rows = list(self.result['relocs'])
        index = next(i for i, row in enumerate(rows) if row[0] == 0x576e488)
        row = list(rows[index]); row[5] = 'memcpy'; rows[index] = tuple(row)
        with self.assertRaises(packet.EvidenceError):
            packet.validate_relocations(rows)

    def test_bad_table_target_rejected(self):
        altered = self.overlay((0x215184, b'\0\0\0\0'))
        with self.assertRaises(packet.EvidenceError):
            packet.table_rows(altered, set(self.by_site))

    def test_bad_context_call_rejected(self):
        altered = self.overlay((0x13ad60a, b'\0\0\0\0'))
        with self.assertRaises(packet.EvidenceError):
            packet.context_rows(altered)

    def test_bad_context_table_slot_rejected(self):
        altered = self.overlay((0x20fac0, b'\0\0\0\0'))
        with self.assertRaises(packet.EvidenceError):
            packet.context_rows(altered)

    def test_bad_context_field_literal_rejected(self):
        altered = self.overlay((0x21bb8d, b'x'))
        with self.assertRaises(packet.EvidenceError):
            packet.context_rows(altered)

    def test_bad_prior_field_boundaries_rejected(self):
        for address, raw in ((0x14a8039, b'\x19'), (0x216b00, b'\0\0\0\0')):
            with self.subTest(address=address):
                with self.assertRaises(packet.EvidenceError):
                    packet.context_rows(self.overlay((address, raw)))

    def test_lsda_header_corruption_rejected(self):
        selected, all_fdes = packet.selected_fdes(self.view)
        altered = self.overlay((0x91ed34, b'\0'))
        with self.assertRaises(packet.EvidenceError):
            packet.lsda_rows(altered, selected, all_fdes, self.instructions)

    def test_dispatch_target_stays_in_binary_reader(self):
        reader_starts = {r['site'] for r in self.instructions if r['role'] == 'binary_field_map'}
        rows = self.result['tables']
        self.assertEqual(len(rows), 550)
        self.assertTrue(all(row[-1] in reader_starts for row in rows))
        groups = {name: sum(row[0] == name for row in rows) for name, _, _, _ in packet.TABLES}
        self.assertEqual(groups, {'outer_cached_tag': 225, 'outer_extended': 18,
                                  'outer_raw_marker': 32, 'value_cached_tag': 225,
                                  'value_extended': 18, 'value_raw_marker': 32})

    def test_cached_and_fresh_marker_joins_differ_where_expected(self):
        rows = {row[0]: row for row in self.result['markers']}
        self.assertEqual(rows[0x81], (0x81, 0x80, 1, 0x13c0338, 0x13c0338, 0x13c092d, 0x13c092d))
        self.assertEqual(rows[0x92], (0x92, 0x90, 2, 0x13c100f, 0x13c100f, 0x13c0a5e, 0x13c0a5e))
        self.assertEqual(rows[0xa1], (0xa1, 0xa0, 1, 0x13c01c0, 0x13c01c4, 0x13c048c, 0x13c0490))
        self.assertEqual(rows[0xc0], (0xc0, 0xc0, None, 0x13bffd9, 0x13bffd9, 0x13c042f, 0x13c0431))
        self.assertEqual(rows[0xdf][1:3], (0xdf, None))
        self.assertEqual(rows[0xe0][1:3], (0xe0, 0xe0))
        self.assertEqual(rows[0xff][1:3], (0xe0, 0xff))

    def test_marker_model_rejects_outside_byte_domain(self):
        for value in (-1, 256, True, 1.0):
            with self.subTest(value=value):
                with self.assertRaises(packet.EvidenceError):
                    packet.marker_class(value, self.result['limits'])

    def test_fixed_array_arity_and_failure_order(self):
        model = packet.model_array_pair
        self.assertEqual(model(0, 'value', 'value', 2, 2), 'missing_first')
        self.assertEqual(model(1, 'value', 'value', 2, 2), 'missing_second')
        self.assertEqual(model(2, 'value', 'value', 2, 2), 'pair_with_second_value')
        self.assertEqual(model(2, 'value', 'null', 2, 2), 'pair_with_null_second')
        self.assertEqual(model(3, 'value', 'value', 2, 2), 'extra_item_cleanup')
        self.assertEqual(model(3, 'error', 'value', 2, 2), 'first_reader_error')
        self.assertEqual(model(3, 'value', 'error', 2, 2), 'second_reader_error')
        self.assertEqual(model(3, 'missing', 'value', 2, 2), 'missing_first')
        self.assertEqual(model(3, 'value', 'missing', 2, 2), 'missing_second')
        self.assertEqual(model(2, 'value', 'value', 0, 2), 'depth_zero_failure_call')
        self.assertEqual(model(2, 'value', 'value', 1, 2), 'depth_exhausted')
        self.assertEqual(model(2, 'value', 'null', 0xffff, 2), 'pair_with_null_second')
        self.assertEqual(model(0xffffffff, 'value', 'null', 2, 2), 'extra_item_cleanup')
        for invalid in (-1, 0x100000000, True):
            with self.assertRaises(packet.EvidenceError):
                model(invalid, 'value', 'value', 2, 2)
        for depth in (-1, 0x10000, True):
            with self.assertRaises(packet.EvidenceError):
                model(2, 'value', 'value', depth, 2)
        with self.assertRaises(packet.EvidenceError):
            model(2, 'null', 'value', 2, 2)

    def test_full_node_split_boundaries_and_controls(self):
        model = lambda index: packet.split_model(index, 11, 4, 5, 6, 7)
        self.assertEqual(model(0), (4, 'old', 0, 4, 6, 5, 6))
        self.assertEqual(model(4), (4, 'old', 4, 4, 6, 5, 6))
        self.assertEqual(model(5), (5, 'old', 5, 5, 5, 6, 5))
        self.assertEqual(model(6), (5, 'new', 0, 5, 5, 5, 6))
        self.assertEqual(model(7), (6, 'new', 0, 6, 4, 6, 5))
        self.assertEqual(model(11), (6, 'new', 4, 6, 4, 6, 5))
        for invalid in (-1, 12, True):
            with self.assertRaises(packet.EvidenceError):
                model(invalid)

    def test_fixed_map_value_type_error_and_depth_controls(self):
        model = packet.model_bad_value_map
        for count in (0, 1, 15):
            self.assertEqual(model(count, 2), 'invalid_type_then_map_cleanup')
        self.assertEqual(model(0, 0), 'depth_zero_failure_call')
        self.assertEqual(model(15, 1), 'depth_exhausted')
        for count, depth in ((-1, 2), (0x100000000, 2), (0, 65536), (True, 2)):
            with self.assertRaises(packet.EvidenceError):
                model(count, depth)
        self.assertEqual(self.by_label['map_value_error_call'][-1], 0x14d4c60)
        self.assertEqual(self.by_label['map_value_error_branch'][-1], 0x13c1288)
        self.assertEqual(self.by_label['map_value_error_sentinel'][4], '48b80000000000000080')
        self.assertEqual(packet.relative_target(self.view, 0x14d4cb3, '488d35'), 0x20193e)
        self.assertTrue(packet.reaches(self.result['graph'], 0x13c1288, 0x13c144f))
        self.assertFalse(packet.reaches(self.result['graph'], 0x13c1288, 0x13c0e46))

    def test_value_container_headers_and_truncation(self):
        model = packet.model_value_header
        self.assertEqual(model(0x92, b'extra'), ('array', 2, 0, 'ok'))
        self.assertEqual(model(0x8f, b''), ('map', 15, 0, 'ok'))
        self.assertEqual(model(0xdc, b'\x00\x02\xff'), ('array', 2, 2, 'ok'))
        self.assertEqual(model(0xdd, b'\x00\x01\x00\x00'), ('array', 65536, 4, 'ok'))
        self.assertEqual(model(0xdd, b'\xff\xff\xff\xff'), ('array', 0xffffffff, 4, 'ok'))
        self.assertEqual(model(0xde, b'\x01\x00'), ('map', 256, 2, 'ok'))
        self.assertEqual(model(0xdf, b'\x00\x00\x01\x00'), ('map', 256, 4, 'ok'))
        for marker, kind, width in ((0xdc, 'array', 2), (0xdd, 'array', 4),
                                    (0xde, 'map', 2), (0xdf, 'map', 4)):
            for n in range(width):
                with self.subTest(marker=marker, payload_length=n):
                    self.assertEqual(model(marker, b'\xff' * n), (kind, None, n, 'truncated'))
        for marker, payload in ((0xc0, b''), (-1, b''), (True, b''), (0xdc, 'bad')):
            with self.assertRaises(packet.EvidenceError):
                model(marker, payload)
        for label in ('array16_short_header', 'array32_short_header',
                      'map16_short_header', 'map32_short_header'):
            self.assertEqual(self.by_label[label][-1], 0x13c113b)

    def test_outer_map_header_empty_and_loop_paths(self):
        targets = {(name, index): dest for name, index, _, _, _, dest in self.result['tables']}
        self.assertEqual(targets['outer_raw_marker', 0xde], 0x13c0138)
        self.assertEqual(targets['outer_raw_marker', 0xdf], 0x13c00e0)
        for name in ('outer_map16_short_header', 'outer_map32_short_header'):
            self.assertEqual(self.by_label[name][-1], 0x13c0219)
        self.assertEqual(self.by_label['outer_remaining_count_finish'][-1], 0x13c0fc3)
        self.assertTrue(packet.reaches(self.result['graph'], 0x13c0f02, 0x13c14e6))
        self.assertFalse(packet.reaches(self.result['graph'], 0x13c0f02, 0x13c03c0))
        self.assertTrue(packet.reaches(self.result['graph'], 0x13c03aa, 0x13c0fc3))

    def test_key_order_prefix_equality_and_unsigned_bytes(self):
        model = packet.model_key_order
        self.assertEqual(model(b'', b''), 0)
        self.assertEqual(model(b'', b'\0'), -1)
        self.assertEqual(model(b'ab', b'a'), 1)
        self.assertEqual(model(b'a', b'ab'), -1)
        self.assertEqual(model(b'\xff', b'\x7f'), 1)
        self.assertEqual(model(b'a\0', b'a\xff'), -1)
        self.assertEqual(model(b'same', b'same'), 0)
        with self.assertRaises(packet.EvidenceError):
            model('string', b'string')

    def test_local_graph_replacement_bypasses_length_increment(self):
        graph = self.result['graph']
        self.assertTrue(packet.reaches(graph, 0x14cc08b, 0x14cc104))
        self.assertFalse(packet.reaches(graph, 0x14cc08b, 0x14cc27f))
        self.assertTrue(packet.reaches(graph, 0x14cc0b6, 0x14cc27f))
        with self.assertRaises(packet.EvidenceError):
            packet.reaches(graph, 0x14cc08c, 0x14cc27f)

    def test_cfg_rejects_corrupt_indirect_dispatch_target(self):
        rows = list(self.result['tables'])
        row = list(rows[0]); row[-1] = 0x13bffa2; rows[0] = tuple(row)
        with self.assertRaises(packet.EvidenceError):
            packet.build_graph(self.fdes, self.instructions, rows)

    def test_selected_call_graph_preserves_external_boundaries(self):
        calls = {r['site']: r['target'] for r in self.instructions if r['kind'] == 'call'}
        self.assertEqual(calls[0x13c0ae8], 0x13aa5f0)
        self.assertEqual(calls[0x13c0e46], 0x14cbfa0)
        self.assertEqual(calls[0x14cc1b6], 0x13a3440)
        self.assertEqual(calls[0x14daad5], 0x14cd630)
        self.assertEqual(calls[0x13aa69d], 0x13bdcd0)
        self.assertNotIn(0x13bdcd0, {f['start'] for f in self.fdes})

    def test_optional_null_is_distinct_from_special_missing_slot(self):
        self.assertEqual(self.by_label['optional_null_branch'][-1], 0x13aa67f)
        self.assertEqual(bytes.fromhex(self.by_label['optional_none_value'][4])[-8:],
                         bytes.fromhex('0000000000000080'))
        self.assertEqual(self.by_label['special_slot_branch'][-1], 0x13c12f3)
        self.assertEqual(self.by_label['second_value_call'][-1], 0x13aa5f0)

    def test_success_and_corruption_controls_follow_local_branch_targets(self):
        expected = {'value_length_zero_branch': 0x13c129d,
                    'value_length_one_branch': 0x13c12f3,
                    'value_length_other_branch': 0x13c0bf8,
                    'first_value_error': 0x13c12ba,
                    'second_value_error': 0x13c132f,
                    'map_insert_call': 0x14cbfa0,
                    'map_error_drop': 0x14daa70,
                    'insert_match_branch': 0x14cc08b,
                    'insert_capacity_failure': 0x14cc2bb,
                    'insert_allocate_fail': 0x14cc2a6,
                    'split_leaf_alloc_fail': 0x13a439b,
                    'split_internal_fail': 0x13a434f}
        for label, target in expected.items():
            with self.subTest(label=label):
                self.assertEqual(self.by_label[label][-1], target)

    def test_old_value_and_new_value_stores_are_distinct(self):
        for label, raw in (('insert_old_value_copy2', '0f115720'),
                           ('insert_new_value_store0', '0f110403'),
                           ('insert_collection_increment', '49ff442410')):
            self.assertEqual(self.by_label[label][4], raw)
        self.assertEqual(self.by_label['insert_replace_return'][2], 0x14cc104)
        self.assertGreater(self.by_label['insert_collection_increment'][2], 0x14cc104)
        self.assertEqual(self.by_label['replaced_first_empty_branch'][-1], 0x13c0e75)
        self.assertEqual(self.by_label['replaced_second_none_branch'][-1], 0x13c03aa)
        self.assertEqual(self.by_label['replaced_second_zero_branch'][-1], 0x13c03aa)
        self.assertEqual(self.by_label['replaced_first_release'][-1], 0x576e010)
        self.assertEqual(self.by_label['replaced_second_release'][-1], 0x576e010)
        self.assertEqual(self.by_label['discard_second_release'][-1], 0x576e010)

    def test_lsda_call_sites_are_contained(self):
        fdes = {f['role']: f for f in self.fdes}
        self.assertEqual(len(self.result['lsda']), 50)
        for role, _, _, _, start, end, landing, _, _ in self.result['lsda']:
            with self.subTest(role=role, start=start):
                self.assertLessEqual(fdes[role]['start'], start)
                self.assertLessEqual(end, fdes[role]['end'])
                if landing is not None:
                    self.assertIn(landing, self.by_site)

    def test_selected_unwind_landing_routes_and_corruption(self):
        routes = {row[0]: row for row in self.result['unwinds']}
        self.assertEqual(routes['second_value_reader'][4], 0x13c1655)
        self.assertEqual(routes['insert_call'][4], 0x13c16fc)
        self.assertEqual(routes['split_leaf_alloc_failure_handler'][4], 0x13a447c)
        self.assertIn(0x13c1707, routes['second_value_reader'][6])
        self.assertEqual(routes['second_value_reader'][-1], 0x13c170f)
        rows = list(self.result['lsda'])
        index = next(i for i, row in enumerate(rows) if 0x13c0ae8 in row[-1])
        for field, replacement in ((6, 0x13c16fc), (7, 1)):
            corrupt = list(rows)
            row = list(corrupt[index]); row[field] = replacement; corrupt[index] = tuple(row)
            with self.subTest(field=field):
                with self.assertRaises(packet.EvidenceError):
                    packet.unwind_routes(corrupt, self.result['graph'], self.by_site)

    def test_regeneration_is_exact_and_repeatable(self):
        with tempfile.TemporaryDirectory() as d:
            left, right = Path(d) / 'left', Path(d) / 'right'
            packet.emit(self.data, left)
            packet.emit(self.data, right)
            old = packet.ROOT / 'research/work-items/RE-015-etherscan-pairs-94'
            names = sorted(p.name for p in left.iterdir())
            self.assertEqual(names, sorted(p.name for p in right.iterdir()))
            self.assertEqual(len(names), 18)
            for name in names:
                with self.subTest(name=name):
                    self.assertEqual((left / name).read_bytes(), (right / name).read_bytes())
                    self.assertEqual((left / name).read_bytes(), (old / name).read_bytes())


if __name__ == '__main__':
    unittest.main()
