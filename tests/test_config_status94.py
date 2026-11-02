"""Static target-backed checks for the node 94 configured status-file path."""
import copy
import hashlib
import struct
import unittest

from tools import config_status94 as subject


class StatusConfig94Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.CAPTURE.read_bytes()
        cls.observed = subject.collect(cls.data)
        cls.instructions, cls.branches, cls.transfers, cls.relocs, cls.queries = subject.make_tables(cls.observed)

    def mutated_view(self, address, byte):
        original = self.observed['view']
        payload = bytearray(self.data)
        payload[original.offset(address, 1)] = byte
        return subject.View(payload, original.sections)

    def test_authenticated_identity_and_corruption(self):
        subject.verify_identity(self.data)
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), subject.DIGEST)
        bad = bytearray(self.data)
        bad[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            subject.verify_identity(bad)
        with self.assertRaises(ValueError):
            subject.verify_identity(self.data[:-1])

    def test_fdes_have_file_backed_ranges_and_independent_body_digests(self):
        funcs = self.observed['functions']
        self.assertEqual(len(funcs), len(subject.FUNCTIONS))
        starts = set()
        for f in funcs:
            start, end = int(f['start_va'], 16), int(f['end_va'], 16)
            self.assertNotIn(start, starts)
            starts.add(start)
            body = self.observed['view'].read(start, end - start)
            self.assertEqual(hashlib.sha256(body).hexdigest(), f['body_sha256'])
            self.assertEqual(len(body), f['size'])
            self.assertTrue(f['fde_va'].startswith('0x'))
        self.assertEqual(starts, {entry for _, entry in subject.FUNCTIONS})

    def test_existing_parent_passes_exact_new_entry_and_fixed_name(self):
        path = self.observed['path']
        self.assertEqual(path['parent_call_target'], '0x25ae060')
        self.assertEqual(path['name_descriptor_ref_site'], '0x220c10b')
        self.assertEqual(path['name_descriptor'], '0x569dc78')
        self.assertEqual(path['location_descriptor'], '0x569dc88')
        self.assertEqual((path['location_source_tail'], path['location_line'], path['location_column']),
                         ('l1/src/abci/engine.rs', 259, 41))
        self.assertEqual(path['root_field_offset'], '0x18')
        self.assertEqual(path['root_once_offset'], '0x50')
        self.assertEqual(path['name'], 'visor_abci_state')
        self.assertEqual(path['name_length'], len(path['name']))
        self.assertEqual(path['root_cell'], '0x577b288')
        self.assertEqual(path['prior_initializer_va'], '0x164ff00')
        self.assertEqual(path['boundary_call_target'], '0x28eb6a0')
        self.assertEqual(path['template_hex'], 'c0122f68797065726c69717569645f646174612fc0012ec000')

    def test_all_six_named_fields_and_offsets_match_both_writers(self):
        fields = self.observed['fields']
        self.assertEqual([(f['name'], f['input_offset']) for f in fields], [
            ('initial_height', '0x20'), ('height', '0x28'), ('scheduled_freeze_height', '0x0'),
            ('consensus_time', '0x30'), ('wall_clock_time', '0x3c'), ('reference_lag', '0x10')])
        for row in fields:
            self.assertEqual(row['length'], len(row['name'].encode('ascii')))
            self.assertEqual(int(row['name_file_offset'], 16),
                             self.observed['view'].offset(int(row['name_va'], 16), row['length']))
            for key in ('json_call_site', 'binary_call_site'):
                call = self.observed['instructions'][int(row[key], 16)]
                self.assertEqual(call['kind'], 'call')

    def test_each_field_failure_reaches_a_return_before_success_completion(self):
        fields = self.observed['fields']
        jgraph = self.observed['decoded']['status_json_writer']
        bgraph = self.observed['decoded']['status_binary_writer']
        for row in fields:
            self.assertEqual(row['json_error_target'], '0x276cf22')
            self.assertFalse(subject.reachable(jgraph, int(row['json_error_target'], 16), 0x276cf01))
        for error in (0x276d0ce, 0x276d1f4, 0x276d212):
            self.assertFalse(subject.reachable(bgraph, error, 0x276d1de))
        self.assertEqual(fields[2]['binary_fallthrough'], '0x276d0ce')
        self.assertEqual(fields[2]['binary_taken_target'], '0x276d11c')

    def test_height_discriminant_is_format_specific_for_noncanonical_words(self):
        for tag, j, binary in [(0, 'null', 'nil'), (1, 'value', 'value'), (2, 'null', 'nil'),
                               (3, 'value', 'nil'), (0x101, 'value', 'nil'),
                               (0x100000001, 'value', 'value')]:
            self.assertEqual(subject.json_optional_height(tag), j)
            self.assertEqual(subject.binary_optional_height(tag), binary)
        for wrong in (-1, 1 << 64, 1.0):
            with self.assertRaises(ValueError):
                subject.json_optional_height(wrong)
            with self.assertRaises(ValueError):
                subject.binary_optional_height(wrong)

    def test_float_presence_and_nonfinite_boundaries(self):
        for tag in range(256):
            self.assertEqual(subject.binary_optional_float(tag), 'delegate-value' if tag & 1 else 'nil')
        for bits in (0, 1 << 63, 1, 0x7fefffffffffffff, 0xffefffffffffffff):
            self.assertEqual(subject.json_optional_float(0, bits), 'null')
            self.assertEqual(subject.json_optional_float(1, bits), 'delegate-finite')
        for bits in (0x7ff0000000000000, 0xfff0000000000000,
                     0x7ff0000000000001, 0xfff8000000000000):
            self.assertEqual(subject.json_optional_float(1, bits), 'null')
        self.assertEqual(subject.json_optional_float(2, 0), 'delegate-finite')
        self.assertEqual(subject.binary_optional_float(2), 'nil')
        for tag, bits in ((-1, 0), (256, 0), (1, -1), (1, 1 << 64)):
            with self.assertRaises(ValueError):
                subject.json_optional_float(tag, bits)

    def test_call_edges_reach_the_selected_writers_and_helpers(self):
        edges = {(row['function'], row['resolved_va'], row['selected_target_function']) for row in self.transfers}
        self.assertIn(('status_file_route', '0x276cd60', 'status_json_writer'), edges)
        self.assertIn(('status_file_route', '0x276cfa0', 'status_binary_writer'), edges)
        self.assertIn(('status_json_writer', '0x296c640', 'json_optional_float'), edges)
        self.assertIn(('status_binary_writer', '0x27b25e0', 'binary_optional_float'), edges)

    def test_file_route_error_arms_skip_the_file_steps_in_cfg(self):
        graph = self.observed['decoded']['status_file_route']
        self.assertTrue(subject.reachable(graph, 0x28eb6a0, 0x28eb7fa))
        self.assertFalse(subject.reachable(graph, 0x28eb846, 0x28eb7fa))
        self.assertFalse(subject.reachable(graph, 0x28eb887, 0x28eb7fa))
        self.assertFalse(subject.reachable(graph, 0x28eb81a, 0x28eb814))
        self.assertFalse(subject.reachable(graph, 0x28eb835, 0x28eb7c8))
        with self.assertRaises(ValueError):
            subject.reachable(graph, 0x28eb6a2, 0x28eb7fa)

    def test_branch_corruption_that_targets_inside_instruction_is_rejected(self):
        f = next(x for x in self.observed['functions'] if x['role'] == 'status_file_route')
        start, end = int(f['start_va'], 16), int(f['end_va'], 16)
        body = bytearray(self.observed['view'].read(start, end - start))
        subject.decode_body(body, start)
        branch_disp = 0x28eb6c8 - start + 1
        body[branch_disp] = 1
        with self.assertRaisesRegex(ValueError, 'branch into an instruction'):
            subject.decode_body(body, start)
        body[branch_disp] = 0x80
        with self.assertRaisesRegex(ValueError, 'outside selected extent'):
            subject.decode_body(body, start)
        body[0] = 0x62
        with self.assertRaises(ValueError):
            subject.decode_body(body, start)
        with self.assertRaises(ValueError):
            subject.decode_one(b'\x0f', 0, start)

    def test_corrupted_contract_and_field_operand_fail(self):
        item = next(c for c in subject.CONTRACTS if c[0] == 'json_float_tag')
        subject.check_bytes(self.observed['view'], *item)
        bad = self.mutated_view(item[1], self.observed['view'].read(item[1], 1)[0] ^ 1)
        with self.assertRaisesRegex(ValueError, 'changed instruction'):
            subject.check_bytes(bad, *item)
        field = next(c for c in subject.FIELD_OPERANDS if c[0] == 'json_lag_offset')
        bad_field = self.mutated_view(field[1] + 3, 0x11)
        with self.assertRaises(ValueError):
            subject.check_bytes(bad_field, *field)

    def test_relocation_type_addend_and_missing_slot_controls(self):
        original = self.observed['relocations']
        self.assertEqual(subject.relative_target(original, 0x576e928), 0x577b288)
        self.assertEqual(subject.relative_target(original, 0x577b288), 0x164ff00)
        broken = copy.deepcopy(original)
        broken[0x576e928]['type'] = 7
        with self.assertRaises(ValueError):
            subject.relative_target(broken, 0x576e928)
        broken = copy.deepcopy(original)
        broken[0x576e928]['symbol'] = 1
        with self.assertRaises(ValueError):
            subject.relative_target(broken, 0x576e928)
        with self.assertRaises(ValueError):
            subject.read_relocations(self.observed['view'], {0xffffffffffffffff})

    def test_field_text_corruption_is_rejected_by_extraction(self):
        view = self.observed['view']
        data = bytearray(self.data)
        pos = view.offset(0x3f023b, 1)
        data[pos] ^= 1
        with self.assertRaisesRegex(ValueError, 'field label'):
            subject.collect(data, check_digest=False)

    def test_duplicate_selected_relocation_is_rejected_from_real_elf(self):
        view = self.observed['view']
        rela = view.section('.rela.dyn')
        data = bytearray(self.data)
        self.assertNotEqual(struct.unpack_from('<Q', data, rela['offset'])[0], 0x576e928)
        struct.pack_into('<Q', data, rela['offset'], 0x576e928)
        altered = subject.View(data, view.sections)
        with self.assertRaisesRegex(ValueError, 'duplicate selected relocation'):
            subject.read_relocations(altered, {0x576e928})

    def test_no_nobits_or_out_of_range_mapping(self):
        view = self.observed['view']
        bss = next(s for s in view.sections if s['name'] == '.bss')
        self.assertEqual(bss['type'], 8)
        for va, size in ((bss['address'], 1), (0xffffffffffffffff, 2), (-1, 1), (0, 0)):
            with self.assertRaises(ValueError):
                view.offset(va, size)

    def test_template_corruption_and_truncation(self):
        view = self.observed['view']
        raw, tokens = subject.read_template(view, 0x1f2309)
        self.assertEqual(len([t for t in tokens if t['kind'] == 'argument']), 3)
        self.assertEqual(bytes(raw), bytes.fromhex(self.observed['path']['template_hex']))
        bad = self.mutated_view(0x1f2309, 0x80)
        with self.assertRaises(ValueError):
            subject.read_template(bad, 0x1f2309)
        sec = view.section('.rodata')
        end = sec['address'] + sec['size']
        with self.assertRaises(ValueError):
            subject.read_template(view, end)

    def test_lsda_header_corruption_fails_closed(self):
        f = next(x for x in self.observed['functions'] if x['lsda_va'])
        start, end, va = (int(f[key], 16) for key in ('start_va', 'end_va', 'lsda_va'))
        header, entries = subject.parse_lsda(self.observed['view'], start, end, va)
        self.assertEqual(header['entries'], len(entries))
        self.assertTrue(entries)
        bad = self.mutated_view(va, 0)
        with self.assertRaises(ValueError):
            subject.parse_lsda(bad, start, end, va)

    def test_raw_tag_constants_are_pinned_to_instruction_immediates(self):
        view = self.observed['view']
        self.assertEqual(view.read(0x295c6bc, 1), b'\x01')
        self.assertEqual(view.read(0x276d116, 1), b'\xc0')
        self.assertEqual(view.read(0x295c714, 4), b'null')
        self.assertEqual(struct.unpack('<Q', view.read(0x296c6b1, 8))[0], 0x7ff0000000000000)
        self.assertEqual(view.read(0x220c107, 4), b'\0' * 4)


if __name__ == '__main__':
    unittest.main()
