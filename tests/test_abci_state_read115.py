"""Static corruption controls for the node-115 state read evidence."""

import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from tools import abci_state_read115 as m


class StateReadEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = bytearray(m.TARGET.read_bytes())
        m.authenticate(cls.data)
        cls.rows = m.sections(cls.data)
        _, fdes = m.eh_frame_records(cls.data, cls.rows)
        cls.fdes = {row['start']: row for row in fdes}

    def mutate_check(self, va, check, *, executable=False):
        off, _ = m.file_mapping(self.data, self.rows, va, 1, executable)
        original = self.data[off]
        self.data[off] ^= 1
        try:
            with self.assertRaises(ValueError):
                check()
        finally:
            self.data[off] = original

    def test_artifact_identity(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), m.TARGET_SHA256)
        with self.assertRaises(ValueError):
            m.authenticate(b'not the captured ELF')
        with self.assertRaises(ValueError):
            m.authenticate(self.data, '0' * 64)

    def test_wrong_digest_creates_no_output(self):
        with tempfile.TemporaryDirectory() as parent:
            out = Path(parent) / 'result'
            with self.assertRaises(ValueError):
                m.generate(b'corrupt', out)
            self.assertFalse(out.exists())

    def test_file_ranges_and_nobits(self):
        sec = {'name': '.bss', 'type': 8, 'flags': 6, 'address': 0x1000,
               'offset': 0, 'size': 32}
        with self.assertRaises(ValueError):
            m.read_va(bytes(32), [sec], 0x1000, 1)
        sec = dict(sec, name='.text', type=1)
        self.assertEqual(m.read_va(bytes(32), [sec], 0x1000, 32, True), bytes(32))
        for addr, size in ((0x0fff, 1), (0x1020, 1), (0x101f, 2), (0x1000, 0)):
            with self.subTest(addr=addr, size=size), self.assertRaises(ValueError):
                m.read_va(bytes(32), [sec], addr, size)
        with self.assertRaises(ValueError):
            m.read_va(bytes(32), [sec, dict(sec)], 0x1000, 1)
        with self.assertRaises(ValueError):
            m.read_va(bytes(32), [dict(sec, flags=2)], 0x1000, 1, True)

    def test_selected_fde_reconciliation(self):
        rows, _ = m.selected_fdes(self.data, self.rows)
        self.assertEqual(len(rows), 25)
        self.assertEqual(next(r for r in rows if r['role'] == 'json_outer_state')['length'], 2242)
        self.assertEqual(next(r for r in rows if r['role'] == 'binary_outer_state')['length'], 5239)
        self.assertNotIn('0x422e410', [r['start_va'] for r in rows])

    def test_changed_fde_extent_is_rejected(self):
        rec = self.fdes[0x564a680]
        off, _ = m.file_mapping(self.data, self.rows, rec['fde'], 16)
        original = self.data[off + 12]
        self.data[off + 12] ^= 1
        try:
            with self.assertRaises(ValueError):
                m.selected_fdes(self.data, self.rows)
        finally:
            self.data[off + 12] = original

    def test_every_selected_instruction_window(self):
        rows = m.pinned_windows(self.data, self.rows)
        self.assertEqual(len(rows), 96)
        self.assertEqual(sum(r['ownership'] == 'context' for r in rows), 4)
        for name, va, _, _ in m.WINDOWS:
            with self.subTest(window=name):
                self.mutate_check(va, lambda: m.pinned_windows(self.data, self.rows), executable=True)

    def test_selected_transfers(self):
        edges = {row['role']: row for row in m.selected_edges(self.data, self.rows)}
        self.assertEqual(len(edges), 119)
        self.assertEqual(edges['wrapper_read']['target_va'], '0x422e410')
        self.assertEqual(edges['json_root']['target_va'], '0x404c260')
        self.assertEqual(edges['binary_decode']['target_va'], '0x3266520')
        self.assertEqual(edges['nested_json_map']['target_va'], '0x3efb050')
        self.assertEqual(edges['nested_json_sequence_child']['target_va'], '0x4112920')
        self.assertEqual(edges['rmp_child_map']['target_va'], '0x32caf70')
        self.assertEqual(edges['exchange_locus_decode']['target_va'], '0x4112920')
        self.assertEqual(edges['locus_ctx_decode']['target_va'], '0x409c990')
        self.assertEqual(edges['context_height_number']['target_va'], '0x3ef2dc0')

    def test_every_transfer_opcode_and_displacement(self):
        for name, va, prefix, _ in m.EDGES:
            with self.subTest(edge=name, part='opcode'):
                self.mutate_check(va, lambda: m.selected_edges(self.data, self.rows), executable=True)
            with self.subTest(edge=name, part='displacement'):
                self.mutate_check(va + len(bytes.fromhex(prefix)),
                                  lambda: m.selected_edges(self.data, self.rows), executable=True)

    def test_transfer_decoder_refuses_unknown_form(self):
        for prefix in ('90', 'ff15', '0f01', ''):
            with self.subTest(prefix=prefix), self.assertRaises(ValueError):
                m.transfer(self.data, self.rows, 0x564a68c, prefix)
        with self.assertRaises(ValueError):
            m.transfer(self.data, self.rows, 0x564a68c, '75')

    def test_rip_relative_references_and_corruption(self):
        refs = {row['role']: row for row in m.selected_references(self.data, self.rows)}
        self.assertEqual(len(refs), 38)
        self.assertEqual(refs['wrapper_location']['target_va'], '0x64767d8')
        self.assertEqual(refs['binary_dispatch']['target_va'], '0x70087c')
        for name, va, _, _ in m.RIP_REFS:
            for offset in (0, 3):
                with self.subTest(reference=name, offset=offset):
                    self.mutate_check(va + offset,
                                      lambda: m.selected_references(self.data, self.rows), executable=True)

    def test_relative_dispatch_counts_and_examples(self):
        rows = m.selected_tables(self.data, self.rows)
        self.assertEqual(len(rows), 498)
        counts = {name: sum(row['table'] == name for row in rows)
                  for name, _, _, _ in m.TABLES}
        self.assertEqual(counts, {'rmp_primary': 225, 'rmp_primary_sub': 18,
                                  'rmp_inner': 225, 'rmp_inner_sub': 18,
                                  'rmp_error_cleanup': 7})
        table = {(row['table'], row['index']): row['target_va'] for row in rows}
        self.assertEqual(table['rmp_primary', 0x80], '0x3266671')
        self.assertEqual(table['rmp_primary', 0x90], '0x3266e36')
        self.assertEqual(table['rmp_primary', 0xc1], '0x3266f99')
        self.assertEqual([table['rmp_error_cleanup', i] for i in range(7)],
                         ['0x422eb16', '0x422eb16', '0x422eb42', '0x422eb42',
                          '0x422eb42', '0x422eb27', '0x422eb27'])
        self.assertEqual(table['exchange_name_length', 3], '0x3bdaaa3')
        self.assertEqual(table['exchange_field_index', 0], '0x3efb3dc')
        self.assertEqual(table['locus_field_index', 0], '0x4112b8f')
        self.assertEqual(table['context_name_length', 3], '0x41fc5af')
        self.assertEqual(table['context_field_index', 2], '0x409d03a')

    def test_dispatch_table_corruption_at_edges_and_interior(self):
        for name, base, count, _ in m.TABLES:
            for idx in sorted({0, count // 2, count - 1}):
                with self.subTest(table=name, index=idx):
                    self.mutate_check(base + 4 * idx,
                                      lambda: m.selected_tables(self.data, self.rows))
        for name, base, index, _ in m.NESTED_TABLE_ENTRIES:
            with self.subTest(table=name, index=index):
                self.mutate_check(base + 4 * index,
                                  lambda: m.selected_tables(self.data, self.rows))

    def test_location_and_literal_identity(self):
        constants = m.selected_constants(self.data, self.rows)
        self.assertEqual(constants['location']['path'], 'l1/src/abci/state.rs')
        self.assertEqual((constants['location']['line'], constants['location']['column']), (102, 40))
        self.assertEqual(constants['diagnostic_location']['path'], 'node/src/hl_node.rs')
        self.assertEqual((constants['diagnostic_location']['line'],
                          constants['diagnostic_location']['column']), (346, 66))
        self.assertEqual(constants['whitespace_mask'], '0x100002600')
        self.assertEqual(constants['whitespace_bytes'], [9, 10, 13, 32])
        self.assertEqual({r['role']: r['ascii'] for r in constants['literals']}['exchange'], 'exchange')
        self.assertEqual([r['ascii'] for r in constants['literals']
                          if r['role'] in ('locus', 'ctx', 'height')], ['locus', 'ctx', 'height'])
        self.assertEqual((constants['decimal_threshold']['quotient'],
                          constants['decimal_threshold']['remainder']), divmod((1 << 64) - 1, 10))
        self.assertEqual(constants['copy_import']['name'], 'memcpy')
        self.assertEqual(constants['copy_import']['relocation_type'], 6)

    def test_changed_actual_locations_and_literals(self):
        for va in (0x64767d8 + 16, 0x443168, 0x64ab040 + 16, 0x436a23, 0x92a732, 0x458fc8, 0x7c95c0, 0x4325c4,
                   0x7c4360, 0x7c374d, 0x7c1db3, 0x3ef24b2 + 2, 0x3ef251f + 3,
                   0x43351b, 0x44a800, 0x43aa8a, 0x43dbe4, 0x438862, 0x434555,
                   0x404c3d5 + 2, 0x3266acb + 2, 0x3ef1922 + 2, 0x404c2c7 + 2):
            with self.subTest(va=hex(va)):
                self.mutate_check(va, lambda: m.selected_constants(self.data, self.rows))

    def test_relocation_requires_unique_relative_record(self):
        slot = 0x1000
        good = struct.pack('<QQq', slot, 8, 0x2000)
        sec = {'name': '.rela.dyn', 'type': 4, 'offset': 0, 'size': 24}
        self.assertEqual(m.one_relocation(good, [sec], slot), 0x2000)
        with self.assertRaises(ValueError):
            m.one_relocation(good, [sec], slot + 8)
        with self.assertRaises(ValueError):
            m.one_relocation(good + good, [dict(sec, size=48)], slot)
        with self.assertRaises(ValueError):
            m.one_relocation(struct.pack('<QQq', slot, 7, 0x2000), [sec], slot)
        with self.assertRaises(ValueError):
            m.one_relocation(good + b'x', [dict(sec, size=25)], slot)
        with self.assertRaises(ValueError):
            m.one_relocation(good, [sec, dict(sec)], slot)

    def test_dynamic_copy_import_corruption(self):
        record = m.external_copy_symbol(self.data, self.rows)
        self.assertEqual(record['role'], 'context_external_dependency')
        for va in (int(record['relocation_va'], 16) + 8,
                   int(record['symbol_va'], 16), int(record['name_va'], 16)):
            with self.subTest(va=hex(va)):
                self.mutate_check(va, lambda: m.external_copy_symbol(self.data, self.rows))

    def test_pair_normalization_is_bounded(self):
        pair = m.normalize_pair(self.data, self.rows)
        self.assertEqual(pair['length'], 167)
        self.assertEqual(pair['masked_bytes'], 16)
        self.assertEqual(pair['raw_difference_count'], 16)
        self.assertEqual(pair['normalized_sha256'],
                         '7b6923088ad76e1db08593a18635765e59a08af0779086ca5f56e47e02978caa')
        self.assertEqual([x['offset'] for x in pair['masks']], ['0x2b', '0x4f', '0x7b', '0xa3'])

    def test_masked_displacements_and_unmasked_bytes_are_attacked(self):
        for va in (0x3f22186, 0x3007996):
            for offset in (0x00, 0x2b, 0x4f, 0x7b, 0xa3):
                with self.subTest(va=hex(va), offset=hex(offset)):
                    self.mutate_check(va + offset,
                                      lambda: m.normalize_pair(self.data, self.rows), executable=True)

    def test_lsda_known_landing(self):
        rows = m.lsda_table(self.data, self.rows, self.fdes[0x564a680])
        covered = [r for r in rows if int(r['start_va'], 16) <= 0x564a6c2
                   < int(r['end_va_exclusive'], 16)]
        self.assertEqual(len(covered), 1)
        self.assertEqual(covered[0]['landing_va'], '0x564a6ca')
        self.assertEqual(m.lsda_table(self.data, self.rows, self.fdes[0x5c56920]), [])

    def test_lsda_bad_header_rejected(self):
        rec = self.fdes[0x564a680]
        self.mutate_check(rec['lsda'], lambda: m.lsda_table(self.data, self.rows, rec))

    def test_lsda_synthetic_bounds_and_witness_changes(self):
        payload = bytes([0xff, 0xff, 0x01, 0x04, 0, 1, 1, 0])
        sec = {'name': '.gcc_except_table', 'type': 1, 'flags': 2,
               'address': 0x100, 'offset': 0, 'size': len(payload)}
        fde = {'start': 0x200, 'end': 0x210, 'lsda': 0x100}
        record = m.lsda_table(payload, [sec], fde)
        self.assertEqual(record[0]['landing_va'], '0x201')
        invalid = bytearray(payload)
        invalid[-1] = 0x80
        with self.assertRaises(ValueError):
            m.lsda_table(invalid, [sec], fde)
        invalid = bytearray(payload)
        invalid[3] = 30
        with self.assertRaises(ValueError):
            m.lsda_table(invalid, [sec], fde)
        invalid = bytearray(payload)
        invalid[6] = 0x20
        with self.assertRaises(ValueError):
            m.lsda_table(invalid, [sec], fde)
        record[0]['role'] = 'synthetic'
        witness = m.selected_unwind_witnesses(record, [('good', 0x200, 0x201, 0)])
        self.assertEqual(witness[0]['witness'], 'good')
        with self.assertRaises(ValueError):
            m.selected_unwind_witnesses(record, [('bad', 0x200, 0x202, 0)])
        with self.assertRaises(ValueError):
            m.selected_unwind_witnesses(record, [('missing', 0x205, None, 0)])
        with self.assertRaises(ValueError):
            m.selected_unwind_witnesses(record + record, [('duplicate', 0x200, 0x201, 0)])

    def test_suffix_byte_classifier_all_256_values(self):
        mask = int(m.selected_constants(self.data, self.rows)['whitespace_mask'], 16)
        accepted = [n for n in range(256) if m.suffix_step(bytes([n]), 0, mask)[0] == 'accept']
        self.assertEqual(accepted, [0x09, 0x0a, 0x0d, 0x20])
        self.assertEqual(m.suffix_step(b'\t \nX ', 0, mask), ('reject', 3))
        self.assertEqual(m.suffix_step(b'!\r', 1, mask), ('accept', 2))
        self.assertEqual(m.suffix_step(b'', 0, mask), ('accept', 0))
        for cursor in (-1, 3):
            with self.subTest(cursor=cursor), self.assertRaises(ValueError):
                m.suffix_step(b'ab', cursor, mask)

    def test_depth_branch_boundaries(self):
        self.assertEqual(m.depth_step(False, 0), ('guard', 0))
        self.assertEqual(m.depth_step(False, 1), ('error', 0))
        self.assertEqual(m.depth_step(False, 2), ('enter', 1))
        self.assertEqual(m.depth_step(False, 128), ('enter', 127))
        self.assertEqual(m.depth_step(True, 0), ('bypass', 0))
        for value in (-1, 256):
            with self.subTest(value=value), self.assertRaises(ValueError):
                m.depth_step(False, value)
        with self.assertRaises(ValueError):
            m.depth_step(2, 1)

    def test_key_and_sequence_decisions(self):
        field = b'exchange'
        self.assertEqual(m.map_key_choice(False, field, field), 'decode-child')
        self.assertEqual(m.map_key_choice(True, field, field), 'duplicate')
        for index in range(len(field)):
            wrong = bytearray(field)
            wrong[index] ^= 1
            self.assertEqual(m.map_key_choice(False, bytes(wrong), field), 'other-key-helper')
        self.assertEqual(m.map_key_choice(False, b'exchanges', field), 'other-key-helper')
        self.assertEqual(m.binary_sequence_choice(0, True), 'invalid-length-helper')
        self.assertEqual(m.binary_sequence_choice(1, False), 'child-error')
        self.assertEqual(m.binary_sequence_choice(1, True), 'single-child')
        self.assertEqual(m.binary_sequence_choice(2, True), 'length-error-and-cleanup')
        self.assertEqual(m.binary_sequence_choice(0xffffffff, True), 'length-error-and-cleanup')
        for count in (-1, 0x100000000):
            with self.subTest(count=count), self.assertRaises(ValueError):
                m.binary_sequence_choice(count, True)
        with self.assertRaises(ValueError):
            m.map_key_choice(False, 'exchange', field)

    def test_nested_field_controls(self):
        constants = m.selected_constants(self.data, self.rows)
        fields = {r['role']: bytes.fromhex(r['bytes']) for r in constants['literals']}
        for name in ('locus', 'ctx', 'height'):
            token = fields[name]
            self.assertEqual(m.map_key_choice(False, token, token), 'decode-child')
            self.assertEqual(m.map_key_choice(True, token, token), 'duplicate')
            for index in range(len(token)):
                wrong = bytearray(token)
                wrong[index] ^= 1
                self.assertEqual(m.map_key_choice(False, bytes(wrong), token), 'other-key-helper')

    def test_height_flow_offsets_and_operand_corruption(self):
        flow = m.trace_height_offsets(self.data, self.rows)
        self.assertEqual(len(flow['instructions']), 43)
        self.assertEqual(flow['offsets'], {
            'context_output': '0x28', 'locus_first_local_stack': '0x2d8',
            'locus_result_stack': '0x1638', 'locus_output': '0x28',
            'exchange_output': '0x28', 'nested_output': '0x28',
            'allocated_outer_object': '0x28'})
        for name, va, prefix, _, _ in m.HEIGHT_OPERANDS:
            with self.subTest(instruction=name, part='opcode'):
                self.mutate_check(va, lambda: m.trace_height_offsets(self.data, self.rows), executable=True)
            with self.subTest(instruction=name, part='operand'):
                self.mutate_check(va + len(bytes.fromhex(prefix)),
                                  lambda: m.trace_height_offsets(self.data, self.rows), executable=True)

    def test_decimal_accumulator_overflow_boundary(self):
        threshold = m.selected_constants(self.data, self.rows)['decimal_threshold']
        q, r = threshold['quotient'], threshold['remainder']
        self.assertEqual(m.decimal_accumulator_step(q - 1, 9, q, r), ('accumulate', (q - 1) * 10 + 9))
        self.assertEqual(m.decimal_accumulator_step(q, 5, q, r), ('accumulate', (1 << 64) - 1))
        self.assertEqual(m.decimal_accumulator_step(q, 6, q, r), ('fallback', None))
        self.assertEqual(m.decimal_accumulator_step(q + 1, 0, q, r), ('fallback', None))
        for acc, digit in ((-1, 0), (1 << 64, 0), (0, -1), (0, 10)):
            with self.subTest(acc=acc, digit=digit), self.assertRaises(ValueError):
                m.decimal_accumulator_step(acc, digit, q, r)
        with self.assertRaises(ValueError):
            m.decimal_accumulator_step(0, 0, q + 1, r)

    def test_historical_input_must_be_authenticated(self):
        with self.assertRaises(ValueError):
            m.compare_old(b'not node 94', self.data)


if __name__ == '__main__':
    unittest.main()
