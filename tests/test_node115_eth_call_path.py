"""Target-backed controls for the node 115 eth_call path evidence."""
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import node115_eth_call_path as m
from elf_index import sections, unwind_index


class EthCallPathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = m.TARGET.read_bytes()
        m.authenticate(cls.data)
        cls.sec, cls.index = unwind_index(cls.data)
        cls.relocs = m.relocation_index(cls.data, cls.sec)
        cls.functions = m.get_functions(cls.data, cls.sec, cls.index)
        cls.tables = m.get_tables(cls.data, cls.sec, cls.functions)

    def test_target_digest_is_required_before_creating_output(self):
        damaged = bytearray(self.data)
        damaged[m.file_offset(self.sec, 0x2a09b59, 1, True)] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            m.authenticate(damaged)
        with tempfile.TemporaryDirectory() as root:
            out = Path(root) / 'evidence'
            with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
                m.generate(b'corrupt artifact', out)
            self.assertFalse(out.exists())

    def test_file_backed_mapping_rejects_nobits_ambiguity_and_overrun(self):
        base = {'address': 0x1000, 'offset': 0, 'size': 16, 'flags': 4, 'type': 1, 'name': 'code'}
        self.assertEqual(m.file_offset([base], 0x100f, 1, True), 15)
        with self.assertRaises(ValueError):
            m.file_offset([{**base, 'type': 8}], 0x1000, 1)
        with self.assertRaises(ValueError):
            m.file_offset([base], 0x100f, 2)
        with self.assertRaises(ValueError):
            m.file_offset([base, {**base, 'name': 'overlap'}], 0x1000, 1)
        with self.assertRaises(ValueError):
            m.file_offset([base], -1, 1)

    def test_direct_branch_target_and_corrupt_displacement(self):
        target, raw = m.decode_branch(self.data, self.sec, 0x2e377b8, b'\xe8', 0x2a05f60)
        self.assertEqual(target, 0x2a05f60)
        fake_sec = [{'address': 0x1000, 'offset': 0, 'size': 32, 'flags': 4, 'type': 1}]
        good = b'\xe8' + struct.pack('<i', 3) + bytes(27)
        self.assertEqual(m.decode_branch(good, fake_sec, 0x1000, b'\xe8', 0x1008)[0], 0x1008)
        with self.assertRaisesRegex(ValueError, 'target mismatch'):
            m.decode_branch(b'\xe8' + struct.pack('<i', 4) + bytes(27), fake_sec, 0x1000, b'\xe8', 0x1008)
        with self.assertRaisesRegex(ValueError, 'opcode'):
            m.decode_branch(b'\xe9' + good[1:], fake_sec, 0x1000, b'\xe8')
        with self.assertRaises(ValueError):
            m.decode_branch(b'\xe8' + struct.pack('<i', 1000) + bytes(27), fake_sec, 0x1000, b'\xe8')
        self.assertEqual(raw[0], 0xe8)

    def test_conditional_gas_branches(self):
        self.assertEqual(m.decode_branch(self.data, self.sec, 0x2a09b57, b'\x75', 0x2a09b67)[0], 0x2a09b67)
        self.assertEqual(m.decode_branch(self.data, self.sec, 0x2a09b65, b'\x72', 0x2a09b7f)[0], 0x2a09b7f)
        self.assertEqual(m.decode_branch(self.data, self.sec, 0x2a04c8f, b'\x75', 0x2a04ca0)[0], 0x2a04ca0)

    def test_rip_relative_and_relative_relocation(self):
        slot, _ = m.decode_rip(self.data, self.sec, 0x2a3549a, b'\xff\x15', 0x64e22b0)
        self.assertEqual(m.relative_relocation(self.data, self.sec, self.relocs, slot, 0x175d250)[0], 0x175d250)
        for row in ((6, 0x175d250, 0), (8, 0x175d251, 0), (8, -1, 0)):
            with self.assertRaises(ValueError):
                m.relative_relocation(self.data, self.sec, {slot: row}, slot, 0x175d250)
        with self.assertRaises(ValueError):
            m.relative_relocation(self.data, self.sec, {}, slot, 0x175d250)
        with self.assertRaises(ValueError):
            m.decode_rip(self.data, self.sec, 0x2a3549a, b'\xff\x14')

    def test_got_copy_symbol_and_relocation(self):
        info, _, _ = self.relocs[0x64df508]
        self.assertEqual(info & 0xffffffff, 6)
        self.assertEqual(m.dynamic_symbol_name(self.data, self.sec, info >> 32), 'memcpy')
        slot, _ = m.decode_rip(self.data, self.sec, 0x2a2a48d, b'\xff\x15', 0x64df568)
        self.assertEqual(m.dynamic_symbol_name(self.data, self.sec, self.relocs[slot][0] >> 32), 'memmove')
        with self.assertRaises(ValueError):
            m.dynamic_symbol_name(self.data, self.sec, 1 << 30)
        with self.assertRaises(ValueError):
            m.dynamic_symbol_name(self.data, self.sec, -1)

    def test_selected_fde_header_identity_and_nonmatching_control(self):
        selected = {row['role']: row for row in self.functions}
        self.assertEqual(selected['call_handler_future']['start_va'], '0x2a2a0e0')
        self.assertEqual(selected['call_handler_future']['end_va_exclusive'], '0x2a2b882')
        fake_fde = {'start': 0x1000, 'end': 0x1004, 'fde': 0x2000}
        fake_index = [{'start': 0x1000, 'fde': 0x2001, 'next_index_upper_bound': 0x1010}]
        with mock.patch.object(m, 'FUNCTIONS', (('fake', 0x1000),)), \
             mock.patch.object(m, 'eh_frame_records', return_value=({}, [fake_fde])):
            with self.assertRaisesRegex(ValueError, 'cross-indexed'):
                m.get_functions(b'', [], fake_index)

    def test_instruction_window_rejects_one_changed_byte(self):
        name, va, size, expected = m.WINDOWS[0]
        raw = bytearray(m.read_va(self.data, self.sec, va, size, True))
        sec = [{'address': va, 'offset': 0, 'size': size, 'flags': 4, 'type': 1}]
        functions = [{'start_va': hex(va), 'end_va_exclusive': hex(va + size)}]
        with mock.patch.object(m, 'WINDOWS', ((name, va, size, expected),)):
            self.assertEqual(len(m.get_windows(raw, sec, functions)), 1)
            raw[-1] ^= 1
            with self.assertRaisesRegex(ValueError, 'fingerprint mismatch'):
                m.get_windows(raw, sec, functions)

    def test_relative_jump_table_and_out_of_range_control(self):
        table = self.tables[0]
        self.assertEqual(table['entries'][1]['target_va'], '0x299fe72')
        obj = self.tables[1]
        self.assertEqual(obj['entries'][6]['target_va'], '0x1e269fe')
        va, owner, count = 0x600974, 0x299fd90, 19
        raw = bytearray(m.read_va(self.data, self.sec, va, count * 4))
        func = next(f for f in self.functions if f['role'] == 'field_name_from_bytes')
        end = int(func['end_va_exclusive'], 16)
        sec = [{'address': va, 'offset': 0, 'size': len(raw), 'flags': 2, 'type': 1},
               {'address': owner, 'offset': len(raw), 'size': end - owner, 'flags': 4, 'type': 1}]
        data = raw + bytearray(end - owner)
        with mock.patch.object(m, 'TABLES', (('test', va, count, owner),)):
            self.assertEqual(len(m.get_tables(data, sec, [func])[0]['entries']), count)
            struct.pack_into('<i', data, 4, 0)
            with self.assertRaisesRegex(ValueError, 'outside selected FDE'):
                m.get_tables(data, sec, [func])

    def test_gas_classifier_and_missing_parameter(self):
        d = m.get_decisions(self.data, self.sec, self.tables)
        self.assertEqual(d['gas_field']['name'], 'gas')
        self.assertEqual(d['gas_field']['duplicate_error_name'], 'gas')
        self.assertEqual(d['gas_field']['classifier_tag'], 28)
        self.assertEqual(d['gas_field']['object_dispatch_index'], 6)
        self.assertEqual((d['gas_field']['parser_request_tag_offset'],
                          d['gas_field']['parser_request_word_offset']), (0x80, 0x88))
        self.assertEqual(d['missing_parameter']['code'], -32602)
        self.assertEqual(d['missing_parameter']['message'], 'Invalid params')
        self.assertEqual(d['missing_parameter']['detail'], 'No more params')
        self.assertEqual(d['missing_parameter']['type_name'], 'TransactionRequest')

    def test_optional_parameter_labels_and_absence(self):
        labels = m.parameter_error_labels(self.data, self.sec)
        self.assertEqual([(item['name'], item['type']) for item in labels], [
            ('block_id', 'Option < BlockId >'),
            ('state_overrides', 'Option < StateOverride >'),
            ('block_overrides', 'Option < Box < BlockOverrides > >'),
        ])
        self.assertEqual(m.decode_branch(self.data, self.sec, 0x2d0f30e, b'\x74', 0x2d0f33a)[0], 0x2d0f33a)
        self.assertEqual(m.decode_branch(self.data, self.sec, 0x2d0f5cd, b'\x0f\x84', 0x2d0f84e)[0], 0x2d0f84e)

    def test_duplicate_gas_and_poll_states(self):
        self.assertEqual(m.read_va(self.data, self.sec, 0x1e269fe, 6, True), bytes.fromhex('48837c246802'))
        self.assertEqual(m.decode_branch(self.data, self.sec, 0x1e26a04, b'\x0f\x85', 0x1e28583)[0], 0x1e28583)
        self.assertEqual(m.read_va(self.data, self.sec, 0x2a2a2ea, 4, True), bytes.fromhex('4080fd29'))
        self.assertEqual(m.read_va(self.data, self.sec, 0x2a2a426, 4, True), bytes.fromhex('4080fd28'))
        self.assertEqual(m.decode_branch(self.data, self.sec, 0x2d090d2, b'\x75', 0x2d090f2)[0], 0x2d090f2)

    def test_gas_bound_at_unsigned_edges(self):
        decisions = m.get_decisions(self.data, self.sec, self.tables)
        cap = decisions['gas_bound']['cap']
        self.assertEqual(cap, 30000000)
        for value in (0, 1, cap - 1, cap):
            self.assertEqual(m.normalize_gas(1, value, cap), (1, value))
        for value in (cap + 1, (1 << 64) - 1):
            self.assertEqual(m.normalize_gas(1, value, cap), (1, cap))
        self.assertEqual(m.normalize_gas(0, 0, cap), (1, cap))
        self.assertEqual(m.normalize_gas(0, cap + 1, cap), (1, cap))
        for tag, value in ((2, 0), (-1, 0), (1, -1), (1, 1 << 64), (True, 1)):
            with self.assertRaises(ValueError):
                m.normalize_gas(tag, value, cap)

    def test_gas_value_reaches_downstream_argument(self):
        flow = m.trace_gas_copies(self.data, self.sec, 0x88)
        self.assertEqual(flow['prepare_output_word_offset'], '0xd8')
        self.assertEqual(flow['adapter_second_bound_stack_word'], '0x6e8')
        self.assertEqual(flow['downstream_argument_word_offset'], '0xd8')
        with self.assertRaisesRegex(ValueError, 'selected request words'):
            m.trace_gas_copies(self.data, self.sec, 0x80)

    def test_null_and_zero_literal_machine_paths(self):
        self.assertEqual(m.read_va(self.data, self.sec, 0x29a05ff, 2, True), b'\x31\xc9')
        self.assertEqual(m.read_va(self.data, self.sec, 0x29a062d, 5, True), b'\xb9\x01\x00\x00\x00')
        self.assertEqual(m.read_va(self.data, self.sec, 0x29ffd49, 5, True), b'\x35\x30\x78\x00\x00')
        self.assertEqual(m.read_va(self.data, self.sec, 0x29ffd53, 3, True), b'\x83\xf1\x30')
        self.assertEqual(m.decode_branch(self.data, self.sec, 0x29ffd59, b'\x0f\x84', 0x29fffdc)[0], 0x29fffdc)

    def test_vtables_and_location_records(self):
        tables = m.get_vtables(self.data, self.sec, self.relocs)
        self.assertEqual([row['slot_24_addend_va'] for row in tables], ['0x2dd67c0', '0x2d087e0', '0x2a2a0e0'])
        locations = m.get_locations(self.data, self.sec, self.relocs)
        selected = next(row for row in locations if row['role'] == 'limiter_selection')
        self.assertEqual((selected['line'], selected['column']), (107, 24))
        self.assertEqual(selected['path'], 'evm_rpc/src/expensive_call_limiter.rs')

    def test_selected_fork_markers_exist_in_target(self):
        rows = m.get_fork_prefixes(self.data, self.sec)
        by_name = {row['prefix']: row['occurrences'] for row in rows}
        self.assertTrue(by_name['z_forks/revm-precompile/'])
        self.assertTrue(by_name['z_vendor/revm-interpreter/'])
        self.assertNotIn('z_vendor/nonexistent/', by_name)


if __name__ == '__main__':
    unittest.main()
