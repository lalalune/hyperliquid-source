"""Static controls for the node-115 history adapter evidence collector."""
from contextlib import contextmanager
import math
import struct
import unittest

from tools import evm_fee_history115 as evidence


class InstructionModelTests(unittest.TestCase):
    def test_ucomisd_unordered_flag_effect(self):
        # UCOMISD produces CF=ZF=PF=1 on unordered: JA is false, JBE true.
        self.assertEqual(evidence.compare_f64(float('nan'), 100.0), 'unordered')
        self.assertEqual(evidence.compare_f64(100.0, float('nan')), 'unordered')
        self.assertEqual(evidence.compare_f64(-1.0, 0.0), 'less')
        self.assertEqual(evidence.compare_f64(100.0, 100.0), 'equal')
        self.assertEqual(evidence.compare_f64(101.0, 100.0), 'greater')

    def test_percentile_pair_edges(self):
        f = lambda xs: evidence.local_percentile_branch(1, xs, 100, 100.0)
        self.assertEqual(f(None), 'continue')
        self.assertEqual(f([]), 'continue')
        self.assertEqual(f([101.0]), 'continue')
        self.assertEqual(f([100.0, 101.0]), 'continue')
        self.assertEqual(f([101.0, 101.0]), 'invalid')
        self.assertEqual(f([3.0, 2.0]), 'invalid')
        self.assertEqual(f([-1.0, 0.0]), 'continue')
        self.assertEqual(f([0.0] * 100), 'continue')
        self.assertEqual(f([0.0] * 101), 'invalid')
        self.assertEqual(evidence.local_percentile_branch(0, [0.0] * 101, 100, 100.0), 'zero_count')

    def test_unordered_cases_are_only_register_level(self):
        f = lambda xs: evidence.local_percentile_branch(1, xs, 100, 100.0)
        self.assertEqual(f([float('nan'), 0.0]), 'continue')
        self.assertEqual(f([0.0, float('nan')]), 'continue')
        self.assertEqual(f([float('inf'), float('inf')]), 'invalid')
        self.assertEqual(f([float('-inf'), 0.0]), 'continue')

    def test_range_clamp_and_selector_four_saturating_subtraction(self):
        f = lambda count, newest, selector=5: evidence.local_range(count, newest, selector, 5)
        self.assertEqual(f(0, 0), {'route': 'zero_count'})
        self.assertEqual(f(1, 0), {'route': 'range', 'limited_count': 1, 'oldest': 0, 'newest': 0})
        self.assertEqual(f(6, 5), {'route': 'range', 'limited_count': 5, 'oldest': 1, 'newest': 5})
        self.assertEqual(f(6, 5, 4), {'route': 'range', 'limited_count': 4, 'oldest': 2, 'newest': 5})
        self.assertEqual(f(3, 9, 4), {'route': 'range', 'limited_count': 2, 'oldest': 8, 'newest': 9})
        self.assertEqual(f(1, 0, 4)['route'], 'range_order_error')
        self.assertEqual(f(1, (1 << 64) - 1)['route'], 'increment_overflow')
        self.assertEqual(f((1 << 64) - 1, 5)['limited_count'], 5)
        for count, newest in ((-1, 0), (0, -1), (1 << 64, 0), (0, 1 << 64)):
            with self.subTest(count=count, newest=newest), self.assertRaises(ValueError):
                f(count, newest)

    def test_rel32_call_decode_rejects_wrong_opcode_and_truncation(self):
        self.assertEqual(evidence.decode_rel32(0x100, bytes.fromhex('e805000000')), 0x10a)
        self.assertEqual(evidence.decode_rel32(0x100, bytes.fromhex('e8f6ffffff')), 0xfb)
        for raw in (b'', bytes.fromhex('e8'), bytes.fromhex('e905000000')):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                evidence.decode_rel32(0x100, raw)

    def test_indirect_call_decode_rejects_wrong_opcode_and_truncation(self):
        self.assertEqual(evidence.decode_indirect_slot(0x100, bytes.fromhex('ff150a000000')), 0x110)
        self.assertEqual(evidence.decode_indirect_slot(0x100, bytes.fromhex('ff15f6ffffff')), 0xfc)
        for raw in (b'', bytes.fromhex('ff15'), bytes.fromhex('e8150a000000')):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                evidence.decode_indirect_slot(0x100, raw)

    def test_range_key_model_order_and_corruption_controls(self):
        prefix = bytes.fromhex('4206')
        nums = (0, 1, 255, 256, (1 << 64) - 1)
        keys = [evidence.model_bound_key(prefix, n) for n in nums]
        self.assertEqual(keys, sorted(keys))
        self.assertEqual(keys[3], bytes.fromhex('42060000000000000100'))
        self.assertEqual([evidence.model_key_suffix(prefix, k) for k in keys], list(nums))
        for bad in (keys[0][:-1], keys[0] + b'X', b'X' + keys[0][1:]):
            self.assertIsNone(evidence.model_key_suffix(prefix, bad))
        for n in (-1, 1 << 64):
            with self.assertRaises(ValueError):
                evidence.model_bound_key(prefix, n)

    def test_reward_selection_empty_and_threshold_boundaries(self):
        f = evidence.model_reward_selection
        self.assertEqual(f([0.0, 50.0, 100.0], [], 10), [0, 0, 0])
        self.assertEqual(f([], [(5, 7)], 5), [])
        self.assertEqual(f([0.0, 10.0, 11.0, 100.0], [(1, 7), (9, 9)], 10), [7, 7, 7, 9])
        self.assertEqual(f([0.0, 50.0, 100.0], [(0, 7), (2, 9)], 2), [7, 9, 9])
        self.assertEqual(f([0.0, 100.0], [(5, 7)], 5), [7, 7])

    def test_reward_cursor_and_float_cast_are_local_models(self):
        f = evidence.model_reward_selection
        self.assertEqual(f([50.0, 0.0], [(0, 7), (2, 9)], 2), [9, 9])
        self.assertEqual(f([float('nan'), -1.0, 0.0, 100.0, float('inf')],
                           [(0, 7), (2, 9)], 2), [7, 7, 7, 9, 9])

    def test_reward_selection_rejects_overflow_and_bad_rows(self):
        f = evidence.model_reward_selection
        maximum = (1 << 64) - 1
        with self.assertRaises(OverflowError):
            f([100.0], [(maximum - 1, 7), (2, 9)], maximum)
        for rows, total in (([(-1, 0)], 0), ([(1 << 64, 0)], 0),
                            ([(0, -1)], 0), ([(0, 1 << 128)], 0), ([], -1)):
            with self.subTest(rows=rows, total=total), self.assertRaises(ValueError):
                f([0.0], rows, total)

    def test_branch_decode_rejects_bad_forms(self):
        self.assertEqual(evidence.decode_branch(0x100, bytes.fromhex('75fc')), ('jne', 0xfe))
        self.assertEqual(evidence.decode_branch(0x100, bytes.fromhex('0f8403000000')), ('je', 0x109))
        for raw in (b'', bytes.fromhex('7500ff'), bytes.fromhex('e900000000'), bytes.fromhex('0f85')):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                evidence.decode_branch(0x100, raw)

    def test_lea_decode_rejects_wrong_addressing(self):
        self.assertEqual(evidence.decode_lea(0x100, bytes.fromhex('488d0509000000')), 0x110)
        for raw in (b'', bytes.fromhex('488b0509000000'), bytes.fromhex('488d0409000000')):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                evidence.decode_lea(0x100, raw)

    def test_nobits_ambiguity_and_interval_boundaries(self):
        backed = {'name': '.data', 'type': 1, 'flags': 2, 'address': 0x100, 'offset': 0x10, 'size': 8}
        zero_fill = {'name': '.bss', 'type': 8, 'flags': 2, 'address': 0x100, 'offset': 0x80, 'size': 8}
        self.assertEqual(evidence.file_offset([backed, zero_fill], 0x102, 2), 0x12)
        for rows, addr, size in (([zero_fill], 0x100, 1), ([backed], 0x108, 1),
                                 ([backed], 0x107, 2), ([backed], -1, 1),
                                 ([backed, dict(backed)], 0x100, 1), ([backed], 0x100, 0)):
            with self.subTest(addr=addr, size=size), self.assertRaises(ValueError):
                evidence.file_offset(rows, addr, size)


class TargetEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = bytearray(evidence.BINARY.read_bytes())
        cls.image = evidence.Image(cls.data)

    @contextmanager
    def patch_offset(self, offset, replacement):
        saved = self.data[offset:offset + len(replacement)]
        self.data[offset:offset + len(replacement)] = replacement
        try:
            yield
        finally:
            self.data[offset:offset + len(replacement)] = saved

    def test_digest_and_indexed_fde_bounds(self):
        self.assertEqual(self.image.digest, evidence.DIGEST)
        rows = self.image.fde_rows()
        self.assertEqual(len(rows), 28)
        selected = {r['role']: r for r in rows}
        self.assertEqual(selected['history_future']['start_va'], '0x2a1fd20')
        self.assertEqual(selected['history_future']['end_va_exclusive'], '0x2a21c6d')
        self.assertEqual(selected['outer_future']['start_va'], '0x2d0bee0')
        self.assertEqual(selected['outer_future']['end_va_exclusive'], '0x2d0d282')
        # The FDE end is exclusive, and the next-index upper bound is not used as its size.
        f = self.image.selected[0x2d024e0][1]
        self.image.owner(f['end'] - 1)
        with self.assertRaises(ValueError):
            self.image.owner(f['end'])

    def test_corrupted_input_digest_is_rejected_before_parsing(self):
        with self.patch_offset(0x10, b'\x00'):
            with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
                evidence.Image(self.data)
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            evidence.Image(b'not an elf')

    def test_frozen_instruction_corruption_is_rejected(self):
        offset = self.image.offset(0x2a2009f, 1)
        with self.patch_offset(offset, bytes([self.data[offset] ^ 1])):
            with self.assertRaisesRegex(ValueError, 'frozen instruction'):
                self.image.window_rows()
        self.assertEqual(len(self.image.window_rows()), 133)

    def test_branch_corruption_is_rejected(self):
        offset = self.image.offset(0x2a200b0, 1)
        with self.patch_offset(offset, b'\x77'):
            with self.assertRaisesRegex(ValueError, 'branch condition'):
                self.image.branch_rows()

    def test_state_table_target_outside_own_fde_is_rejected(self):
        offset = self.image.offset(0x601410, 4)
        with self.patch_offset(offset, struct.pack('<i', 0x7fffffff)):
            with self.assertRaisesRegex(ValueError, 'outside its FDE'):
                self.image.table_rows()
        rows = self.image.table_rows()
        self.assertEqual(len(rows), 44)
        top = {row['index']: row['target_va'] for row in rows if row['table'] == 'history'}
        self.assertEqual(top, {0: '0x2a1fd5b', 1: '0x2a217e5', 2: '0x2a217d8', 3: '0x2a1fddb'})

    def test_wrong_table_pointer_opcode_is_rejected(self):
        offset = self.image.offset(0x2a1fd46 + 1, 1)
        with self.patch_offset(offset, b'\x8b'):
            with self.assertRaisesRegex(ValueError, 'RIP-relative LEA'):
                self.image.table_rows()

    def test_selected_relocation_target_corruption_is_rejected(self):
        original = self.image.relocs
        loc = original[0x6450a60]['file_offset'] + 16
        changed = struct.pack('<q', 0x2d0bee0 + 1)
        try:
            with self.patch_offset(loc, changed):
                self.image.relocs = self.image.read_relocations()
                with self.assertRaisesRegex(ValueError, 'addend differs'):
                    self.image.relocation_rows()
        finally:
            self.image.relocs = original

    def test_duplicate_relocation_is_rejected(self):
        section = evidence.read_unique_section(self.image.secs, '.rela.dyn')
        off = section['offset']
        while struct.unpack_from('<Q', self.data, off)[0] in self.image.relocs:
            off += 24
        with self.patch_offset(off, struct.pack('<QQq', 0x6450a60, 8, 0x2d0bee0)):
            with self.assertRaisesRegex(ValueError, 'duplicate selected relocation'):
                self.image.read_relocations()

    def test_unexpected_relocation_type_is_rejected(self):
        off = self.image.relocs[0x6450a60]['file_offset'] + 8
        with self.patch_offset(off, struct.pack('<Q', 1)):
            with self.assertRaisesRegex(ValueError, 'not R_X86_64_RELATIVE'):
                self.image.read_relocations()

    def test_corrupt_literal_is_rejected(self):
        offset = self.image.offset(self.image.lea(0x2d0cce1), 1)
        with self.patch_offset(offset, b'X'):
            with self.assertRaisesRegex(ValueError, 'literal differs'):
                self.image.literal_rows()

    def test_missing_argument_text_and_signed_error(self):
        literals = {r['label']: r['value'] for r in self.image.literal_rows()}
        self.assertEqual(literals['missing_parameter_message'], 'No more params')
        self.assertEqual(literals['invalid_params'], 'Invalid params')
        self.assertEqual(literals['block_number_diagnostic'], 'eth_blockNumber')
        self.assertEqual(literals['candidate_method_literal'], 'eth_feeHistory')
        self.assertEqual([literals[x] for x in ('error', 'code', 'message', 'data')],
                         ['error', 'code', 'message', 'data'])
        constants = self.image.constants()
        self.assertEqual(constants['missing_parameter_error_code'], -32602)
        self.assertEqual(constants['missing_parameter_error_class'], 5)
        self.assertEqual(constants['invalid_percentile_tag'], 0x17)

    def test_wire_error_class_five_maps_to_same_signed_code(self):
        rows = self.image.wire_error_code_rows()
        self.assertEqual(len(rows), 8)
        self.assertEqual(rows[5]['target_va'], '0x260cc52')
        self.assertEqual(rows[5]['code'], -32602)
        self.assertEqual(rows[7]['code'], 'input_i32_at_offset_0x34')
        off = self.image.offset(0x260cc52 + 1, 1)
        with self.patch_offset(off, bytes([self.data[off] ^ 1])):
            with self.assertRaisesRegex(ValueError, 'wire code differs'):
                self.image.wire_error_code_rows()

    def test_descriptor_to_poll_chain(self):
        desc = {r['label']: r for r in self.image.table_descriptors()}
        self.assertEqual((desc['outer_future']['size'], desc['history_future']['size']), (0x90, 0x2f8))
        edges = {r['label']: r['addend_va'] for r in self.image.relocation_rows()}
        self.assertEqual(edges, {'descriptor_callback_a': '0x2d032b0', 'descriptor_callback_b': '0x2d032b0',
                                 'outer_poll': '0x2d0bee0', 'history_poll': '0x2a1fd20',
                                 'task_run': '0x2b230d0', 'task_join_poll': '0x2b16880'})
        self.assertEqual(self.image.lea(0x2b3db6a), 0x64494c0)

    def test_indirect_call_slot_and_addend_corruption_are_rejected(self):
        rows = {r['label']: r for r in self.image.indirect_call_rows()}
        self.assertEqual(len(rows), 10)
        self.assertEqual(rows['iterator_key']['slot_va'], '0x64e20b0')
        self.assertEqual(rows['iterator_key']['addend_va'], '0x5d34900')
        instruction_offset = self.image.offset(0x269822a + 2, 1)
        with self.patch_offset(instruction_offset, bytes([self.data[instruction_offset] ^ 1])):
            with self.assertRaisesRegex(ValueError, 'indirect call slot differs'):
                self.image.indirect_call_rows()
        original = self.image.relocs
        loc = original[0x64e20b0]['file_offset'] + 16
        try:
            with self.patch_offset(loc, struct.pack('<q', 0x5d34901)):
                self.image.relocs = self.image.read_relocations()
                with self.assertRaisesRegex(ValueError, 'indirect call relocation addend differs'):
                    self.image.indirect_call_rows()
        finally:
            self.image.relocs = original

    def test_selected_external_symbols_and_corruption_controls(self):
        rows = {r['label']: r for r in self.image.external_symbol_rows()}
        self.assertEqual({k: v['name'] for k, v in rows.items()},
                         {'concat_copy': 'memcpy', 'prefix_equality': 'bcmp', 'range_bound_compare': 'memcmp'})
        off = int(rows['concat_copy']['name_file_offset'], 16)
        with self.patch_offset(off, b'X'):
            with self.assertRaisesRegex(ValueError, 'external symbol name differs'):
                self.image.external_symbol_rows()
        off = int(rows['prefix_equality']['rela_file_offset'], 16) + 8
        info = struct.unpack_from('<Q', self.data, off)[0]
        with self.patch_offset(off, struct.pack('<Q', (info & ~0xffffffff) | 1)):
            with self.assertRaisesRegex(ValueError, 'unexpected external relocation'):
                self.image.external_symbol_rows()

    def test_call_chain_and_serializer(self):
        edges = {r['label']: r['target_va'] for r in self.image.call_rows()}
        self.assertEqual(edges['block_range_poll'], '0x2a0acc0')
        self.assertEqual(edges['construct_block_task'], '0x2b3daa0')
        self.assertEqual(edges['poll_block_task'], '0x2e4a980')
        self.assertEqual(edges['response_bridge'], '0x22d7a70')
        self.assertEqual(edges['response_envelope'], '0x260b360')
        self.assertEqual(edges['history_fields'], '0x22e0850')
        self.assertEqual(edges['reward_field'], '0x2338940')
        self.assertEqual(edges['task_run_range_iterator'], '0x2698000')
        self.assertEqual(edges['lower_bound_key'], '0x26990d0')
        self.assertEqual(edges['upper_bound_key'], '0x26990d0')
        self.assertEqual(edges['key_segments_concat'], '0x231fef0')
        self.assertEqual(edges['decode_range_value'], '0x26985d0')
        self.assertEqual(edges['project_range_values'], '0x231bc30')
        self.assertEqual(edges['block_number_uninstrumented'], '0x2a3eb60')
        self.assertEqual(edges['block_number_instrumented'], '0x2a3eb60')
        self.assertEqual(edges['serialize_error'], '0x260cb30')

    def test_typed_context_keys_and_floating_constants(self):
        c = self.image.constants()
        self.assertEqual(c['block_count_cap'], 5)
        self.assertEqual(c['percentile_count_cap'], 100)
        self.assertEqual(c['block_row_stride'], 0x3e0)
        self.assertEqual(c['store_entry_stride'], 0x3e8)
        self.assertEqual(c['store_decoded_value_size'], 0x3e0)
        self.assertEqual(c['store_key_suffix_width'], 8)
        self.assertEqual(c['block_number_context_pointer_offset'], 0xb00)
        self.assertEqual(c['block_number_nested_value_offset'], 0x39d8)
        self.assertEqual(c['typed_key_words'], ['0x37ae65ed6e200eef', '0xa65ad9692065030d'])
        doubles = c['binary64_constants']
        self.assertEqual([x['binary64'] for x in doubles[:2]], [100.0, 786432.0])
        self.assertEqual([x['bytes'] for x in doubles[2:]], ['000000000000e043', 'ffffffffffffef43'])

    def test_serializer_gates_and_input_offsets(self):
        rows = {r['field']: r for r in self.image.field_gate_rows()}
        self.assertEqual(rows['baseFeePerGas']['input_offset'], '0x10')
        self.assertEqual(rows['baseFeePerBlobGas']['input_offset'], '0x40')
        self.assertEqual(rows['blobGasUsedRatio']['input_offset'], '0x58')
        self.assertEqual(rows['reward']['input_offset'], '0x60')
        self.assertEqual(rows['reward']['skip_condition'], 'jo')
        self.assertEqual(rows['baseFeePerGas']['skip_condition'], 'je')

    def test_locations_and_dependency_paths(self):
        locations = {x['label']: x for x in self.image.location_rows()}
        self.assertEqual((locations['history_helper_36']['line'], locations['history_helper_36']['column']), (36, 29))
        self.assertEqual((locations['history_helper_145']['line'], locations['history_helper_145']['column']), (145, 54))
        self.assertEqual(locations['store_465']['path'], 'evm_rpc/src/evm_store.rs')
        fork = {x['prefix']: x for x in self.image.forks()}
        self.assertEqual(len(fork), 29)
        self.assertEqual(fork['z_forks/reth-rpc-eth-types/']['first_path'],
                         'z_forks/reth-rpc-eth-types/src/fee_history.rs')
        self.assertEqual(fork['z_forks/revm-precompile/']['occurrences'], 12)

    def test_selected_windows_are_file_backed(self):
        with self.assertRaises(ValueError):
            self.image.read(0, 8)
        with self.assertRaises(ValueError):
            self.image.read(0x2a1fd20, 0)
        with self.assertRaises(ValueError):
            self.image.read(0x459498, 8, executable=True)


if __name__ == '__main__':
    unittest.main()
