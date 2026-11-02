"""Static evidence and synthetic boundary controls for node #94 input memory."""
import copy
import csv
import hashlib
import io
import json
import unittest
from unittest import mock

from tools import re21_input_memory94 as m


class ArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = bytearray(m.TARGET.read_bytes())
        cls.secs = m.sections(cls.data)
        cls.export = m.collect(cls.data)
        cls.relocs = m.relocations(cls.data, cls.secs,
                                   set(m.SLOTS) | {m.TABLE_VA + 8 * x for x in m.OPCODES})

    def test_full_target_digest(self):
        self.assertEqual(m.check_digest(self.data), m.TARGET_SHA256)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            m.check_digest(b'not the target')

    def test_one_bit_corruption_changes_full_digest(self):
        off = m.file_offset(self.secs, 0x26bd8b0, 1, True)
        self.data[off] ^= 1
        try:
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                m.check_digest(self.data)
        finally:
            self.data[off] ^= 1

    def test_body_corruption_is_detected_after_digest_gate(self):
        off = m.file_offset(self.secs, 0x26bd8b0, 1, True)
        self.data[off] ^= 1
        try:
            with mock.patch.object(m, 'check_digest', return_value=m.TARGET_SHA256):
                with self.assertRaisesRegex(ValueError, 'body changed'):
                    m.collect(self.data)
        finally:
            self.data[off] ^= 1

    def test_changed_creation_cost_operand_rejected(self):
        off = m.file_offset(self.secs, 0x279e81e, 1, True)
        self.data[off] ^= 1
        try:
            changed = dict(m.FUNCTIONS)
            end, _, role = changed[0x279e770]
            body = m.read_va(self.data, self.secs, 0x279e770, end - 0x279e770, True)
            changed[0x279e770] = (end, hashlib.sha256(body).hexdigest(), role)
            with mock.patch.object(m, 'check_digest', return_value=m.TARGET_SHA256):
                with mock.patch.object(m, 'FUNCTIONS', changed):
                    with self.assertRaisesRegex(ValueError, 'operand value changed'):
                        m.collect(self.data)
        finally:
            self.data[off] ^= 1

    def test_fde_end_corruption_rejected(self):
        changed = dict(m.FUNCTIONS)
        end, digest, role = changed[0x26bd8b0]
        changed[0x26bd8b0] = (end - 1, digest, role)
        with mock.patch.object(m, 'FUNCTIONS', changed):
            with self.assertRaisesRegex(ValueError, 'FDE end'):
                m.collect(self.data)

    def test_fde_start_missing_rejected(self):
        changed = dict(m.FUNCTIONS)
        changed[0x26bd8b1] = changed.pop(0x26bd8b0)
        with mock.patch.object(m, 'FUNCTIONS', changed):
            with self.assertRaisesRegex(ValueError, 'missing selected FDE'):
                m.collect(self.data)

    def test_wrong_body_hash_rejected(self):
        changed = dict(m.FUNCTIONS)
        end, _, role = changed[0x26bd8b0]
        changed[0x26bd8b0] = (end, '00' * 32, role)
        with mock.patch.object(m, 'FUNCTIONS', changed):
            with self.assertRaisesRegex(ValueError, 'body changed'):
                m.collect(self.data)

    def test_invalid_elf_and_truncation(self):
        with self.assertRaises(ValueError):
            m.sections(self.data[:40])
        with self.assertRaises(ValueError):
            m.sections(b'\0' * 64)

    def test_nobits_is_not_file_backed(self):
        bss = next(s for s in self.secs if s['name'] == '.bss')
        self.assertEqual(bss['type'], 8)
        with self.assertRaisesRegex(ValueError, 'NOBITS'):
            m.read_va(self.data, self.secs, bss['address'], 1)

    def test_negative_zero_and_cross_section_ranges(self):
        sec = next(s for s in self.secs if s['name'] == '.text')
        for address, size in ((-1, 1), (sec['address'], 0), (sec['address'] + sec['size'] - 1, 2)):
            with self.subTest(address=address, size=size), self.assertRaises(ValueError):
                m.file_offset(self.secs, address, size, True)

    def test_ambiguous_mapping_rejected(self):
        sec = next(s for s in self.secs if s['name'] == '.text')
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            m.file_offset(self.secs + [dict(sec)], sec['address'], 1, True)

    def test_data_is_not_executable(self):
        sec = next(s for s in self.secs if s['name'] == '.dynstr')
        with self.assertRaises(ValueError):
            m.file_offset(self.secs, sec['address'], 1, True)

    def test_operand_shape_corruption(self):
        off = m.file_offset(self.secs, 0x26bd958, 1, True)
        self.data[off] ^= 1
        try:
            with self.assertRaisesRegex(ValueError, 'operand opcode'):
                m.operand(self.data, self.secs, 0x26bd958, '4c8b9f', 4)
        finally:
            self.data[off] ^= 1

    def test_bad_relocation_type_and_target(self):
        slot = m.TABLE_VA + 8 * 0x37
        for field, bad in (('type', 6), ('index', 1), ('addend', 0)):
            altered = copy.deepcopy(self.relocs)
            altered[slot][field] = bad
            with self.subTest(field=field), self.assertRaises(ValueError):
                m.checked_relative(altered, slot, m.OPCODES[0x37])

    def test_bad_symbol_and_addend(self):
        for field, bad in (('symbol', 'memmove'), ('index', 0), ('addend', 1)):
            altered = copy.deepcopy(self.relocs)
            altered[0x576dfe0][field] = bad
            with self.subTest(field=field), self.assertRaises(ValueError):
                m.checked_slot(altered, 0x576dfe0, 6, 'memcpy', 0)

    def test_missing_relocation_rejected(self):
        with self.assertRaisesRegex(ValueError, 'missing relocation'):
            m.relocations(self.data, self.secs, {0})

    def test_opcode_relocations_and_helpers(self):
        for op, target in m.OPCODES.items():
            self.assertEqual(m.checked_relative(self.relocs, m.TABLE_VA + 8 * op, target)['addend'], target)
        for slot, spec in m.SLOTS.items():
            self.assertEqual(m.checked_slot(self.relocs, slot, *spec)['slot'], slot)

    def test_duplicate_or_nobits_relocation_sections_rejected(self):
        rel = next(s for s in self.secs if s['name'] == '.rela.dyn')
        with self.assertRaisesRegex(ValueError, 'duplicate relocation section'):
            m.relocations(self.data, self.secs + [dict(rel)], {0})
        altered = [dict(s, type=8) if s['name'] == '.dynstr' else s for s in self.secs]
        with self.assertRaisesRegex(ValueError, 'section type'):
            m.relocations(self.data, altered, {0})

    def test_changed_branch_target_rejected(self):
        changed = list(m.BRANCHES)
        name, site, target, taken, fallthrough = changed[0]
        changed[0] = (name, site, target + 1, taken, fallthrough)
        with mock.patch.object(m, 'BRANCHES', changed):
            with self.assertRaisesRegex(ValueError, 'selected branch changed'):
                m.collect(self.data)

    def test_synthetic_program_stack_and_return_claims(self):
        flow = json.loads(self.export['synthetic-flow.json'])
        program = bytes.fromhex(flow['program_hex'])
        self.assertEqual(program[14], 0xf4)
        self.assertEqual(flow['stack_before_delegatecall_bottom_first'], [0, 0, 213, 0, 9, 255])
        self.assertTrue(flow['memory_prefix_equals_input'])
        self.assertEqual(flow['synthetic_action_output_sha256'], flow['synthetic_return_sha256'])
        self.assertEqual((flow['synthetic_action_status'], flow['synthetic_action_tag']), (2, 2))
        self.assertEqual(flow['synthetic_creation_outcome'], 'conditional-install')
        self.assertEqual(program[15:], bytes.fromhex('60405f5f3e60405ff3'))
        self.assertEqual(flow['synthetic_copy_stack_push_charge'], 3 + 2 + 2)
        self.assertEqual(flow['synthetic_return_copy_gas_after'], 20000 - 7 - 9)
        self.assertEqual(flow['synthetic_return_stack_push_charge'], 3 + 2)
        self.assertEqual(flow['synthetic_return_action_gas_after'], 20000 - 7 - 9 - 5)
        self.assertEqual(flow['synthetic_creation_gas_after'], 20000 - 7 - 9 - 5 - 64 * 200)
        self.assertEqual((flow['synthetic_resume_stack_count'],
                          flow['synthetic_return_copy_stack_after'],
                          flow['synthetic_return_action_stack_after']), (1, 1, 1))
        self.assertIn('not derived', flow['synthetic_resume_gas_note'])

    def test_unsupported_and_truncated_instructions_rejected(self):
        for raw in (b'\x62', b'\xe8\x00', b'\x0f', b'\x66' * 16):
            with self.subTest(raw=raw.hex()), self.assertRaises(ValueError):
                m.decode(raw, 0x1000)

    def test_jump_into_instruction_rejected(self):
        with self.assertRaisesRegex(ValueError, 'branch into instruction'):
            m.decode(bytes.fromhex('eb014889c0c3'), 0x1000)

    def test_decoded_signed_branch(self):
        rows = m.decode(bytes.fromhex('90ebfd'), 0x4000)
        self.assertEqual(rows[1]['target'], 0x4000)
        self.assertEqual(rows[1]['kind'], 'jump')

    def test_decoded_operand_and_boundaries(self):
        for name, site, prefix, width, expected in m.OPERANDS:
            with self.subTest(name=name):
                value, raw = m.operand(self.data, self.secs, site, prefix, width)
                self.assertEqual(value, expected)
                self.assertEqual(len(raw), len(bytes.fromhex(prefix)) + width)

    def test_control_flow_selected_edges(self):
        rows = list(csv.DictReader(io.StringIO(self.export['control.tsv'].decode('ascii')), delimiter='\t'))
        by_site = {int(r['va'], 16): r for r in rows}
        expected = {
            0x26bd8c6: 0x26bd8d4, 0x26bd928: 0x26bd936,
            0x26bd962: 0x26bd970, 0x26bd97a: 0x26bda90,
            0x26bd9c7: 0x26bda26, 0x26bda83: 0x26bd9c0,
            0x26bdd13: 0x26bdd2a, 0x26bdd1c: 0x26bdd2a,
            0x26bdd7f: 0x26bc9e0, 0x26bd39c: 0x21c27c0,
            0x26beaf5: 0x26be730, 0x26be7c9: 0x26be8d0,
            0x26be98c: 0x26be823, 0x276e166: 0x279e770,
            0x279e89f: 0x26bcaa0, 0x279e8cf: 0x2788050,
            0x279e7c1: 0x279e7e6, 0x279e805: 0x279e81a,
        }
        for site, target in expected.items():
            with self.subTest(site=hex(site)):
                self.assertEqual(int(by_site[site]['target'], 16), target)

    def test_action_drop_landing_and_lsda_bounds(self):
        rows = list(csv.DictReader(io.StringIO(self.export['exception-sites.tsv'].decode('ascii')), delimiter='\t'))
        matches = [row for row in rows if int(row['start_va'], 16) <= 0x26be926 < int(row['end_va'], 16)]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]['landing_va'], '0x26be9ee')
        matches = [row for row in rows if int(row['start_va'], 16) <= 0x2788171 < int(row['end_va'], 16)]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]['landing_va'], '0x27881be')

    def test_lsda_corruption_rejected(self):
        frame = {'start': 0x26be730, 'end': 0x26bea52, 'lsda': 0xa1ba70}
        off = m.file_offset(self.secs, frame['lsda'], 1)
        original = self.data[off]
        self.data[off] = 0
        try:
            with self.assertRaisesRegex(ValueError, 'landing-base encoding'):
                m.exception_table(self.data, self.secs, frame)
        finally:
            self.data[off] = original

    def test_relocation_bytes_corruption_rejected(self):
        slot = m.TABLE_VA + 8 * 0xf3
        off = self.relocs[slot]['file_offset'] + 8
        self.data[off] ^= 1
        try:
            altered = m.relocations(self.data, self.secs, {slot})
            with self.assertRaises(ValueError):
                m.checked_relative(altered, slot, m.OPCODES[0xf3])
        finally:
            self.data[off] ^= 1

    def test_creation_callback_relocation_corruption_rejected(self):
        slot = 0x56bfb88
        off = self.relocs[slot]['file_offset'] + 16
        self.data[off] ^= 1
        try:
            altered = m.relocations(self.data, self.secs, {slot})
            with self.assertRaisesRegex(ValueError, 'indirect relocation mismatch'):
                m.checked_slot(altered, slot, *m.SLOTS[slot])
        finally:
            self.data[off] ^= 1

    def test_no_embedded_workspace_paths(self):
        for name, content in self.export.items():
            with self.subTest(name=name):
                for word in (b'tmp', b'mnt', b'srv', b'home', b'root', b'opt'):
                    forbidden = bytes([47]) + word + bytes([47])
                    self.assertNotIn(forbidden, content)

    def test_retained_files_match_generator(self):
        folder = m.ROOT / 'research/work-items/RE-021-precompile-input-memory-94'
        for name, expected in self.export.items():
            with self.subTest(name=name):
                self.assertEqual((folder / name).read_bytes(), expected)

    def test_summary_counts_are_from_export(self):
        summary = json.loads(self.export['summary.json'])
        functions = list(csv.DictReader(io.StringIO(self.export['functions.tsv'].decode()), delimiter='\t'))
        controls = list(csv.DictReader(io.StringIO(self.export['control.tsv'].decode()), delimiter='\t'))
        self.assertEqual(summary['selected_fde_intervals'], len(functions))
        self.assertEqual(summary['selected_fde_bytes'], sum(int(row['size']) for row in functions))
        self.assertEqual(summary['control_rows'], len(controls))
        self.assertEqual(summary['selected_opcode_relocations'], len(m.OPCODES))


class SyntheticModels(unittest.TestCase):
    def test_mstore_all_symbolic_bit_lanes(self):
        lanes = m.shuffle_word_lanes(0x4e, 0x1b, 0x1b)
        self.assertEqual(sorted(lanes), list(range(32)))
        for bit in range(256):
            stack_bytes = (1 << bit).to_bytes(32, 'little')
            memory = bytes(stack_bytes[index] for index in lanes)
            with self.subTest(bit=bit):
                self.assertEqual(memory, (1 << bit).to_bytes(32, 'big'))

    def test_shuffle_mutation_fails_identity(self):
        self.assertNotEqual(m.shuffle_word_lanes(0x4f, 0x1b, 0x1b), list(reversed(range(32))))
        self.assertNotEqual(m.shuffle_word_lanes(0x4e, 0x1a, 0x1b), list(reversed(range(32))))
        self.assertNotEqual(m.shuffle_word_lanes(0x4e, 0x1b, 0x1a), list(reversed(range(32))))

    def test_copy_charge_against_integer_oracle(self):
        for length in range(8193):
            self.assertEqual(m.copy_charge(length), 3 + 3 * ((length + 31) // 32))
        self.assertEqual(m.copy_charge(m.U64), 3 + 3 * (m.U64 >> 5))
        with self.assertRaises(ValueError):
            m.copy_charge(1 << 64)

    def test_calldataload_boundaries(self):
        source = bytes(range(35))
        for off in (0, 1, 3, 4, 31, 34, 35, 36, m.U64, 1 << 64, m.U256):
            selected = source[off:off + 32] if off < len(source) else b''
            expected = sum(value << (8 * (31 - i)) for i, value in enumerate(selected))
            with self.subTest(offset=off):
                self.assertEqual(m.calldata_load(source, off), expected)

    def test_copy_against_bytewise_reference(self):
        old = bytes([0xa5] * 96)
        for source_length in range(34):
            source = bytes(range(source_length))
            for length in range(34):
                for src in (0, 1, 7, 31, 32, 33, m.U64, 1 << 64):
                    dst = 3
                    result = m.copy_projection(source, old, dst, src, length, 1000)
                    expected = bytearray(old)
                    for i in range(length):
                        expected[dst + i] = source[src + i] if src + i < len(source) else 0
                    self.assertEqual(result['status'], 0)
                    self.assertEqual(result['memory'], bytes(expected))
                    self.assertEqual(result['gas'], 1000 - (3 + 3 * ((length + 31) // 32)))

    def test_copy_213_success_and_growth_cost(self):
        source = m.synthetic_data()
        result = m.copy_projection(source, b'', 0, 0, 213, 45)
        self.assertEqual(result['status'], 0)
        self.assertEqual(result['gas'], 0)
        self.assertEqual(result['memory'][:213], source)
        self.assertEqual(len(result['memory']), 224)

    def test_copy_growth_insufficient_preserves_base_deduction(self):
        result = m.copy_projection(m.synthetic_data(), b'', 0, 0, 213, 44)
        self.assertEqual((result['status'], result['gas'], result['stack_count']), (0x51, 20, 0))
        self.assertEqual(result['memory'], b'')

    def test_copy_base_insufficient_preserves_gas(self):
        result = m.copy_projection(m.synthetic_data(), b'', 0, 0, 213, 23)
        self.assertEqual((result['status'], result['gas'], result['stack_count']), (0x50, 23, 0))

    def test_copy_stack_short_precedes_every_other_check(self):
        result = m.copy_projection(b'', b'', m.U256, m.U256, m.U256, 0, 2)
        self.assertEqual((result['status'], result['gas'], result['stack_count']), (0x5b, 0, 2))

    def test_copy_length_high_precedes_gas_charge(self):
        result = m.copy_projection(b'', b'', 0, 0, 1 << 64, 0)
        self.assertEqual((result['status'], result['gas']), (0x54, 0))

    def test_zero_copy_bypasses_address_width_checks(self):
        result = m.copy_projection(b'', b'', m.U256, m.U256, 0, 3)
        self.assertEqual((result['status'], result['gas']), (0, 0))
        self.assertEqual(result['memory'], b'')

    def test_nonzero_copy_destination_high_is_post_charge(self):
        result = m.copy_projection(b'', b'', 1 << 64, 0, 1, 6)
        self.assertEqual((result['status'], result['gas']), (0x54, 0))

    def test_high_source_copies_zeroes(self):
        result = m.copy_projection(b'abc', b'', 0, 1 << 64, 4, 9)
        self.assertEqual(result['status'], 0)
        self.assertEqual(result['memory'], bytes(32))

    def test_zero_return_at_exact_end_versus_past_end(self):
        a = m.copy_projection(b'abcd', b'', m.U256, 4, 0, 3, return_mode=0)
        b = m.copy_projection(b'abcd', b'', m.U256, 5, 0, 3, return_mode=0)
        c = m.copy_projection(b'abcd', b'', m.U256, 5, 0, 3, return_mode=1)
        self.assertEqual((a['status'], b['status'], c['status']), (0, 0x5d, 0))
        self.assertEqual((a['gas'], b['gas'], c['gas']), (0, 0, 0))

    def test_return_mode_zero_rejects_and_one_zero_pads(self):
        reject = m.copy_projection(b'abcd', b'', 0, 3, 2, 100, return_mode=0)
        accept = m.copy_projection(b'abcd', b'', 0, 3, 2, 100, return_mode=1)
        self.assertEqual((reject['status'], reject['gas']), (0x5d, 94))
        self.assertEqual(accept['status'], 0)
        self.assertEqual(accept['memory'][:2], b'd\0')

    def test_return_gas_check_precedes_source_bounds(self):
        result = m.copy_projection(b'abcd', b'', 0, 9, 2, 5, return_mode=0)
        self.assertEqual((result['status'], result['gas']), (0x50, 5))

    def test_memmove_overlap_in_both_directions(self):
        self.assertEqual(m.move_projection(b'abcdef', 2, 0, 4), b'ababcd')
        self.assertEqual(m.move_projection(b'abcdef', 0, 2, 4), b'cdefef')
        with self.assertRaises(ValueError):
            m.move_projection(b'abc', 1, 2, 2)

    def test_invalid_model_domains(self):
        for args in ((-1, 0, 0), (0, -1, 0), (0, 0, -1), (0, 0, 1 << 256)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                m.copy_projection(b'', b'', *args, 10)
        with self.assertRaises(ValueError):
            m.copy_projection(b'', b'', 0, 0, 1, 10, return_mode=2)
        with self.assertRaises(ValueError):
            m._grow(b'', 1_000_001, 10)

    def test_return_action_copies_complete_slice(self):
        data = bytes(range(64))
        result = m.return_projection(data, 0, 64, 0)
        self.assertEqual((result['status'], result['action_tag'], result['gas'], result['stack_count']),
                         (2, 2, 0, 0))
        self.assertEqual(result['output'], data)

    def test_return_zero_length_ignores_high_offset(self):
        result = m.return_projection(b'', m.U256, 0, 0)
        self.assertEqual((result['status'], result['action_tag'], result['output']), (2, 2, b''))

    def test_return_high_size_or_offset_fails_after_pop(self):
        a = m.return_projection(b'', 0, 1 << 64, 0)
        b = m.return_projection(b'', 1 << 64, 1, 100)
        self.assertEqual((a['status'], a['stack_count']), (0x54, 0))
        self.assertEqual((b['status'], b['stack_count']), (0x54, 0))
        self.assertIsNone(a['output'])
        self.assertIsNone(b['output'])

    def test_return_stack_underflow_precedes_width(self):
        result = m.return_projection(b'', m.U256, m.U256, 0, stack_count=1)
        self.assertEqual((result['status'], result['stack_count']), (0x5b, 1))

    def test_return_expansion_gas_boundary(self):
        fail = m.return_projection(b'', 0, 64, 5)
        success = m.return_projection(b'', 0, 64, 6)
        self.assertEqual((fail['status'], fail['gas']), (0x51, 5))
        self.assertEqual((success['status'], success['gas']), (2, 0))
        self.assertEqual(success['output'], bytes(64))

    def test_creation_prefix_and_status_precedence(self):
        reject = m.creation_projection(2, 1, 0xef, 0, 0, 1)
        prior = m.creation_projection(5, 1, 0xef, 0, 0, 1)
        self.assertEqual((reject['outcome'], reject['status']), ('rollback-prefix', 0x63))
        self.assertEqual((prior['outcome'], prior['status']), ('rollback-original-status', 5))

    def test_creation_size_boundary_and_prefix_empty(self):
        empty = m.creation_projection(2, 0, None, 0, 0x6000, 1)
        equal = m.creation_projection(2, 0x6000, 7, 0x6000 * 200, 0x6000, 1)
        high = m.creation_projection(2, 0x6001, 7, m.U64, 0x6000, 1)
        self.assertEqual(empty['outcome'], 'conditional-install')
        self.assertEqual((equal['outcome'], equal['gas']), ('conditional-install', 0))
        self.assertEqual((high['outcome'], high['status']), ('rollback-size', 0x62))

    def test_creation_gas_equality_and_failure(self):
        for length in range(4097):
            first = None if length == 0 else 1
            exact = m.creation_projection(2, length, first, 200 * length, 0x6000, 1)
            self.assertEqual((exact['outcome'], exact['gas'], exact['depth']), ('conditional-install', 0, 0))
            if length:
                short = m.creation_projection(2, length, first, 200 * length - 1, 0x6000, 1)
                self.assertEqual((short['outcome'], short['status']), ('rollback-gas', 0x50))

    def test_creation_overflow_and_zero_depth(self):
        overflow = m.creation_projection(2, m.U64 // 200 + 1, 1, m.U64, m.U64, 1)
        depth = m.creation_projection(2, 1, 1, 200, 0x6000, 0)
        self.assertEqual(overflow['outcome'], 'product-overflow')
        self.assertEqual((depth['outcome'], depth['gas']), ('depth-failure-after-charge', 0))

    def test_creation_model_rejects_malformed_scalars(self):
        for args in ((-1, 0, None, 0, 0, 0), (2, 0, 1, 0, 0, 0),
                     (2, 1, None, 0, 0, 0), (2, 1, 256, 0, 0, 0),
                     (2, 1, 1, -1, 0, 0), (2, 1, 1, 0, -1, 0)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                m.creation_projection(*args)

    def test_sample_program_is_labeled_synthetic(self):
        payload = m.synthetic_data()
        self.assertEqual(len(payload), 213)
        self.assertEqual(payload[:4], b'\x00\x00\x00\x0c')
        self.assertEqual(payload[-1], 1)
        self.assertEqual(hashlib.sha256(payload).hexdigest(),
                         'f6d7061362e134f81a20cbccfe1ab26cca7f2efdd63c9838603208434e97e0f6')


if __name__ == '__main__':
    unittest.main()
