from pathlib import Path
import hashlib
import mmap
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import re010_claim_rewards_115 as research
from fde_extents import eh_frame_records


class ClaimRewards115Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = research.ARTIFACT.read_bytes()
        cls.image = research.Image(cls.data)
        cls.c = research.constants(cls.image)

    def test_authenticated_digest(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), research.DIGEST)

    def test_truncated_digest_rejected_without_copying_the_binary(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            research.verify_digest(memoryview(self.data)[:-1])

    def test_foreign_bytes_digest_rejected(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            research.verify_digest(b'corrupted input')

    def test_selected_indexed_fdes_and_body_hashes(self):
        self.assertEqual(len(self.image.functions), 33)
        for role, start, end, digest in research.FUNCTIONS:
            row, actual = self.image.functions[role]
            with self.subTest(role=role):
                self.assertEqual((row['start'], row['end']), (start, end))
                self.assertIn('index', row)
                self.assertEqual(actual, digest)

    def test_changed_window_fingerprint_rejected(self):
        start = 0x3c17fc0
        raw = bytearray(self.image.read(start, 32, executable=True))
        original = bytes(raw)
        raw[0] ^= 1
        with self.assertRaisesRegex(ValueError, 'unexpected bytes'):
            research.expect(bytes(raw), original, 'mutated writer')

    def test_corrupted_fde_start_disagrees_with_the_unwind_index(self):
        expected = self.image.functions['reward_writer'][0]
        fde_offset = self.image.offset(expected['fde'], 12)
        with research.ARTIFACT.open('rb') as stream:
            with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_COPY) as copied:
                copied[fde_offset + 8] ^= 1
                _, records = eh_frame_records(copied, self.image.secs)
                corrupt = next(row for row in records if row['fde'] == expected['fde'])
        self.assertNotEqual(corrupt['start'], expected['start'])
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), research.DIGEST)

    def test_five_selected_switch_entries(self):
        self.assertEqual((self.c['tag_base'], self.c['ordinal']), (0x86, 5))
        tables = research.selected_tables(self.image, self.c)
        self.assertEqual([x[-1] for x in tables],
                         [0x54a3584, 0x371567e, 0x4d8344c, 0x4e0fd5d, 0x55fb3de])
        self.assertEqual(self.c['tag_base'] + self.c['ordinal'], 0x8b)

    def test_corrupted_switch_entry_is_rejected(self):
        original = self.image.read

        def tampered(va, length, *, executable=False):
            raw = original(va, length, executable=executable)
            return b'\xff' * length if va == 0x927c8c else raw

        with patch.object(self.image, 'read', side_effect=tampered):
            with self.assertRaisesRegex(ValueError, 'selected target'):
                research.selected_tables(self.image, self.c)

    def test_corrupted_top_dispatch_entry_is_rejected(self):
        original = self.image.read

        def tampered(va, length, *, executable=False):
            raw = original(va, length, executable=executable)
            return bytes(length) if va == 0x926730 else raw

        with patch.object(self.image, 'read', side_effect=tampered):
            with self.assertRaisesRegex(ValueError, 'selected target'):
                research.selected_tables(self.image, self.c)

    def test_top_route_calls_wrapper_then_handler(self):
        self.assertEqual(self.image.direct(0x54a358d)[2], 0x550ac60)
        self.assertEqual(self.image.direct(0x550b25c)[2], 0x54e3030)
        self.assertEqual(self.image.read(0x550b257, 5, executable=True).hex(),
                         '488b542428')

    def test_top_wrapper_gate_and_handler_branches(self):
        self.assertEqual(self.image.direct(0x550b20b)[2], 0x550b2d1)
        self.assertEqual(self.image.direct(0x550b249)[2], 0x550b385)
        self.assertEqual(self.image.direct(0x550b26f)[2], 0x550b2ca)
        self.assertEqual(self.image.read(0x550b1c4, 9, executable=True).hex(),
                         '66c740102001c6000f')
        self.assertEqual(self.image.read(0x550b261, 2, executable=True).hex(), 'b00e')
        self.assertEqual(self.image.read(0x550b2c8, 2, executable=True).hex(), 'b00f')

    def test_changed_tag_bias_is_rejected(self):
        original = self.image.read

        def tampered(va, length, *, executable=False):
            raw = original(va, length, executable=executable)
            if va == 0x55faadc:
                return raw[:2] + b'\x87' + raw[3:]
            return raw

        with patch.object(self.image, 'read', side_effect=tampered):
            with self.assertRaises(ValueError):
                research.constants(self.image)

    def test_name_and_type_literals(self):
        for site, prefix, length, expected in (
            (0x4d8348a, b'\x48\x8d\x05', 12, b'claimRewards'),
            (0x4d83460, b'\x48\x8d\x05', 12, b'ClaimRewards'),
            (0x4d834a4, b'\x48\x8d\x35', 18, b'ClaimRewardsAction'),
        ):
            with self.subTest(site=hex(site)):
                _, value = research.literal_at_lea(self.image, site, prefix, length, expected)
                self.assertEqual(value, expected)

    def test_corrupted_literal_is_rejected(self):
        original = self.image.read

        def tampered(va, length, *, executable=False):
            raw = original(va, length, executable=executable)
            return b'X' + raw[1:] if va == 0x9161c4 else raw

        with patch.object(self.image, 'read', side_effect=tampered):
            with self.assertRaisesRegex(ValueError, 'target literal'):
                research.literal_at_lea(self.image, 0x4d8348a, b'\x48\x8d\x05', 12, b'claimRewards')

    def test_name_matcher_length_switch_and_result(self):
        result = research.selected_name_match(self.image, self.c)
        self.assertEqual(result[:3], (12, 4, 36))
        self.assertEqual((result[3], result[4], result[6]), (0x913ea4, 0x913ec4, 0x4d6817c))
        self.assertEqual((result[7], result[8], result[9]), (b'claimRewards', 0x4d684f2, 0x0509))

    def test_name_matcher_rejects_a_corrupted_immediate(self):
        original = self.image.read

        def tampered(va, length, *, executable=False):
            raw = original(va, length, executable=executable)
            return raw[:2] + b'X' + raw[3:] if va == 0x4d6819c else raw

        with patch.object(self.image, 'read', side_effect=tampered):
            with self.assertRaisesRegex(ValueError, 'matcher name'):
                research.selected_name_match(self.image, self.c)

    def test_name_matcher_rejects_a_corrupted_result_word(self):
        original = self.image.read

        def tampered(va, length, *, executable=False):
            raw = original(va, length, executable=executable)
            return raw[:-1] + b'\x06' if va == 0x4d684f2 else raw

        with patch.object(self.image, 'read', side_effect=tampered):
            with self.assertRaisesRegex(ValueError, 'packed result'):
                research.selected_name_match(self.image, self.c)

    def test_each_name_byte_participates_in_the_selected_equality(self):
        name = research.selected_name_match(self.image, self.c)[7]
        first = int.from_bytes(name[:8], 'little')
        last = int.from_bytes(name[8:], 'little')
        for index in range(len(name)):
            candidate = bytearray(name)
            candidate[index] ^= 1
            combined = (int.from_bytes(candidate[:8], 'little') ^ first) | (int.from_bytes(candidate[8:], 'little') ^ last)
            with self.subTest(index=index):
                self.assertNotEqual(combined, 0)

    def test_name_to_boxed_action_decode_route(self):
        route = research.selected_decode_route(self.image, self.c)
        self.assertEqual((route[0], route[1], route[2], route[4]),
                         (13, 0x931b34, 0x931b64, 0x57aebff))
        self.assertEqual((route[5], route[6], route[8], route[9], route[10]),
                         (0x9136b8, 0x9136cc, 0x4d410a3, 0x918775, 0x8b))

    def test_corrupted_content_selector_is_rejected(self):
        original = self.image.read

        def tampered(va, length, *, executable=False):
            raw = original(va, length, executable=executable)
            return bytes(length) if va == 0x931b64 else raw

        with patch.object(self.image, 'read', side_effect=tampered):
            with self.assertRaisesRegex(ValueError, 'content arm'):
                research.selected_decode_route(self.image, self.c)

    def test_corrupted_decoder_switch_is_rejected(self):
        original = self.image.read

        def tampered(va, length, *, executable=False):
            raw = original(va, length, executable=executable)
            return bytes(length) if va == 0x9136cc else raw

        with patch.object(self.image, 'read', side_effect=tampered):
            with self.assertRaisesRegex(ValueError, 'decoder ordinal arm'):
                research.selected_decode_route(self.image, self.c)

    def test_corrupted_decoder_tag_is_rejected(self):
        original = self.image.read

        def tampered(va, length, *, executable=False):
            raw = original(va, length, executable=executable)
            return raw[:2] + b'\x8c' + raw[3:] if va == 0x4d410c9 else raw

        with patch.object(self.image, 'read', side_effect=tampered):
            with self.assertRaisesRegex(ValueError, 'decoded internal tag'):
                research.selected_decode_route(self.image, self.c)

    def test_decoder_payload_failure_and_empty_content_success(self):
        self.assertEqual(self.image.direct(0x4d410c3)[2], 0x4d41e73)
        self.assertEqual(self.image.direct(0x573ddbb)[2], 0x573dedd)
        self.assertEqual(self.image.read(0x573dedd, 3, executable=True).hex(), 'c60309')

    def test_container_handoff_keeps_box_for_selected_three_fields(self):
        self.assertEqual(self.image.direct(0x5707df2)[2], 0x5708456)
        self.assertEqual(self.image.direct(0x5708608)[2], 0x4d3f940)
        self.assertEqual(self.image.direct(0x5708614)[2], 0x5708bbf)
        self.assertEqual(self.image.read(0x570861a, 5, executable=True).hex(), '488b5c2478')
        self.assertEqual(self.image.read(0x570864f, 4, executable=True).hex(), '49895d00')
        self.assertEqual(self.image.direct(0x5708661)[2], 0x5708b59)

    def test_container_handoff_rejects_changed_pointer_store(self):
        original = self.image.read

        def tampered(va, length, *, executable=False):
            raw = original(va, length, executable=executable)
            return b'\x90' + raw[1:] if va == 0x570864f else raw

        with patch.object(self.image, 'read', side_effect=tampered):
            with self.assertRaisesRegex(ValueError, 'container decoded pointer store'):
                research.selected_decode_route(self.image, self.c)

    def test_nested_outer_decoder_and_parent_pointer_offsets(self):
        tag, ordinal, tables, content, boxed, payload, parent = research.selected_nested_handoff(self.image, self.c)
        self.assertEqual((tag, ordinal), (0xba, 52))
        self.assertEqual([(row[1], row[3]) for row in tables],
                         [(0x913788, 0x4d41bd0), (0x9267ec, 0x54a384d)])
        self.assertEqual((content, boxed, payload, parent), (0x18, 0x20, 8, 0x18))

    def test_nested_handoff_rejects_changed_outer_switch(self):
        original = self.image.read

        def tampered(va, length, *, executable=False):
            raw = original(va, length, executable=executable)
            return bytes(length) if va == 0x9267ec else raw

        with patch.object(self.image, 'read', side_effect=tampered):
            with self.assertRaisesRegex(ValueError, 'outer selected table target'):
                research.selected_nested_handoff(self.image, self.c)

    def test_nested_handoff_rejects_changed_child_store(self):
        original = self.image.read

        def tampered(va, length, *, executable=False):
            raw = original(va, length, executable=executable)
            return raw[:-1] + b'\x20' if va == 0x56f9414 else raw

        with patch.object(self.image, 'read', side_effect=tampered):
            with self.assertRaisesRegex(ValueError, 'outer child pointer store'):
                research.selected_nested_handoff(self.image, self.c)

    def test_selected_direct_calls_and_branches(self):
        self.assertEqual(self.image.direct(0x551d1e4)[2], 0x55faa80)
        self.assertEqual(self.image.direct(0x55fb3e7)[2], 0x54e3030)
        self.assertEqual(self.image.direct(0x3c18145)[2], 0x3c180f0)
        self.assertEqual(self.image.direct(0x3c1815b)[2], 0x3c1819b)
        self.assertEqual(len(research.DIRECT_EDGES), 129)
        for _, site in research.DIRECT_EDGES:
            kind, raw, target = self.image.direct(site)
            with self.subTest(site=hex(site)):
                self.assertIn(kind.split('-')[0], ('call', 'jmp', 'jcc'))
                self.assertTrue(raw)
                self.assertGreater(target, 0)

    def test_unknown_and_truncated_branch_encodings_are_rejected(self):
        for raw in (b'\x90\x00', b'\x0f\x84\x00', b'\xe8\x00'):
            with self.subTest(raw=raw.hex()), self.assertRaises(ValueError):
                research.decode_direct(raw, 0x1000)

    def test_out_of_range_branch_target_is_rejected(self):
        original = self.image.read

        def tampered(va, length, *, executable=False):
            if va == 0x3c18145 and length == 6:
                return bytes.fromhex('e90000008090')
            return original(va, length, executable=executable)

        with patch.object(self.image, 'read', side_effect=tampered):
            with self.assertRaisesRegex(ValueError, 'invalid virtual-address range|file-backed'):
                self.image.direct(0x3c18145)

    def test_rip_relative_and_short_operand_controls(self):
        self.assertEqual(research.decode_rip(bytes.fromhex('ff159c490001'),
                                             0x54e3076, b'\xff\x15'), 0x64e7a18)
        with self.assertRaises(ValueError):
            research.decode_rip(bytes.fromhex('ff149c490001'), 0x54e3076, b'\xff\x15')
        with self.assertRaises(ValueError):
            research.decode_rip(bytes.fromhex('ff159c49'), 0x54e3076, b'\xff\x15')

    def test_indirect_calls_resolve_relative_records(self):
        expected = {0x54e3076: 0x3c17fc0, 0x3c18118: 0x3c49360,
                    0x54e3298: 0x434f790, 0x54e359d: 0x51fb310}
        for site, addend in expected.items():
            with self.subTest(site=hex(site)):
                _, row = self.image.indirect(site)
                self.assertEqual(row[1], 8)
                self.assertEqual(row[2], addend)

    def test_missing_or_duplicate_relocation_is_rejected(self):
        row = (0x1000, 8, 0x2000, 0x40)
        with self.assertRaisesRegex(ValueError, 'missing or duplicate'):
            research.unique_relocation([], 0x1000)
        with self.assertRaisesRegex(ValueError, 'missing or duplicate'):
            research.unique_relocation([row, row], 0x1000)

    def test_nonrelative_relocation_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'RELATIVE'):
            research.unique_relocation([(0x1000, 6, 0x2000, 0x40)], 0x1000)

    def test_selected_dynamic_imports(self):
        for site, expected in ((0x4553936, 'memcmp'), (0x51ca55d, 'memcpy'),
                               (0x4d423d2, 'memcpy')):
            with self.subTest(site=hex(site)):
                _, row, index, name = self.image.imported(site)
                self.assertEqual(row[1] & 0xffffffff, 6)
                self.assertGreater(index, 0)
                self.assertEqual(name, expected)

    def test_bad_dynamic_symbol_index_and_type_rejected(self):
        row = (0x1000, (2 << 32) | 6, 0, 0)
        with self.assertRaisesRegex(ValueError, 'symbol index'):
            research.imported_symbol(row, bytes(48), b'\0memcmp\0')
        with self.assertRaisesRegex(ValueError, 'GLOB_DAT'):
            research.imported_symbol((0x1000, (1 << 32) | 8, 0, 0), bytes(48), b'\0memcmp\0')

    def test_bad_dynamic_symbol_name_bounds_rejected(self):
        row = (0x1000, (1 << 32) | 6, 0, 0)
        symbols = bytes(24) + struct.pack('<IBBHQQ', 99, 0, 0, 0, 0, 0)
        with self.assertRaisesRegex(ValueError, 'outside string'):
            research.imported_symbol(row, symbols, b'\0memcmp\0')
        symbols = bytes(24) + struct.pack('<IBBHQQ', 1, 0, 0, 0, 0, 0)
        with self.assertRaisesRegex(ValueError, 'unterminated'):
            research.imported_symbol(row, symbols, b'\0memcmp')

    def test_nobits_section_is_never_file_backed(self):
        sec = {'type': 8, 'flags': 6, 'address': 0x1000, 'offset': 0, 'size': 64}
        with self.assertRaisesRegex(ValueError, 'file-backed'):
            research.file_offset([sec], 64, 0x1000, 1)

    def test_ambiguous_section_mapping_is_rejected(self):
        sec = {'type': 1, 'flags': 6, 'address': 0x1000, 'offset': 0, 'size': 16}
        with self.assertRaisesRegex(ValueError, 'uniquely'):
            research.file_offset([sec, dict(sec)], 32, 0x1000, 1)

    def test_range_crossing_section_end_is_rejected(self):
        sec = {'type': 1, 'flags': 6, 'address': 0x1000, 'offset': 0, 'size': 16}
        self.assertEqual(research.file_offset([sec], 16, 0x100f, 1), 15)
        for address, length in ((0x100f, 2), (0xfff, 1), (0x1010, 1), (0x1000, 0)):
            with self.subTest(address=address, length=length), self.assertRaises(ValueError):
                research.file_offset([sec], 16, address, length)

    def test_non_executable_mapping_is_rejected_for_code(self):
        sec = {'type': 1, 'flags': 2, 'address': 0x1000, 'offset': 0, 'size': 16}
        with self.assertRaises(ValueError):
            research.file_offset([sec], 16, 0x1000, 1, executable=True)

    def test_status_words_are_target_specific(self):
        self.assertEqual((self.c['not_found'], self.c['nonzero_but_unclaimed'], self.c['success']),
                         (0xaa, 0xab, 0x1a2))
        self.assertNotEqual(self.c['success'], 0x186)

    def test_writer_comparison_and_status_instructions(self):
        actual = self.image.read(0x3c18135, 18, executable=True)
        self.assertEqual(actual.hex(), '4939d60f93c120c16641bdab0080f90175a9')
        kind, _, target = self.image.direct(0x3c18145)
        self.assertEqual((kind, target), ('jcc-5', 0x3c180f0))

    def test_writer_store_order_and_unsigned_saturation_instructions(self):
        actual = self.image.read(0x3c18147, 22, executable=True)
        self.assertEqual(actual.hex(), '49c744240800000000498b5c24104889d84c01f0723e')
        overflow = self.image.read(0x3c181aa, 20, executable=True)
        self.assertEqual(overflow.hex(), '4c01f348c7c0ffffffff480f42d84889d8498944')

    def test_decimal_inputs_and_conversion_width_instruction_anchors(self):
        self.assertEqual(self.image.read(0x3c49377, 19, executable=True).hex(),
                         '488b47200fb648494869d6580100002a4c1048')
        self.assertEqual(self.image.read(0x4217e81, 15, executable=True).hex(),
                         '0fb65408492a5408480f82e1000000')
        self.assertEqual(self.image.read(0x4217ede, 11, executable=True).hex(),
                         '31c04885f60f94c04889ca')

    def test_wide_division_low_divisor_instruction_anchor(self):
        self.assertEqual(self.image.read(0x63eff39, 17, executable=True).hex(),
                         '4c39c6730c4889f84889f249f7f031d2c3')

    def test_value_limit_and_cap_instruction_anchors(self):
        self.assertEqual(self.image.read(0x434f7d6, 11, executable=True).hex(),
                         'ba640000004889c848f7e2')
        self.assertEqual(self.image.read(0x434f82c, 24, executable=True).hex(),
                         '4885f60f94c048ba5c8fc2f5285c8f024839d10f92c220c2')
        self.assertEqual(self.image.read(0x54e32ff, 25, executable=True).hex(),
                         '48837c08400475114801c8488b40388b003b05fa6bf7fa749a')

    def test_collector_comparison_and_branch_instruction_anchor(self):
        self.assertEqual(self.image.read(0x51fb367, 11, executable=True).hex(),
                         '31c0483b8398070000712c')
        self.assertEqual(self.image.direct(0x51fb370)[2], 0x51fb39e)

    def test_compact_lookup_and_representation_threshold_anchors(self):
        self.assertEqual(self.image.read(0x455397e, 13, executable=True).hex(),
                         '85c0b8000000000f95c04d01ee')
        self.assertEqual(self.image.read(0x3c003ed, 12, executable=True).hex(),
                         '4883f8200f92c220ca80fa01')
        self.assertEqual(self.image.read(0x3c004b9, 12, executable=True).hex(),
                         '4885c0745349837f183f764c')

    def test_empty_asset_tree_insertion_anchors(self):
        self.assertEqual(self.image.read(0x370e17c, 5, executable=True).hex(), 'bf68000000')
        self.assertEqual(self.image.read(0x370e1a4, 27, executable=True).hex(),
                         '0fb748624883f90b7345498b56088d710166897062488954c80831')
        self.assertEqual(self.image.read(0x370e1c0, 7, executable=True).hex(), '49ff4710498b36')

    def test_event_sink_vector_append_anchors(self):
        self.assertEqual(self.image.read(0x51ca541, 49, executable=True).hex(),
                         '4969c6f8000000480387b8000000baf80000004989ff4889c74889de'
                         'ff15a54f310149ffc64d89b7c0000000e9f2010000')

    def test_side_map_representation_boundaries(self):
        c = self.c
        self.assertEqual((c['side_tree_to_compact_below'], c['side_compact_to_tree_above']), (32, 63))
        for is_tree, count, found, expected in (
            (True, 31, False, False), (True, 31, True, False),
            (True, 32, False, True), (False, 63, False, False),
            (False, 64, False, True), (False, 64, True, False),
        ):
            with self.subTest(tree=is_tree, count=count, found=found):
                self.assertEqual(research.model_side_map_representation(is_tree, count, found, c), expected)

    def test_missing_empty_and_zero_rows(self):
        for present, rows in ((False, []), (True, []), (True, [(3, 0, 9, 1)])):
            with self.subTest(present=present, rows=rows):
                status, _, paid = research.model_rows(present, rows, self.c)
                self.assertEqual((status, paid), (0xaa, []))

    def test_threshold_equal_and_adjacent(self):
        for amount, status in ((99, 0xab), (100, 0x1a2), (101, 0x1a2)):
            with self.subTest(amount=amount):
                result, rows, paid = research.model_rows(True, [(9, amount, 7, 100)], self.c)
                self.assertEqual(result, status)
                self.assertEqual(bool(paid), amount >= 100)
                self.assertEqual(rows[0][1], 0 if amount >= 100 else amount)

    def test_zero_threshold_still_skips_a_zero_amount(self):
        result, rows, paid = research.model_rows(True, [(1, 0, 4, 0), (2, 1, 4, 0)], self.c)
        self.assertEqual((result, rows, paid), (0x1a2, [(1, 0, 4), (2, 0, 5)], [(2, 1)]))

    def test_unrepresentable_threshold_does_not_claim(self):
        maximum = (1 << 64) - 1
        result, rows, paid = research.model_rows(True, [(4, maximum, 9, None)], self.c)
        self.assertEqual((result, rows, paid), (0xab, [(4, maximum, 9)], []))

    def test_saturating_u64_claim_and_mixed_rows(self):
        maximum = (1 << 64) - 1
        result, rows, paid = research.model_rows(True, [(1, 7, maximum - 2, 7),
                                                        (2, 4, 12, 5)], self.c)
        self.assertEqual(result, 0x1a2)
        self.assertEqual(rows, [(1, 0, maximum), (2, 4, 12)])
        self.assertEqual(paid, [(1, 7)])

    def test_negative_and_too_large_row_inputs_rejected(self):
        for row in ((1, -1, 0, 1), (1, 1 << 64, 0, 1), (1, 1, 0, -1), (True, 1, 0, 1)):
            with self.subTest(row=row), self.assertRaises(ValueError):
                research.model_rows(True, [row], self.c)

    def test_floor_threshold_calculation(self):
        n = self.c['threshold_numerator']
        self.assertEqual(n, 100000000)
        self.assertEqual(research.threshold(8, 0, 8, n), 100000000)
        self.assertEqual(research.threshold(8, 2, 6, n), 1000000)
        self.assertEqual(research.threshold(19, 0, 0, n), 0)
        self.assertEqual(research.threshold(19, 0, 19, n), 100000000)

    def test_bad_metadata_and_power_boundaries(self):
        n = self.c['threshold_numerator']
        for args in ((7, 8, 8, n), (8, 2, 1, n), (20, 0, 8, n),
                     (8, 0, 20, n), (256, 0, 8, n), (True, 0, 8, n), (8, 0, 8, -1)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                research.threshold(*args)

    def test_threshold_quotient_larger_than_u64(self):
        self.assertIsNone(research.threshold(0, 0, 19, self.c['threshold_numerator']))

    def test_value_caps_and_exact_name(self):
        cap = 10 ** 16
        for asset, name, expected in ((1, b'X', 2 * cap), (2, b'HYPE', 2 * cap),
                                      (2, b'OTHER', cap), (2, b'hype', cap),
                                      (2, b'HYPE2', cap)):
            with self.subTest(asset=asset, name=name):
                self.assertEqual(research.model_value(asset, 2 * cap, 100, 0, name, self.c), expected)

    def test_zero_asset_and_missing_mark(self):
        self.assertEqual(research.model_value(0, 12349, 0, 0, b'', self.c), 123)
        self.assertEqual(research.model_value(2, 12349, 0, 0, b'HYPE', self.c), 0)

    def test_value_conversion_limit_is_strict(self):
        limit = self.c['value_conversion_limit']
        self.assertEqual(research.model_value(1, limit - 1, 100, 0, b'', self.c), limit - 1)
        self.assertEqual(research.model_value(1, limit, 100, 0, b'', self.c), 0)

    def test_value_division_rounds_down(self):
        self.assertEqual(research.model_value(1, 999, 13, 1, b'', self.c), 12)

    def test_value_input_controls(self):
        for args in ((1, -1, 1, 0, b''), (1, 1, 1, 20, b''), (1, 1, 1, 0, 'HYPE')):
            with self.subTest(args=args), self.assertRaises(ValueError):
                research.model_value(*args, self.c)

    def test_signed_account_saturates(self):
        maximum = (1 << 63) - 1
        self.assertEqual(research.model_account_add(maximum - 1, 10000), maximum)
        self.assertEqual(research.model_account_add(maximum - 1, 20000), maximum)
        self.assertEqual(research.model_account_add(-10, 19999), -9)

    def test_collector_sentinel_branch(self):
        sentinel = self.c['layout_sentinel']
        self.assertFalse(research.model_event_enabled(sentinel, sentinel))
        for value in (0, sentinel - 1, sentinel + 1, (1 << 64) - 1):
            with self.subTest(value=value):
                self.assertTrue(research.model_event_enabled(value, sentinel))

    def test_account_magic_division_against_integer_division(self):
        magic = self.c['account_divisor_magic']
        samples = list(range(30001)) + [9999, 10000, 10001, (1 << 63) - 1,
                                        (1 << 64) - 1, 10 ** 16, 10 ** 18]
        for value in samples:
            self.assertEqual(((value * magic) >> 64) >> 11, value // 10000)

    def test_zero_asset_magic_division_against_integer_division(self):
        magic = self.c['zero_asset_divisor_magic']
        samples = list(range(20001)) + [99, 100, 101, (1 << 63) - 1, (1 << 64) - 1]
        for value in samples:
            self.assertEqual(((((value >> 2) * magic) >> 64) >> 2), value // 100)

    def test_reproduction_matches_the_checked_in_evidence(self):
        reference = research.ROOT / 'research/work-items/RE-010-claim-rewards-path-115'
        with tempfile.TemporaryDirectory() as name:
            out = Path(name)
            research.generate(self.image, out)
            generated = sorted(p.name for p in out.iterdir())
            self.assertEqual(len(generated), 12)
            for filename in generated:
                with self.subTest(filename=filename):
                    self.assertEqual((out / filename).read_bytes(), (reference / filename).read_bytes())


if __name__ == '__main__':
    unittest.main()
