"""Static extraction and negative controls for the #94 signer-recovery path."""
import copy
import hashlib
import itertools
from pathlib import Path
import struct
import unittest

from tools import re21_signer_recovery94 as m


class SignerRecoveryEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (m.ROOT / m.TARGET).read_bytes()
        cls.image = m.Image(cls.data)
        cls.fdes = m.selected_fdes(cls.data)
        cls.rows, cls.by_site = m.build_instruction_maps(cls.image, cls.fdes)
        cls.relas = m.relocations(cls.image)
        cls.generated = m.collect(cls.data)

    def test_input_hash_is_exact(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), m.SHA256)
        m.authenticate(self.data)
        with self.assertRaises(m.EvidenceError):
            m.authenticate(b'tampered target')

    def test_target_corruption_rejected_before_parsing(self):
        edited = bytearray(self.data)
        edited[self.image.offset(0x4e57ca3, 1)] ^= 1
        with self.assertRaisesRegex(m.EvidenceError, 'digest mismatch'):
            m.Image(edited)

    def test_invalid_elf_rejected(self):
        with self.assertRaises(ValueError):
            m.Image(b'not an ELF', check_hash=False)

    def test_file_mapping_rejects_unmapped_crossing_and_nobits(self):
        with self.assertRaises(m.EvidenceError):
            self.image.offset(0, 1)
        with self.assertRaises(m.EvidenceError):
            self.image.offset(0x5788468, 8)
        text = self.image.section('.text')
        with self.assertRaises(m.EvidenceError):
            self.image.offset(text['address'] + text['size'] - 1, 2, executable=True)
        with self.assertRaises(m.EvidenceError):
            self.image.offset(-1, 1)
        with self.assertRaises(m.EvidenceError):
            self.image.offset(0x4e57c90, 0)

    def test_ambiguous_mapping_rejected(self):
        fake = object.__new__(m.Image)
        fake.data = bytes(16)
        sec = {'name': 'x', 'type': 1, 'flags': 6, 'address': 0x1000, 'offset': 0, 'size': 8}
        fake.sections = [sec, dict(sec, name='duplicate')]
        with self.assertRaises(m.EvidenceError):
            fake.offset(0x1001, 1)

    def test_selected_fdes_are_unique_and_indexed(self):
        self.assertEqual(set(self.fdes), set(m.FUNCTIONS))
        for start, f in self.fdes.items():
            self.assertEqual(start, f['start'])
            self.assertLess(start, f['end'])
            self.assertIn('index', f)
            self.image.offset(start, f['end'] - start, executable=True)

    def test_missing_and_duplicate_fdes_rejected(self):
        records = list(self.fdes.values())
        with self.assertRaises(m.EvidenceError):
            m.select_fde_records(records[:-1])
        with self.assertRaises(m.EvidenceError):
            m.select_fde_records(records + [records[0]])
        bad = [dict(row) for row in records]
        bad[0]['end'] = bad[0]['start']
        with self.assertRaises(m.EvidenceError):
            m.select_fde_records(bad)

    def test_all_selected_instruction_shapes_are_pinned(self):
        m.validate_pins(self.by_site)
        for site in m.PINS:
            altered = dict(self.by_site)
            record = dict(altered[site])
            raw = bytearray(record['raw'])
            raw[-1] ^= 1
            record['raw'] = bytes(raw)
            altered[site] = record
            with self.subTest(site=hex(site)), self.assertRaises(m.EvidenceError):
                m.validate_pins(altered)

    def test_missing_instruction_boundary_rejected(self):
        with self.assertRaises(m.EvidenceError):
            m.instruction(self.by_site, 0x4e57ca4)

    def test_unknown_and_truncated_instruction_rejected(self):
        with self.assertRaises(m.EvidenceError):
            m.decode_instruction(bytes.fromhex('0f0f'))
        with self.assertRaises(m.EvidenceError):
            m.decode_instruction(bytes.fromhex('e801'))
        with self.assertRaises(m.EvidenceError):
            m.decode_instruction(bytes.fromhex('f001c0'))

    def test_branch_into_instruction_rejected(self):
        site = 0x4e57ca6
        fde = self.fdes[0x4e57c90]
        original = self.image
        class Mutated:
            def read(self, va, size, executable=False):
                raw = bytearray(original.read(va, size, executable))
                pos = site - va
                struct.pack_into('<i', raw, pos + 2, (site + 1) - (site + 6))
                return bytes(raw)
        with self.assertRaisesRegex(m.EvidenceError, 'into instruction'):
            m.decode_body(Mutated(), fde)

    def test_relative_branch_targets(self):
        self.assertEqual(m.relative_target(self.by_site[0x4e57ca6]), 0x4e57fe9)
        self.assertEqual(m.relative_target(self.by_site[0x564078f]), 0x56407e8)
        self.assertEqual(m.relative_target(self.by_site[0x5640905]), 0x563ecc0)

    def test_relocation_bindings_and_dynamic_symbol(self):
        self.assertEqual(int(self.relas[0x576fe68]['addend'], 16), 0x5640710)
        self.assertEqual(int(self.relas[0x576fd30]['addend'], 16), 0x5640860)
        self.assertEqual(int(self.relas[0x576fe70]['addend'], 16), 0x5640530)
        self.assertEqual(self.relas[0x576dfe0]['symbol'], 'memcpy')
        self.assertEqual(len(m.verify_relocation_edges(self.by_site, self.relas)), 17)

    def test_wrong_relocation_type_rejected(self):
        edited = bytearray(self.data)
        off = int(self.relas[0x576fe68]['entry_file_offset'], 16)
        struct.pack_into('<Q', edited, off + 8, 7)
        broken = m.Image(edited, check_hash=False)
        with self.assertRaises(m.EvidenceError):
            m.relocations(broken)

    def test_wrong_relocation_addend_rejected(self):
        edited = bytearray(self.data)
        off = int(self.relas[0x576fd30]['entry_file_offset'], 16)
        struct.pack_into('<q', edited, off + 16, 0x5640861)
        broken = m.Image(edited, check_hash=False)
        with self.assertRaises(m.EvidenceError):
            m.relocations(broken)

    def test_corrupt_call_slot_displacement_rejected(self):
        edited = dict(self.by_site)
        row = dict(edited[0x4e57ce6])
        raw = bytearray(row['raw'])
        raw[2] ^= 1
        row['raw'] = bytes(raw)
        edited[0x4e57ce6] = row
        with self.assertRaises(m.EvidenceError):
            m.verify_relocation_edges(edited, self.relas)

    def test_once_context_points_to_nobits(self):
        layout = m.static_layout(self.image, self.by_site, self.relas)
        self.assertFalse(layout['context_pointer_file_backed'])
        self.assertEqual(layout['context_section_type'], 8)
        self.assertEqual(layout['reported_context_size'], 208)
        self.assertEqual(layout['construction_flags'], 0x301)
        self.assertEqual(layout['descriptor_method_addend'], '0x4eb8650')

    def test_wrong_once_callback_rejected(self):
        relas = copy.deepcopy(self.relas)
        relas[0x5750e60]['addend'] = '0x4eb8651'
        with self.assertRaises(m.EvidenceError):
            m.static_layout(self.image, self.by_site, relas)

    def test_selftest_matches_independent_sha256(self):
        value = m.selftest(self.image, self.by_site)
        self.assertEqual(value['message_length'], 63)
        self.assertEqual(hashlib.sha256(bytes.fromhex(value['message_hex'])).hexdigest(),
                         value['expected_digest'])
        self.assertEqual(value['expected_digest'],
                         'f08a78cbbaee082b052ae0708f32fa1e50c5c421aa772ba5dbb406a2ea6be342')

    def test_selftest_message_corruption_rejected(self):
        original = self.image
        class Mutated:
            def read(self, va, size, executable=False):
                raw = bytearray(original.read(va, size, executable))
                if va == 0x203ad0:
                    raw[0] ^= 1
                return bytes(raw)
        with self.assertRaises(m.EvidenceError):
            m.selftest(Mutated(), self.by_site)

    def test_selftest_expected_digest_corruption_rejected(self):
        original = self.image
        class Mutated:
            def read(self, va, size, executable=False):
                raw = bytearray(original.read(va, size, executable))
                if va == 0x806880:
                    raw[-1] ^= 1
                return bytes(raw)
        with self.assertRaises(m.EvidenceError):
            m.selftest(Mutated(), self.by_site)

    def test_field_output_matches_independent_integer_encoding(self):
        for bit in range(256):
            value = 1 << bit
            limbs = [(value >> (52 * i)) & ((1 << 52) - 1) for i in range(5)]
            self.assertEqual(m.limb_bytes(limbs), value.to_bytes(32, 'big'))
        for value in (0, 1, (1 << 256) - 1, 0x123456789abcdef):
            limbs = [(value >> (52 * i)) & ((1 << 52) - 1) for i in range(5)]
            self.assertEqual(m.limb_bytes(limbs), value.to_bytes(32, 'big'))
        with self.assertRaises(m.EvidenceError):
            m.limb_bytes([0, 0, 0, 0, 1 << 48])

    def test_modified_field_shift_rejected(self):
        rows = {k: [dict(x) for x in value] for k, value in self.rows.items()}
        ins = next(x for x in rows[0x5632c40] if x['site'] == 0x5632c7b)
        raw = bytearray(ins['raw'])
        raw[-1] ^= 1
        ins['raw'] = bytes(raw)
        with self.assertRaises(m.EvidenceError):
            m.field_store_rows(rows)

    def test_serializer_capacity_boundaries_and_prefixes(self):
        params = m.serializer_parameters(self.by_site)
        self.assertEqual(params['base_size'], 33)
        self.assertEqual(params['uncompressed_extra'], 32)
        small = m.serializer_projection(params, capacity=64, flags=2)
        self.assertEqual((small['reason'], small['length_word'], small['cleared_bytes']),
                         ('capacity_callback', 'unchanged', 0))
        exact = m.serializer_projection(params, capacity=65, flags=2)
        self.assertEqual((exact['reason'], exact['length_word'], exact['prefix']),
                         ('success', 'required', 4))
        compressed = m.serializer_projection(params, capacity=33, flags=0x102, y_low_bit=1)
        self.assertEqual((compressed['reason'], compressed['prefix']), ('success', 3))

    def test_serializer_failure_order_and_memory_effects(self):
        p = m.serializer_parameters(self.by_site)
        null_length = m.serializer_projection(p, capacity=65, flags=2, length_pointer=False,
                                              output_pointer=False)
        self.assertEqual((null_length['reason'], null_length['length_word'], null_length['cleared_bytes']),
                         ('null_length_callback', 'unchanged', 0))
        null_output = m.serializer_projection(p, capacity=65, flags=2, output_pointer=False)
        self.assertEqual((null_output['reason'], null_output['length_word'], null_output['cleared_bytes']),
                         ('null_output_callback', 'zero', 0))
        null_key = m.serializer_projection(p, capacity=66, flags=2, key_pointer=False)
        self.assertEqual((null_key['reason'], null_key['length_word'], null_key['cleared_bytes']),
                         ('null_key_callback', 'zero', 66))
        invalid = m.serializer_projection(p, capacity=65, flags=0)
        self.assertEqual((invalid['reason'], invalid['length_word'], invalid['cleared_bytes']),
                         ('invalid_flag_callback', 'zero', 65))
        failed = m.serializer_projection(p, capacity=65, flags=2, conversion_ok=False)
        self.assertEqual((failed['returns'], failed['length_word'], failed['cleared_bytes']), (0, 'zero', 65))
        with self.assertRaises(m.EvidenceError):
            m.serializer_projection(p, capacity=-1, flags=2)

    def test_serializer_size_operand_corruption_rejected(self):
        altered = dict(self.by_site)
        record = dict(altered[0x564057b])
        record['raw'] = bytes.fromhex('4883c522')
        altered[0x564057b] = record
        with self.assertRaises(m.EvidenceError):
            m.serializer_parameters(altered)

    def test_parser_status_and_recovery_failure_precedence(self):
        self.assertEqual(m.recovery_projection(0, 0, 0, 1), 'serialize_public_key')
        self.assertEqual(m.recovery_projection(3, 1, 0, 1), 'outer_error_3')
        self.assertEqual(m.recovery_projection(3, 0, 1, 1), 'outer_error_3')
        self.assertEqual(m.recovery_projection(0, 0, 0, 0), 'outer_error_3')
        self.assertEqual(m.recovery_projection(4, 1, 1, 0), 'outer_error_6')
        with self.assertRaises(m.EvidenceError):
            m.recovery_projection(-1, 0, 0, 1)
        with self.assertRaises(m.EvidenceError):
            m.recovery_projection(0, 1 << 32, 0, 1)

    def test_every_recovery_byte_and_helper_status(self):
        for recid in range(256):
            for first, second, recovered in ((0, 0, 1), (1, 0, 1), (0, 1, 1), (0, 0, 0)):
                expected = ('outer_error_6' if recid >= 4 else
                            'serialize_public_key' if (first, second, recovered) == (0, 0, 1)
                            else 'outer_error_3')
                self.assertEqual(m.recovery_projection(recid, first, second, recovered), expected)

    def test_parser_checks_combined_status_after_both_calls(self):
        rows = m.parser_call_order(self.rows, self.by_site)
        self.assertEqual(len(rows), 8)
        self.assertEqual(rows[1][2], rows[5][2])
        self.assertLess(int(rows[5][0], 16), int(rows[7][0], 16))
        edited = dict(self.by_site)
        record = dict(edited[0x5640780])
        record['raw'] = bytes.fromhex('448b6c2410')
        edited[0x5640780] = record
        with self.assertRaises(m.EvidenceError):
            m.parser_call_order(self.rows, edited)

    def test_compact_temporary_copy_lanes(self):
        lanes = m.compact_copy_lanes(self.by_site)
        self.assertEqual(len(lanes), 64)
        for bit in range(512):
            temporary = bytearray(64)
            temporary[bit // 8] = 1 << (bit % 8)
            result = bytearray(64)
            for source, destination, *_ in lanes:
                result[destination] = temporary[source]
            self.assertEqual(result, temporary)

    def test_corrupt_compact_copy_operand_rejected(self):
        edited = dict(self.by_site)
        row = dict(edited[0x5640791])
        row['raw'] = bytes.fromhex('660f6f4c2411')
        edited[0x5640791] = row
        with self.assertRaises(m.EvidenceError):
            m.compact_copy_lanes(edited)

    def test_each_result_bit_preserves_the_expected_digest_lane(self):
        lanes = m.address_lane_rows(self.by_site)
        for bit in range(256):
            digest = bytearray(32)
            digest[bit // 8] = 1 << (bit % 8)
            out = bytearray(21)
            for _, _, src, dst in lanes:
                out[dst] = digest[src]
            self.assertEqual(out[1:], digest[12:])

    def test_dynamic_symbol_corruption_rejected(self):
        edited = bytearray(self.data)
        strings = self.image.section('.dynstr')
        blob = bytes(edited[strings['offset']:strings['offset'] + strings['size']])
        position = blob.find(b'memcpy\0')
        self.assertGreaterEqual(position, 0)
        edited[strings['offset'] + position] ^= 1
        with self.assertRaises(m.EvidenceError):
            m.relocations(m.Image(edited, check_hash=False))

    def test_digest_to_address_lanes(self):
        lanes = m.address_lane_rows(self.by_site)
        self.assertEqual([row[2] for row in lanes], list(range(12, 32)))
        self.assertEqual([row[3] for row in lanes], list(range(1, 21)))
        digest = bytes(range(32))
        output = bytearray(21)
        for _, _, src, dst in lanes:
            output[dst] = digest[src]
        self.assertEqual(output[1:], digest[-20:])

    def test_corrupted_result_store_rejected(self):
        edited = dict(self.by_site)
        row = dict(edited[0x4e57fe0])
        row['raw'] = bytes.fromhex('0f114302')
        edited[0x4e57fe0] = row
        with self.assertRaises(m.EvidenceError):
            m.address_lane_rows(edited)

    def test_exception_table_and_landing(self):
        fde = self.fdes[0x4eb8650]
        starts = {row['site'] for row in self.rows[fde['start']]}
        rows, header = m.exception_table(self.image, fde, starts)
        self.assertEqual(len(rows), 3)
        self.assertEqual([row[6] for row in rows if row[6]], ['0x4eb86fd'])
        self.assertIsNotNone(header)
        with self.assertRaises(m.EvidenceError):
            m.exception_table(self.image, fde, set())

    def test_corrupt_exception_encoding_rejected(self):
        fde = self.fdes[0x4eb8650]
        edited = bytearray(self.data)
        edited[self.image.offset(fde['lsda'], 1)] ^= 1
        fake = copy.copy(self.image)
        fake.data = edited
        starts = {row['site'] for row in self.rows[fde['start']]}
        with self.assertRaises(m.EvidenceError):
            m.exception_table(fake, fde, starts)

    def test_target_assertions_are_file_backed(self):
        assertions = m.assertion_strings(self.image, self.by_site)
        self.assertIn('input64 != NULL', [x['value'] for x in assertions])
        self.assertIn('recid >= 0 && recid <= 3', [x['value'] for x in assertions])

    def test_retained_evidence_matches_fresh_generation(self):
        directory = m.ROOT / 'research/work-items/RE-021-signer-recovery-94'
        for name, content in self.generated.items():
            with self.subTest(name=name):
                self.assertEqual((directory / name).read_bytes(), content)


if __name__ == '__main__':
    unittest.main()
