"""Static, non-executing controls for the selected node #94 transaction paths."""
import copy
import json
from pathlib import Path
import struct
import unittest
from unittest import mock

from tools import re21_typed34_inputs94 as subject


def rlp_encode(value):
    """Small independent fixture encoder; this is not a target execution."""
    if isinstance(value, int):
        if value < 0:
            raise ValueError('negative integer')
        value = value.to_bytes((value.bit_length() + 7) // 8, 'big')
    if isinstance(value, list):
        payload = b''.join(rlp_encode(x) for x in value)
        offset = 0xc0
    elif isinstance(value, bytes):
        payload = value
        if len(payload) == 1 and payload[0] < 0x80:
            return payload
        offset = 0x80
    else:
        raise TypeError('unsupported fixture value')
    if len(payload) < 56:
        return bytes([offset + len(payload)]) + payload
    n = len(payload).to_bytes((len(payload).bit_length() + 7) // 8, 'big')
    return bytes([offset + 55 + len(n)]) + n + payload


def rlp_read(data, pos=0):
    """Independent strict decoder for test fixtures and their negative controls."""
    if pos >= len(data):
        raise ValueError('truncated prefix')
    byte = data[pos]
    if byte < 0x80:
        return bytes([byte]), pos + 1
    if byte < 0xb8:
        length, offset, is_list = byte - 0x80, pos + 1, False
    elif byte < 0xc0:
        count = byte - 0xb7
        if pos + 1 + count > len(data) or data[pos + 1] == 0:
            raise ValueError('bad long string length')
        length = int.from_bytes(data[pos + 1:pos + 1 + count], 'big')
        if length < 56:
            raise ValueError('noncanonical long string')
        offset, is_list = pos + 1 + count, False
    elif byte < 0xf8:
        length, offset, is_list = byte - 0xc0, pos + 1, True
    else:
        count = byte - 0xf7
        if pos + 1 + count > len(data) or data[pos + 1] == 0:
            raise ValueError('bad long list length')
        length = int.from_bytes(data[pos + 1:pos + 1 + count], 'big')
        if length < 56:
            raise ValueError('noncanonical long list')
        offset, is_list = pos + 1 + count, True
    end = offset + length
    if end > len(data):
        raise ValueError('truncated payload')
    if not is_list:
        result = data[offset:end]
        if length == 1 and result[0] < 0x80:
            raise ValueError('noncanonical one-byte string')
        return result, end
    result = []
    while offset < end:
        value, offset = rlp_read(data, offset)
        if offset > end:
            raise ValueError('nested value exceeds list')
        result.append(value)
    return result, end


class StaticPathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.TARGET.read_bytes()
        subject.authenticate(cls.data)
        cls.sections = subject.sections(cls.data)
        cls.image = subject.Image(cls.data, cls.sections)
        cls.fdes = subject.selected_fdes(cls.data, cls.sections)
        cls.decoded = {a: subject.decode_body(cls.image, f) for a, f in cls.fdes.items()}
        cls.boundaries = {i['site'] for seq in cls.decoded.values() for i in seq}
        cls.boundaries.update(f['end'] for f in cls.fdes.values())
        cls.outputs = subject.collect(cls.data)
        cls.packet = subject.ROOT / 'research/work-items/RE-021-typed34-state-input-94'

    def test_authenticated_artifact(self):
        self.assertEqual(subject.digest(self.data), subject.DIGEST)
        bad = bytearray(self.data)
        bad[100] ^= 1
        with self.assertRaisesRegex(subject.EvidenceError, 'digest'):
            subject.authenticate(bad)

    def test_full_regeneration_matches_saved_evidence(self):
        self.assertEqual(len(self.outputs), 22)
        for name, content in self.outputs.items():
            with self.subTest(name=name):
                self.assertEqual((self.packet / name).read_bytes(), content)

    def test_selected_extents_bind_actual_unwind_records(self):
        self.assertEqual(set(self.fdes), set(subject.ROLES))
        self.assertEqual(len(self.fdes), 21)
        for start, record in self.fdes.items():
            with self.subTest(start=hex(start)):
                self.assertGreater(record['end'], start)
                self.assertEqual(sum(len(i['raw']) for i in self.decoded[start]), record['end'] - start)
                subject.validate_local_branches(self.decoded[start], start, record['end'])

    def test_corrupt_unwind_pointer_rejected(self):
        first = self.fdes[0x1346db0]
        hdr = next(s for s in self.sections if s['name'] == '.eh_frame_hdr')
        off = hdr['offset'] + 12 + first['index'] * 8 + 4
        bad = bytearray(self.data)
        original = struct.unpack_from('<i', bad, off)[0]
        struct.pack_into('<i', bad, off, original + 1)
        with self.assertRaises((ValueError, subject.EvidenceError)):
            subject.selected_fdes(bad, self.sections)

    def test_missing_and_duplicate_fde_are_rejected(self):
        with mock.patch.object(subject, 'ROLES', {1: 'not an unwind entry'}):
            with self.assertRaises(subject.EvidenceError):
                subject.selected_fdes(self.data, self.sections)
        cies, rows = subject.eh_frame_records(self.data, self.sections)
        target = next(r for r in rows if r['start'] == 0x1346db0)
        with mock.patch.object(subject, 'eh_frame_records', return_value=(cies, rows + [target])):
            with self.assertRaises(subject.EvidenceError):
                subject.selected_fdes(self.data, self.sections)

    def test_every_reviewed_window_rejects_a_byte_mutation(self):
        mutable = bytearray(self.data)
        image = subject.Image(mutable, self.sections)
        for site, name, encoded in subject.PINS:
            with self.subTest(window=name):
                expected = bytes.fromhex(encoded)
                _, offset = image.mapping(site, len(expected), True)
                mutable[offset] ^= 1
                try:
                    with self.assertRaises(subject.EvidenceError):
                        subject.verify_pins(image, self.boundaries)
                finally:
                    mutable[offset] ^= 1

    def test_each_prior_interface_anchor_rejects_corruption(self):
        mutable = bytearray(self.data)
        image = subject.Image(mutable, self.sections)
        for site, name, encoded in subject.BOUNDARY_PINS:
            with self.subTest(window=name):
                _, offset = image.mapping(site, len(bytes.fromhex(encoded)), True)
                mutable[offset] ^= 1
                try:
                    with self.assertRaises(subject.EvidenceError):
                        subject.verify_boundary_pins(image)
                finally:
                    mutable[offset] ^= 1

    def test_wrong_recipient_predicate_and_branch_target_fail(self):
        mutable = bytearray(self.data)
        image = subject.Image(mutable, self.sections)
        for site in (0x134701d, 0x134701e, 0x1347020, 0x134979d, 0x134979e, 0x13497a0):
            with self.subTest(site=hex(site)):
                _, off = image.mapping(site, 1, True)
                mutable[off] ^= 1
                try:
                    with self.assertRaises(subject.EvidenceError):
                        subject.verify_pins(image, self.boundaries)
                finally:
                    mutable[off] ^= 1

    def test_handoff_lanes_preserve_all_recipient_bits(self):
        rows = [line.split('\t') for line in self.outputs['handoff-lanes.tsv'].decode('ascii').splitlines()[1:]]
        self.assertEqual(len(rows), 40)
        for typ in (3, 4):
            selected = [row for row in rows if int(row[0]) == typ]
            self.assertEqual(len(selected), 20)
            for bit in range(160):
                original = bytearray(20)
                original[bit // 8] = 1 << (bit % 8)
                projected = {int(row[5], 16): original[int(row[1])] for row in selected}
                self.assertEqual(bytes(projected[0x13d + i] for i in range(20)), bytes(original))
                self.assertEqual({int(row[4], 16) for row in selected}, {0x13c})

    def test_unmapped_bss_ambiguous_and_crossing_reads_fail(self):
        bss = next(s for s in self.sections if s['name'] == '.bss')
        text = next(s for s in self.sections if s['name'] == '.text')
        for va, size in ((0, 1), (bss['address'], 8), (text['address'] + text['size'] - 1, 2)):
            with self.subTest(va=hex(va)):
                with self.assertRaises(subject.EvidenceError):
                    self.image.read(va, size)
        duplicate = subject.Image(self.data, [text, dict(text)])
        with self.assertRaises(subject.EvidenceError):
            duplicate.read(text['address'], 1)
        with self.assertRaises(subject.EvidenceError):
            self.image.read(text['address'], 0)

    def test_relative_relocation_types_duplicates_and_addends(self):
        records = subject.relocations(self.image)
        slot = 0x576e120
        row = subject.validate_binding(records, slot, 0x1346db0)
        self.assertEqual(row['type'], 8)
        bad_records = copy.deepcopy({slot: records[slot]})
        bad_records[slot].append(dict(bad_records[slot][0]))
        with self.assertRaises(subject.EvidenceError):
            subject.validate_binding(bad_records, slot, 0x1346db0)
        with self.assertRaises(subject.EvidenceError):
            subject.validate_binding(records, slot, 0x1349530)
        mutable = bytearray(self.data)
        struct.pack_into('<Q', mutable, row['file_offset'] + 8, 9)
        changed = subject.relocations(subject.Image(mutable, self.sections))
        with self.assertRaises(subject.EvidenceError):
            subject.validate_binding(changed, slot, 0x1346db0)

    def test_corrupt_exception_header_rejected(self):
        fde = self.fdes[0x1346db0]
        self.assertIsNotNone(fde['lsda'])
        _, offset = self.image.mapping(fde['lsda'], 1)
        mutable = bytearray(self.data)
        mutable[offset] ^= 1
        with self.assertRaises(subject.EvidenceError):
            subject.exception_records(subject.Image(mutable, self.sections), fde)

    def test_decoder_rejects_unsupported_truncated_and_middle_target(self):
        for bad in (b'\x0f', b'\xe8\x00', b'\x0f\xff'):
            with self.subTest(data=bad.hex()):
                with self.assertRaises(subject.EvidenceError):
                    subject.decode_instruction(bad)
        code = b'\xeb\xff\xc3'
        decoded = [subject.decode_instruction(code, 0, 0), subject.decode_instruction(code, 2, 0)]
        with self.assertRaises(subject.EvidenceError):
            subject.validate_local_branches(decoded, 0, len(code))

    def test_short_recipient_success_and_error_precedence(self):
        key = bytes.fromhex('00' * 19 + '09')
        cases = ((b'', 2, 0), (b'\x00', 5, 1), (b'\x80', 5, 1),
                 (b'\x81\x00', 3, 1), (b'\x93' + key[:19], 5, 20),
                 (b'\x94' + key[:19], 2, 1), (b'\x94' + key, None, 21))
        for payload, error, consumed in cases:
            with self.subTest(payload=payload.hex()):
                got, count, value = subject.short_fixed(payload, 20)
                self.assertEqual((got, count), (error, consumed))
                if error is None:
                    self.assertEqual(value, key)
        with self.assertRaises(subject.EvidenceError):
            subject.short_fixed(b'\xb8', 20)

    def test_all_recipient_bit_flips_preserve_distinct_lanes(self):
        key = bytes.fromhex('00' * 19 + '09')
        for bit in range(160):
            other = bytearray(key)
            other[bit // 8] ^= 1 << (bit % 8)
            error, consumed, value = subject.short_fixed(b'\x94' + bytes(other), 20)
            self.assertIsNone(error)
            self.assertEqual(consumed, 21)
            self.assertEqual(value, bytes(other))
            self.assertNotEqual(value, key)
        lanes = self.outputs['recipient-lanes.tsv'].decode('ascii').splitlines()[1:]
        self.assertEqual(len(lanes), 40)
        for typ, base in ((3, 0xb8), (4, 0xa8)):
            rows = [line.split('\t') for line in lanes if int(line.split('\t')[0]) == typ]
            for bit in range(160):
                data = bytearray(20)
                data[bit // 8] = 1 << (bit % 8)
                projected = {int(row[2], 16): data[int(row[1])] for row in rows}
                self.assertEqual(bytes(projected[base + i] for i in range(20)), bytes(data))

    def test_32_byte_vector_boundaries_and_bit_flips(self):
        item = bytes(range(32))
        self.assertEqual(subject.list32_short(b'\xc0'), (None, []))
        self.assertEqual(subject.list32_short(b'\xe1\xa0' + item), (None, [item]))
        self.assertEqual(subject.list32_short(b'\xe0\x9f' + item[:31]), (5, None))
        self.assertEqual(subject.list32_short(b'\xe1\xa0' + item[:31]), (2, None))
        for bit in range(256):
            changed = bytearray(item)
            changed[bit // 8] ^= 1 << (bit % 8)
            error, values = subject.list32_short(b'\xe1\xa0' + bytes(changed))
            self.assertIsNone(error)
            self.assertEqual(values, [bytes(changed)])
            self.assertNotEqual(values[0], item)
        lanes = [line.split('\t') for line in self.outputs['key32-lanes.tsv'].decode('ascii').splitlines()[1:]]
        self.assertEqual(len(lanes), 32)
        for bit in range(256):
            data = bytearray(32)
            data[bit // 8] = 1 << (bit % 8)
            projected = {int(row[1]): data[int(row[0])] for row in lanes}
            self.assertEqual(bytes(projected[i] for i in range(32)), bytes(data))

    def test_authorization_address_lanes_are_distinct_from_recipient(self):
        rows = [line.split('\t') for line in self.outputs['authorization-lanes.tsv'].decode('ascii').splitlines()[1:]]
        self.assertEqual(len(rows), 20)
        for bit in range(160):
            data = bytearray(20)
            data[bit // 8] = 1 << (bit % 8)
            projected = {int(row[2], 16): data[int(row[0])] for row in rows}
            self.assertEqual(bytes(projected[0x28 + i] for i in range(20)), bytes(data))

    def test_authorization_vector_prior_handoff_and_row_boundaries(self):
        layout = json.loads(self.outputs['layout.json'])['type4_authorization_handoff']
        self.assertEqual((layout['unsigned_capacity_offset'], layout['unsigned_pointer_offset'],
                          layout['unsigned_count_offset']), (0x90, 0x98, 0xa0))
        self.assertEqual((layout['prior_tagged_pointer_offset'], layout['prior_tagged_count_offset']),
                         (0xa8, 0xb0))
        self.assertEqual((layout['prior_converter_tag_offset'], layout['prior_converter_tag_value'],
                          layout['prior_converter_capacity_offset'], layout['prior_converter_pointer_offset'],
                          layout['prior_converter_count_offset']), (0x70, 0, 0x78, 0x80, 0x88))
        self.assertEqual(layout['prior_converter_copy_bytes_per_row'], 136)
        row1 = bytes((i * 7) & 255 for i in range(136))
        row2 = bytes((i * 13 + 1) & 255 for i in range(136))
        for rows in ([], [row1], [row1, row2]):
            source = b''.join(rows)
            copied = [source[i:i + layout['prior_converter_copy_bytes_per_row']]
                      for i in range(0, len(source), layout['prior_converter_copy_bytes_per_row'])]
            self.assertEqual(copied, rows)
        self.assertNotEqual(row1[0x28:0x3c], row2[0x28:0x3c])

    def test_long_input_length_and_truncation(self):
        data = bytes(range(213))
        self.assertEqual(subject.long_one_byte_string(b'\xb8'), (2, 1, None))
        self.assertEqual(subject.long_one_byte_string(b'\xb8\x00'), (1, 2, None))
        self.assertEqual(subject.long_one_byte_string(b'\xb8\x37' + bytes(55)), (4, 2, None))
        self.assertEqual(subject.long_one_byte_string(b'\xb8\xd5' + data[:-1]), (2, 2, None))
        self.assertEqual(subject.long_one_byte_string(b'\xb8\xd5' + data), (None, 215, data))
        with self.assertRaises(subject.EvidenceError):
            subject.long_one_byte_string(b'\x80')

    def test_payload_words_and_clone_table_bindings(self):
        rows = [line.split('\t') for line in self.outputs['payload-words.tsv'].decode('ascii').splitlines()[1:]]
        self.assertEqual(len(rows), 8)
        for row in rows:
            _, _, source, unsigned, tagged, environment = row
            self.assertEqual(int(unsigned, 16), 0x20 + int(source, 16))
            self.assertEqual(int(tagged, 16), 0x10 + int(unsigned, 16))
            self.assertEqual(int(environment, 16), 0xc0 + int(source, 16))
        records = subject.relocations(self.image)
        for slot, target in ((0x576e140, 0x5670ae8), (0x576e148, 0x5670ac0),
                             (0x5670ae8, 0x1510c60), (0x5670ac0, 0x1510c10)):
            subject.validate_binding(records, slot, target)
        with self.assertRaises(subject.EvidenceError):
            subject.validate_binding(records, 0x576e140, 0x5670ac0)

    def test_integer_payload_width_and_error_precedence(self):
        for width in (8, 16, 32):
            self.assertEqual(subject.uint_payload(b'', width), (None, 0))
            self.assertEqual(subject.uint_payload(b'\x00', width), (1, None))
            for length in range(1, width + 1):
                payload = bytes([length]) + bytes((i * 17) & 255 for i in range(length - 1))
                self.assertEqual(subject.uint_payload(payload, width), (None, int.from_bytes(payload, 'big')))
            too_long = b'\x01' + bytes(width)
            self.assertEqual(subject.uint_payload(too_long, width), (0, None))
            leading_zero = bytes(width + 1)
            self.assertEqual(subject.uint_payload(leading_zero, width), (1 if width == 32 else 0, None))
        with self.assertRaises(subject.EvidenceError):
            subject.uint_payload(b'\x01', 64)

    def test_32_byte_integer_oversize_store_uses_offset_not_error_value(self):
        # mov ecx, 8 supplies the destination offset; xor edx, edx supplies
        # the word stored there. Validate the actual pinned instruction window.
        for name in ('uint32_order', 'uint32_order4', 'row32_order'):
            encoded = next(encoded for _, label, encoded in subject.PINS if label == name)
            raw = bytes.fromhex(encoded)
            marker = bytes.fromhex('b90800000031d24889140f')
            self.assertIn(marker, raw)
            stored_word = 0  # xor edx, edx, followed by mov [rdi+rcx], rdx
            self.assertEqual(subject.uint_payload(b'\x01' + bytes(32), 32), (stored_word, None))
            self.assertEqual(subject.uint_payload(bytes(33), 32), (1, None))

    def test_row_parity_projection_is_not_signature_validation(self):
        self.assertEqual(subject.parity_payload(b''), (None, 0))
        self.assertEqual(subject.parity_payload(b'\x00'), (1, None))
        self.assertEqual(subject.parity_payload(b'\x01'), (None, 1))
        self.assertEqual(subject.parity_payload(b'\x01\x00'), (0, None))

    def test_synthetic_typed_envelopes_and_corruption_controls(self):
        address = bytes.fromhex('00' * 19 + '09')
        authority = bytes.fromhex('33' * 20)
        key = bytes(range(32))
        payload = bytes(213)
        common = [1, 0, 2, 3, 300000, address, 0, payload, [[address, [key]]]]
        fields = {3: common + [4, [key], 0, 1, 1],
                  4: common + [[[1, authority, 0, 1, 1, 1]], 0, 1, 1]}
        for typ, values in fields.items():
            encoded = bytes([typ]) + rlp_encode(values)
            parsed, end = rlp_read(encoded, 1)
            self.assertEqual(end, len(encoded))
            self.assertEqual(parsed[5], address)
            self.assertEqual(parsed[7], payload)
            self.assertEqual(parsed[8][0][0], address)
            if typ == 4:
                self.assertEqual(parsed[9][0][1], authority)
                self.assertNotEqual(parsed[9][0][1], parsed[5])
            with self.assertRaises(ValueError):
                rlp_read(encoded[:-1], 1)
        with self.assertRaises(ValueError):
            rlp_read(b'\x81\x00')

    def test_summary_counts_follow_selected_outputs(self):
        summary = json.loads(self.outputs['summary.json'])
        self.assertEqual(summary['selected_fde_count'], len(self.fdes))
        self.assertEqual(summary['selected_bytes'], sum(f['end'] - f['start'] for f in self.fdes.values()))
        self.assertEqual(summary['decoded_instructions'], sum(len(s) for s in self.decoded.values()))
        self.assertEqual(summary['pinned_windows'], len(subject.PINS))
        self.assertEqual(summary['annotated_decisions'], len(subject.DECISIONS))
        self.assertEqual(summary['ordered_field_calls'], 19)
        self.assertEqual(summary['payload_word_rows'], 8)
        self.assertEqual(summary['projected_recipient_lanes'], 40)
        self.assertEqual(summary['projected_key_lanes'], 32)
        self.assertEqual(summary['projected_authorization_address_lanes'], 20)
        self.assertEqual(summary['projected_handoff_lanes'], 40)
        self.assertEqual(summary['prior_interface_anchors'], len(subject.BOUNDARY_PINS))


if __name__ == '__main__':
    unittest.main()
