"""Static #94 evidence controls; no target instructions are executed."""
import binascii
import hashlib
import json
from pathlib import Path
import struct
import unittest
from unittest import mock

from tools import re21_call_input94 as subject


def hex_projection(text, nibble_table):
    """Bounded source-level model of the selected text path, not an emulator."""
    if len(text) & 1:
        return ('odd',)
    if text.startswith(b'0x'):
        text = text[2:]
    for index, byte in enumerate(text):
        if nibble_table[byte] == 0xff:
            return ('invalid', byte, index)
    return ('ok', bytes((nibble_table[text[i]] << 4) | nibble_table[text[i + 1]]
                        for i in range(0, len(text), 2)))


def field_projection(fields, table):
    """Model only a sequence already delivered to the collector's entry loop."""
    seen = set()
    result = {'input': None, 'data': None}
    for name, value in fields:
        if name not in result:
            continue
        if name in seen:
            return ('duplicate', name)
        seen.add(name)
        if value is None:
            result[name] = None
        else:
            parsed = hex_projection(value, table)
            if parsed[0] != 'ok':
                return parsed
            result[name] = parsed[1]
    return ('ok', result['input'], result['data'])


def fee_projection(cap, tip, base):
    """Interpret the selected helper's canonical option tags and integer branches."""
    limit = (1 << 256) - 1
    if not 0 <= base <= limit or any(x is not None and not 0 <= x <= limit for x in (cap, tip)):
        raise ValueError('outside canonical 256-bit domain')
    tip = 0 if tip is None else tip
    if cap is not None:
        if (cap or tip) and cap < base:
            return ('error', 13)
        if cap < tip:
            return ('error', 10)
    total = base + tip
    if total > limit:
        return ('error', 11)
    return ('ok', total if cap is None else min(total, cap))


def radix_projection(base, digits):
    """Project supplied digit values; the external classifier is not modeled."""
    value = 0
    maximum = (1 << 128) - 1
    for digit in digits:
        if digit >= base or digit < 0:
            return ('digit', digit)
        value = value * base + digit
        if value > maximum:
            return ('overflow', digit)
    return ('ok', value)


def radix_digits(value, base):
    if value == 0:
        return [0]
    digits = []
    while value:
        value, digit = divmod(value, base)
        digits.append(digit)
    return list(reversed(digits))


def shared_drop_projection(refcount, allocation_size):
    """Single-threaded projection for a valid nonzero reference count."""
    if not 0 < refcount < 1 << 64 or not 0 <= allocation_size < 1 << 64:
        raise ValueError('outside modeled owner domain')
    if refcount != 1:
        return ('retain', refcount - 1)
    if allocation_size >= 1 << 63:
        return ('size-error',)
    return ('free-data-and-owner', allocation_size, 24)


def odd_drop_projection(owner, data_pointer, length):
    """Projection of the odd-owner branch for a valid ordered pointer span."""
    if not (0 <= owner <= data_pointer < 1 << 64 and owner & 1 and 0 <= length < 1 << 64):
        raise ValueError('outside modeled pointer domain')
    size = data_pointer - owner + length
    if size >= 1 << 64:
        return ('carry-error',)
    if size >= 1 << 63:
        return ('size-error',)
    return ('free', owner, size)


def memory_view(data, va=0x1000):
    return subject.View(bytes(data), [{'name': '.test', 'type': 1, 'flags': 2,
                                      'address': va, 'offset': 0, 'size': len(data)}])


def data_view_for_nibbles(table, constants):
    data = bytearray(table)
    rows = [{'name': 'table', 'type': 1, 'flags': 2, 'address': 0x251994,
             'offset': 0, 'size': len(table)}]
    for (_, va), byte in zip(subject.VECTOR_CONSTANTS, constants):
        rows.append({'name': 'vector', 'type': 1, 'flags': 2, 'address': va,
                     'offset': len(data), 'size': 16})
        data.extend(bytes([byte]) * 16)
    return subject.View(bytes(data), rows)


class ArtifactEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.TARGET.read_bytes()
        cls.sections = subject.sections(cls.data)
        cls.view = subject.View(cls.data, cls.sections)
        cls.outputs = subject.records(cls.data)
        cls.summary = json.loads(cls.outputs['summary.json'])
        cls.table, cls.vector, _ = subject.nibble_rows(cls.view)

    def test_full_digest_and_corruption(self):
        self.assertEqual(subject.authenticate(self.data), subject.EXPECTED_SHA256)
        self.assertRaisesRegex(ValueError, 'SHA-256', subject.authenticate, b'corrupt input')

    def test_evidence_inventory(self):
        self.assertEqual(len(self.outputs), 14)
        self.assertEqual(self.summary['selected_unwind_extents'], 18)
        self.assertEqual(self.summary['selected_extent_bytes'], 11073)
        self.assertEqual(self.summary['bounded_switch_entries'], 37)
        self.assertEqual(self.summary['nibble_table_entries'], 256)
        self.assertEqual(self.summary['valid_nibble_characters'], 22)
        self.assertEqual(self.summary['lsda_call_sites'], 74)
        self.assertEqual(self.summary['lsda_landing_pads'], 46)

    def test_selected_fdes_have_unique_index_and_file_bytes(self):
        rows, bodies, frame_records = subject.checked_extents(self.data, self.view)
        self.assertEqual(len({r['start_va'] for r in rows}), len(rows))
        self.assertEqual(len(bodies), len(rows))
        self.assertEqual(len(frame_records), len(rows))
        for row, body, unwind in zip(rows, bodies, frame_records):
            self.assertEqual(row['size'], int(row['end_va'], 16) - int(row['start_va'], 16))
            self.assertEqual(hashlib.sha256(bytes.fromhex(body['bytes'])).hexdigest(), row['body_sha256'])
            self.assertGreater(len(bytes.fromhex(unwind['fde_bytes'])), 8)

    def test_exception_sites_link_to_selected_ranges(self):
        fdes, _, _ = subject.checked_extents(self.data, self.view)
        rows, headers = subject.exception_tables(self.view, fdes)
        self.assertEqual(len(rows), 74)
        self.assertEqual(sum(bool(r['landing_va']) for r in rows), 46)
        self.assertGreater(len(headers), 0)
        collector = [r for r in rows if r['function'] == 'input-field-collector']
        self.assertEqual(collector[0]['start_va'], '0x26afb3c')
        self.assertEqual(collector[0]['landing_va'], '0x26b00aa')

    def test_all_windows_and_direct_edges(self):
        windows = [subject.checked_window(self.view, *x) for x in subject.WINDOWS]
        edges = [subject.direct_transfer(self.view, *x) for x in subject.TRANSFERS]
        self.assertEqual(len(windows), 100)
        self.assertEqual(len(edges), 120)
        mapping = {e['name']: e['destination_va'] for e in edges}
        self.assertEqual(mapping['visitor-to-collector'], '0x26afab0')
        self.assertEqual(mapping['collector-name'], '0x214d7c0')
        self.assertEqual(mapping['collector-input-parser'], '0x209ce20')
        self.assertEqual(mapping['value-to-sequence'], '0x28096c0')
        self.assertEqual(mapping['value-to-text-borrowed'], '0x2809db0')
        self.assertEqual(mapping['decoder-invalid-details'], '0x156e5d0')
        self.assertEqual(mapping['decoder-vector-call'], '0x156e890')
        self.assertEqual(mapping['visitor-quantity-one'], '0x258cbf0')
        self.assertEqual(mapping['optional-to-quantity'], '0x28fc450')
        self.assertEqual(mapping['quantity-to-radix'], '0x28f7ae0')
        self.assertEqual(mapping['fee-with-blob'], '0x4e60470')
        self.assertEqual(mapping['fee-without-blob'], '0x4e60470')

    def test_selected_sites_and_external_anchor_separation(self):
        fdes, _, _ = subject.checked_extents(self.data, self.view)
        windows = [subject.checked_window(self.view, *x) for x in subject.WINDOWS]
        edges = [subject.direct_transfer(self.view, *x) for x in subject.TRANSFERS]
        rip = [subject.rip_reference(self.view, *x) for x in subject.RIP_REFERENCES]
        subject.validate_selection(fdes, windows, edges, rip)
        moved = list(edges)
        moved[1] = dict(moved[1], site_va='0x1bdb893')
        self.assertRaisesRegex(ValueError, 'outside', subject.validate_selection, fdes, windows, moved, rip)
        moved = list(edges)
        moved[0] = dict(moved[0], site_va='0x1bdb894')
        self.assertRaisesRegex(ValueError, 'external anchor', subject.validate_selection, fdes, windows, moved, rip)

    def test_relative_slots_and_names(self):
        relocs = subject.relocation_rows(self.data, self.sections)
        by_name = {r['name']: r for r in relocs}
        self.assertEqual(by_name['hex-decoder']['addend_va'], '0x156ec60')
        self.assertEqual(by_name['fee-input-selector']['addend_va'], '0x4e60140')
        self.assertEqual(by_name['even-pointer-clone-slot']['addend_va'], '0x1510c60')
        self.assertEqual(by_name['odd-pointer-clone-slot']['addend_va'], '0x1510c10')
        self.assertEqual(by_name['shared-bytes-clone-slot']['addend_va'], '0x1510360')
        self.assertEqual(by_name['odd-pointer-drop-slot']['addend_va'], '0x1510a30')
        self.assertEqual(by_name['shared-bytes-drop-slot']['addend_va'], '0x15102c0')
        self.assertEqual(by_name['field-name-input']['addend_va'], '0x3b96af')
        self.assertEqual(by_name['field-name-data']['addend_va'], '0x20a08c')
        constants = json.loads(self.outputs['constants.json'])
        self.assertEqual([x['ascii'] for x in constants['field_names']], ['input', 'data'])
        self.assertEqual(constants['type_name']['ascii'], 'TransactionInput')
        self.assertEqual(constants['quantity_special_zero']['ascii'], '0x0')

    def test_extracted_operand_values(self):
        rows = {r['name']: r['value'] for r in subject.operand_rows(self.view)}
        self.assertEqual(len(rows), 29)
        self.assertEqual(rows['seen-input-stack-offset'], '0x10')
        self.assertEqual(rows['seen-data-stack-offset'], '0x38')
        self.assertEqual(rows['result-input-offset'], '0x8')
        self.assertEqual(rows['result-data-offset'], '0x28')
        self.assertEqual(rows['hex-prefix-first-byte'], hex(ord('0')))
        self.assertEqual(rows['hex-prefix-second-byte'], hex(ord('x')))
        self.assertEqual(rows['vector-output-threshold'], '0x20')
        mask = int(rows['json-whitespace-mask'], 16)
        self.assertEqual([c for c in range(33) if mask & (1 << c)], [9, 10, 13, 32])
        self.assertEqual(rows['shared-owner-refcount-offset'], '0x10')
        self.assertEqual(rows['shared-owner-free-size'], '0x18')
        self.assertEqual(rows['odd-owner-free-size'], '0x18')
        self.assertEqual(rows['fee-legacy-mixed-error'], '0xc')
        self.assertEqual(rows['fee-cap-less-than-base-code'], '0xd')
        self.assertEqual(rows['fee-cap-less-than-tip-code'], '0xa')
        self.assertEqual(rows['fee-overflow-error-code'], '0xb')
        self.assertEqual([rows['radix-base-' + n] for n in ('two', 'eight', 'ten', 'sixteen')],
                         ['0x2', '0x8', '0xa', '0x10'])

    def test_switch_tables_are_bounded_and_link_the_arms(self):
        rows = subject.jump_table(self.view, 'field', 0x3c91d0, 15)
        self.assertEqual(rows[12]['destination_va'], '0x214d803')
        rows = subject.jump_table(self.view, 'value', 0x3cf128, 22)
        self.assertEqual(rows[12]['destination_va'], '0x219c2cd')
        self.assertEqual(rows[13]['destination_va'], '0x219c287')
        self.assertEqual(rows[20]['destination_va'], '0x219c0e9')

    def test_scalar_and_vector_validation_for_every_byte(self):
        self.assertEqual(self.vector, [0xc6, 0xf5, 0xdf, 0xb9, 0xf9])
        standard = b'0123456789abcdefABCDEF'
        for c in range(256):
            with self.subTest(character=c):
                self.assertEqual(self.table[c] != 0xff, c in standard)
                if c in standard:
                    self.assertEqual(self.table[c], int(bytes([c]), 16))
                    self.assertEqual((c & 15) + 9 * (c >> 6), self.table[c])

    def test_all_valid_nibble_pairs(self):
        alphabet = b'0123456789abcdefABCDEF'
        for a in alphabet:
            for b in alphabet:
                pair = bytes([a, b])
                self.assertEqual(hex_projection(pair, self.table), ('ok', binascii.unhexlify(pair)))

    def test_decoder_length_boundaries_and_prefix(self):
        for n in (0, 1, 7, 8, 15, 16, 31, 32, 33, 212, 213, 214):
            expected = bytes(i % 256 for i in range(n))
            for prefix in (b'', b'0x'):
                with self.subTest(length=n, prefix=prefix):
                    self.assertEqual(hex_projection(prefix + expected.hex().encode(), self.table), ('ok', expected))
        self.assertEqual(len(b'0x' + b'00' * 213), 428)
        self.assertEqual(hex_projection(b'0x', self.table), ('ok', b''))
        self.assertEqual(hex_projection(b'', self.table), ('ok', b''))

    def test_error_precedence_and_index_after_prefix(self):
        cases = ((b'0xg', ('odd',)), (b'g', ('odd',)),
                 (b'0X', ('invalid', ord('X'), 1)),
                 (b'0x0g', ('invalid', ord('g'), 1)),
                 (b'0xf0a?', ('invalid', ord('?'), 3)),
                 (b'0gff', ('invalid', ord('g'), 1)),
                 (bytes([0xff, ord('0')]), ('invalid', 0xff, 0)))
        for text, expected in cases:
            with self.subTest(text=text):
                self.assertEqual(hex_projection(text, self.table), expected)

    def test_invalid_character_at_each_position(self):
        for length in (2, 16, 64, 426):
            for position in range(length):
                text = bytearray(b'0' * length)
                text[position] = ord('?')
                self.assertEqual(hex_projection(b'0x' + text, self.table), ('invalid', ord('?'), position))

    def test_u128_accumulator_boundaries(self):
        maximum = (1 << 128) - 1
        for base in (2, 8, 10, 16):
            with self.subTest(base=base):
                self.assertEqual(radix_projection(base, radix_digits(maximum, base)), ('ok', maximum))
                self.assertEqual(radix_projection(base, radix_digits(maximum + 1, base))[0], 'overflow')
                self.assertEqual(radix_projection(base, [0, base]), ('digit', base))
                self.assertEqual(radix_projection(base, []), ('ok', 0))

    def test_fee_branch_boundaries_and_order(self):
        maximum = (1 << 256) - 1
        cases = (
            (None, None, 5, ('ok', 5)),
            (None, 1, maximum, ('error', 11)),
            (None, 0, maximum, ('ok', maximum)),
            (0, 0, 1, ('ok', 0)),
            (0, 1, 1, ('error', 13)),
            (2, 3, 2, ('error', 10)),
            (2, 3, 4, ('error', 13)),
            (5, 2, 3, ('ok', 5)),
            (9, 2, 3, ('ok', 5)),
            (maximum, maximum, 1, ('error', 11)),
            (maximum, 1, maximum - 1, ('ok', maximum)),
        )
        for cap, tip, base, expected in cases:
            with self.subTest(cap=cap, tip=tip, base=base):
                self.assertEqual(fee_projection(cap, tip, base), expected)
        self.assertRaises(ValueError, fee_projection, None, None, maximum + 1)
        self.assertRaises(ValueError, fee_projection, -1, None, 0)

    def test_fee_carry_at_each_64_bit_limb(self):
        maximum = (1 << 256) - 1
        for bit in (64, 128, 192, 256):
            base = (1 << bit) - 1
            expected = ('error', 11) if bit == 256 else ('ok', 1 << bit)
            with self.subTest(boundary=bit, capped=False):
                self.assertEqual(fee_projection(None, 1, base), expected)
            with self.subTest(boundary=bit, capped=True):
                self.assertEqual(fee_projection(maximum, 1, base), expected)

    def test_shared_drop_refcount_and_size(self):
        self.assertEqual(shared_drop_projection(2, 213), ('retain', 1))
        self.assertEqual(shared_drop_projection(1, 213), ('free-data-and-owner', 213, 24))
        self.assertEqual(shared_drop_projection(1, (1 << 63) - 1), ('free-data-and-owner', (1 << 63) - 1, 24))
        self.assertEqual(shared_drop_projection(1, 1 << 63), ('size-error',))
        self.assertEqual(shared_drop_projection(2, 1 << 63), ('retain', 1))
        self.assertRaises(ValueError, shared_drop_projection, 0, 0)

    def test_odd_drop_size_and_overflow(self):
        self.assertEqual(odd_drop_projection(0x1001, 0x1001, 213), ('free', 0x1001, 213))
        self.assertEqual(odd_drop_projection(0x1001, 0x1005, 10), ('free', 0x1001, 14))
        self.assertEqual(odd_drop_projection(1, 1, 1 << 63), ('size-error',))
        self.assertEqual(odd_drop_projection(1, (1 << 64) - 1, 2), ('carry-error',))
        self.assertRaises(ValueError, odd_drop_projection, 2, 2, 1)
        self.assertRaises(ValueError, odd_drop_projection, 3, 1, 1)

    def test_collector_options_and_duplicate_order(self):
        self.assertEqual(field_projection([], self.table), ('ok', None, None))
        self.assertEqual(field_projection([('input', None)], self.table), ('ok', None, None))
        self.assertEqual(field_projection([('input', b'0x')], self.table), ('ok', b'', None))
        self.assertEqual(field_projection([('input', b'00'), ('data', b'ff')], self.table), ('ok', b'\0', b'\xff'))
        self.assertEqual(field_projection([('data', None), ('data', b'0')], self.table), ('duplicate', 'data'))
        self.assertEqual(field_projection([('input', None), ('input', b'')], self.table), ('duplicate', 'input'))
        self.assertEqual(field_projection([('input', b'0'), ('input', b'00')], self.table), ('odd',))
        self.assertEqual(field_projection([('other', b'0'), ('data', b'00')], self.table), ('ok', None, b'\0'))


class CorruptionControls(unittest.TestCase):
    def test_fixed_window_rejects_changed_byte_and_outside_range(self):
        view = memory_view(bytes.fromhex('90 48 01 c0 c3'))
        subject.checked_window(view, 'good', 0x1001, '4801c0')
        self.assertRaisesRegex(ValueError, 'window mismatch', subject.checked_window, view, 'bad', 0x1001, '4801c1')
        self.assertRaisesRegex(ValueError, 'span', subject.checked_window, view, 'outside', 0x1004, 'c390')

    def test_file_mapping_rejects_nobits_ambiguity_and_negative(self):
        raw = b'01234567'
        nobits = {'name': '.bss', 'type': 8, 'flags': 3, 'address': 0x1000, 'offset': 0, 'size': len(raw)}
        self.assertRaisesRegex(ValueError, 'file-backed', subject.View(raw, [nobits]).read, 0x1000, 1)
        one = dict(nobits, type=1)
        self.assertRaisesRegex(ValueError, 'ambiguous', subject.View(raw, [one, one]).read, 0x1000, 1)
        self.assertRaisesRegex(ValueError, 'invalid', subject.View(raw, [one]).read, -1, 1)
        self.assertRaisesRegex(ValueError, 'invalid', subject.View(raw, [one]).read, 0x1000, 0)

    def test_transfer_opcode_and_displacement_corruption(self):
        view = memory_view(bytes.fromhex('e80500000090'))
        row = subject.direct_transfer(view, 'call', 0x1000, 'e8', 0x100a)
        self.assertEqual(row['destination_va'], '0x100a')
        self.assertRaisesRegex(ValueError, 'opcode', subject.direct_transfer, view, 'bad', 0x1000, 'e9', 0x100a)
        self.assertRaisesRegex(ValueError, 'target', subject.direct_transfer, view, 'bad', 0x1000, 'e8', 0x1009)
        self.assertRaisesRegex(ValueError, 'unsupported', subject.direct_transfer, view, 'bad', 0x1000, '90', 0x1009)

    def test_rip_target_and_opcode_corruption(self):
        view = memory_view(bytes.fromhex('ff1504000000'))
        self.assertEqual(subject.rip_reference(view, 'slot', 0x1000, 'ff15', 0x100a)['target_va'], '0x100a')
        self.assertRaisesRegex(ValueError, 'target', subject.rip_reference, view, 'bad', 0x1000, 'ff15', 0x100b)
        self.assertRaisesRegex(ValueError, 'opcode', subject.rip_reference, view, 'bad', 0x1000, 'ff25', 0x100a)

    def test_relocation_type_addend_and_duplicates(self):
        one = struct.pack('<QQq', 0x2000, 8, 0x3000)
        section = {'name': '.rela.dyn', 'type': 4, 'offset': 0, 'size': len(one)}
        slots = (('slot', 0x2000, 0x3000),)
        self.assertEqual(subject.relocation_rows(one, [section], slots)[0]['addend_va'], '0x3000')
        self.assertRaisesRegex(ValueError, 'unexpected', subject.relocation_rows, struct.pack('<QQq', 0x2000, 6, 0x3000), [section], slots)
        self.assertRaisesRegex(ValueError, 'unexpected', subject.relocation_rows, struct.pack('<QQq', 0x2000, 8, 0x3001), [section], slots)
        self.assertRaisesRegex(ValueError, 'duplicate', subject.relocation_rows, one + one, [dict(section, size=48)], slots)
        self.assertRaisesRegex(ValueError, 'missing', subject.relocation_rows, one, [section], (('slot', 0x2001, 0x3000),))

    def test_operand_byte_corruption(self):
        view = memory_view(bytes.fromhex('41f6c501'))
        with mock.patch.object(subject, 'OPERANDS', (('odd-mask', 0x1000, '41f6c5', 1, 1),)):
            self.assertEqual(subject.operand_rows(view)[0]['value'], '0x1')
            self.assertRaisesRegex(ValueError, 'operand value', subject.operand_rows, memory_view(bytes.fromhex('41f6c500')))
            self.assertRaisesRegex(ValueError, 'operand opcode', subject.operand_rows, memory_view(bytes.fromhex('41f6c401')))

    def test_table_and_vector_constant_corruption(self):
        table = bytearray([0xff] * 256)
        for c in b'0123456789abcdefABCDEF':
            table[c] = int(bytes([c]), 16)
        constants = [0xc6, 0xf5, 0xdf, 0xb9, 0xf9]
        subject.nibble_rows(data_view_for_nibbles(table, constants))
        table[ord('g')] = 1
        self.assertRaisesRegex(ValueError, 'disagree', subject.nibble_rows, data_view_for_nibbles(table, constants))
        table[ord('g')] = 0xff
        constants[0] ^= 1
        self.assertRaisesRegex(ValueError, 'SIMD constants', subject.nibble_rows, data_view_for_nibbles(table, constants))

    def test_malformed_exception_tables_fail_closed(self):
        fdes = [{'name': 'one', 'start_va': '0x1000', 'end_va': '0x1002', 'lsda_va': '0x3000'}]
        raw = bytes.fromhex('ff ff 01 04 00 02 01 00')
        def view(data):
            return subject.View(data, [{'name': '.gcc_except_table', 'type': 1, 'flags': 2,
                                        'address': 0x3000, 'offset': 0, 'size': len(data)}])
        rows, headers = subject.exception_tables(view(raw), fdes)
        self.assertEqual(rows[0]['landing_va'], '0x1001')
        self.assertEqual(headers[0]['table_bytes'], 4)
        self.assertRaisesRegex(ValueError, 'landing base', subject.exception_tables, view(b'\x00' + raw[1:]), fdes)
        self.assertRaisesRegex(ValueError, 'call-site range', subject.exception_tables, view(raw[:5] + b'\x03' + raw[6:]), fdes)
        self.assertRaisesRegex(ValueError, 'landing', subject.exception_tables, view(raw[:6] + b'\x02' + raw[7:]), fdes)
        self.assertRaisesRegex(ValueError, 'extent', subject.exception_tables, view(raw[:-1]), fdes)

    def test_fde_index_disagreement_is_rejected(self):
        fde = {'start': 0x1000, 'end': 0x1002, 'fde': 0x2000, 'cie': 0x2010, 'lsda': None}
        index = {'start': 0x1000, 'fde': 0x2001, 'next_index_upper_bound': 0x1002,
                 'section': '.test', 'index': 0}
        view = memory_view(b'\x90\xc3')
        with mock.patch.object(subject, 'FUNCTIONS', (('one', 0x1000),)), \
             mock.patch.object(subject, 'unwind_index', return_value=(view.sections, [index])), \
             mock.patch.object(subject, 'eh_frame_records', return_value=({0x2010: {}}, [fde])):
            self.assertRaisesRegex(ValueError, 'disagreement', subject.checked_extents, view.data, view)


if __name__ == '__main__':
    unittest.main()
