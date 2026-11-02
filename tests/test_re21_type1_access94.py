"""Static controls for the node-94 type-1 access-list evidence (MIT)."""
import csv
import io
import json
import struct
import unittest

from tools import re21_type1_access94 as evidence

PACKET = evidence.ROOT / 'research/work-items/RE-021-type1-access-list-94'


def encode_rlp(value):
    """Independent synthetic-fixture encoder; no target execution."""
    if isinstance(value, list):
        payload = b''.join(encode_rlp(v) for v in value)
        short, long = 0xc0, 0xf7
    else:
        payload = bytes(value)
        if len(payload) == 1 and payload[0] < 0x80:
            return payload
        short, long = 0x80, 0xb7
    if len(payload) < 56:
        return bytes([short + len(payload)]) + payload
    size = len(payload).to_bytes((len(payload).bit_length() + 7) // 8, 'big')
    return bytes([long + len(size)]) + size + payload


def decode_rlp(data, start=0, limit=None):
    """Strict independent RLP oracle for small synthetic test inputs."""
    if limit is None:
        limit = len(data)
    if not 0 <= start < limit <= len(data):
        raise ValueError('truncated prefix')
    tag, pos = data[start], start + 1
    if tag < 0x80:
        return bytes([tag]), pos
    list_kind = tag >= 0xc0
    if tag < 0xb8:
        count = tag - 0x80
    elif tag < 0xc0:
        n = tag - 0xb7
        if pos + n > limit or data[pos] == 0:
            raise ValueError('bad long-string length')
        count = int.from_bytes(data[pos:pos + n], 'big')
        pos += n
        if count < 56:
            raise ValueError('noncanonical long string')
    elif tag < 0xf8:
        count = tag - 0xc0
    else:
        n = tag - 0xf7
        if pos + n > limit or data[pos] == 0:
            raise ValueError('bad long-list length')
        count = int.from_bytes(data[pos:pos + n], 'big')
        pos += n
        if count < 56:
            raise ValueError('noncanonical long list')
    end = pos + count
    if end > limit:
        raise ValueError('truncated payload')
    if not list_kind:
        val = data[pos:end]
        if len(val) == 1 and val[0] < 0x80:
            raise ValueError('noncanonical single byte')
        return val, end
    val = []
    while pos < end:
        item, pos = decode_rlp(data, pos, end)
        val.append(item)
    return val, end


def check_access_list(rows, address_width, key_width):
    """Small synthetic structural model, not an implementation of target code."""
    if not isinstance(rows, list):
        raise ValueError('outer shape')
    for row in rows:
        if not isinstance(row, list) or len(row) != 2:
            raise ValueError('row shape')
        address, keys = row
        if not isinstance(address, bytes) or len(address) != address_width:
            raise ValueError('address width')
        if not isinstance(keys, list):
            raise ValueError('key list shape')
        if any(not isinstance(key, bytes) or len(key) != key_width for key in keys):
            raise ValueError('key width')
    return rows


class Type1AccessEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = evidence.TARGET.read_bytes()
        evidence.authenticate(cls.data)
        cls.secs = evidence.sections(cls.data)
        cls.image = evidence.Image(cls.data, cls.secs)
        cls.fdes = evidence.selected_fdes(cls.data, cls.secs)
        cls.decoded = {start: evidence.decode_body(cls.image, fde)
                       for start, fde in cls.fdes.items()}
        cls.by_site = {item['site']: (start, item)
                       for start, seq in cls.decoded.items() for item in seq}
        cls.product = evidence.collect(cls.data)
        cls.layout = json.loads(cls.product['layout.json'])
        cls.growth = json.loads(cls.product['growth.json'])

    def test_input_identity_rejects_corruption(self):
        evidence.authenticate(self.data)
        changed = bytearray(self.data)
        changed[len(changed) // 2] ^= 1
        with self.assertRaises(evidence.EvidenceError):
            evidence.authenticate(changed)
        with self.assertRaises(evidence.EvidenceError):
            evidence.authenticate(b'')

    def test_all_generated_files_match(self):
        for name, content in self.product.items():
            with self.subTest(name=name):
                self.assertEqual((PACKET / name).read_bytes(), content)

    def test_selected_fdes_have_header_bindings_and_distinct_extents(self):
        self.assertEqual(set(self.fdes), set(evidence.ROLES))
        ordered = sorted(self.fdes.values(), key=lambda f: f['start'])
        self.assertEqual(len(ordered), 14)
        for prev, cur in zip(ordered, ordered[1:]):
            self.assertLessEqual(prev['end'], cur['start'])
        for fde in ordered:
            self.assertGreater(fde['end'], fde['start'])
            self.image.mapping(fde['start'], fde['end'] - fde['start'], executable=True)

    def test_unwind_pointer_corruption_is_rejected(self):
        header = next(s for s in self.secs if s['name'] == '.eh_frame_hdr')
        first = self.fdes[min(self.fdes)]
        pos = header['offset'] + 12 + 8 * first['index'] + 4
        changed = bytearray(self.data)
        changed[pos:pos + 4] = b'\x00' * 4
        with self.assertRaises(ValueError):
            evidence.selected_fdes(changed, self.secs)

    def test_fde_record_corruption_is_rejected(self):
        first = self.fdes[min(self.fdes)]
        _, pos = self.image.mapping(first['fde'], 4)
        changed = bytearray(self.data)
        changed[pos:pos + 4] = b'\xff' * 4
        with self.assertRaises(ValueError):
            evidence.selected_fdes(changed, self.secs)

    def test_section_mapping_excludes_nobits_and_bad_ranges(self):
        bss = next(s for s in self.secs if s['name'] == '.bss')
        with self.assertRaises(evidence.EvidenceError):
            self.image.read(bss['address'] + bss['size'] // 2, 1)
        with self.assertRaises(evidence.EvidenceError):
            self.image.read(0, 0)
        with self.assertRaises(evidence.EvidenceError):
            self.image.read(1 << 63, 1)
        code = next(s for s in self.secs if s['name'] == '.text')
        with self.assertRaises(evidence.EvidenceError):
            self.image.read(code['address'] + code['size'] - 1, 2, True)
        with self.assertRaises(evidence.EvidenceError):
            self.image.read(next(s for s in self.secs if s['name'] == '.rodata')['address'], 1, True)

    def test_ambiguous_file_mapping_is_rejected(self):
        text = next(s for s in self.secs if s['name'] == '.text')
        image = evidence.Image(self.data, [text, dict(text)])
        with self.assertRaises(evidence.EvidenceError):
            image.read(text['address'], 1, True)

    def test_each_pinned_window_detects_one_byte_corruption(self):
        changed = bytearray(self.data)
        image = evidence.Image(changed, self.secs)
        boundaries = set(self.by_site) | {f['end'] for f in self.fdes.values()}
        evidence.verify_pins(image, boundaries)
        for va, name, expected in evidence.PINS:
            _, offset = image.mapping(va, len(bytes.fromhex(expected)), True)
            changed[offset] ^= 1
            with self.subTest(name=name), self.assertRaises(evidence.EvidenceError):
                evidence.verify_pins(image, boundaries)
            changed[offset] ^= 1

    def test_pin_boundary_corruption_is_rejected(self):
        boundaries = set(self.by_site) | {f['end'] for f in self.fdes.values()}
        boundaries.remove(evidence.PINS[0][0])
        with self.assertRaises(evidence.EvidenceError):
            evidence.verify_pins(self.image, boundaries)

    def test_rejects_truncated_and_unsupported_instruction(self):
        for raw in (b'\xe8\x00', b'\x0f\xff', b'\x0f', b'\x48\x8d\xc0'):
            with self.subTest(raw=raw.hex()), self.assertRaises(evidence.EvidenceError):
                evidence.decode_instruction(raw)

    def test_branch_into_instruction_is_rejected(self):
        code = b'\x75\x01\x48\x89\xe5\xc3'
        pos, items = 0, []
        while pos < len(code):
            item = evidence.decode_instruction(code, pos, 0x1000)
            items.append(item)
            pos += len(item['raw'])
        with self.assertRaises(evidence.EvidenceError):
            evidence.validate_local_branches(items, 0x1000, 0x1000 + len(code))
        good = b'\x75\x00\xc3'
        items = [evidence.decode_instruction(good, 0, 0x1000),
                 evidence.decode_instruction(good, 2, 0x1000)]
        evidence.validate_local_branches(items, 0x1000, 0x1003)

    def test_relative_slot_bindings_and_corruptions(self):
        rows = evidence.relocations(self.image)
        bindings = ((0x576e220, 0x134f840), (0x576e158, 0x1353a90),
                    (0x576e160, 0x135b590))
        for slot, target in bindings:
            with self.subTest(slot=hex(slot)):
                entry = evidence.validate_relative_entry(rows, slot)
                self.assertEqual(entry['addend'], target)
                evidence.validate_binding(rows, slot, target)
                with self.assertRaises(evidence.EvidenceError):
                    evidence.validate_binding({slot: [dict(entry, addend=target + 1)]}, slot, target)
                for key, bad_value in (('type', 1), ('symbol', 1), ('addend', -1)):
                    altered = dict(entry, **{key: bad_value})
                    with self.assertRaises(evidence.EvidenceError):
                        evidence.validate_relative_entry({slot: [altered]}, slot)
                with self.assertRaises(evidence.EvidenceError):
                    evidence.validate_relative_entry({slot: [entry, entry]}, slot)
                with self.assertRaises(evidence.EvidenceError):
                    evidence.validate_relative_entry({}, slot)

    def test_actual_relocation_type_byte_corruption_is_detected(self):
        slot = 0x576e220
        entry = evidence.validate_relative_entry(evidence.relocations(self.image), slot)
        changed = bytearray(self.data)
        struct.pack_into('<Q', changed, entry['file_offset'] + 8, 1)
        corrupted = evidence.relocations(evidence.Image(changed, self.secs))
        with self.assertRaises(evidence.EvidenceError):
            evidence.validate_relative_entry(corrupted, slot)

    def test_exception_header_and_range_corruption_are_rejected(self):
        fde = self.fdes[0x1350e50]
        rows, header = evidence.exception_records(self.image, fde)
        self.assertTrue(any(row[6] for row in rows))
        changed = bytearray(self.data)
        changed[int(header['file_offset'], 16)] = 0
        with self.assertRaises(evidence.EvidenceError):
            evidence.exception_records(evidence.Image(changed, self.secs), fde)
        bad_fde = dict(fde, end=fde['start'] + 1)
        with self.assertRaises(evidence.EvidenceError):
            evidence.exception_records(self.image, bad_fde)

    def test_row_layout_and_error_immediates(self):
        self.assertEqual(self.layout['address_width'], 20)
        self.assertEqual(self.layout['key_width'], 32)
        self.assertEqual(self.layout['row_stride'], 48)
        self.assertEqual(self.layout['key_stride'], 32)
        self.assertEqual([r['offset'] for r in self.layout['row_layout']], [0, 8, 16, 24])
        self.assertEqual(self.layout['unsigned_list_vector_offset'], 0x68)
        self.assertEqual(self.layout['unsigned_list_count_offset'], 0x78)
        self.assertEqual(self.layout['unsigned_recipient_offset'], 0x80)
        self.assertEqual(self.layout['unsigned_copy_size'], 0xa0)
        self.assertEqual(self.layout['signed_copy_size'], 0xe0)
        self.assertEqual(self.layout['empty_outer_pointer'], 8)
        self.assertEqual(self.layout['empty_key_pointer'], 1)
        cases = list(csv.DictReader(io.StringIO(self.product['error-stores.tsv'].decode()), delimiter='\t'))
        actual = {r['case']: int(r['immediate']) for r in cases}
        self.assertEqual(actual, {'empty_input': 2, 'zero_leading_length': 1,
                                 'noncanonical_single_byte': 3,
                                 'noncanonical_long_length': 4, 'address_width': 5,
                                 'key_width': 5, 'row_not_list': 6,
                                 'row_length_mismatch': 8, 'envelope_length_mismatch': 8})
        with self.assertRaises(evidence.EvidenceError):
            evidence.immediate_error(b'\x90')

    def test_checked_vector_size_boundaries(self):
        row_size = self.growth['row_size']
        row_limit = self.growth['row_count_bound']
        key_shift = self.growth['key_byte_shift']
        key_high = self.growth['key_count_high_shift']
        signed_max = (1 << 63) - 1
        self.assertEqual(row_limit, signed_max // row_size)
        key_limit = signed_max // (1 << key_shift)
        for n in (0, 1, row_limit - 1, row_limit, row_limit + 1):
            with self.subTest(row_count=n):
                self.assertEqual(n <= row_limit, n * row_size <= signed_max)
        for n in (0, 1, key_limit - 1, key_limit, key_limit + 1, 1 << key_high):
            with self.subTest(key_count=n):
                shifted = (n << key_shift) & ((1 << 64) - 1)
                observed_guard = (n >> key_high) == 0 and (shifted >> 63) == 0
                self.assertEqual(observed_guard, n * (1 << key_shift) <= signed_max)
        self.assertEqual(self.growth['minimum_capacity'], 4)
        self.assertEqual(self.growth['double_capacity_compare'], 5)

    def test_all_address_and_key_bits_survive_symbolic_projection(self):
        lanes = evidence.project_lanes(self.by_site, self.layout['address_width'],
                                       self.layout['key_width'], self.layout['row_stride'])
        for name, size, base in (('address', 20, 24), ('key', 32, 0)):
            selected = [(out, source) for field, _, out, source in lanes if field == name]
            self.assertEqual(len(selected), size)
            for bit in range(size * 8):
                src = bytearray(size)
                src[bit // 8] = 1 << (bit % 8)
                dst = bytearray(base + size)
                for out, source in selected:
                    dst[out] = src[source]
                self.assertEqual(dst[base:], src)

    def test_lane_projection_rejects_changed_source_and_destination(self):
        for site in (0x135111c, 0x13514af, 0x13512be):
            altered = dict(self.by_site)
            owner, item = altered[site]
            bad = dict(item)
            raw = bytearray(bad['raw'])
            raw[-1] ^= 1
            bad['raw'] = bytes(raw)
            altered[site] = (owner, bad)
            with self.subTest(site=hex(site)), self.assertRaises(evidence.EvidenceError):
                evidence.project_lanes(altered, 20, 32, 48)

    def test_independent_rlp_transaction_and_duplicate_list(self):
        address = bytes(19) + b'\x09'
        key_a, key_b = bytes(range(32)), bytes(reversed(range(32)))
        rows = [[address, [key_a, key_b, key_a]], [address, []]]
        fields = [b'\x01', b'', b'\x01', (100000).to_bytes(3, 'big'),
                  address, b'', bytes(213), rows, b'', b'', b'']
        synthetic = b'\x01' + encode_rlp(fields)
        decoded, end = decode_rlp(synthetic, 1)
        self.assertEqual(end, len(synthetic))
        self.assertEqual(decoded[4], address)
        self.assertEqual(len(decoded[6]), 213)
        self.assertEqual(check_access_list(decoded[7], 20, 32), rows)
        self.assertEqual(decoded[7][0][1][0], decoded[7][0][1][2])

    def test_independent_rlp_rejects_truncated_and_noncanonical(self):
        for malformed in (b'', b'\x81', b'\x81\x00', b'\xb8\x01\x80',
                          b'\xf8\x01\xc0', b'\xc2\x80'):
            with self.subTest(value=malformed.hex()), self.assertRaises(ValueError):
                decode_rlp(malformed)

    def test_model_rejects_wrong_widths_and_shapes(self):
        for width in (19, 21):
            with self.subTest(address_width=width), self.assertRaises(ValueError):
                check_access_list([[bytes(width), []]], 20, 32)
        for width in (31, 33):
            with self.subTest(key_width=width), self.assertRaises(ValueError):
                check_access_list([[bytes(20), [bytes(width)]]], 20, 32)
        for bad in (b'', [[bytes(20)]], [[bytes(20), b'']], [[b'\x09', []]]):
            with self.subTest(value=bad), self.assertRaises(ValueError):
                check_access_list(bad, 20, 32)
        self.assertEqual(check_access_list([], 20, 32), [])

    def test_short_outer_cursor_precedes_nested_shape_validation(self):
        # The independently parsed outer list contains a byte, not a row. Its
        # selected binary cursor store is pinned before the row-prefix guard.
        raw = b'\xc1\x00\x80'
        payload_length = raw[0] - 0xc0
        self.assertEqual(payload_length, 1)
        advanced, remaining = 1 + payload_length, len(raw) - 1 - payload_length
        self.assertEqual((advanced, remaining), (2, 1))
        decoded, end = decode_rlp(raw)
        self.assertEqual(end, advanced)
        with self.assertRaises(ValueError):
            check_access_list(decoded, 20, 32)
        rows = {r['name']: r for r in csv.DictReader(
            io.StringIO(self.product['windows.tsv'].decode()), delimiter='\t')}
        self.assertLess(int(rows['outer_cursor_advance']['site_va'], 16),
                        int(rows['item_prefix_check']['site_va'], 16))

    def test_source_length_compare_precedes_destination_writes(self):
        decisions = {int(r['site_va'], 16): r for r in csv.DictReader(
            io.StringIO(self.product['decisions.tsv'].decode()), delimiter='\t')}
        self.assertLess(0x4e54ff7, 0x4e55017)
        self.assertEqual(decisions[0x4e54ffe]['target_va'], '0x4e55013')
        self.assertEqual(decisions[0x4e55020]['target_va'], '0x4e55160')
        self.assertLess(0x4e55017, 0x4e550dd)

    def test_empty_key_copy_bypasses_both_allocation_sites(self):
        decisions = {int(r['site_va'], 16): r for r in csv.DictReader(
            io.StringIO(self.product['decisions.tsv'].decode()), delimiter='\t')}
        self.assertEqual(decisions[0x4e5507e]['target_va'], '0x4e550a5')
        self.assertEqual(decisions[0x4e529f6]['target_va'], '0x4e52a30')
        # Each selected empty arm writes the same nonzero pointer sentinel.
        for site in (0x4e550a5, 0x4e52a30):
            raw = self.by_site[site][1]['raw']
            self.assertIn(raw[0], (0xb8, 0xbd))
            self.assertEqual(int.from_bytes(raw[1:], 'little'), 1)


if __name__ == '__main__':
    unittest.main()
