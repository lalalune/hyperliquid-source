"""Controls for the static node-115 storage-read evidence collector."""
import copy
import hashlib
import itertools
import mmap
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import re011_storage_read115 as subject
from fde_extents import eh_frame_records


class StorageReadEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # ACCESS_COPY alters only private pages; the artifact remains read-only.
        cls.artifact = subject.TARGET.open('rb')
        cls.mapping = mmap.mmap(cls.artifact.fileno(), 0, access=mmap.ACCESS_COPY)
        cls.image = subject.Image(cls.mapping)
        cls.names = subject.field_names(cls.image)
        cls.sizes = subject.layout(cls.image)

    @classmethod
    def tearDownClass(cls):
        cls.mapping.close()
        cls.artifact.close()

    def mutate_reject(self, offset, verifier):
        old = self.mapping[offset]
        try:
            self.mapping[offset] = old ^ 1
            with self.assertRaises(subject.EvidenceError):
                verifier()
        finally:
            self.mapping[offset] = old

    def test_authentic_target_digest(self):
        self.assertEqual(subject.authenticate(self.mapping), subject.SHA256)
        self.assertEqual(hashlib.sha256(self.mapping).hexdigest(), subject.SHA256)

    def test_bad_hash_is_rejected(self):
        self.mutate_reject(0, lambda: subject.authenticate(self.mapping))
        with self.assertRaises(subject.EvidenceError):
            subject.authenticate(b'not an authenticated node')

    def test_all_selected_witnesses_match(self):
        subject.check_all(self.image)
        self.assertEqual(len(subject.WINDOWS), 122)
        self.assertEqual(len(subject.EDGES), 149)

    def test_each_selected_window_rejects_corruption(self):
        for record in subject.WINDOWS:
            label, va, raw = record
            with self.subTest(label=label):
                off = self.image.offset(va, len(bytes.fromhex(raw)), True)
                self.mutate_reject(off, lambda: subject.check_window(self.image, record))

    def test_each_transfer_rejects_corruption(self):
        for record in subject.EDGES:
            label, va, raw, _, _ = record
            with self.subTest(label=label):
                off = self.image.offset(va, len(bytes.fromhex(raw)), True)
                self.mutate_reject(off + len(bytes.fromhex(raw)) - 1,
                                   lambda: subject.check_edge(self.image, record))

    def test_each_data_reference_rejects_corruption(self):
        self.assertEqual(len(subject.DATA_REFS), 13)
        for record in subject.DATA_REFS:
            label, va, raw, _, _ = record
            with self.subTest(label=label):
                off = self.image.offset(va, len(bytes.fromhex(raw)), True)
                self.mutate_reject(off + len(bytes.fromhex(raw)) - 1,
                                   lambda: subject.check_data_ref(self.image, record))
        label, va, raw, target, size = subject.DATA_REFS[1]
        with self.assertRaises(subject.EvidenceError):
            subject.check_data_ref(self.image, (label, va, raw, target + 1, size))

    def test_descriptor_and_method_links(self):
        refs = {row[0]: row for row in subject.DATA_REFS}
        descriptor, descriptor_bytes = subject.check_data_ref(self.image, refs['constructor_descriptor'])
        self.assertEqual(len(descriptor_bytes), 48)
        relocs = self.image.relocations()
        self.assertEqual(relocs[descriptor + 32]['addend'], 0x2d018b0)
        self.assertEqual(relocs[descriptor + 40]['addend'], 0x2d018b0)
        self.assertEqual(relocs[0x64e7060]['addend'], 0x43c89a0)
        _, method = subject.check_data_ref(self.image, refs['adapter_method'])
        self.assertEqual(method, b'eth_getStorageAt')

    def test_each_literal_rejects_corruption(self):
        self.assertEqual(len(subject.LITERALS), 14)
        for record in subject.LITERALS:
            label, va, literal = record
            with self.subTest(label=label):
                off = self.image.offset(va, len(literal))
                self.mutate_reject(off, lambda: subject.check_literal(self.image, record))

    def test_missing_parameter_immediates_and_corruption(self):
        size, offset, first, second, detail, code = subject.missing_parameter(self.image)
        self.assertEqual((size, offset, detail, code), (14, 6, b'No more params', -32602))
        self.assertEqual(first[:2], second[-2:])
        for va in (0x2d01e78, 0x2d01e8d, 0x2d01e98, 0x2d01e9b, 0x2d01ed7):
            with self.subTest(va=va):
                self.mutate_reject(self.image.offset(va, 1, True),
                                   lambda: subject.missing_parameter(self.image))

    def test_transfer_decoder_controls(self):
        self.assertEqual(subject.parse_edge(0x100, bytes.fromhex('ebfe')), ('jmp', 0x100))
        self.assertEqual(subject.parse_edge(0x100, bytes.fromhex('e8fbffffff')), ('call', 0x100))
        self.assertEqual(subject.parse_edge(0x100, bytes.fromhex('0f8401000000')), ('jcc', 0x107))
        self.assertEqual(subject.parse_edge(0x100, bytes.fromhex('ff1501000000')), ('indirect', 0x107))
        for bad in (b'', b'\x90\x90', b'\xe8\x00', b'\x0f\x84', b'\xeb\x00\x00'):
            with self.subTest(raw=bad.hex()), self.assertRaises(subject.EvidenceError):
                subject.parse_edge(0x100, bad)

    def test_fde_boundaries_and_header_pointer(self):
        fde = self.image.owner(0x2d018b0)
        self.assertEqual(fde['start'], 0x2d018b0)
        self.assertEqual(self.image.owner(fde['end'] - 1)['start'], fde['start'])
        with self.assertRaises(subject.EvidenceError):
            self.image.owner(fde['start'], fde['end'] - fde['start'] + 1)
        self.assertEqual(self.image.index[fde['start']]['fde'], fde['fde'])

    def test_corrupt_fde_is_rejected_by_shared_parser(self):
        fde = self.image.owner(0x2d018b0)
        off = self.image.offset(fde['fde'], 4)
        previous = self.mapping[off:off + 4]
        try:
            self.mapping[off:off + 4] = b'\xff\xff\xff\xff'
            with self.assertRaises(ValueError):
                eh_frame_records(self.mapping, self.image.secs)
        finally:
            self.mapping[off:off + 4] = previous

    def test_range_and_nobits_controls(self):
        for va, n in ((0, 1), (-1, 1), (1 << 63, 1), (0x2d018b0, 0)):
            with self.subTest(va=va, n=n), self.assertRaises(subject.EvidenceError):
                self.image.read(va, n)
        text = subject.named_section(self.image.secs, '.text')
        with self.assertRaises(subject.EvidenceError):
            self.image.read(text['address'] + text['size'] - 1, 2, True)
        # A NOBITS-only virtual range cannot supply file bytes.
        fake = [{'name': '.bss', 'type': 8, 'flags': 3, 'address': 0x1000,
                 'size': 0x20, 'offset': 0}]
        with self.assertRaises(subject.EvidenceError):
            subject.va_offset(fake, 0x1000, 1)
        duplicate = [{'name': '.x', 'type': 1, 'flags': 2, 'address': 0x2000,
                      'size': 8, 'offset': 0}] * 2
        with self.assertRaises(subject.EvidenceError):
            subject.va_offset(duplicate, 0x2000, 1)
        with self.assertRaises(subject.EvidenceError):
            subject.named_section(duplicate, '.x')

    def test_relocation_corrupt_addend(self):
        row = self.image.relocations()[0x64e7060]
        clone = copy.copy(self.image)
        clone._relocs = None
        self.mutate_reject(row['file_offset'] + 16, clone.relocations)

    def test_relocation_corrupt_slot(self):
        clone = copy.copy(self.image)
        clone._relocs = None
        self.mutate_reject(self.image.offset(0x6450750, 8), clone.relocations)

    def test_relocation_duplicate_slot(self):
        sec = subject.named_section(self.image.secs, '.rela.dyn')
        off = sec['offset']
        previous = self.mapping[off:off + 8]
        self.assertNotEqual(struct.unpack('<Q', previous)[0], 0x64e7060)
        try:
            self.mapping[off:off + 8] = struct.pack('<Q', 0x64e7060)
            clone = copy.copy(self.image)
            clone._relocs = None
            with self.assertRaisesRegex(subject.EvidenceError, 'duplicate'):
                clone.relocations()
        finally:
            self.mapping[off:off + 8] = previous

    def test_import_name_corruption(self):
        clone = copy.copy(self.image)
        clone._relocs = None
        row = self.image.relocations()[0x64df508]
        sym = subject.named_section(self.image.secs, '.dynsym')
        strings = subject.named_section(self.image.secs, '.dynstr')
        nameoff = struct.unpack_from('<I', self.mapping,
                                     sym['offset'] + 24 * row['symbol_index'])[0]
        self.mutate_reject(strings['offset'] + nameoff, clone.relocations)

    def test_all_field_comparisons_against_independent_oracle(self):
        oracle = {b'address': 'address', b'index': 'index',
                  b'blockId': 'block', b'block_id': 'block'}
        count = 0
        for key in oracle:
            self.assertEqual(subject.classify_field(key, self.names), oracle[key])
            for index, old in enumerate(key):
                for byte in range(256):
                    if byte == old:
                        continue
                    value = key[:index] + bytes([byte]) + key[index + 1:]
                    self.assertEqual(subject.classify_field(value, self.names),
                                     oracle.get(value, 'other'))
                    count += 1
        self.assertEqual(count, 6885)
        for value in (b'', b'Address', b'indexx', b'blockid', b'block-ID'):
            self.assertEqual(subject.classify_field(value, self.names), 'other')

    def test_named_field_order_and_duplicate_alias(self):
        address, index, camel, snake = self.names
        self.assertEqual(subject.named_flow([], self.names), 'missing_address')
        self.assertEqual(subject.named_flow([index], self.names), 'missing_address')
        self.assertEqual(subject.named_flow([address], self.names), 'missing_index')
        for values in itertools.permutations((address, index, camel)):
            self.assertEqual(subject.named_flow(values, self.names), 'complete_block_given')
        self.assertEqual(subject.named_flow([address, index], self.names), 'complete_block_absent')
        self.assertEqual(subject.named_flow([address, index, camel, snake], self.names), 'duplicate_block')
        self.assertEqual(subject.named_flow([address, index, snake, camel], self.names), 'duplicate_block')
        self.assertEqual(subject.named_flow([address, address], self.names), 'duplicate_address')
        self.assertEqual(subject.named_flow([index, index], self.names), 'duplicate_index')
        self.assertEqual(subject.named_flow([b'other', address, index], self.names), 'complete_block_absent')

    def test_key_layout_all_single_bits(self):
        address = bytes(range(20))
        for value in [0, (1 << 256) - 1] + [1 << i for i in range(256)]:
            with self.subTest(value=value):
                limbs = tuple((value >> (64 * i)) & ((1 << 64) - 1) for i in range(4))
                self.assertEqual(subject.key_suffix(address, limbs, self.sizes),
                                 address + value.to_bytes(32, 'big'))

    def test_guard_fast_gate_release_and_corruption(self):
        constants = subject.guard_constants(self.image)
        self.assertEqual(constants[0], 0x6a8)
        for old in range(256):
            expected = 'slow_gate' if old & 8 else 'fast'
            arm, new = subject.guard_acquire(old, True, constants)
            self.assertEqual(arm, expected)
            self.assertEqual(new, old + 16 if expected == 'fast' else None)
            release, wake = subject.guard_release(old, constants)
            self.assertEqual(release, (old - 16) % (1 << 64))
            self.assertEqual(wake, (old & 0xfffffffffffffff2) == 0x12)
        self.assertEqual(subject.guard_acquire(0, False, constants), ('slow_cas_mismatch', None))
        self.assertEqual(subject.guard_acquire((1 << 64) - 16, True, constants), ('slow_gate', None))
        self.assertEqual(subject.guard_acquire((1 << 64) - 17, True, constants)[0], 'slow_gate')
        self.assertEqual(subject.guard_acquire((1 << 64) - 25, True, constants),
                         ('fast', (1 << 64) - 9))
        with self.assertRaises(subject.EvidenceError):
            subject.guard_acquire(1 << 64, True, constants)
        self.mutate_reject(self.image.offset(0x2a39bf1, 1, True),
                           lambda: subject.guard_constants(self.image))

    def test_key_layout_rejects_wrong_width_and_endian(self):
        address = bytes(range(20))
        limbs = (0x0102030405060708, 9, 10, 11)
        result = subject.key_suffix(address, limbs, self.sizes)
        self.assertNotEqual(result[20:], b''.join(n.to_bytes(8, 'little') for n in limbs))
        for bad_address, bad_limbs in ((address[:-1], limbs), (address + b'x', limbs),
                                       (address, limbs[:-1]), (address, (-1, 0, 0, 0)),
                                       (address, (1 << 64, 0, 0, 0))):
            with self.subTest(address=bad_address, limbs=bad_limbs), self.assertRaises(subject.EvidenceError):
                subject.key_suffix(bad_address, bad_limbs, self.sizes)

    def test_index_representation_variants(self):
        for value in (0, 1, 1 << 64, 1 << 200, (1 << 256) - 1):
            big = value.to_bytes(32, 'big')
            little = value.to_bytes(32, 'little')
            self.assertEqual(subject.index_limbs(0, big), subject.index_limbs(1, little))
            self.assertEqual(subject.key_suffix(bytes(20), subject.index_limbs(0, big), self.sizes)[20:], big)
        with self.assertRaises(subject.EvidenceError):
            subject.index_limbs(2, bytes(32))
        with self.assertRaises(subject.EvidenceError):
            subject.index_limbs(1, bytes(31))

    def test_result_tag_matrix_and_reverse_control(self):
        payload = bytes(range(32))
        for account, storage in itertools.product(range(3), repeat=2):
            expected = payload[::-1] if (account, storage) == (1, 1) else bytes(32)
            self.assertEqual(subject.result_word(account, storage, payload), expected)
        self.assertNotEqual(subject.result_word(1, 1, payload), payload)
        with self.assertRaises(subject.EvidenceError):
            subject.result_word(3, 1, payload)
        with self.assertRaises(subject.EvidenceError):
            subject.result_word(1, 1, payload[:-1])

    def test_empty_present_value_error_chain_and_corruption(self):
        witness = subject.empty_value_witness(self.image)
        self.assertEqual(witness, (1, 0, 1, 0x3d48292, 1, 4, 2))
        self.assertEqual(subject.result_word(1, witness[-1], bytes(range(32))), bytes(32))
        for va in (0x3d481b4, 0x3151edb, 0x3152427, 0x3d482d1, 0x3d487c3):
            with self.subTest(va=va):
                self.mutate_reject(self.image.offset(va, 1, True),
                                   lambda: subject.empty_value_witness(self.image))

    def test_dispatch_table_entries_and_mutation(self):
        rows = subject.jump_tables(self.image)
        self.assertEqual(len(rows), 51)
        self.assertEqual(rows[12][-1], '0x21cf9b7')
        self.assertEqual(rows[14][-1], '0x21cfa03')
        self.assertEqual(rows[22 + 12][-1], '0x21cfe5e')
        self.mutate_reject(self.image.offset(subject.TABLES[0][1], 4),
                           lambda: subject.jump_tables(self.image))

    def test_hex_classifier_all_bytes_and_simd_lanes(self):
        table = subject.nibble_table(self.image)
        constants = subject.simd_constants(self.image)
        for byte in range(256):
            if 48 <= byte <= 57:
                expected = byte - 48
            elif 65 <= byte <= 70:
                expected = byte - 65 + 10
            elif 97 <= byte <= 102:
                expected = byte - 97 + 10
            else:
                expected = 255
            self.assertEqual(table[byte], expected)
            for _lane in range(16):
                self.assertEqual(subject.hex_invalid_simd(byte, constants), expected == 255)
        self.mutate_reject(self.image.offset(subject.NIBBLE_TABLE, 256) + ord('A'),
                           lambda: subject.nibble_table(self.image))
        self.mutate_reject(self.image.offset(subject.SIMD_CONSTANTS[0], 16),
                           lambda: subject.simd_constants(self.image))

    def test_fixed_hex_lengths_pairs_and_prefix_order(self):
        table = subject.nibble_table(self.image)
        alphabet = b'0123456789abcdefABCDEF'
        for first, second in itertools.product(alphabet, repeat=2):
            raw = bytes((first, second)) + b'0' * 62
            status, value = subject.fixed_hex(raw, table, 32)
            self.assertEqual(status, 'ok')
            self.assertEqual(value, bytes.fromhex(raw.decode('ascii')))
        self.assertEqual(subject.fixed_hex(b'0' * 64, table, 32), ('ok', bytes(32)))
        self.assertEqual(subject.fixed_hex(b'0x' + b'0' * 64, table, 32), ('ok', bytes(32)))
        self.assertEqual(subject.fixed_hex(b'0x' + b'0' * 63, table, 32)[0], 'odd_length')
        self.assertEqual(subject.fixed_hex(b'0X' + b'0' * 64, table, 32)[0], 'wrong_length')
        self.assertEqual(subject.fixed_hex(b'0X' + b'0' * 62, table, 32)[0], 'invalid_character')
        self.assertEqual(subject.fixed_hex(b'z' + b'0' * 63, table, 32)[0], 'invalid_character')
        self.assertEqual(subject.fixed_hex(b'z' + b'0' * 61, table, 32)[0], 'wrong_length')

    def test_radix_dispatch_all_two_byte_prefixes_and_boundaries(self):
        prefixes = subject.radix_prefixes(self.image)
        expected = {b'0x': 16, b'0X': 16, b'0o': 8,
                    b'0O': 8, b'0b': 2, b'0B': 2}
        for first in range(256):
            for second in range(256):
                data = bytes((first, second))
                radix = expected.get(data, 10)
                self.assertEqual(subject.radix_route(data, prefixes),
                                 (radix, b'' if data in expected else data))
        for byte in range(256):
            data = b'0x' + bytes([byte])
            selected = 10 if 0x80 <= byte <= 0xbf else 16
            self.assertEqual(subject.radix_route(data, prefixes)[0], selected)
        self.assertEqual(subject.radix_route(b'0x', prefixes), (16, b''))
        self.assertEqual(subject.radix_route(b'0X', prefixes), (16, b''))
        self.assertEqual(subject.radix_route(b'1', prefixes), (10, b'1'))

    def test_power_of_two_parser_all_single_bytes(self):
        for base in (2, 8, 16):
            for byte in range(256):
                data = bytes([byte])
                status, value = subject.power2_parse(data, base, 256)
                if data == b'_':
                    self.assertEqual((status, value), ('ok', 0))
                    continue
                try:
                    oracle = int(data.decode('ascii'), base)
                except (ValueError, UnicodeDecodeError):
                    self.assertEqual(status, 'invalid_digit')
                else:
                    self.assertEqual((status, value), ('ok', oracle))

    def test_power_of_two_parser_short_inputs_against_integer_oracle(self):
        alphabet = b'019aAfF_g!'
        for base in (2, 8, 16):
            for length in range(4):
                for seq in itertools.product(alphabet, repeat=length):
                    digits = bytes(seq)
                    cleaned = digits.replace(b'_', b'')
                    try:
                        oracle = int(cleaned.decode('ascii') or '0', base)
                    except ValueError:
                        self.assertEqual(subject.power2_parse(digits, base, 256)[0], 'invalid_digit')
                    else:
                        self.assertEqual(subject.power2_parse(digits, base, 256), ('ok', oracle))

    def test_power_of_two_overflow_and_scan_order(self):
        for base, format_code in ((2, 'b'), (8, 'o'), (16, 'x')):
            for value in (0, 1, (1 << 256) - 1, 1 << 256, (1 << 256) + 1):
                digits = format(value, format_code).encode('ascii')
                status, actual = subject.power2_parse(digits, base, 256)
                self.assertEqual(status, 'ok' if value < 1 << 256 else 'overflow')
                if status == 'ok':
                    self.assertEqual(actual, value)
            self.assertEqual(subject.power2_parse(b'0' * 300 + b'1', base, 256), ('ok', 1))
            self.assertEqual(subject.power2_parse(b'___', base, 256), ('ok', 0))
        self.assertEqual(subject.power2_parse(b'g' + b'f' * 65, 16, 256)[0], 'overflow')
        self.assertEqual(subject.power2_parse(b'1' + b'f' * 64 + b'g', 16, 256)[0], 'invalid_digit')
        with self.assertRaises(subject.EvidenceError):
            subject.power2_parse(b'1', 10, 256)

    def test_decimal_chunks_boundaries_and_error_order(self):
        base, width = subject.decimal_chunk_width(self.image)
        self.assertEqual((base, width), (10, 19))
        values = (0, 1, 10 ** 19 - 1, 10 ** 19, 10 ** 38 - 1,
                  (1 << 256) - 1, 1 << 256, (1 << 256) + 1)
        for value in values:
            status, actual = subject.decimal_parse(str(value).encode(), 256, width)
            self.assertEqual(status, 'ok' if value < 1 << 256 else 'overflow')
            if status == 'ok':
                self.assertEqual(actual, value)
        self.assertEqual(subject.decimal_parse(b'', 256, width), ('ok', 0))
        self.assertEqual(subject.decimal_parse(b'___', 256, width), ('ok', 0))
        self.assertEqual(subject.decimal_parse(b'0' * 100 + b'1', 256, width), ('ok', 1))
        self.assertEqual(subject.decimal_parse(b'9' * 78 + b'!', 256, width)[0], 'invalid_digit')
        self.assertEqual(subject.decimal_parse(b'9' * 95 + b'!', 256, width)[0], 'overflow')
        with self.assertRaises(subject.EvidenceError):
            subject.decimal_parse(b'1', 256, 18)

    def test_decimal_short_inputs_against_integer_oracle(self):
        alphabet = b'019_a!'
        for length in range(5):
            for seq in itertools.product(alphabet, repeat=length):
                digits = bytes(seq)
                cleaned = digits.replace(b'_', b'')
                try:
                    value = int(cleaned or b'0', 10)
                except ValueError:
                    self.assertEqual(subject.decimal_parse(digits, 256, 19)[0], 'invalid_digit')
                else:
                    self.assertEqual(subject.decimal_parse(digits, 256, 19), ('ok', value))

    def test_records_have_deterministic_scoped_counts(self):
        output = subject.records(self.image)
        self.assertEqual(len(output), 20)
        summary = __import__('json').loads(output['summary.json'])
        self.assertEqual(summary['selected_fdes'], 22)
        self.assertEqual(summary['selected_parameter_errors'], 1)
        self.assertEqual(summary['field_classification_vectors'], 6889)
        self.assertEqual(summary['field_flow_vectors'], 781)
        self.assertEqual(summary['key_vectors'], 258)
        self.assertEqual(summary['guard_vectors'], 24)
        self.assertEqual(summary['lookup_vectors'], 18)
        self.assertEqual(summary['dispatch_entries'], 51)
        self.assertEqual(summary['empty_value_cases'], 1)
        self.assertEqual(summary['hex_classes'], 256)
        self.assertEqual(summary['hex_vectors'], 264)
        self.assertEqual(summary['radix_vectors'], 16)
        self.assertEqual(summary['power_vectors'], 33)
        self.assertEqual(summary['decimal_chunk_digits'], 19)
        self.assertEqual(summary['decimal_vectors'], 10)
        self.assertNotIn(b'\r\n', output['field-vectors.tsv'])


if __name__ == '__main__':
    unittest.main()
