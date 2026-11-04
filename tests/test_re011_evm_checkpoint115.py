"""Offline controls for selected #115 EVM checkpoint evidence."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import re011_evm_checkpoint115 as packet


class Node115CheckpointEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = packet.BINARY.read_bytes()
        packet.check_digest(cls.data)
        cls.image = packet.Image(cls.data)
        cls.outputs = packet.build(cls.image)
        cls.vectors = json.loads(cls.outputs['vectors.json'])

    def test_authenticated_target(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), packet.SHA256)
        with self.assertRaises(ValueError):
            packet.check_digest(b'not the captured binary')

    def test_bad_digest_does_not_create_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake, out = root / 'fake', root / 'evidence'
            fake.write_bytes(b'not the captured binary')
            with mock.patch.object(packet, 'BINARY', fake):
                with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
                    packet.main(['--out', str(out)])
            self.assertFalse(out.exists())

    def test_wrapper_trailing_sentinel_and_null_failure(self):
        raw = self.image.read(0x518d1e0, 10)
        self.assertEqual(raw[:2], bytes.fromhex('49be'))
        sentinel = struct.unpack_from('<Q', raw, 2)[0]
        self.assertEqual(sentinel, 1 << 63)
        cases = ((0, 0, 0, 'other_variant'),
                 (sentinel - 1, 0, 1, 'other_variant'),
                 (sentinel + 1, 0, 1, 'other_variant'),
                 (sentinel, 0, 0, 'sentinel_empty'),
                 (sentinel, 1, 0, 'sentinel_empty'),
                 (sentinel, 0, 1, 'sentinel_null_failure'),
                 (sentinel, 1, 1, 'sentinel_nonempty'))
        for tag, first, flag, expected in cases:
            with self.subTest(tag=tag, first=first, flag=flag):
                self.assertEqual(packet.trailing_region_case(tag, first, flag, sentinel), expected)
        for invalid in (-1, 1 << 64, True):
            with self.assertRaises(ValueError):
                packet.trailing_region_case(invalid, 0, 0, sentinel)

    def test_missing_binary_does_not_create_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            out = root / 'evidence'
            with mock.patch.object(packet, 'BINARY', root / 'missing'):
                with self.assertRaises(FileNotFoundError):
                    packet.main(['--out', str(out)])
            self.assertFalse(out.exists())

    def test_fde_index_agrees_and_rejects_wrong_extent(self):
        for name, start, end in packet.FUNCTIONS:
            with self.subTest(name=name):
                row = self.image.fde(start, end)
                self.assertEqual(row['start'], start)
                with self.assertRaises(ValueError):
                    self.image.fde(start, end - 1)
                with self.assertRaises(ValueError):
                    self.image.fde(start + 1, end)

    def test_raw_frame_records_reject_invalid_length_and_address(self):
        _, start, end = packet.FUNCTIONS[0]
        va = self.image.fde(start, end)['fde']
        raw = packet.frame_record(self.image, va)
        self.assertEqual(struct.unpack_from('<I', raw)[0] + 4, len(raw))
        with self.assertRaisesRegex(ValueError, 'outside section'):
            packet.frame_record(self.image, start)
        original = self.image.read
        for length in (0, 3, 0xffffffff, self.image.named['.eh_frame']['size']):
            def damaged(address, size):
                return struct.pack('<I', length) if (address, size) == (va, 4) else original(address, size)
            with self.subTest(length=length), mock.patch.object(self.image, 'read', side_effect=damaged):
                with self.assertRaisesRegex(ValueError, 'invalid frame record length'):
                    packet.frame_record(self.image, va)
        rows = self.outputs['frames.tsv'].decode().splitlines()
        self.assertTrue(any(line.startswith('fde\t' + hex(va) + '\t') for line in rows))
        self.assertTrue(any(line.startswith('cie\t') for line in rows))

    def test_selected_intervals_are_disjoint(self):
        rows = sorted((s, e) for _, s, e in packet.FUNCTIONS)
        self.assertTrue(all(a[1] <= b[0] for a, b in zip(rows, rows[1:])))
        with self.assertRaises(ValueError):
            self.image.containing_selected(0, 1)
        first = packet.FUNCTIONS[0]
        with self.assertRaises(ValueError):
            self.image.containing_selected(first[2] - 1, 2)

    def test_file_mapping_bounds_and_nobits(self):
        self.assertTrue(all(s['type'] != 8 for s in self.image.file_backed))
        bss = self.image.named['.bss']
        self.assertEqual(bss['type'], 8)
        with self.assertRaises(ValueError):
            self.image.offset(bss['address'], 1)
        for address, size in ((0, 1), (-1, 1), (1, 0), (1 << 64, 1)):
            with self.subTest(address=address, size=size):
                with self.assertRaises(ValueError):
                    self.image.offset(address, size)
        text = self.image.named['.text']
        self.assertEqual(self.image.offset(text['address']), text['offset'])

    def test_every_window_detects_corruption(self):
        for name, va, expected in packet.WINDOWS:
            raw = self.image.read(va, len(bytes.fromhex(expected)))
            packet.check_window(raw, expected)
            for idx in {0, len(raw) - 1}:
                changed = bytearray(raw)
                changed[idx] ^= 1
                with self.subTest(window=name, index=idx):
                    with self.assertRaises(ValueError):
                        packet.check_window(changed, expected)

    def test_every_transfer_rejects_changed_opcode_and_displacement(self):
        for name, va, expected, kind, target in packet.EDGES:
            raw = bytes.fromhex(expected)
            self.assertEqual(packet.decode_transfer(va, raw), (kind, target), name)
            wrong_opcode = bytes([0x90]) + raw[1:]
            with self.subTest(name=name, mutation='opcode'):
                with self.assertRaises(ValueError):
                    packet.decode_transfer(va, wrong_opcode)
            wrong_target = raw[:-1] + bytes([raw[-1] ^ 1])
            with self.subTest(name=name, mutation='displacement'):
                with self.assertRaises(ValueError):
                    packet.check_window(wrong_target, expected)
                self.assertNotEqual(packet.decode_transfer(va, wrong_target), (kind, target))

    def test_truncated_transfer_is_rejected(self):
        for bad in (b'', b'\xe8', b'\x0f\x84\x00', b'\xff\x15\x00'):
            with self.subTest(raw=bad):
                with self.assertRaises(ValueError):
                    packet.decode_transfer(0x100, bad)

    def test_indirect_slots_resolve_to_checked_functions(self):
        for slot, target in packet.EDGE_SLOTS.items():
            with self.subTest(slot=slot):
                self.assertEqual(self.image.relative(slot), target)
        with self.assertRaises(ValueError):
            self.image.relative(0)

    def test_duplicate_relative_relocations_are_rejected(self):
        record = struct.pack('<QQq', 0x100, 8, 0x200)
        fake = packet.Image.__new__(packet.Image)
        fake.data = record * 2
        fake.named = {'.rela.dyn': {'offset': 0, 'size': len(fake.data), 'type': 4}}
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            fake._relative_relocations()
        fake.named['.rela.dyn']['size'] -= 1
        with self.assertRaisesRegex(ValueError, 'invalid'):
            fake._relative_relocations()

    def test_wrong_indirect_relocation_fails_extraction(self):
        original = self.image.relative
        def wrong(slot):
            return original(slot) + 1 if slot == 0x64e95a0 else original(slot)
        with mock.patch.object(self.image, 'relative', side_effect=wrong):
            with self.assertRaisesRegex(ValueError, 'relocation mismatch'):
                packet.build(self.image)

    def test_wrong_prefix_relocation_fails_extraction(self):
        original = self.image.relative
        def wrong(slot):
            return original(slot) + 2 if slot == 0x6479ec0 else original(slot)
        with mock.patch.object(self.image, 'relative', side_effect=wrong):
            with self.assertRaisesRegex(ValueError, 'prefix table'):
                packet.build(self.image)

    def test_bad_location_line_is_rejected(self):
        slot = 0x646e818
        original = self.image.read
        def wrong(va, length):
            value = original(va, length)
            if va == slot + 8 and length == 16:
                value = value[:8] + struct.pack('<I', 190) + value[12:]
            return value
        with mock.patch.object(self.image, 'read', side_effect=wrong):
            with self.assertRaisesRegex(ValueError, 'location mismatch'):
                packet.location_record(self.image, slot, packet.LOCATION_SLOTS[slot])

    def test_prefixes_and_fork_fragments(self):
        rows = self.outputs['prefixes.tsv'].decode().splitlines()
        self.assertEqual([line.split('\t')[6] for line in rows[1:]], ['Ea', 'Ec', 'Es'])
        self.assertEqual([int(line.split('\t')[1]) for line in rows[1:]], [26, 27, 28])
        self.assertEqual(len(packet.marker_offsets(self.image, 'z_forks/revm-precompile/')), 12)
        with self.assertRaises(ValueError):
            packet.marker_offsets(self.image, 'z_forks/this-marker-is-absent/')

    def test_json_fields_and_corrupt_string(self):
        rows = [line.split('\t') for line in self.outputs['schema.tsv'].decode().splitlines()[1:]]
        self.assertEqual([(r[1], int(r[6]), r[7]) for r in rows], [
            ('accounts_hash', 0, 'Ea'), ('contracts_hash', 2064, 'Ec'),
            ('storage_hash', 4128, 'Es'), ('n_elements', 2048, ''),
            ('n_bytes', 2056, ''), ('hash', 0, '')])
        original = self.image.read
        def wrong(va, length):
            value = original(va, length)
            if va == 0x7a1422:
                value = b'X' + value[1:]
            return value
        with mock.patch.object(self.image, 'read', side_effect=wrong):
            with self.assertRaisesRegex(ValueError, 'schema string'):
                packet.string_reference(self.image, 0x38c2285, 0x38c2291, 'accounts_hash')
        def wrong_extension(va, length):
            return b'bad' if (va, length) == (0x4659e5, 3) else original(va, length)
        with mock.patch.object(self.image, 'read', side_effect=wrong_extension):
            with self.assertRaisesRegex(ValueError, 'writer extension bytes'):
                packet.build(self.image)

    def test_corrupt_record_offset_is_rejected(self):
        original = self.image.read
        def wrong(va, length):
            value = original(va, length)
            if va == 0x38c230e:
                value = b'X' + value[1:]
            return value
        with mock.patch.object(self.image, 'read', side_effect=wrong):
            with self.assertRaisesRegex(ValueError, 'offset instruction'):
                packet.record_offset(self.image, 0x38c230e, '488dbb')

    def test_classify_key_prefix_and_exact_suffix_width(self):
        prefix, n = b'Ea', self.vectors['selected_key_suffix_bytes']
        cases = [(b'', 'stop'), (b'E', 'stop'), (b'Eb' + bytes(n), 'stop'),
                 (prefix, 'skip'), (prefix + bytes(n-1), 'skip'),
                 (prefix + bytes(n), 'decode'), (prefix + bytes(n+1), 'skip')]
        for key, expected in cases:
            with self.subTest(key=key):
                self.assertEqual(packet.classify_key(key, prefix, n), expected)
        with self.assertRaises(ValueError):
            packet.classify_key(prefix, prefix, -1)

    def test_hash_sequence_length_boundaries(self):
        size = self.vectors['payload_bytes']
        for count, expected in ((0, 'short'), (size-1, 'short'), (size, 'exact'), (size+1, 'long')):
            with self.subTest(count=count):
                self.assertEqual(packet.sequence_count_case(count, size), expected)
        for count, expected in ((-1, size), (0, 0), (True, size)):
            with self.assertRaises(ValueError):
                packet.sequence_count_case(count, expected)

    def test_string_decoder_tag_and_decoded_length_gate(self):
        expected = self.vectors['payload_bytes']
        for tag in (0, 1, 2):
            for length in (expected-1, expected, expected+1):
                with self.subTest(tag=tag, length=length):
                    self.assertEqual(packet.decoded_string_gate(tag, length, expected),
                                     tag in (0, 1) and length == expected)
        for tag, length in ((3, expected), (0, -1), (True, expected)):
            with self.assertRaises(ValueError):
                packet.decoded_string_gate(tag, length, expected)

    def test_numeric_byte_tags_and_unsigned_range(self):
        for tag in range(4):
            for word in (0, 1, 255, 256, (1 << 64)-1):
                with self.subTest(tag=tag, word=word):
                    self.assertEqual(packet.numeric_byte_variant(tag, word), tag in (1, 2) and word <= 255)
        for word in (-1, 1 << 64, True):
            with self.assertRaises(ValueError):
                packet.numeric_byte_variant(1, word)

    def test_required_field_precedence_all_presence_masks(self):
        for fields in (('accounts_hash', 'contracts_hash', 'storage_hash'),
                       ('n_elements', 'n_bytes', 'hash')):
            expected = [fields[0], fields[1], fields[0], fields[2],
                        fields[0], fields[1], fields[0], None]
            for mask, outcome in enumerate(expected):
                with self.subTest(fields=fields, mask=mask):
                    self.assertEqual(packet.first_missing(mask, fields), outcome)
            for mask in (-1, 8, True):
                with self.assertRaises(ValueError):
                    packet.first_missing(mask, fields)

    def test_missing_and_duplicate_field_names_are_target_backed(self):
        rows = [line.split('\t') for line in self.outputs['parse-errors.tsv'].decode().splitlines()[1:]]
        self.assertEqual([(r[0], r[1]) for r in rows], [
            ('outer', 'accounts_hash'), ('outer', 'contracts_hash'), ('outer', 'storage_hash'),
            ('inner', 'n_elements'), ('inner', 'n_bytes'), ('inner', 'hash')])
        self.assertEqual(packet.error_field_reference(self.image, 0x41200d9, 'accounts_hash'),
                         packet.error_field_reference(self.image, 0x4120212, 'accounts_hash'))
        with self.assertRaises(ValueError):
            packet.error_field_reference(self.image, 0x41200d9, 'storage_hash')
        original = self.image.read
        def wrong(va, length):
            value = original(va, length)
            if va == 0x41200d9 + 15 and length == 12:
                value = value[:-4] + (12).to_bytes(4, 'little')
            return value
        with mock.patch.object(self.image, 'read', side_effect=wrong):
            with self.assertRaisesRegex(ValueError, 'error field name'):
                packet.error_field_reference(self.image, 0x41200d9, 'accounts_hash')

    def test_trailing_json_bytes_all_values(self):
        mask = int(self.vectors['trailing_byte_mask'], 16)
        limit = self.vectors['trailing_byte_max']
        self.assertEqual(self.vectors['trailing_accepted_bytes'], [9, 10, 13, 32])
        self.assertTrue(packet.valid_json_tail(b'', limit, mask))
        self.assertTrue(packet.valid_json_tail(bytes([32, 9, 10, 13, 32]), limit, mask))
        for value in range(256):
            with self.subTest(value=value):
                self.assertEqual(packet.valid_json_tail(bytes([value]), limit, mask), value in {9, 10, 13, 32})
        self.assertFalse(packet.valid_json_tail(bytes([32, 9, 0, 10]), limit, mask))
        for bad in (b'X', bytes([0x7f]), bytes([0xff])):
            self.assertFalse(packet.valid_json_tail(bad, limit, mask))
        with self.assertRaises(ValueError):
            packet.valid_json_tail(b'', -1, mask)

    def test_decimal_byte_all_values_and_boundaries(self):
        table = bytes.fromhex(self.vectors['decimal_table_hex'])
        for value in range(256):
            with self.subTest(value=value):
                self.assertEqual(packet.decimal_byte(value, table), str(value).encode('ascii'))
        for value in (-1, 256, True):
            with self.assertRaises(ValueError):
                packet.decimal_byte(value, table)
        with self.assertRaises(ValueError):
            packet.decimal_byte(10, table[:-1])
        corrupt = bytearray(table)
        corrupt[20] ^= 1
        self.assertNotEqual(packet.decimal_byte(10, corrupt), b'10')

    def test_corrupt_decimal_table_fails_extraction(self):
        original = self.image.read
        table_va = int(self.vectors['decimal_table_va'], 16)
        def wrong(va, length):
            value = original(va, length)
            if va == table_va and length == 200:
                value = bytes([value[0] ^ 1]) + value[1:]
            return value
        with mock.patch.object(self.image, 'read', side_effect=wrong):
            with self.assertRaisesRegex(ValueError, 'decimal table contents'):
                packet.build(self.image)

    def test_three_prefix_key_widths(self):
        widths = self.vectors['all_key_suffix_bytes']
        self.assertEqual(widths, {'Ea': 20, 'Ec': 32, 'Es': 52})
        for text, width in widths.items():
            prefix = text.encode('ascii')
            for delta, expected in ((-1, 'skip'), (0, 'decode'), (1, 'skip')):
                with self.subTest(prefix=text, delta=delta):
                    self.assertEqual(packet.classify_key(prefix + bytes(width+delta), prefix, width), expected)
            self.assertEqual(packet.classify_key(b'X' + prefix + bytes(width), prefix, width), 'stop')

    def test_composite_key_split_and_full_32_byte_reversal(self):
        first, second = bytes(range(20)), bytes(range(32))
        key = b'Es' + first + second
        self.assertEqual(packet.split_es_key(key, b'Es', 20, 32), (first, second[::-1]))
        self.assertEqual(self.vectors['es_composite_vector']['second_field_reversed_hex'], second[::-1].hex())
        for bad in (key[:-1], key + b'X', b'Ex' + key[2:]):
            with self.subTest(key=bad):
                with self.assertRaises(ValueError):
                    packet.split_es_key(bad, b'Es', 20, 32)

    def test_batch_boundary_and_empty_tail(self):
        limit = self.vectors['batch_capacity']
        cases = [(0, (0, 0)), (1, (0, 1)), (limit-1, (0, limit-1)),
                 (limit, (1, 0)), (limit+1, (1, 1)), (limit*2, (2, 0))]
        for count, expected in cases:
            with self.subTest(count=count):
                self.assertEqual(packet.chunk_plan(count, limit), expected)
        for count, capacity in [(-1, limit), (1, 0), (1, -1), (True, limit)]:
            with self.assertRaises(ValueError):
                packet.chunk_plan(count, capacity)

    def test_big_endian_lanes_wrap_without_neighbor_carry(self):
        payload = self.vectors['payload_bytes']
        left, right = bytearray(payload+16), bytearray(payload+16)
        left[:8] = bytes.fromhex('00ffffff1234ffff')
        right[:8] = bytes.fromhex('0001000100010001')
        result = packet.merge_records(left, right, payload)
        self.assertEqual(result[:8].hex(), '0100000012350000')
        self.assertEqual(result[8:payload], bytes(payload-8))

    def test_lane_model_checks_full_record_and_end(self):
        payload = self.vectors['payload_bytes']
        left, right = bytearray(payload+16), bytearray(payload+16)
        left[payload-2:payload], right[payload-2:payload] = b'\xff\xff', b'\x00\x01'
        self.assertEqual(packet.merge_records(left, right, payload)[payload-2:payload], b'\x00\x00')
        for bad_left, bad_right, width in [(left[:-1], right, payload),
                                           (left, right[:-1], payload),
                                           (left, right, payload-1), (left, right, 0)]:
            with self.assertRaises(ValueError):
                packet.merge_records(bad_left, bad_right, width)

    def test_two_counters_saturate_independently(self):
        payload = self.vectors['payload_bytes']
        left, right = bytearray(payload+16), bytearray(payload+16)
        maximum = (1 << 64)-1
        struct.pack_into('<QQ', left, payload, maximum, maximum-2)
        struct.pack_into('<QQ', right, payload, 1, 1)
        result = packet.merge_records(left, right, payload)
        self.assertEqual(struct.unpack_from('<QQ', result, payload), (maximum, maximum-1))
        struct.pack_into('<QQ', right, payload, 0, 3)
        result = packet.merge_records(left, right, payload)
        self.assertEqual(struct.unpack_from('<QQ', result, payload), (maximum, maximum))

    def test_generated_records_have_expected_scope(self):
        self.assertEqual(set(self.outputs), {'data.tsv', 'functions.tsv', 'frames.tsv', 'windows.tsv', 'transfers.tsv',
                         'locations.tsv', 'prefixes.tsv', 'relocations.tsv',
                         'fork-markers.tsv', 'schema.tsv', 'parse-errors.tsv', 'presence-vectors.tsv',
                         'decimal-vectors.tsv', 'trailing-bytes.tsv', 'sequence-vectors.tsv',
                         'numeric-byte-vectors.tsv', 'string-length-vectors.tsv', 'vectors.json'})
        counts = self.vectors['counts']
        self.assertEqual(counts['selected_fdes'], len(packet.FUNCTIONS))
        self.assertEqual(counts['windows'], len(packet.WINDOWS))
        self.assertEqual(counts['transfers'], len(packet.EDGES))
        self.assertEqual(counts['prefixes'], 3)
        self.assertEqual(self.vectors['target_sha256'], packet.SHA256)


if __name__ == '__main__':
    unittest.main()
