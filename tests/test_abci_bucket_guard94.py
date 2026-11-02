"""Controls for the static guard-loader evidence extractor."""
import hashlib
import mmap
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import abci_bucket_guard94 as guard


class GuardEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.file = guard.ARTIFACT.open('rb')
        cls.data = mmap.mmap(cls.file.fileno(), 0, access=mmap.ACCESS_READ)
        guard.check_digest(cls.data)
        cls.sections = guard.sections(cls.data)

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.file.close()

    def bytes_at(self, va, size):
        return guard.read_va(self.data, self.sections, va, size)

    def test_expected_artifact_digest(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), guard.DIGEST)

    def test_wrong_digest_does_not_create_output(self):
        with mmap.mmap(self.file.fileno(), 0, access=mmap.ACCESS_COPY) as damaged:
            damaged[0x40] ^= 1
            with tempfile.TemporaryDirectory() as directory:
                out = Path(directory) / 'evidence'
                with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                    guard.generate(damaged, out)
                self.assertFalse(out.exists())

    def test_text_va_resolves_to_file_offset(self):
        off, section = guard.file_offset(self.data, self.sections, 0x325dd60, 5)
        self.assertEqual((off, section), (0x325cd60, '.text'))
        self.assertEqual(bytes(self.data[off:off + 5]), bytes.fromhex('534883ec10'))

    def test_unmapped_and_wrapping_ranges_are_rejected(self):
        for va, size in ((0, 1), (0xffffffffffffffff, 2), (-1, 1), (0x325dd60, 0)):
            with self.subTest(va=va, size=size), self.assertRaises(ValueError):
                guard.file_offset(self.data, self.sections, va, size)

    def test_nobits_and_ambiguous_mappings_are_rejected(self):
        data = b'abcdefgh'
        nobits = {'type': 8, 'flags': 2, 'address': 10, 'size': 4, 'offset': 0, 'name': 'n'}
        with self.assertRaises(ValueError):
            guard.file_offset(data, [nobits], 10, 1)
        first = dict(nobits, type=1)
        second = dict(first, name='other', offset=1)
        with self.assertRaises(ValueError):
            guard.file_offset(data, [first, second], 10, 1)

    def test_fde_index_and_full_body_digests(self):
        rows = guard.checked_fdes(self.data, self.sections, guard.FUNCTIONS)
        self.assertEqual(len(rows), 6)
        bounds = {row[1]: row[2] for row in rows}
        self.assertEqual(bounds[0x3143ec0], 0x3144696)
        self.assertEqual(bounds[0x2a9c3a0], 0x2a9da87)
        self.assertEqual(bounds[0x2aae4c0], 0x2aae580)

    def test_damaged_body_is_rejected_even_if_va_is_mapped(self):
        off, _ = guard.file_offset(self.data, self.sections, 0x3143ec0, 1)
        with mmap.mmap(self.file.fileno(), 0, access=mmap.ACCESS_COPY) as damaged:
            damaged[off] ^= 1
            with self.assertRaisesRegex(ValueError, 'body differs'):
                guard.checked_fdes(damaged, self.sections, [0x3143ec0])

    def test_damaged_fde_start_does_not_match_unwind_index(self):
        offset, _ = guard.file_offset(self.data, self.sections, 0x114c5bc, 12)
        with mmap.mmap(self.file.fileno(), 0, access=mmap.ACCESS_COPY) as damaged:
            damaged[offset + 8] ^= 1
            with self.assertRaises(ValueError):
                guard.checked_fdes(damaged, self.sections, [0x3143ec0])

    def test_unknown_fde_start_is_rejected(self):
        with self.assertRaises(ValueError):
            guard.checked_fdes(self.data, self.sections, [0x3143ec1])

    def test_fixed_instruction_window_tamper(self):
        name, va, expected_hex = next(row for row in guard.PINS if row[0] == 'json_map_children')
        expected = bytes.fromhex(expected_hex)
        actual = self.bytes_at(va, len(expected))
        guard.check_pin(actual, expected)
        bad = bytearray(actual)
        bad[len(bad) // 2] ^= 1
        with self.assertRaisesRegex(ValueError, 'window differs'):
            guard.check_pin(bad, expected)
        self.assertEqual(name, 'json_map_children')

    def test_direct_call_signed_displacement_and_corruption(self):
        raw = self.bytes_at(0x325dd84, 5)
        self.assertEqual(guard.rel_call(raw, 0x325dd84, 0x3143ec0), 0x3143ec0)
        with self.assertRaises(ValueError):
            guard.rel_call(bytes([0xe9]) + raw[1:], 0x325dd84, 0x3143ec0)
        with self.assertRaises(ValueError):
            guard.rel_call(raw[:-1] + bytes([raw[-1] ^ 1]), 0x325dd84, 0x3143ec0)

    def test_all_selected_call_displacements_are_checked(self):
        for name, va, target in guard.CALLS:
            with self.subTest(name=name):
                raw = self.bytes_at(va, 5)
                self.assertEqual(guard.rel_call(raw, va, target), target)
                damaged = bytearray(raw)
                damaged[1] ^= 1
                with self.assertRaises(ValueError):
                    guard.rel_call(damaged, va, target)

    def test_branch_targets_and_corrupted_opcode_or_displacement(self):
        for _, va, target in guard.BRANCHES:
            with self.subTest(va=hex(va)):
                raw = self.bytes_at(va, 6)
                size, _, actual = guard.rel_branch(raw, va, target)
                self.assertEqual(actual, target)
                self.assertIn(size, (2, 6))
                bad_opcode = bytes([0x90]) + raw[1:]
                with self.assertRaises(ValueError):
                    guard.rel_branch(bad_opcode, va, target)
                bad_displacement = bytearray(raw)
                bad_displacement[size - 1] ^= 1
                with self.assertRaises(ValueError):
                    guard.rel_branch(bad_displacement, va, target)

    def test_json_presence_is_distinct_from_width_value(self):
        self.assertEqual(self.bytes_at(0x314431e, 5), bytes.fromhex('f644244001'))
        self.assertEqual(self.bytes_at(0x3144323, 6), bytes.fromhex('0f8435010000'))
        self.assertEqual(self.bytes_at(0x3144329, 5), bytes.fromhex('488b442438'))
        self.assertEqual(self.bytes_at(0x3144331, 3), bytes.fromhex('4885c0'))
        self.assertEqual(self.bytes_at(0x3144334, 6), bytes.fromhex('0f843b010000'))

    def test_msgpack_presence_is_distinct_from_width_value(self):
        self.assertEqual(self.bytes_at(0x2a9d704, 8), bytes.fromhex('f68424b800000001'))
        self.assertEqual(self.bytes_at(0x2a9d71c, 6), bytes.fromhex('0f8481f3ffff'))
        self.assertEqual(self.bytes_at(0x2a9d722, 3), bytes.fromhex('4d85e4'))
        self.assertEqual(self.bytes_at(0x2a9d725, 6), bytes.fromhex('0f846b010000'))

    def test_duplicate_exits_reach_correct_field_names(self):
        cases = ((0x31440c3, 0x31445c0, 0x31445c0, 0x57dc27, b'last_bucket'),
                 (0x31441e6, 0x31445a9, 0x31445a9, 0x57dc32, b'bucket_millis'),
                 (0x2a9d6bb, 0x2a9d992, 0x2a9d995, 0x577098, b'last_bucket'),
                 (0x2a9d617, 0x2a9d978, 0x2a9d97b, 0x5770a3, b'bucket_millis'))
        for branch, target, lea, literal, name in cases:
            with self.subTest(branch=hex(branch)):
                self.assertEqual(guard.rel_branch(self.bytes_at(branch, 6), branch, target)[2], target)
                self.assertEqual(guard.rip_reference(self.bytes_at(lea, 7), lea, bytes.fromhex('488d05'), literal), literal)
                self.assertEqual(self.bytes_at(literal, len(name)), name)

    def test_key_comparison_chains_and_negative_names(self):
        body = self.bytes_at(0x2aae4c0, 0xc0)
        rows, words = guard.decode_classifier(body)
        self.assertEqual(words, [b'last_bucket', b'bucket_millis'])
        self.assertEqual(len(rows), 24)
        for tag, word in enumerate(words):
            self.assertEqual(guard.classify_key(words, word), tag)
            self.assertEqual(guard.classify_key(words, word[:-1]), 2)
            self.assertEqual(guard.classify_key(words, word + b'x'), 2)
            for index in range(len(word)):
                candidate = bytearray(word)
                candidate[index] ^= 1
                self.assertEqual(guard.classify_key(words, bytes(candidate)), 2)

    def test_each_key_compare_byte_corruption_is_detected(self):
        original = self.bytes_at(0x2aae4c0, 0xc0)
        rows, _ = guard.decode_classifier(original)
        for tag, index, cmp_va, _, _, _ in rows:
            with self.subTest(tag=tag, index=index):
                damaged = bytearray(original)
                immediate = cmp_va - 0x2aae4c0 + (2 if index == 0 else 3)
                damaged[immediate] ^= 1
                with self.assertRaises(ValueError):
                    guard.decode_classifier(damaged)

    def test_key_classifier_branch_corruption_is_detected(self):
        original = self.bytes_at(0x2aae4c0, 0xc0)
        rows, _ = guard.decode_classifier(original)
        for _, index, _, _, branch, _ in rows:
            with self.subTest(index=index, branch=hex(branch)):
                damaged = bytearray(original)
                damaged[branch - 0x2aae4c0 + 1] ^= 1
                with self.assertRaises(ValueError):
                    guard.decode_classifier(damaged)

    def test_literal_lengths_and_corrupt_immediates(self):
        for name, va, prefix_hex, expected in guard.IMMEDIATES:
            with self.subTest(name=name):
                prefix = bytes.fromhex(prefix_hex)
                raw = self.bytes_at(va, len(prefix) + 4)
                self.assertEqual(guard.immediate32(raw, prefix, expected), expected)
                damaged = bytearray(raw)
                damaged[-1] ^= 1
                with self.assertRaises(ValueError):
                    guard.immediate32(damaged, prefix, expected)

    def test_rip_relative_name_links_and_corruption(self):
        names = []
        for name, va, prefix_hex, expected, target in guard.REFERENCES:
            with self.subTest(name=name):
                prefix = bytes.fromhex(prefix_hex)
                raw = self.bytes_at(va, len(prefix) + 4)
                self.assertEqual(guard.rip_reference(raw, va, prefix, expected), expected)
                self.assertEqual(self.bytes_at(expected, len(target)), target)
                damaged = bytearray(raw)
                damaged[-1] ^= 1
                with self.assertRaises(ValueError):
                    guard.rip_reference(damaged, va, prefix, expected)
                if 'guard_name' in name:
                    names.append(target)
        self.assertEqual(names, [b'begin_block_logic_guard'] * 2)

    def test_wide_marker_table_and_every_entry_corruption(self):
        raw = self.bytes_at(guard.WIDE_MARKER_TABLE, 128)
        rows = guard.wide_marker_entries(raw)
        self.assertEqual(len(rows), 32)
        targets = {marker: target for marker, _, _, target in rows}
        self.assertEqual(targets[0xdc], 0x2a9c6fe)
        self.assertEqual(targets[0xdd], 0x2a9c66d)
        self.assertEqual(targets[0xde], 0x2a9c69a)
        self.assertEqual(targets[0xdf], 0x2a9c640)
        for i in range(32):
            with self.subTest(marker=hex(0xc0 + i)):
                damaged = bytearray(raw)
                damaged[i * 4] ^= 1
                with self.assertRaisesRegex(ValueError, 'jump table differs'):
                    guard.wide_marker_entries(damaged)

    def test_selected_state_dispatch_and_corruption(self):
        raw = self.bytes_at(0x4313fc, 4)
        self.assertEqual(guard.state_selector_entry(raw), 0x2a9c6c4)
        damaged = bytearray(raw)
        damaged[0] ^= 1
        with self.assertRaisesRegex(ValueError, 'target differs'):
            guard.state_selector_entry(damaged)
        with self.assertRaises(ValueError):
            guard.state_selector_entry(raw[:3])

    def test_marker_bounds_are_derived_from_comparisons(self):
        lower = self.bytes_at(0x2a9cde0, 4)
        upper = self.bytes_at(0x2a9c956, 4)
        self.assertEqual(guard.marker_bounds(lower, upper), (0xc0, 0xdf))
        for i in range(4):
            bad = bytearray(lower)
            bad[i] ^= 1
            with self.subTest(i=i), self.assertRaises(ValueError):
                guard.marker_bounds(bad, upper)

    def test_marker_target_outside_body_is_rejected(self):
        raw = bytearray(self.bytes_at(guard.WIDE_MARKER_TABLE, 128))
        raw[0:4] = (0x7fffffff).to_bytes(4, 'little', signed=True)
        with patch.object(guard, 'WIDE_MARKER_SHA256', hashlib.sha256(raw).hexdigest()):
            with self.assertRaisesRegex(ValueError, 'outside selected FDE'):
                guard.wide_marker_entries(raw)

    def test_container_length_reads_and_truncation_exits(self):
        for va, target in ((0x2a9c702, 0x2a9c77e), (0x2a9c671, 0x2a9c77e),
                           (0x2a9c69e, 0x2a9c77e), (0x2a9c644, 0x2a9c77e)):
            with self.subTest(va=hex(va)):
                self.assertEqual(guard.rel_branch(self.bytes_at(va, 6), va, target)[2], target)
        self.assertEqual(self.bytes_at(0x2a9c708, 7), bytes.fromhex('0fb71166c1c208'))
        self.assertEqual(self.bytes_at(0x2a9c67b, 7), bytes.fromhex('448b394883c104'))
        self.assertEqual(self.bytes_at(0x2a9c682, 3), bytes.fromhex('410fcf'))
        self.assertEqual(self.bytes_at(0x2a9c77e, 17), bytes.fromhex('4801c148894e1048c7461800000000b001'))

    def test_selected_parent_to_materializer_offsets(self):
        for _, va, prefix_hex, expected in guard.OFFSETS:
            with self.subTest(va=hex(va)):
                prefix = bytes.fromhex(prefix_hex)
                raw = self.bytes_at(va, len(prefix) + 4)
                self.assertTrue(raw.startswith(prefix))
                self.assertEqual(int.from_bytes(raw[-4:], 'little', signed=True), expected)
        self.assertEqual(guard.OFFSETS[0][-1], guard.OFFSETS[2][-1])
        self.assertEqual(guard.OFFSETS[0][-1], guard.OFFSETS[3][-1])
        self.assertEqual(guard.OFFSETS[6][-1], 0x38f8)


if __name__ == '__main__':
    unittest.main()
