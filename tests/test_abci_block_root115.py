"""Static, target-grounded and negative controls for the selected block path."""
import contextlib
import hashlib
import mmap
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

from tools import abci_block_root115 as study


class StaticPathTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.handle = study.TARGET.open('rb')
        cls.data = mmap.mmap(cls.handle.fileno(), 0, access=mmap.ACCESS_COPY)
        cls.image = study.Image(cls.data)
        cls.captures = study.captures(cls.image)
        cls.jobs, cls.count, cls.allocation, cls.group = study.parse_descriptor_stream(
            cls.image, cls.captures)
        cls.facts = study.constants(cls.image, cls.count, cls.allocation, cls.group)

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.handle.close()

    @contextlib.contextmanager
    def changed(self, va, new_bytes):
        off = self.image.offset(va, len(new_bytes))
        old = self.data[off:off + len(new_bytes)]
        self.data[off:off + len(new_bytes)] = new_bytes
        try:
            yield
        finally:
            self.data[off:off + len(new_bytes)] = old

    def test_digest_and_fde_index(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), study.DIGEST)
        self.assertEqual(len(self.image.fdes), 32)
        for _, va in study.FUNCTIONS:
            with self.subTest(va=hex(va)):
                f = self.image.fdes[va]
                self.assertEqual(f['fde'], self.image.index[va]['fde'])
                self.assertGreater(f['end'], va)
                self.assertEqual(self.image.containing_fde(va)['start'], va)

    def test_corrupted_binary_hash_is_rejected(self):
        old = self.data[0]
        self.data[0] = old ^ 1
        try:
            with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                study.Image(self.data)
        finally:
            self.data[0] = old

    def test_overlapping_or_missing_fde_is_rejected(self):
        chosen = {'start': 0x100, 'end': 0x120, 'fde': 0x10}
        study.check_extent_overlaps([chosen], [chosen])
        for other in ({'start': 0x110, 'end': 0x130, 'fde': 0x20},
                      {'start': 0xf0, 'end': 0x101, 'fde': 0x30}, chosen.copy()):
            with self.assertRaisesRegex(ValueError, 'overlaps'):
                study.check_extent_overlaps([chosen], [chosen, other])
        with self.assertRaisesRegex(ValueError, 'overlaps'):
            study.check_extent_overlaps([chosen], [])

    def test_missing_or_wrong_input_produces_no_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / 'output'
            with mock.patch.object(study, 'TARGET', root / 'missing'):
                with self.assertRaises(FileNotFoundError):
                    study.main(['--out', str(destination)])
            self.assertFalse(destination.exists())
            invalid = root / 'invalid'
            invalid.write_bytes(b'not a matching ELF')
            with mock.patch.object(study, 'TARGET', invalid):
                with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                    study.main(['--out', str(destination)])
            self.assertFalse(destination.exists())

    def test_each_pinned_window_rejects_a_changed_byte(self):
        self.assertEqual(len(study.check_windows(self.image)), 64)
        for label, start, _, _ in study.WINDOWS:
            with self.subTest(window=label):
                original = self.image.read(start, 1)
                with self.changed(start, bytes([original[0] ^ 1])):
                    with self.assertRaisesRegex(ValueError, 'changed instruction window'):
                        study.check_windows(self.image)

    def test_transfer_targets_and_corrupt_opcode(self):
        rows = {row['label']: row for row in study.transfer_rows(self.image)}
        self.assertEqual(len(rows), 144)
        for label, target in (
            ('outer_direct_to_upper', '0x4fcb590'),
            ('outer_instrumented_to_upper', '0x4fcb590'),
            ('upper_to_entry', '0x56186c0'),
            ('entry_to_engine', '0x5a06600'),
            ('engine_to_begin', '0x5483f50'),
            ('action_collect_finish', '0x59618e0'),
            ('item_transform_to_guard', '0x5868030'),
            ('item_guard_to_state_update', '0x560dbb0'),
            ('engine_to_end', '0x5a08720'),
            ('root_to_hash_adapter', '0x548d8c0'),
            ('root_to_history', '0x5a03fa0'),
            ('digest_leaf_string', '0x41c6110'),
        ):
            self.assertEqual(rows[label]['target'], target)
        self.assertEqual(rows['digest_leaf_hex']['resolved_addend'], '0x2eabb50')
        self.assertEqual(rows['item_guard_predicate']['resolved_addend'], '0x3c3cfc0')
        with self.changed(0x5618710, b'\x90'):
            with self.assertRaisesRegex(ValueError, 'unsupported transfer'):
                study.decode_transfer(self.image, 0x5618710, 'call')

    def test_invalid_and_non_file_backed_ranges(self):
        for va, size in ((-1, 1), (0, 1), (1 << 64, 1), (0x56186c0, 0)):
            with self.subTest(va=va, size=size):
                with self.assertRaises(ValueError):
                    self.image.offset(va, size)
        # TLS NOBITS may share a VA with a different file-backed section.
        nobits = self.image.by_name['.bss']
        self.assertEqual(nobits['type'], 8)
        with self.assertRaisesRegex(ValueError, 'not uniquely file backed'):
            self.image.offset(nobits['address'], 1)
        text = self.image.by_name['.text']
        with self.assertRaises(ValueError):
            self.image.offset(text['address'] + text['size'] - 1, 2, executable=True)

    def test_capture_layout_and_group(self):
        self.assertEqual(len(self.captures), 74)
        offsets = [int(row['stack_offset'], 16) for row in self.captures]
        self.assertEqual(offsets, list(range(offsets[0], offsets[0] + 74 * 8, 8)))
        self.assertEqual((self.count, self.allocation, self.group), (59, 1416, 16))
        self.assertEqual(len({row['descriptor_va'] for row in self.jobs}), 45)
        self.assertEqual([row['index'] for row in self.jobs], list(range(59)))
        self.assertEqual(self.jobs[0]['capture_index'], '0..15')

    def test_capture_opcode_and_duplicate_slot_are_rejected(self):
        with self.changed(0x4e34346, b'\x90'):
            with self.assertRaises(ValueError):
                study.captures(self.image)
        first = int(self.captures[0]['stack_offset'], 16)
        second_site = int(self.captures[1]['store_va'], 16)
        with self.changed(second_site + 4, struct.pack('<I', first)):
            with self.assertRaises(ValueError):
                study.captures(self.image)

    def test_descriptor_sources_and_vtable_entries(self):
        expected = (
            (13, '0x1c58', '0x64a8340', '0x4d3ebe0'),
            (26, '0x1c68', '0x64a84a8', '0x4d3f3a0'),
        )
        for index, state_offset, descriptor, visit in expected:
            row = self.jobs[index]
            self.assertEqual(row['state_offset'], state_offset)
            self.assertEqual(row['descriptor_va'], descriptor)
            self.assertEqual(row['visit_target_va'], visit)
            self.assertEqual(row['create_target_va'], '0x4d3e540')
            self.assertEqual((row['size'], row['alignment']), (16, 8))

    def test_invalid_descriptor_stream_and_wrong_capture_rejected(self):
        with self.changed(0x54423c7, b'\x90'):
            with self.assertRaises(ValueError):
                study.parse_descriptor_stream(self.image, self.captures)
        with self.changed(0x5442518, struct.pack('<I', 0xe8)):
            with self.assertRaisesRegex(ValueError, 'source order changed'):
                study.parse_descriptor_stream(self.image, self.captures)

    def test_invalid_descriptor_alignment_rejected(self):
        with self.changed(0x64a8340 + 16, struct.pack('<Q', 3)):
            with self.assertRaisesRegex(ValueError, 'descriptor layout'):
                study.parse_descriptor_stream(self.image, self.captures)

    def test_missing_duplicate_and_non_relative_relocations_rejected(self):
        slot = 0x64a8340 + 24
        saved = self.image.relocations[slot]
        try:
            for invalid in ([], saved + saved, [(1, saved[0][1], saved[0][2])]):
                self.image.relocations[slot] = invalid
                with self.subTest(entries=len(invalid)):
                    with self.assertRaisesRegex(ValueError, 'relocation'):
                        study.relative_relocation(self.image, slot)
        finally:
            self.image.relocations[slot] = saved

    def test_source_locations_and_corruption(self):
        rows = {row['label']: row for row in study.location_rows(self.image)}
        self.assertEqual((rows['engine_guard']['line'], rows['engine_guard']['column']), (168, 13))
        self.assertEqual((rows['hash_adapter']['line'], rows['hash_adapter']['column']), (28, 37))
        self.assertEqual((rows['digest_update']['line'], rows['digest_update']['column']), (861, 33))
        address = int(rows['hash_adapter']['location_va'], 16)
        with self.changed(address + 16, bytes(4)):
            with self.assertRaisesRegex(ValueError, 'Location fields'):
                study.location_rows(self.image)
        path_va = int(rows['hash_adapter']['path_va'], 16)
        length = rows['hash_adapter']['path_length']
        with self.changed(path_va + length - 1, b'!'):
            with self.assertRaisesRegex(ValueError, 'suffix mismatch'):
                study.location_rows(self.image)

    def test_periodic_test_matches_modulo_at_boundaries(self):
        magic = int(self.facts['test_multiplier_le_u64'], 16)
        threshold = int(self.facts['unsigned_limit'], 16)
        rotate = self.facts['rotate_bits']
        self.assertEqual(self.facts['derived_divisor'], 10000)
        samples = list(range(65536))
        maximum = (1 << 64) - 1
        samples += [maximum - delta for delta in range(20001)]
        samples += [((1 << 63) + delta) for delta in range(-10001, 10002)]
        for height in samples:
            self.assertEqual(study.periodic_test(height, magic, rotate, threshold), height % 10000 == 0)
        for bad in (-1, 1 << 64):
            with self.assertRaises(ValueError):
                study.periodic_test(bad, magic, rotate, threshold)
        with self.assertRaises(ValueError):
            study.periodic_test(0, magic, 0, threshold)

    def test_selector_branch_order_and_division(self):
        cases = (
            ((10001, 1, 10000, 2, 0), 'past_first'),
            ((10000, 1, 9999, 2, 0), 'mode_sentinel'),
            ((10000, 1, 9999, 0, 0), 'past_second'),
            ((10000, 0, 0, 0, 0), 'hash_special'),
            ((10001, 1, 10001, 0, 0), 'hash_special'),
            ((10001, 1, 10002, 0, 73), 'hash_interval'),
            ((10001, 0, 0, 0, 2), 'skip_interval'),
            ((10001, 0, 0, 0, 0), 'divide_by_zero'),
            ((10001, 0, 0, 2, 0), 'mode_sentinel'),
            (((1 << 64) - 1, 0, 0, 0, 1), 'hash_interval'),
        )
        for inputs, expected in cases:
            with self.subTest(inputs=inputs):
                self.assertEqual(study.selector_model(*inputs), expected)
        for invalid in ((-1, 0, 0, 0, 1), (1, -1, 0, 0, 1), (1, 0, 0, 1 << 32, 1)):
            with self.assertRaises(ValueError):
                study.selector_model(*invalid)

    def test_entry_to_begin_to_selector_conditions(self):
        self.assertEqual(self.facts['begin_counter_offset'], '0x28')
        self.assertEqual(study.entry_freeze_model(1, 99, 100), 'past')
        self.assertEqual(study.entry_freeze_model(1, 100, 100), 'equal')
        self.assertEqual(study.entry_freeze_model(1, 101, 100), 'continue')
        self.assertEqual(study.entry_freeze_model(2, 0, 100), 'continue')
        self.assertEqual(study.entry_freeze_model(0x100000001, 0, 100), 'continue')
        self.assertEqual(study.selector_model(10001, 1, 10000, 0, 1), 'past_first')
        new_height = study.begin_height_model(100)
        self.assertEqual(new_height, 101)
        self.assertEqual(study.selector_model(new_height, 1, 101, 0, 0), 'hash_special')
        maximum = (1 << 64) - 1
        self.assertEqual(study.begin_height_model(maximum), maximum)
        self.assertEqual(study.entry_freeze_model(1, maximum, maximum), 'equal')
        for value in (-1, 1 << 64):
            with self.assertRaises(ValueError):
                study.begin_height_model(value)
            with self.assertRaises(ValueError):
                study.entry_freeze_model(1, value, 0)
        with self.changed(0x5483fe1, b'\x90'):
            with self.assertRaisesRegex(ValueError, 'begin height saturation form changed'):
                study.constants(self.image, self.count, self.allocation, self.group)

    def test_begin_word_comparison_signedness_and_boundaries(self):
        self.assertTrue(study.begin_words_model((0x7fffffff, 0, 0), (0xffffffff, 0, 0)))
        self.assertFalse(study.begin_words_model((0x80000000, 0xffffffff, 0), (0, 0, 0)))
        self.assertTrue(study.begin_words_model((0, 0xffffffff, 0), (0, 0, 0xffffffff)))
        self.assertTrue(study.begin_words_model((0, 0, 1), (0, 0, 0)))
        self.assertFalse(study.begin_words_model((0, 0, 0), (0, 0, 0)))
        with self.assertRaises(ValueError):
            study.begin_words_model((0, 0), (0, 0, 0))
        with self.assertRaises(ValueError):
            study.begin_words_model((0, 0, 1 << 32), (0, 0, 0))
        with self.changed(0x5483f90, b'\x90'):
            with self.assertRaisesRegex(ValueError, 'comparison form changed'):
                study.constants(self.image, self.count, self.allocation, self.group)

    def test_selector_other_tags_and_leaf_extremes(self):
        self.assertEqual(study.selector_model(10001, 3, 0, 0, 2), 'skip_interval')
        self.assertEqual(study.selector_model(0, 0, 0, 0, 0), 'hash_special')
        self.assertEqual(study.leaf_preimage(bytes(32)), b'\xd9\x42' + b'0x' + b'00' * 32)
        self.assertEqual(study.leaf_preimage(bytes([255]) * 32), b'\xd9\x42' + b'0x' + b'ff' * 32)

    def test_upper_state_and_result_projection_and_corruption(self):
        rows, facts = study.upper_projection(self.image)
        self.assertEqual(len(rows), 25)
        self.assertEqual(facts['input_to_owner_offset'], '0x20')
        self.assertEqual(facts['owner_to_context_offset'], '0x6b0')
        self.assertEqual(facts['context_to_state_pointer_offset'], '0x450')
        self.assertEqual(facts['owner_to_state_pointer_offset'], '0xb00')
        self.assertEqual(facts['engine_result_fragment_offset'], '0x18')
        self.assertEqual((facts['fragment_bytes'], facts['outer_result_fragment_offset']), (24, 0))
        with self.changed(0x4fcb86d + 3, struct.pack('<I', 0xb08)):
            with self.assertRaisesRegex(ValueError, 'state-pointer offset does not join'):
                study.upper_projection(self.image)
        with self.changed(0x4fcb7a3 + 5, b'\x21'):
            with self.assertRaises(ValueError):
                study.upper_projection(self.image)

    def test_result_flag_raw_bits_and_corruption(self):
        self.assertEqual(self.facts['engine_result_flag_offset'], '0xf8')
        self.assertEqual(study.result_flag_model(0, 0, 4, 5), 0)
        self.assertEqual(study.result_flag_model(0, 1, 4, 5), 1)
        self.assertEqual(study.result_flag_model(1, 0, 4, 5), 1)
        self.assertEqual(study.result_flag_model(1, 1, 4, 4), 0)
        self.assertEqual(study.result_flag_model(1, 1, 4, 5), 1)
        self.assertEqual(study.result_flag_model(1, 2, 4, 5), 3)
        self.assertEqual(study.result_flag_model(0x100, 0, 4, 5), 0)
        for values in ((-1, 0, 0, 0), (0, 1 << 32, 0, 0), (0, 0, -1, 0)):
            with self.assertRaises(ValueError):
                study.result_flag_model(*values)
        with self.changed(0x5a077fc, b'\x90'):
            with self.assertRaisesRegex(ValueError, 'result flag form changed'):
                study.constants(self.image, self.count, self.allocation, self.group)

    def test_constants_and_changed_instructions(self):
        self.assertEqual(self.facts['leaf_hex_alphabet'], '0123456789abcdef')
        self.assertEqual((self.facts['leaf_input_bytes'], self.facts['leaf_hex_bytes'],
                          self.facts['leaf_preimage_bytes']), (32, 66, 68))
        for va in (0x5a08742, 0x41c51f6, 0x2eabb62, 0x41c6160):
            with self.subTest(va=hex(va)):
                with self.changed(va, b'\x90'):
                    with self.assertRaises(ValueError):
                        study.constants(self.image, self.count, self.allocation, self.group)
        with self.changed(0x455d40, b'!'):
            with self.assertRaises(ValueError):
                study.constants(self.image, self.count, self.allocation, self.group)

    def test_item_state_counter_paths_and_corruption(self):
        self.assertEqual(self.facts['item_counter_first_offset'], '0x16b0')
        self.assertEqual(self.facts['item_counter_second_offset'], '0x16b8')
        self.assertEqual(self.facts['item_counter_second_tag_u16'], '0x1a2')
        maximum = (1 << 64) - 1
        self.assertEqual(study.item_counter_model(0, 0, 0), (1, 0))
        self.assertEqual(study.item_counter_model(0, 0, 0x1a2), (1, 1))
        self.assertEqual(study.item_counter_model(3, 7, 0x1a1), (4, 7))
        self.assertEqual(study.item_counter_model(maximum, maximum, 0x1a2), (maximum, maximum))
        self.assertEqual(study.item_counter_model(maximum - 1, maximum - 1, 0x1a2),
                         (maximum, maximum))
        for values in ((-1, 0, 0), (0, 1 << 64, 0), (0, 0, 1 << 16)):
            with self.assertRaises(ValueError):
                study.item_counter_model(*values)
        with self.changed(0x560dc39 + 3, struct.pack('<I', 0x16c0)):
            with self.assertRaisesRegex(ValueError, 'load/store offsets differ'):
                study.constants(self.image, self.count, self.allocation, self.group)
        with self.changed(0x560dbdd, b'\x90'):
            with self.assertRaisesRegex(ValueError, 'saturation form changed'):
                study.constants(self.image, self.count, self.allocation, self.group)

    def test_leaf_preimage_exact_and_invalid_lengths(self):
        expected = (b'\xd9\x42' + b'0x' +
                    b'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
        self.assertEqual(study.leaf_preimage(bytes(range(32))), expected)
        self.assertEqual(len(expected), 68)
        for invalid in (bytes(31), bytes(33), 'a' * 32, bytearray(32)):
            with self.assertRaises(ValueError):
                study.leaf_preimage(invalid)


if __name__ == '__main__':
    unittest.main()
