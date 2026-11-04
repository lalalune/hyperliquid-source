"""Static and corruption controls for the selected #115 observer path."""
import copy
import hashlib
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import node115_scheduled_factor as tool


class ScheduledObserverEvidenceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.blob = tool.TARGET.read_bytes()
        cls.image = tool.Image(cls.blob, tool.SHA115, tool.SIZE115)
        cls.generated = tool.collect(cls.image)

    def corrupted_va(self, va, mask=1):
        other = copy.copy(self.image)
        data = bytearray(self.blob)
        data[self.image.offset(va, 1)] ^= mask
        other.blob = data
        return other

    def test_complete_target_identity(self):
        self.assertEqual(hashlib.sha256(self.blob).hexdigest(), tool.SHA115)
        self.assertEqual(len(self.blob), tool.SIZE115)

    def test_reject_wrong_digest_before_parsing(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            tool.Image(self.blob, tool.SHA94, tool.SIZE115)

    def test_reject_truncated_capture(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            tool.Image(self.blob[:-1], tool.SHA115, tool.SIZE115)

    def test_reject_same_size_corrupted_capture(self):
        damaged = bytearray(self.blob)
        damaged[self.image.offset(0x1548cb6, 1)] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            tool.Image(damaged, tool.SHA115, tool.SIZE115)

    def test_reject_non_file_backed_and_unmapped_addresses(self):
        sections = [{'type': 8, 'flags': 2, 'address': 0x1000, 'size': 8, 'offset': 0}]
        with self.assertRaises(ValueError):
            tool.file_offset(b'12345678', sections, 0x1000, 1)
        with self.assertRaises(ValueError):
            self.image.offset(0xfffffffffffffff0, 32)
        with self.assertRaises(ValueError):
            self.image.offset(0, 0)

    def test_reject_ambiguous_mapping_and_crossing_span(self):
        secs = [dict(type=1, flags=2, address=0x1000, size=8, offset=0),
                dict(type=1, flags=2, address=0x1000, size=8, offset=0)]
        with self.assertRaises(ValueError):
            tool.file_offset(b'12345678', secs, 0x1000, 1)
        with self.assertRaises(ValueError):
            tool.file_offset(b'12345678', secs[:1], 0x1007, 2)

    def test_selected_fde_must_match_actual_end_and_index(self):
        row, index = self.image.fde(0x15474d0, 0x1547529)
        self.assertEqual(row['fde'], index['fde'])
        with self.assertRaises(ValueError):
            self.image.fde(0x15474d0, 0x1547528)
        with self.assertRaises(ValueError):
            self.image.fde(0x15474d1, 0x1547529)

    def test_global_guard_branch_target(self):
        name, fallthrough, target, _ = tool.branch(self.image, 0x15ed60f, 'jne', 0x15ed73c)
        self.assertEqual((name, fallthrough, target), ('jne', 0x15ed615, 0x15ed73c))
        with self.assertRaises(ValueError):
            tool.branch(self.corrupted_va(0x15ed611), 0x15ed60f, 'jne', 0x15ed73c)

    def test_wrong_branch_condition_is_rejected(self):
        damaged = self.corrupted_va(0x15ed610, 1)
        with self.assertRaises(ValueError):
            tool.branch(damaged, 0x15ed60f, 'jne', 0x15ed73c)

    def test_wrong_call_displacement_is_rejected(self):
        damaged = self.corrupted_va(0x1548cb8)
        with self.assertRaises(ValueError):
            tool.call_record(damaged, 'factor', 0x1548cb6, 'indirect', 0x64e1008)

    def test_checked_semantic_window_rejects_corruption(self):
        damaged = self.corrupted_va(0x1548dd2)
        with self.assertRaises(ValueError):
            tool.check_windows(damaged)

    def test_relative_binding_rejects_changed_addend(self):
        damaged = copy.copy(self.image)
        damaged.rels = self.image.rels.copy()
        offset, addend = damaged.rels[0x64e1850]
        damaged.rels[0x64e1850] = (offset, addend + 8)
        with self.assertRaises(ValueError):
            damaged.rel(0x64e1850, 0x64f0428)

    def test_mutated_relocation_is_rejected_after_elf_reparse(self):
        damaged = bytearray(self.blob)
        offset, _ = self.image.rels[0x64e1850]
        damaged[offset + 16] ^= 1
        modified_hash = hashlib.sha256(damaged).hexdigest()
        reparsed = tool.Image(damaged, modified_hash, tool.SIZE115)
        with self.assertRaisesRegex(ValueError, 'RELATIVE addend'):
            tool.collect(reparsed)

    def test_duplicate_relative_relocation_is_rejected(self):
        rels = sorted((off, slot) for slot, (off, _) in self.image.rels.items())
        first_offset, first_slot = rels[0]
        second_offset, second_slot = rels[1]
        self.assertNotEqual(first_slot, second_slot)
        damaged = bytearray(self.blob)
        struct.pack_into('<Q', damaged, second_offset, first_slot)
        modified_hash = hashlib.sha256(damaged).hexdigest()
        with self.assertRaisesRegex(ValueError, 'duplicate RELATIVE'):
            tool.Image(damaged, modified_hash, tool.SIZE115)

    def test_template_terminator_and_length_corruption(self):
        raw = tool.template(self.image, 0x44ab69, b'/cham')
        self.assertEqual(raw, b'\xc0\x05/cham\0')
        with self.assertRaises(ValueError):
            tool.template(self.corrupted_va(0x44ab70), 0x44ab69, b'/cham')
        with self.assertRaises(ValueError):
            tool.template(self.corrupted_va(0x44ab6a), 0x44ab69, b'/cham')

    def test_factor_table_rejects_corruption(self):
        image = self.corrupted_va(0x4671d0)
        with self.assertRaises(ValueError):
            tool.selected_tables(image)

    def test_factor_table_pointer_rejects_corruption(self):
        image = self.corrupted_va(0x15474ea)
        with self.assertRaises(ValueError):
            tool.selected_tables(image)

    def test_name_descriptor_length_disagreement(self):
        image = self.corrupted_va(0x6410ef8 + 8)
        with self.assertRaises(ValueError):
            tool.selected_tables(image)

    def test_valid_domain_and_exact_name_factor_boundaries(self):
        count, names, _, _, values, _ = tool.selected_tables(self.image)
        self.assertEqual(count, 79)
        self.assertEqual((values.count(0x3ff0000000000000), values.count(0x4014000000000000)), (18, 61))
        for tag, name, bits in ((13, 'EaTx', 0x3ff0000000000000),
                                (33, 'NvTestnet', 0x4014000000000000),
                                (35, 'NvMainnet', 0x3ff0000000000000),
                                (39, 'DummyNv', 0x4014000000000000)):
            self.assertEqual(names[tag][0], name)
            self.assertEqual(tool.factor_at(values, tag), bits)
        self.assertEqual(tool.factor_at(values, 78), values[78])
        for index in (-1, 79, True):
            with self.assertRaises(ValueError):
                tool.factor_at(values, index)

    def test_nvtestnet_descriptor_coordinates_are_bound_to_their_relocations(self):
        _, first, second, _, _, _ = tool.selected_tables(self.image)
        self.assertEqual(first[33][0], 'NvTestnet')
        self.assertEqual(second[33][0], 'NvTestnet')
        self.assertEqual(self.image.rel(0x63f8998)[1], first[33][1])
        self.assertEqual(self.image.rel(0x6410ef8)[1], second[33][1])
        self.assertEqual(second[33][1], 0x481e30)

    def test_initializer_factor_and_product(self):
        _, _, _, _, values, _ = tool.selected_tables(self.image)
        bits = 0x3fb999999999999a
        params = tool.normalizer_constants(self.image)
        for tag, expected in ((33, 0x3fe0000000000000), (35, 0x3fb999999999999a)):
            product = tool.product_bits(bits, tool.factor_at(values, tag))
            self.assertEqual(product, expected)
            self.assertEqual(tool.normalize_product(product, params), expected)

    def test_product_model_nonfinite_negative_and_zero_boundaries(self):
        constants = tool.normalizer_constants(self.image)
        for before, after in (
            (0x0000000000000000, 0x0000000000000000),
            (0x8000000000000000, 0x8000000000000000),
            (0x0000000000000001, 0x0000000000000001),
            (0x8000000000000001, 0x0000000000000000),
            (0x000fffffffffffff, 0x000fffffffffffff),
            (0x0010000000000000, 0x0010000000000000),
            (0x3ff0000000000000, 0x3ff0000000000000),
            (0xbff0000000000000, 0),
            (0x7fefffffffffffff, 0x7fefffffffffffff),
            (0x7ff0000000000000, 0), (0xfff0000000000000, 0),
            (0x7ff0000000000001, 0), (0x7ff8000000000001, 0),
            (0xfff8000000000001, 0),
        ):
            self.assertEqual(tool.normalize_product(before, constants), after)
        for invalid in (-1, 1 << 64, True):
            with self.assertRaises(ValueError):
                tool.normalize_product(invalid, constants)

    def test_normalizer_exponent_classes_against_independent_oracle(self):
        # Enumerate both signs, every binary64 exponent and boundary fractions.
        constants = tool.normalizer_constants(self.image)
        exponent_count = ((constants[0] ^ constants[4]) >> 52) + 1
        self.assertEqual(exponent_count, 2048)
        fractions = (0, 1, 1 << 51, (1 << 52) - 1)
        checked = 0
        for sign in (0, 1):
            for exponent in range(exponent_count):
                for fraction in fractions:
                    bits = (sign << 63) | (exponent << 52) | fraction
                    magnitude = bits & constants[0]
                    expected = 0 if exponent == 2047 or (sign and magnitude) else bits
                    self.assertEqual(tool.normalize_product(bits, constants), expected)
                    checked += 1
        self.assertEqual(checked, 16384)

    def test_normalizer_operand_corruption(self):
        with self.assertRaises(ValueError):
            tool.normalizer_constants(self.corrupted_va(0x1548ccc))

    def test_state_table_corruption_is_detected(self):
        with self.assertRaisesRegex(ValueError, 'state destination'):
            tool.collect(self.corrupted_va(0x46a064))

    def test_constructor_diagnostic_corruption_is_detected(self):
        with self.assertRaisesRegex(ValueError, 'constructor diagnostic'):
            tool.collect(self.corrupted_va(0x465ab7))

    def test_prefix_corruption_is_detected(self):
        with self.assertRaisesRegex(ValueError, 'prefix operands'):
            tool.collect(self.corrupted_va(0x455fe0))

    def test_prefix_gate_accepts_extension_and_rejects_mutations(self):
        prefix = b'tokio_scheduled_observer'
        self.assertTrue(tool.matches_prefix(prefix, prefix))
        self.assertTrue(tool.matches_prefix(prefix + b'_extra', prefix))
        self.assertFalse(tool.matches_prefix(prefix[:-1], prefix))
        self.assertFalse(tool.matches_prefix(b'T' + prefix[1:], prefix))
        self.assertFalse(tool.matches_prefix(prefix[:-1] + b'X', prefix))
        with self.assertRaises(ValueError):
            tool.matches_prefix('not bytes', prefix)

    def test_key_length_buckets_and_boundaries(self):
        bounds = tool.lookup_thresholds(self.image)
        self.assertEqual(bounds, (17, 7, 3))
        for n, expected in ((0, '0_to_3'), (3, '0_to_3'), (4, '4_to_7'),
                            (7, '4_to_7'), (8, '8_to_16'), (16, '8_to_16'),
                            (17, 'at_least_17'), (33, 'at_least_17')):
            self.assertEqual(tool.lookup_length_bucket(n, bounds), expected)
        for n in (-1, 1 << 64, True):
            with self.assertRaises(ValueError):
                tool.lookup_length_bucket(n, bounds)

    def test_lookup_length_comparison_corruption(self):
        with self.assertRaises(ValueError):
            tool.lookup_thresholds(self.corrupted_va(0x155440f))

    def test_dynamic_bcmp_binding_and_corruption(self):
        offset, index, _, name = tool.dynamic_symbol(self.image, 0x64df9f8, 'bcmp')
        self.assertEqual((index, name), (11, 'bcmp'))
        damaged = copy.copy(self.image)
        damaged.blob = bytearray(self.blob)
        damaged.blob[offset + 12] ^= 1
        with self.assertRaises(ValueError):
            tool.dynamic_symbol(damaged, 0x64df9f8, 'bcmp')

    def test_lookup_hit_sentinel_and_compare_window(self):
        raw = self.image.read(0x155466c, 13)
        self.assertEqual(raw, bytes.fromhex('48b80000000000000080488903'))
        with self.assertRaises(ValueError):
            tool.check_windows(self.corrupted_va(0x15545f3))

    def test_lsda_header_corruption_is_detected(self):
        image = self.corrupted_va(0x185280)
        fde, _ = image.fde(0x15ed290, 0x15ed954)
        with self.assertRaises(ValueError):
            tool.lsda_rows(image, 'poll', fde)

    def test_lsda_binds_observer_call_to_cleanup(self):
        fde, _ = self.image.fde(0x15ed290, 0x15ed954)
        rows = tool.lsda_rows(self.image, 'poll', fde)
        relevant = [row for row in rows if int(row[3], 16) <= 0x15ed63a < int(row[4], 16)]
        self.assertEqual(len(relevant), 1)
        self.assertEqual(relevant[0][5], '0x15ed8d3')

    def test_repeated_collection_is_byte_identical(self):
        self.assertEqual(self.generated, tool.collect(self.image))
        self.assertEqual(len(self.generated), 16)

    def test_wrong_release_historical_input_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            tool.Image(self.blob, tool.SHA94, tool.SIZE94)


if __name__ == '__main__':
    unittest.main()
