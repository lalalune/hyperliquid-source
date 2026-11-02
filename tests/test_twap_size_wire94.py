"""Independent checks for the node #94 TWAP size research packet."""

from contextlib import contextmanager
import itertools
import json
import unittest

from tools import twap_size_wire94 as research


EXPECTED = {
    b'a': 0, b'asset': 0,
    b'b': 1, b'isBuy': 1,
    b's': 2, b'sz': 2,
    b'r': 3, b'reduceOnly': 3,
    b'm': 4, b'minutes': 4,
    b'randomize': 5, b't': 5,
}


class TwapSizeWireTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = research.Image(research.TARGET.read_bytes())
        cls.outputs = research.generate(cls.image)
        cls.info = json.loads(cls.outputs['evidence.json'])
        cls.keys, _, cls.lengths, _, cls.chars = research.key_language(cls.image)
        cls.packed_keys, _, _, _, _ = research.packed_key_language(cls.image)
        cls.owned_keys, _, cls.owned_lengths, _, cls.owned_chars = research.owned_key_language(cls.image)
        _, _, cls.fields = research.descriptor(cls.image, cls.keys)
        cls.classes = dict(cls.keys)
        cls.missing = [(0, 'a'), (1, 'b'), (2, 's'), (4, 'm')]
        cls.names = ['a', 'b', 's', 'r', 'm', 't']

    @contextmanager
    def patched(self, va, replacement):
        old = self.image.patch(va, replacement)
        try:
            yield
        finally:
            self.image.patch(va, old)

    def rejected_edit(self, va, replacement):
        with self.patched(va, replacement):
            with self.assertRaises(ValueError):
                research.generate(self.image)

    def actual_key(self, key, *, owned=False):
        lengths = self.owned_lengths if owned else self.lengths
        chars = self.owned_chars if owned else self.chars
        n = len(key)
        if not 1 <= n <= len(lengths):
            return 6
        start = lengths[n - 1]
        if n == 1:
            index = key[0] - 97
            default = 0x33cb047 if owned else 0x3aebd1e
            start = chars[index] if 0 <= index < len(chars) else default
        domains = tuple(frozenset([ch]) for ch in key)
        hit = research._walk_key(self.image, start, domains, owned=owned)
        self.assertLessEqual(len(hit), 1)
        return hit[0][1] if hit else 6

    def test_real_target_digest_and_corrupted_byte(self):
        research.check_digest(self.image.data)
        original = self.image.read(0x336eae0, 1)[0]
        with self.patched(0x336eae0, bytes([original ^ 1])):
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                research.check_digest(self.image.data)

    def test_unmapped_nobits_and_cross_section_ranges(self):
        with self.assertRaises(ValueError):
            self.image.read(0, 1)
        bss = next(s for s in self.image.sections if s['name'] == '.bss')
        self.assertEqual(bss['type'], 8)
        with self.assertRaises(ValueError):
            self.image.read(bss['address'], 1)
        text = next(s for s in self.image.sections if s['name'] == '.text')
        with self.assertRaises(ValueError):
            self.image.read(text['address'] + text['size'] - 1, 2)

    def test_fde_boundaries_and_call_path(self):
        self.assertEqual(set(self.image.frames), set(research.SUBJECTS.values()))
        for start, frame in self.image.frames.items():
            self.assertLess(start, frame['end'])
            sec, _ = self.image.mapping(start, frame['end'] - start)
            self.assertNotEqual(sec['type'], 8)
            self.assertTrue(sec['flags'] & 4)
        edges = {row['name']: int(row['target_va'], 16) for row in self.info['edges']}
        self.assertEqual(edges['outer to value visitor'], research.SUBJECTS['map_visitor'])
        self.assertEqual(edges['visitor to key cursor'], research.SUBJECTS['key_cursor'])
        self.assertEqual(edges['key cursor to classifier'], research.SUBJECTS['key_classifier'])
        self.assertEqual(edges['size case to string reader'], research.SUBJECTS['size_string'])

    def test_independent_expected_key_set(self):
        self.assertEqual(dict(self.keys), EXPECTED)
        self.assertEqual(dict(self.packed_keys), EXPECTED)
        self.assertEqual(dict(self.owned_keys), EXPECTED)
        self.assertEqual(len(self.fields), 12)
        self.assertEqual(self.info['field_classes'], 6)

    def test_internal_numeric_key_clamps(self):
        lines = self.outputs['key-numeric-model.tsv'].decode().splitlines()[1:]
        byte_rows = [row.split('\t') for row in lines if row.startswith('1\t')]
        self.assertEqual(len(byte_rows), 256)
        for row in byte_rows:
            value, case = int(row[1]), int(row[2])
            self.assertEqual(case, value if value < 6 else 6)
        word_rows = [row.split('\t') for row in lines if row.startswith('4\t')]
        self.assertEqual(len(word_rows), 10)
        self.assertEqual([int(row[2]) for row in word_rows], [0, 1, 2, 3, 4, 5, 6, 6, 6, 6])
        self.assertEqual(self.info['numeric_key_bound_and_fallback'], 6)

    def test_all_one_byte_keys(self):
        for value in range(256):
            key = bytes([value])
            self.assertEqual(self.actual_key(key), EXPECTED.get(key, 6), key)
            self.assertEqual(self.actual_key(key, owned=True), EXPECTED.get(key, 6), key)

    def test_all_two_byte_keys(self):
        # Of 65,536 byte pairs only the complete spelling 'sz' is accepted.
        for first in range(256):
            for second in range(256):
                key = bytes((first, second))
                self.assertEqual(self.actual_key(key), 2 if key == b'sz' else 6, key)
                self.assertEqual(self.actual_key(key, owned=True), 2 if key == b'sz' else 6, key)

    def test_each_long_key_and_every_single_byte_substitution(self):
        for key in (k for k in EXPECTED if len(k) > 2):
            self.assertEqual(self.actual_key(key), EXPECTED[key])
            self.assertEqual(self.actual_key(key, owned=True), EXPECTED[key])
            for i, original in enumerate(key):
                for replacement in range(256):
                    if replacement != original:
                        other = key[:i] + bytes([replacement]) + key[i + 1:]
                        self.assertEqual(self.actual_key(other), EXPECTED.get(other, 6), other)
                        self.assertEqual(self.actual_key(other, owned=True), EXPECTED.get(other, 6), other)

    def test_length_guard_edges(self):
        self.assertEqual(self.actual_key(b''), 6)
        self.assertEqual(self.actual_key(b'reduceOnly!'), 6)
        self.assertEqual(self.actual_key(b'\xff' * 10), 6)
        # The checked instruction uses wrapped u64 (n - 1) <= 9.
        for n, admitted in [(0, False), (1, True), (10, True), (11, False),
                            ((1 << 64) - 1, False)]:
            self.assertEqual(((n - 1) & research.MASK64) <= 9, admitted)

    def test_missing_field_order_and_optional_fields(self):
        model = research.run_map
        self.assertEqual(model([], self.classes, self.missing, self.names), ('missing', 'a', 0))
        self.assertEqual(model([b'a'], self.classes, self.missing, self.names), ('missing', 'b', 0))
        self.assertEqual(model([b'asset', b'isBuy'], self.classes, self.missing, self.names),
                         ('missing', 's', 0))
        self.assertEqual(model([b'a', b'b', b'sz'], self.classes, self.missing, self.names),
                         ('missing', 'm', 0))
        self.assertEqual(model([b'a', b'b', b's', b'm'], self.classes, self.missing, self.names),
                         ('convert', '', 1))
        self.assertEqual(model([b'a', b'b', b's', b'm', b'ignored'], self.classes,
                               self.missing, self.names), ('convert', '', 1))

    def test_duplicates_precede_missing_and_conversion(self):
        for first, second, expected in [(b's', b'sz', 's'), (b'sz', b's', 's'),
                                        (b'randomize', b't', 't'), (b'a', b'asset', 'a')]:
            self.assertEqual(research.run_map([first, second], self.classes, self.missing, self.names),
                             ('duplicate', expected, 0))

    def test_all_six_field_orders(self):
        for order in itertools.permutations([b'a', b'b', b's', b'r', b'm', b't']):
            self.assertEqual(research.run_map(order, self.classes, self.missing, self.names),
                             ('convert', '', 1))
        self.assertEqual(self.info['all_fields_alias_permutations'], 46080)
        self.assertEqual(self.info['all_subset_alias_orderings'], 75973)
        self.assertEqual(self.info['subset_orderings_reaching_conversion'], 54144)
        self.assertEqual(self.info['presence_cases'], 64)
        self.assertEqual(self.info['presence_conversion_reached'], 4)
        self.assertEqual(self.info['duplicate_cases'], 24)

    def test_error_sentinel_and_outer_layout(self):
        self.assertEqual(self.info['visitor_error_sentinel'], '0x8000000000000000')
        self.assertEqual(self.info['conversion_success_tag'], '0x186')
        self.assertEqual(self.info['outer_error_tag'], 2)
        lines = self.outputs['error-paths.tsv'].decode().splitlines()[1:]
        self.assertEqual(len(lines), 10)
        routes = [row.split('\t')[6] for row in lines]
        self.assertEqual(routes.count('common sentinel'), 8)
        self.assertEqual(routes.count('direct sentinel'), 2)
        layout = [row.split('\t')[:3] for row in
                  self.outputs['outer-layout.tsv'].decode().splitlines()[1:]]
        self.assertEqual(layout, [['s', '0', '8'], ['m', '8', '8'], ['a', '16', '4'],
                                  ['b', '20', '1'], ['r', '21', '1'],
                                  ['t_or_error_tag', '22', '1']])
        flow = [row.split('\t') for row in
                self.outputs['size-record-flow.tsv'].decode().splitlines()[1:]]
        self.assertEqual(flow, [['0', '48', '32', '0'], ['1', '56', '152', '8'],
                                ['2', '64', '288', '16']])

    def test_size_type_dispatch_exhaustive(self):
        rows = self.outputs['size-type-dispatch.tsv'].decode().splitlines()[1:]
        accepted = [int(row.split('\t')[0]) for row in rows if '\tselected branch\t' in row]
        self.assertEqual(accepted, [12, 13, 14, 15])
        self.assertEqual(self.info['known_conversion_mode'], 0)
        self.assertEqual(self.info['known_conversion_exponent'], 8)
        paths = self.outputs['size-reader-paths.tsv'].decode()
        self.assertIn('tag 15 helper status equals\t0x3a511a3\terror sentinel\t1', paths)
        self.assertIn('allocation result equals zero\t0x3a511dc\tfailure helper then ud2', paths)

    def test_corrupt_key_comparison_rejected(self):
        self.rejected_edit(0x3aebc92, b'y')

    def test_corrupt_numeric_key_clamp_rejected(self):
        self.rejected_edit(0x3aebaef, b'\x07')

    def test_corrupt_packed_key_comparison_rejected(self):
        self.rejected_edit(0x331875a, b'y')

    def test_corrupt_packed_length_table_rejected(self):
        self.rejected_edit(0x58631c, self.image.read(0x586320, 4))

    def test_corrupt_owned_key_comparison_rejected(self):
        self.rejected_edit(0x33cafbb, b'y')

    def test_corrupt_owned_length_table_rejected(self):
        self.rejected_edit(0x58a50c, self.image.read(0x58a510, 4))

    def test_corrupt_length_jump_table_rejected(self):
        self.rejected_edit(0x5aba20, self.image.read(0x5aba24, 4))

    def test_corrupt_character_jump_table_rejected(self):
        char_base = 0x5aba44
        self.rejected_edit(char_base + 4 * (ord('s') - 97),
                           self.image.read(char_base + 4 * (ord('r') - 97), 4))

    def test_corrupt_map_case_table_rejected(self):
        self.rejected_edit(0x5aa7d0 + 8, self.image.read(0x5aa7d0, 4))

    def test_corrupt_end_case_table_rejected(self):
        self.rejected_edit(0x5aa7d0 + 28, self.image.read(0x5aa7d0 + 24, 4))

    def test_corrupt_size_type_table_rejected(self):
        self.rejected_edit(0x5a9f68, self.image.read(0x5a9f6c, 4))

    def test_corrupt_size_validator_failure_rejected(self):
        self.rejected_edit(0x3a510fa, b'\x85')

    def test_corrupt_size_allocator_failure_rejected(self):
        self.rejected_edit(0x3a511e2, b'\x00')

    def test_corrupt_duplicate_branch_rejected(self):
        self.rejected_edit(0x3aaefde, b'\x84')

    def test_corrupt_missing_branch_rejected(self):
        self.rejected_edit(0x3aaf542, b'\x84')

    def test_corrupt_size_output_store_rejected(self):
        self.rejected_edit(0x336eb46, b'\x88')

    def test_corrupt_size_record_flow_rejected(self):
        self.rejected_edit(0x3aaf650, b'\x25')

    def test_corrupt_type_name_rejected(self):
        self.rejected_edit(0x58c035, b'X')

    def test_corrupt_field_alias_rejected(self):
        self.rejected_edit(0x58a8fe, b'q')

    def test_corrupt_error_template_rejected(self):
        self.rejected_edit(0x1e0fd6, b'D')

    def test_corrupt_error_argument_rejected(self):
        self.rejected_edit(0x3aaf93e, b'\x90')

    def test_corrupt_common_error_sentinel_rejected(self):
        self.rejected_edit(0x3aaf2b3, b'\x01')

    def test_corrupt_direct_error_sentinel_rejected(self):
        self.rejected_edit(0x3aaf593, b'\x01')

    def test_corrupt_common_error_return_edge_rejected(self):
        self.rejected_edit(0x3aaf979, b'\x00')

    def test_corrupt_call_slot_binding_rejected(self):
        slot = 0x5773898
        old = self.image.relocs[slot]
        try:
            self.image.relocs[slot] = 0
            with self.assertRaises(ValueError):
                research.generate(self.image)
        finally:
            self.image.relocs[slot] = old

    def test_repeated_generation_is_identical(self):
        self.assertEqual(research.generate(self.image), self.outputs)


if __name__ == '__main__':
    unittest.main()
