from pathlib import Path
import itertools
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import subaccount_state94 as codec


class SubaccountState94Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = codec.checked_image()
        cls.image = codec.Image(cls.data)
        cls.spec = codec.extract_classifier(cls.image)
        cls.msg_spec = codec.extract_classifier(cls.image, 0x21e6580)
        cls.names = codec.outer_name_sources(cls.image)

    def patched(self, va, new_bytes):
        changed = bytearray(self.data)
        offset = self.image.offset(va, len(new_bytes))
        changed[offset:offset + len(new_bytes)] = new_bytes
        return codec.Image(changed)

    def test_artifact_digest_is_required_before_elf_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            damaged = Path(directory) / 'damaged-node'
            damaged.write_bytes(b'not an ELF and not the selected node')
            with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
                codec.checked_image(damaged)

    def test_file_mapping_rejects_nobits_and_crossing_boundaries(self):
        bss = next(section for section in self.image.secs
                   if section['type'] == 8 and section['size'] > 0 and section['name'] == '.bss')
        with self.assertRaisesRegex(ValueError, 'file bytes'):
            self.image.read(bss['address'], 1)
        text = next(section for section in self.image.secs if section['name'] == '.text')
        with self.assertRaisesRegex(ValueError, 'file bytes'):
            self.image.read(text['address'] + text['size'] - 1, 2, True)
        with self.assertRaises(ValueError):
            self.image.read(-1, 1)
        with self.assertRaises(ValueError):
            self.image.read(text['address'], 0)

    def test_rejects_code_opcode_and_relative_target_mutations(self):
        original = self.image.read(0x21f9851, 5, True)
        with self.assertRaisesRegex(ValueError, 'opcode mismatch'):
            self.patched(0x21f9851, b'\x90').rel_target(0x21f9851, 0x202c4e0, call=True)
        changed = original[:1] + bytes([original[1] ^ 1]) + original[2:]
        with self.assertRaisesRegex(ValueError, 'target mismatch'):
            self.patched(0x21f9851, changed).rel_target(0x21f9851, 0x202c4e0, call=True)
        with self.assertRaisesRegex(ValueError, 'opcode mismatch'):
            self.image.rip_target(0x21f982c, bytes.fromhex('488d05'))

    def test_rejects_classifier_instruction_mutation(self):
        old = self.image.read(0x21e6641, 1, True)
        damaged = self.patched(0x21e6641, bytes([old[0] ^ 1]))
        with self.assertRaisesRegex(ValueError, 'instruction pattern mismatch'):
            codec.extract_classifier(damaged)

    def test_rejects_reader_constant_mutation(self):
        msg_first_head = self.names[0][5]
        old = self.image.read(msg_first_head, 1)
        damaged = self.patched(msg_first_head, bytes([old[0] ^ 1]))
        with self.assertRaisesRegex(ValueError, 'field names differ'):
            codec.outer_name_sources(damaged)

    def test_rejects_duplicate_key_message_mutation(self):
        damaged = self.patched(0x26360bc + 2, b'X')
        with self.assertRaisesRegex(ValueError, 'immediate mismatch'):
            codec.extract_duplicate_key(damaged, 0x26360bc, 0x26360ca)

    def test_rejects_bad_jump_table_target(self):
        table = self.image.rip_target(0x21e662c, bytes.fromhex('488d0d'))
        damaged = self.patched(table, b'\xff\xff\xff\x7f')
        with self.assertRaisesRegex(ValueError, 'outside selected unwind extent'):
            codec.rel_table(damaged, 0x21e662c, bytes.fromhex('488d0d'), 16,
                            0x21e6620, 0x21e66b7, {0: 0x21e663c})

    def test_rejects_zero_length_fde(self):
        records = codec.selected_fdes(self.data, self.image)
        first = next(row for row in records if row['name'] == 'json_row_name_classify')
        damaged = self.patched(first['fde'] + 12, b'\0\0\0\0')
        with self.assertRaisesRegex(ValueError, 'FDE disagree'):
            codec.selected_fdes(damaged.data, damaged)

    def test_all_one_byte_row_keys(self):
        expected = {ord('n'): 0, ord('s'): 1, ord('m'): 2}
        for value in range(256):
            with self.subTest(byte=value):
                self.assertEqual(codec.classify_row_key(bytes([value]), self.spec), expected.get(value, 3))
                self.assertEqual(codec.classify_row_key(bytes([value]), self.msg_spec), expected.get(value, 3))

    def test_independent_reader_classifier_constants_agree(self):
        self.assertEqual(self.spec, self.msg_spec)
        changed = self.patched(0x21e65a1, b'\x92')
        with self.assertRaisesRegex(ValueError, 'instruction pattern mismatch'):
            codec.extract_classifier(changed, 0x21e6580)

    def test_long_aliases_and_every_single_byte_bit_flip(self):
        aliases = (b'name', b'sub_account_user', b'master')
        for tag, alias in enumerate(aliases):
            self.assertEqual(codec.classify_row_key(alias, self.spec), tag)
            self.assertEqual(codec.classify_row_key(alias, self.msg_spec), tag)
            for pos in range(len(alias)):
                altered = alias[:pos] + bytes([alias[pos] ^ 1]) + alias[pos + 1:]
                self.assertEqual(codec.classify_row_key(altered, self.spec), 3)
        for size in (0, 2, 3, 5, 7, 15, 17):
            self.assertEqual(codec.classify_row_key(b'x' * size, self.spec), 3)

    def test_row_presence_and_mixed_alias_duplicate_controls(self):
        pairs = ((b'n', b'name'), (b's', b'sub_account_user'), (b'm', b'master'))
        for choices in itertools.product(*pairs):
            for keys in itertools.permutations(choices):
                self.assertEqual(codec.known_field_outcome(keys, self.spec), 'all-present')
        for tag, (short, long_name) in enumerate(pairs):
            for keys in ((short, long_name), (long_name, short)):
                self.assertEqual(codec.known_field_outcome(keys, self.spec), f'duplicate:{tag}')
        self.assertEqual(codec.known_field_outcome((b's', b'm'), self.spec), 'missing:0')
        self.assertEqual(codec.known_field_outcome((b'n', b'm'), self.spec), 'missing:1')
        self.assertEqual(codec.known_field_outcome((b'n', b's'), self.spec), 'missing:2')
        self.assertEqual(codec.known_field_outcome((b'other',), self.spec), 'unknown-handling-unresolved')

    def test_sequence_arity_boundaries(self):
        for arity in (2, 3):
            for count in range(arity):
                self.assertEqual(codec.sequence_arity_outcome(count, arity), f'missing-index:{count}')
            self.assertEqual(codec.sequence_arity_outcome(arity, arity), 'count-accepted')
            self.assertEqual(codec.sequence_arity_outcome(arity + 1, arity), 'excess-elements')
            self.assertEqual(codec.sequence_arity_outcome(0xffffffff, arity), 'excess-elements')
        with self.assertRaises(ValueError):
            codec.sequence_arity_outcome(-1, 2)

    def test_row_preallocation_caps_initial_reservation(self):
        self.assertEqual(codec.initial_reservation(0, 0x4000, 6), (0, 0))
        self.assertEqual(codec.initial_reservation(0x3fff, 0x4000, 6), (0x3fff, 0xfffc0))
        self.assertEqual(codec.initial_reservation(0x4000, 0x4000, 6), (0x4000, 0x100000))
        self.assertEqual(codec.initial_reservation(0x4001, 0x4000, 6), (0x4000, 0x100000))
        self.assertEqual(codec.initial_reservation(0xffffffff, 0x4000, 6), (0x4000, 0x100000))
        with self.assertRaises(ValueError):
            codec.initial_reservation(-1, 0x4000, 6)
        with self.assertRaises(ValueError):
            codec.initial_reservation(0x100000000, 0x4000, 6)

    def test_fast_row_header_and_key_markers(self):
        self.assertEqual(codec.fast_row_header(0, 1, 4, 0x83), 0x93)
        self.assertEqual(codec.fast_row_header(1, 1, 4, 0x83), 0x83)
        for va, expected in ((0x21f905e,b'\xc6\x04\x31\xa1'),
                             (0x21f9072,b'\xc6\x04\x31n'),
                             (0x21f90cf,b'\xc6\x04\x31s'),
                             (0x21f912a,b'\xc6\x04\x31m')):
            self.assertEqual(self.image.read(va,4,True), expected)
        with self.assertRaises(ValueError):
            codec.fast_row_header(2, 1, 4, 0x83)

    def test_comparator_slot_resolves_and_symbol_corruption_is_rejected(self):
        slot = self.image.rip_target(0x1fe97a2, bytes.fromhex('ff15'))
        resolved = codec.memcmp_import(self.image, slot)
        self.assertEqual(resolved['name'], 'memcmp')
        self.assertEqual(resolved['relocation_type'], 6)
        with self.assertRaisesRegex(ValueError, 'expected memcmp'):
            codec.memcmp_import(self.patched(resolved['name_va'], b'n'), slot)
        with self.assertRaisesRegex(ValueError, 'unique dynamic relocation'):
            codec.memcmp_import(self.image, slot + 1)

    def test_prior_hash_writer_context_and_corruption(self):
        context = codec.hash_writer_context(self.image)
        self.assertEqual(context['target_va'], 0x21f97b0)
        self.assertEqual(context['mode_byte'], 1)
        with self.assertRaisesRegex(ValueError, 'instruction pattern mismatch'):
            codec.hash_writer_context(self.patched(0x2818e6c, b'\0'))

    def test_small_collection_order_and_boundary(self):
        keys = [bytes([b]) + bytes(19) for b in (0x80, 0, 0x7f, 1)]
        for values in itertools.permutations(keys):
            self.assertEqual(codec.small_entry_order(values, 21, 20), sorted(values))
        self.assertEqual(codec.small_entry_order([], 21, 20), [])
        twenty = [bytes([b]) + bytes(19) for b in range(20, 0, -1)]
        self.assertEqual(codec.small_entry_order(twenty, 21, 20), sorted(twenty))
        with self.assertRaises(ValueError):
            codec.small_entry_order(twenty + [bytes(20)], 21, 20)
        with self.assertRaises(ValueError):
            codec.small_entry_order([bytes(19)], 21, 20)

    def test_both_readers_compare_the_writer_field_names(self):
        self.assertEqual([row[0] for row in self.names],
                         ['user_to_sub_accounts', 'sub_account_to_master'])
        names = tuple(row[0].encode('ascii') for row in self.names)
        for tag, name in enumerate(names):
            self.assertEqual(codec.classify_outer_key(name, names), tag)
            for pos in range(len(name)):
                changed = name[:pos] + bytes([name[pos] ^ 1]) + name[pos + 1:]
                self.assertEqual(codec.classify_outer_key(changed, names), 2)
        self.assertEqual(codec.classify_outer_key(b'', names), 2)

    def test_eight_duplicate_key_error_constructions(self):
        sites = ((0x25a4d0a, 0x25a4d18), (0x25a054e, 0x25a055c),
                 (0x265f780, 0x265f78e), (0x2687380, 0x268738e),
                 (0x26360bc, 0x26360ca), (0x26574e9, 0x26574f7),
                 (0x26799e7, 0x26799f5), (0x269dafe, 0x269db0c))
        for first, second in sites:
            self.assertEqual(codec.extract_duplicate_key(self.image, first, second), b'duplicate key')

    def test_field_errors_bind_correct_name_and_failure_class(self):
        errors = codec.field_errors(self.image)
        self.assertEqual(len(errors), 20)
        self.assertEqual(sum(row[-1] == 'missing field `' for row in errors), 10)
        self.assertEqual(sum(row[-1] == 'duplicate field `' for row in errors), 10)
        self.assertEqual({row[3] for row in errors},
                         {'user_to_sub_accounts', 'sub_account_to_master', 'n', 's', 'm'})

    def test_complete_reproduction_matches_selected_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / 'evidence'
            result = codec.generate(self.data, out)
            self.assertEqual(result['selected_fde_count'], 43)
            self.assertEqual(result['direct_call_count'], 104)
            self.assertEqual(result['branch_count'], 60)
            self.assertEqual(result['table_entries'], 106)
            self.assertEqual(result['classifier_cases'], 299)
            self.assertEqual(result['outer_classifier_cases'], 47)
            self.assertEqual(result['presence_cases'], 64)
            self.assertEqual(result['arity_cases'], 25)
            self.assertEqual(result['reservation_cases'], 7)
            self.assertEqual(result['row_header_cases'], 2)
            self.assertEqual(result['selected_indirect_comparisons'], 6)
            self.assertEqual(result['small_sort_cases'], 24)
            self.assertEqual(result['prior_hash_context_calls'], 1)
            self.assertEqual(result['duplicate_key_sites'], 8)
            self.assertEqual(result['field_error_sites'], 20)
            self.assertEqual(len(list(out.iterdir())), 19)


if __name__ == '__main__':
    unittest.main()
