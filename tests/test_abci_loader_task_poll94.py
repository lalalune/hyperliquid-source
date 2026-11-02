"""Target-backed and corruption controls for the RE-017 task handoff."""
import struct
import tempfile
import unittest
from pathlib import Path

from tools.elf_index import sections as shared_sections
from tools import abci_loader_task_poll94 as subject


class LoaderTaskPollTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Missing binaries fail, rather than silently skipping target controls.
        cls.original = subject.TARGET.read_bytes()
        cls.result = subject.collect(cls.original)
        cls.image = subject.Image(cls.original)
        cls.fdes = cls.result['fdes']
        cls.flow = {r['name']: r for r in cls.result['flow']}
        cls.layout = {r['name']: r['value'] for r in cls.result['layout']}

    def mutated(self):
        return bytearray(self.original)

    def image_of(self, data):
        return subject.Image(data, self.image.sections)

    def offset(self, va, size=1):
        return self.image.location(va, size)[1]

    def test_digest_and_census(self):
        self.assertEqual(subject.verify_digest(self.original), subject.SHA256)
        self.assertEqual(len(self.fdes), 23)
        self.assertEqual(len(self.result['windows']), 89)
        self.assertEqual(len(self.result['flow']), 196)
        self.assertEqual(len(self.result['tables']), 38)
        self.assertEqual(len(self.result['relocations']), 4)
        self.assertEqual(len(self.result['locations']), 5)
        self.assertEqual(len(self.result['literals']), 2)
        self.assertEqual(len(self.result['lsda_headers']), 19)
        self.assertEqual(len(self.result['lsda']), 167)
        self.assertEqual(len(self.result['lsda_calls']), 79)
        self.assertEqual(sum(r['landing'] is not None for r in self.result['lsda_calls']), 47)
        self.assertEqual(len(self.result['layout']), 19)
        self.assertEqual(len(self.result['initial_admission']), 2)
        self.assertEqual(sum(len(x) for x in self.result['candidates'].values()), 5)

    def test_input_digest_rejects_single_byte_change(self):
        bad = self.mutated()
        bad[self.offset(0x2013c94)] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            subject.verify_digest(bad)

    def test_three_input_sites_prepare_the_same_future_tag(self):
        for name in ('entry_future_tag_offset', 'alternate_future_tag_offset', 'third_future_tag_offset'):
            self.assertEqual(self.layout[name], 0x216)
        for name in ('future_copy_size', 'future_alloc_size', 'drop_allocation_size'):
            self.assertEqual(self.layout[name], 0x6368)
        self.assertEqual(self.layout['task_alloc_size'], 0x80)
        self.assertEqual(self.flow['entry_spawn']['target'], 0x229ec10)
        self.assertEqual(self.flow['alternate_entry_spawn']['target'], 0x229ec10)
        self.assertEqual(self.flow['third_entry_spawn']['target'], 0x229ec10)

    def test_spawn_and_error_locations(self):
        records = {r['name']: r for r in self.result['locations']}
        for name in ('entry_spawn', 'alternate_spawn', 'third_spawn'):
            self.assertEqual((records[name]['path'], records[name]['line'], records[name]['column']),
                             ('src/hl_node.rs', 5, 5))
        for name in ('entry_error', 'alternate_error'):
            self.assertEqual((records[name]['path'], records[name]['line'], records[name]['column']),
                             ('src/hl_node.rs', 5, 39))
        for source, record in (('entry_spawn_location', 'entry_spawn'),
                               ('entry_error_location', 'entry_error'),
                               ('alternate_spawn_location', 'alternate_spawn'),
                               ('alternate_error_location', 'alternate_error'),
                               ('third_spawn_location', 'third_spawn')):
            self.assertEqual(self.flow[source]['target'], records[record]['va'])

    def test_error_messages_and_fallthrough_traps(self):
        expected = 'called `Result::unwrap()` on an `Err` value'
        for row in self.result['literals']:
            self.assertEqual(row['text'], expected)
            self.assertEqual(row['length'], len(expected))
            self.assertEqual(self.image.read(row['trap'], 2), bytes.fromhex('0f0b'))
        r = self.result['literals'][0]
        for offset in (r['file_offset'], self.offset(r['length_instruction'] + 1), self.offset(r['trap'])):
            bad = self.mutated()
            bad[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                subject.literal_rows(self.image_of(bad))

    def test_spawn_mode_and_allocation_branches(self):
        expected = {
            'spawn_tls_low_bit': ('equal', 0x229edbb),
            'spawn_tls_mode_two': ('equal', 0x229edec),
            'spawn_allocation_null': ('equal', 0x229ed4f),
            'spawn_first_lane': ('', 0x23c3c70),
            'spawn_second_lane': ('', 0x2888350),
            'spawn_reject_drop': ('', 0x22569c0),
            'spawn_tls_two_drop': ('', 0x22569c0),
            'input_allocation_drop': ('', 0x22569c0),
            'first_constructor_unwind_drop': ('', 0x1faa630),
            'second_constructor_unwind_drop': ('', 0x1fa9d50),
            'first_cleanup_variant': ('', 0x1fa3d10),
            'second_cleanup_variant': ('', 0x1fa3d10),
            'first_construct': ('', 0x200b3a0),
            'second_construct': ('', 0x2003d20),
            'first_alloc_null': ('equal', 0x200b481),
            'second_alloc_null': ('equal', 0x2003e01),
        }
        for name, (condition, target) in expected.items():
            with self.subTest(name=name):
                self.assertEqual((self.flow[name]['condition'], self.flow[name]['target']), (condition, target))

    def test_initial_word_reaches_both_poll_entries_if_cas_succeeds(self):
        rows = {r['name']: r for r in self.result['initial_admission']}
        self.assertEqual((rows['first']['old'], rows['first']['new'], rows['first']['selector'], rows['first']['target']),
                         (0xcc, 0xc9, 0, 0x1d7c967))
        self.assertEqual((rows['second']['old'], rows['second']['new'], rows['second']['selector'], rows['second']['target']),
                         (0xcc, 0xc9, 0, 0x1d8e9a7))

    def test_admission_model_boundaries_and_invalid_states(self):
        samples = {
            0x00: ('missing_bit_4', None, None),
            0x04: ('compare_exchange', 0x01, 0),
            0x24: ('compare_exchange', 0x21, 1),
            0x05: ('small_word', None, None),
            0x45: ('compare_exchange', 0x05, 3),
            0x85: ('compare_exchange', 0x45, 2),
            0xffffffffffffffff: ('compare_exchange', 0xffffffffffffffbf, 2),
        }
        for word, expected in samples.items():
            with self.subTest(word=word):
                self.assertEqual(subject.admission_model(word), expected)
        for invalid in (-1, 1 << 64, True, 3.0, '4'):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                subject.admission_model(invalid)

    def test_relocated_table_links(self):
        records = {r['name']: r for r in self.result['relocations']}
        self.assertEqual(records['first_schedule']['slot'], 0x56954a0)
        self.assertEqual(records['first_schedule']['addend'], 0x22a3d20)
        self.assertEqual(records['first_read']['slot'] - records['first_schedule']['slot'], 0x18)
        self.assertEqual(records['first_read']['addend'], 0x229f990)
        self.assertEqual(records['second_schedule']['slot'], 0x5693650)
        self.assertEqual(records['second_schedule']['addend'], 0x22a4460)
        self.assertEqual(records['second_read']['slot'] - records['second_schedule']['slot'], 0x18)
        self.assertEqual(records['second_read']['addend'], 0x229f710)
        self.assertTrue(all((r['type'], r['symbol']) == (8, 0) for r in records.values()))

    def test_thunks_and_location_bound_call(self):
        targets = {
            'first_schedule_thunk': 0x1d7c8f0, 'second_schedule_thunk': 0x1d8e930,
            'first_poll_wrapper': 0x2013c00, 'second_poll_wrapper': 0x2013c00,
            'wrapper_location_bound_future': 0x22ae8a0,
            'first_reader_thunk': 0x1d589c0, 'second_reader_thunk': 0x1d589c0,
        }
        for name, target in targets.items():
            with self.subTest(name=name):
                self.assertEqual(self.flow[name]['target'], target)

    def test_wrapper_and_task_layout(self):
        values = {'task_table_offset': 0x10, 'task_context_offset': 0x20,
                  'task_variant_offset': 0x30, 'task_future_offset': 0x38,
                  'scheduler_context_offset': 0x20, 'wrapper_variant_offset': 0x10,
                  'wrapper_future_offset': 0x18, 'replacement_variant_offset': 0x10,
                  'reader_variant_offset': 0x30, 'wrapper_completed_tag': 2,
                  'completion_tag': 1, 'reader_consumed_tag': 2}
        for name, value in values.items():
            with self.subTest(name=name):
                self.assertEqual(self.layout[name], value)

    def test_completion_and_reader_branches(self):
        expected = {
            'first_poll_zero': ('equal', 0x1d7cb03),
            'second_poll_zero': ('equal', 0x1d8eb27),
            'first_complete_replace': ('', 0x201c250),
            'second_complete_replace': ('', 0x201c250),
            'replace_drop_old': ('', 0x1fa3d10),
            'wrapper_drop_variant': ('', 0x1fa3d10),
            'drop_future_call': ('', 0x1fc6250),
            'reader_admit_zero': ('equal', 0x1d58a37),
            'reader_wrong_tag': ('not_equal', 0x1d58a97),
            'entry_result_tag_zero': ('equal', 0x22b89d9),
            'entry_nonzero_payload': ('not_equal', 0x22b8a1a),
        }
        for name, (condition, target) in expected.items():
            with self.subTest(name=name):
                self.assertEqual((self.flow[name]['condition'], self.flow[name]['target']), (condition, target))

    def test_selected_unwind_call_site_associations(self):
        calls = {r['name']: r for r in self.result['lsda_calls']}
        expected = {
            'spawn_tls_two_drop': (0x229ee23, 0),
            'first_alloc_failure': (0x200b493, 0),
            'second_alloc_failure': (0x2003e13, 0),
            'first_poll_wrapper': (0x1d7cc9c, 5),
            'second_poll_wrapper': (0x1d8ecc6, 5),
            'wrapper_location_bound_future': (0x2013d6c, 0),
            'replace_drop_old': (0x201c31d, 0),
            'drop_future_call': (0x1fa3dc0, 0),
            'input_allocation_drop': (0x22444a3, 0),
        }
        for name, (landing, action) in expected.items():
            with self.subTest(name=name):
                self.assertEqual((calls[name]['landing'], calls[name]['action']), (landing, action))
                self.assertGreaterEqual(calls[name]['lookup'], calls[name]['site'])

    def test_unwind_table_byte_corruption_is_rejected(self):
        row = next(r for r in self.result['lsda'] if r['owner'] == 0x2013c00 and r['action'] == 0)
        offset = row['entry_file_offset'] + len(bytes.fromhex(row['bytes'])) - 1
        bad = self.mutated()
        bad[offset] ^= 1
        with self.assertRaises(ValueError):
            subject.lsda_rows(self.image_of(bad), self.fdes)

    def test_changed_unwind_metadata_pointer_is_rejected(self):
        altered = [dict(r) for r in self.fdes]
        next(r for r in altered if r['role'] == 'future_wrapper')['lsda'] += 1
        with self.assertRaisesRegex(ValueError, 'LSDA pointer'):
            subject.lsda_rows(self.image, altered)

    def test_complete_drop_tag_byte_domain(self):
        cases = [r for r in self.result['tables'] if r['table'] == 'future_drop_poll']
        self.assertEqual([r['input_tag'] for r in cases], list(range(3, 14)))
        second = [r for r in self.result['tables'] if r['table'] == 'future_drop_input']
        self.assertEqual([r['input_tag'] for r in second], list(range(3, 14)))
        self.assertEqual([r['target'] - r['owner'] for r in cases],
                         [r['target'] - r['owner'] for r in second])
        for tag in range(256):
            expected = tag - 3 if 3 <= tag <= 13 else None
            with self.subTest(tag=tag):
                self.assertEqual(subject.future_drop_case(tag), expected)
        for invalid in (-1, 256, True, 1.0, '3'):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                subject.future_drop_case(invalid)

    def test_actual_fde_range_corruption_is_rejected(self):
        bad = self.mutated()
        fde = next(r for r in self.fdes if r['role'] == 'future_wrapper')
        pos = fde['fde_file_offset'] + 12
        struct.pack_into('<I', bad, pos, 1)
        with self.assertRaises(ValueError):
            subject.fde_rows(subject.Image(bad))

    def test_actual_code_and_branch_corruption_are_rejected(self):
        for address in (0x2013c94, 0x2013c95, 0x1d7c9a6):
            bad = self.mutated()
            bad[self.offset(address)] ^= 1
            with self.subTest(address=hex(address)), self.assertRaises(ValueError):
                subject.window_rows(self.image_of(bad), self.fdes)
        bad = self.mutated()
        bad[self.offset(0x2013c94)] = 0x90
        with self.assertRaisesRegex(ValueError, 'wrong direct transfer'):
            subject.decode_site(self.image_of(bad), 0x2013c94, 'call')

    def test_conditional_branch_target_must_stay_in_its_fde(self):
        bad = self.mutated()
        struct.pack_into('<i', bad, self.offset(0x1d7c92b + 2, 4), 0x7fffffff)
        with self.assertRaisesRegex(ValueError, 'conditional target outside selected FDE'):
            subject.flow_rows(self.image_of(bad), self.fdes, self.result['windows'])

    def test_jump_table_wrong_in_range_and_out_of_range_targets(self):
        table_base = 0x3bc20c
        for changed in (0x1d7cac1, 0x7fffffff):
            bad = self.mutated()
            displacement = changed - table_base if changed != 0x7fffffff else changed
            struct.pack_into('<i', bad, self.offset(table_base, 4), displacement)
            with self.subTest(changed=changed), self.assertRaisesRegex(ValueError, 'table entry'):
                subject.table_rows(self.image_of(bad), self.fdes)

    def test_jump_table_target_bytes_are_required(self):
        bad = self.mutated()
        bad[self.offset(0x1d7cb30)] ^= 1
        with self.assertRaisesRegex(ValueError, 'target has no matching fixed window'):
            subject.table_rows(self.image_of(bad), self.fdes)

    def test_drop_table_bound_corruption(self):
        for guard in (0x1fc6263, 0x22569d3):
            bad = self.mutated()
            bad[self.offset(guard)] = 0x0b
            with self.subTest(guard=guard), self.assertRaisesRegex(ValueError, 'guard mismatch'):
                subject.table_rows(self.image_of(bad), self.fdes)

    def test_actual_relative_relocation_type_and_addend_corruption(self):
        r = next(r for r in self.result['relocations'] if r['name'] == 'first_schedule')
        for field_offset in (8, 16):
            bad = self.mutated()
            bad[r['entry_file_offset'] + field_offset] ^= 1
            with self.subTest(field_offset=field_offset), self.assertRaises(ValueError):
                subject.relocation_rows(self.image_of(bad))

    def test_duplicate_relative_relocation_is_rejected(self):
        r = next(r for r in self.result['relocations'] if r['name'] == 'second_schedule')
        bad = self.mutated()
        other = r['entry_file_offset'] + 24
        struct.pack_into('<Q', bad, other, r['slot'])
        with self.assertRaisesRegex(ValueError, 'duplicate selected relocation'):
            subject.relocation_rows(self.image_of(bad))

    def test_wrong_relocation_section_type_is_rejected(self):
        altered = [dict(s) for s in self.image.sections]
        next(s for s in altered if s['name'] == '.rela.dyn')['type'] = 1
        image = subject.Image(self.original, altered)
        with self.assertRaises(ValueError):
            subject.relocation_rows(image)
        with self.assertRaises(ValueError):
            subject.location_rows(image)

    def test_duplicate_or_nobits_exception_table_is_rejected(self):
        original = next(s for s in self.image.sections if s['name'] == '.gcc_except_table')
        duplicate = subject.Image(self.original, self.image.sections + [dict(original)])
        with self.assertRaises(ValueError):
            subject.lsda_rows(duplicate, self.fdes)
        altered = [dict(s) for s in self.image.sections]
        next(s for s in altered if s['name'] == '.gcc_except_table')['type'] = 8
        with self.assertRaises(ValueError):
            subject.lsda_rows(subject.Image(self.original, altered), self.fdes)

    def test_location_record_and_pointer_corruption(self):
        r = next(r for r in self.result['locations'] if r['name'] == 'entry_spawn')
        for offset in (r['file_offset'] + 16, r['relocation_offset'] + 16, r['path_file_offset']):
            bad = self.mutated()
            bad[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                subject.location_rows(self.image_of(bad))

    def test_out_of_range_and_nobits_are_not_file_mappings(self):
        for va, size in ((-1, 1), (0, 0), (1 << 64, 1), (0x2013c00, -1)):
            with self.subTest(va=va, size=size), self.assertRaises(ValueError):
                self.image.read(va, size)
        # TLS .tbss shares a linked VA with file-backed .init_array here;
        # ordinary .bss supplies an unambiguous NOBITS-only address.
        bss = next(s for s in self.image.sections if s['name'] == '.bss' and s['type'] == 8)
        with self.assertRaises(ValueError):
            self.image.read(bss['address'], 1)
        file_section = {'name': 'file', 'type': 1, 'address': 0x1000, 'offset': 0, 'size': 8, 'flags': 0}
        bss_overlap = dict(file_section, name='nobits', type=8)
        tiny = subject.Image(b'abcdefgh', [file_section, bss_overlap])
        self.assertEqual(tiny.read(0x1000, 4), b'abcd')
        ambiguous = subject.Image(b'abcdefgh', [file_section, dict(file_section, name='other')])
        with self.assertRaises(ValueError):
            ambiguous.read(0x1000, 1)

    def test_expected_candidate_sets(self):
        self.assertEqual(self.result['candidates'][0x229ec10], [0x2032528, 0x22b89b3, 0x247bd67])
        self.assertEqual(self.result['candidates'][0x2013c00], [0x1d7c99f, 0x1d8e9dc])

    def test_independent_raw_call_chain_and_cleanup_tables(self):
        # Independently map selected bytes with the shared ELF reader; do not
        # call the producer's Image, transfer, table or admission functions.
        secs = shared_sections(self.original)

        def raw(va, size):
            matches = [s for s in secs if s['type'] != 8 and s['address'] <= va
                       and va + size <= s['address'] + s['size']]
            self.assertEqual(len(matches), 1)
            s = matches[0]
            offset = s['offset'] + va - s['address']
            return self.original[offset:offset + size]

        expected = {
            0x22b89b3: 0x229ec10, 0x2032528: 0x229ec10, 0x247bd67: 0x229ec10,
            0x229edb4: 0x23c3c70, 0x229edc1: 0x2888350,
            0x23c3ca0: 0x200b3a0, 0x2888384: 0x2003d20,
            0x22a3d20: 0x1d7c8f0, 0x22a4460: 0x1d8e930,
            0x1d7c99f: 0x2013c00, 0x1d8e9dc: 0x2013c00, 0x2013c94: 0x22ae8a0,
            0x1d7cb23: 0x201c250, 0x1d8eb4a: 0x201c250,
            0x201c2bc: 0x1fa3d10, 0x1fa3d7d: 0x1fc6250, 0x229edef: 0x22569c0,
            0x229f990: 0x1d589c0, 0x229f710: 0x1d589c0,
        }
        for site, target in expected.items():
            with self.subTest(site=hex(site)):
                instruction = raw(site, 5)
                self.assertIn(instruction[0], (0xe8, 0xe9))
                self.assertEqual(site + 5 + struct.unpack_from('<i', instruction, 1)[0], target)
        offsets = [0x2d, 0xf4, 0x79, 0xc9, 0x57, 0x11e, 0x16e, 0xd7, 0x226, 0x68, 0x1a8]
        for table, owner in ((0x3c373c, 0x1fc6250), (0x3d5b90, 0x22569c0)):
            entries = struct.unpack('<11i', raw(table, 44))
            self.assertEqual([table + delta - owner for delta in entries], offsets)
        for guard in (0x1fc625e, 0x22569ce):
            self.assertEqual(raw(guard, 6), bytes.fromhex('83c0fd83f80a'))
        for immediate in (0x23c3c92, 0x2888376):
            self.assertEqual(raw(immediate, 5), bytes.fromhex('bacc000000'))
        relas = [s for s in secs if s['name'] == '.rela.dyn']
        self.assertEqual(len(relas), 1)
        relocation = relas[0]
        self.assertEqual(relocation['type'], 4)
        wanted = {0x56954a0: 0x22a3d20, 0x56954b8: 0x229f990,
                  0x5693650: 0x22a4460, 0x5693668: 0x229f710}
        found = {}
        for offset in range(relocation['offset'], relocation['offset'] + relocation['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', self.original, offset)
            if slot in wanted:
                self.assertNotIn(slot, found)
                self.assertEqual(info, 8)
                found[slot] = addend
        self.assertEqual(found, wanted)

    def test_write_twice_is_byte_identical(self):
        with tempfile.TemporaryDirectory() as parent:
            first, second = Path(parent) / 'first', Path(parent) / 'second'
            subject.write_evidence(first, self.result)
            subject.write_evidence(second, self.result)
            a = {p.name: p.read_bytes() for p in first.iterdir()}
            b = {p.name: p.read_bytes() for p in second.iterdir()}
            self.assertEqual(a, b)
            self.assertEqual(len(a), 14)


if __name__ == '__main__':
    unittest.main()
