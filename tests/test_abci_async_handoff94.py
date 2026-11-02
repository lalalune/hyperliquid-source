"""Target-backed controls for the selected static state-loader handoff."""
import copy
import mmap
import struct
import unittest

from tools import abci_async_handoff94 as n


class Handoff94Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.file = n.TARGET.open('rb')
        cls.data = mmap.mmap(cls.file.fileno(), 0, access=mmap.ACCESS_READ)
        cls.outputs, cls.summary = n.build(cls.data)
        cls.secs = n.sections(cls.data)
        cls.constants = n.model_constants(cls.data, cls.secs)

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.file.close()

    def rows(self, name):
        return self.outputs[name][1]

    def test_authenticated_target_and_evidence_counts(self):
        self.assertEqual(n.require_identity(self.data), n.TARGET_SHA256)
        self.assertEqual(self.summary['selected_fdes'], 25)
        self.assertEqual(self.summary['fixed_windows'], 55)
        self.assertEqual(self.summary['direct_edges'], 67)
        self.assertEqual(self.summary['conditional_branches'], 113)
        self.assertEqual(self.summary['jump_table_entries'], 50)
        self.assertEqual(self.summary['selected_relative_relocations'], 4)
        self.assertEqual(self.summary['synthetic_words'], 262)
        self.assertEqual(self.summary['synthetic_cleanup_tags'], 512)
        self.assertEqual(self.summary['synthetic_guard_cases'], 28)
        self.assertEqual(self.summary['raw_scan_candidates'], 23)
        functions = {r[0]: r for r in self.rows('functions.tsv')}
        self.assertEqual(functions['poll_bridge'][1:3], ('0x2013c00', '0x2013d86'))
        self.assertEqual(functions['poll_stub_a'][1:3], ('0x22a4460', '0x22a4465'))
        self.assertEqual(functions['read_result'][1:3], ('0x1d589c0', '0x1d58b1c'))
        self.assertNotEqual(functions['poll_bridge'][1], functions['poll_bridge'][3])

    def test_identity_rejects_corrupt_data_and_wrong_digest(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            n.require_identity(b'wrong target')
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            n.require_identity(self.data, '0' * 64)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            n.build(b'')

    def test_two_variants_connect_all_selected_layers(self):
        edges = {r[0]: r for r in self.rows('edges.tsv')}
        for name, target in (
            ('driver_to_tls_parent', '0x247bbf0'),
            ('driver_to_outer_driver', '0x247c020'),
            ('outer_driver_to_outer_parent', '0x2032480'),
            ('driver_to_local_driver', '0x2885a80'),
            ('local_driver_to_local_parent', '0x22b8920'),
        ):
            self.assertEqual(edges[name][-1], target)
        for name in ('outer_parent_to_spawn', 'local_parent_to_spawn', 'tls_parent_to_spawn'):
            self.assertEqual(edges[name][-1], '0x229ec10')
        for variant, queue, allocator, stub, scheduler in (
            ('a', '0x2888350', '0x2003d20', '0x22a4460', '0x1d8e930'),
            ('b', '0x23c3c70', '0x200b3a0', '0x22a3d20', '0x1d7c8f0'),
        ):
            self.assertEqual(edges['spawn_to_queue_' + variant][-1], queue)
            self.assertEqual(edges['queue_' + variant + '_to_allocate_' + variant][-1], allocator)
            self.assertEqual(edges['poll_stub_' + variant + '_to_scheduler_' + variant][-1], scheduler)
            relocs = [r for r in self.rows('relocations.tsv') if r[0] == variant]
            self.assertEqual(relocs[0][-1], stub)
            self.assertEqual([r[3] for r in relocs], [0, 3])
            self.assertTrue(all(r[5] == '0000000000000000' and r[7:9] == (8, 0) for r in relocs))
            self.assertEqual(edges['scheduler_' + variant + '_to_poll_bridge'][-1], '0x2013c00')
            self.assertEqual(edges['scheduler_' + variant + '_ready_to_replace'][-1], '0x201c250')
            self.assertEqual(edges['read_stub_' + variant + '_to_reader'][-1], '0x1d589c0')
        self.assertEqual(edges['poll_bridge_to_previous_state_location_boundary'][-1], '0x22ae8a0')
        self.assertEqual(edges['drop_box_to_poll_cleanup'][-1], '0x1fc6250')
        self.assertEqual(edges['spawn_unwind_to_future_cleanup'][2], '0x229ee6e')
        self.assertEqual(edges['spawn_unwind_to_resume_boundary'][2], '0x229ee76')
        self.assertEqual(edges['spawn_unwind_to_resume_boundary'][-1], '0x5660110')
        unwind_window = next(r for r in self.rows('windows.tsv') if r[0] == 'spawn_unwind_drop')
        self.assertIn(bytes.fromhex('488d7c2410e84d7bfbff4c89f7e895123c03'),
                      bytes.fromhex(unwind_window[-1]))

    def test_layout_and_pointer_handoff(self):
        layout = {r[0]: r[2] for r in self.rows('layout.tsv')}
        for key in ('outer_parent_future_state_offset', 'local_parent_future_state_offset', 'tls_parent_future_state_offset'):
            self.assertEqual(layout[key], '0x216')
            self.assertEqual(layout[key.replace('_offset', '_value')], '0x0')
        for key in ('future_copy_bytes', 'future_allocation_bytes', 'future_heap_copy_bytes', 'future_drop_bytes'):
            self.assertEqual(layout[key], '0x6368')
        for key in ('task_allocation_a_bytes', 'task_allocation_b_bytes'):
            self.assertEqual(layout[key], '0x80')
        self.assertEqual(layout['future_cleanup_selector_offset'], '0x216')
        self.assertEqual(layout['task_table_pointer_offset'], '0x10')
        self.assertEqual(layout['scheduler_inner_object_offset_a'], '0x20')
        self.assertEqual(layout['scheduler_inner_object_offset_b'], '0x20')
        self.assertEqual(layout['allocator_a_source_offset'], '0x190')
        self.assertEqual(layout['allocator_b_source_offset'], '0x1f0')
        self.assertEqual(layout['task_stage_tag_offset'], '0x30')
        self.assertEqual(layout['task_future_pointer_offset'], '0x38')
        windows = {r[0]: bytes.fromhex(r[-1]) for r in self.rows('windows.tsv')}
        self.assertIn(bytes.fromhex('41c70702000000'), windows['poll_bridge_done'])
        self.assertIn(bytes.fromhex('410f114f10410f1107'), windows['replace_drop_and_copy'])
        self.assertIn(bytes.fromhex('41c7463002000000'), windows['read_output_take'])

    def test_tagged_result_is_copied_then_taken(self):
        # The checked producer clears two words and stores an unconstrained RDX
        # as the third. The two SIMD moves replace 32 bytes; the reader writes
        # the old slot tag 2 before its tag-1 check and payload handoff.
        producer = n.read_va(self.data, self.secs, 0x1d7cb03, 28, True)
        self.assertEqual(producer[:4], bytes.fromhex('31c031c9'))
        self.assertIn(bytes.fromhex('48894c2408'), producer)
        self.assertIn(bytes.fromhex('4889442410'), producer)
        self.assertIn(bytes.fromhex('4889542418'), producer)
        self.assertIn(bytes.fromhex('c7042401000000'), producer)
        replace = n.read_va(self.data, self.secs, 0x201c2c1, 18, True)
        self.assertEqual(replace, bytes.fromhex('410f1006410f104e10410f114f10410f1107'))
        reader = n.read_va(self.data, self.secs, 0x1d589f5, 13, True)
        self.assertEqual(reader, bytes.fromhex('41c7463002000000837c242001'))
        with n.TARGET.open('rb') as handle:
            with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_COPY) as altered:
                offset, _ = n.va_offset(altered, self.secs, 0x1d589f5, 8, True)
                altered[offset + 4] ^= 1
                spec = next(x for x in n.WINDOWS if x[0] == 'read_output_take')
                frames = {'read_result': {'start': 0x1d589c0, 'end': 0x1d58b1c}}
                with self.assertRaisesRegex(ValueError, 'pattern mismatch'):
                    n.window_rows(altered, self.secs, frames, [spec])

    def test_relative_table_and_branch_controls(self):
        tables = self.rows('jump-tables.tsv')
        self.assertEqual([r[-1] for r in tables if r[0] == 'scheduler_a_before_poll'],
                         ['0x1d8e9a7', '0x1d8eae5', '0x1d8eb57', '0x1d8eadb'])
        self.assertEqual([r[-1] for r in tables if r[0] == 'scheduler_b_after_poll'],
                         ['0x1d7cb30', '0x1d7ca68', '0x1d7cab7', '0x1d7cb3a'])
        branches = {r[0]: r for r in self.rows('branches.tsv')}
        self.assertEqual(branches['sched_a_poll_result_zero'][-2], '0x1d8eb27')
        self.assertEqual(branches['sched_b_poll_result_zero'][-2], '0x1d7cb03')
        self.assertEqual(branches['parent_result_word_nonzero'][-2], '0x22b8a1a')
        self.assertEqual(branches['read_tag_not_one'][-2], '0x1d58a97')

    def test_future_cleanup_dispatch_exhausts_the_byte_domain(self):
        rows = self.rows('cleanup-stages.tsv')
        self.assertEqual(len(rows), 512)
        expected_targets = [0x22569ed, 0x2256ab4, 0x2256a39, 0x2256a89,
                            0x2256a17, 0x2256ade, 0x2256b2e, 0x2256a97,
                            0x2256be6, 0x2256a28, 0x2256b68]
        for tag, index, dispatch, target, variant in rows:
            delta = 0 if variant == 'spawn' else n.CLEANUP_DELTA
            if 3 <= tag <= 13:
                self.assertEqual((index, dispatch, target),
                                 (hex(tag - 3), 'table', hex(expected_targets[tag - 3] + delta)))
            else:
                self.assertEqual((dispatch, target), ('default', hex(0x2256d21 + delta)))
        self.assertEqual(rows[0][1], '0xfffffffd')
        self.assertEqual(rows[2][1], '0xffffffff')
        self.assertEqual(rows[14][1], '0xb')
        branches = {r[0]: r for r in self.rows('branches.tsv')}
        self.assertEqual(branches['cleanup_stage_outside_3_to_13'][-2], '0x2256d21')
        self.assertEqual(branches['cleanup_nested_first_308_not_three'][-2], '0x2256cd3')
        for name, mutation, start, end in (
            ('future_cleanup_full_fde', 0x22569d3, 0x22569c0, 0x2257080),
            ('poll_cleanup_full_fde', 0x1fc6263, 0x1fc6250, 0x1fc6910),
        ):
            with n.TARGET.open('rb') as handle:
                with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_COPY) as altered:
                    offset, _ = n.va_offset(altered, self.secs, mutation, 1, True)
                    altered[offset] ^= 1
                    spec = next(x for x in n.WINDOWS if x[0] == name)
                    frames = {'cleanup': {'start': start, 'end': end}}
                    with self.assertRaisesRegex(ValueError, 'pattern mismatch'):
                        n.window_rows(altered, self.secs, frames, [spec])

    def test_cleanup_nested_guards_and_reset_data(self):
        self.assertEqual(self.summary['cleanup_field_sites'], 122)
        self.assertEqual(self.summary['cleanup_reset_loads'], 16)
        fields = {r[0]: r for r in self.rows('cleanup-fields.tsv')}
        for suffix, offset in (('318', '0x318'), ('310', '0x310'), ('308', '0x308')):
            for arm in ('first', 'second'):
                row = fields['nested_' + arm + '_guard_' + suffix]
                self.assertEqual((row[3], row[4]), (offset, '0x3'))
        for key, offset in (('stage5_reset_low', '0x230'), ('stage678_reset_low', '0x218'),
                            ('stage1112_reset_low', '0x150'), ('stage13_first_reset_low', '0x2c8'),
                            ('stage13_second_reset_low', '0x230')):
            self.assertEqual(fields[key][3], offset)
        for key, offset in (('guard_word_238', '0x238'), ('guard_arg_240', '0x240'),
                            ('guard_word_220', '0x220'), ('guard_arg_228', '0x228'),
                            ('guard_word_a8', '0xa8'), ('guard_arg_b0', '0xb0')):
            self.assertEqual(fields[key][3], offset)
        for key in ('clear_flag_205', 'clear_flag_206', 'clear_flag_207',
                    'clear_word_208', 'clear_word_210', 'clear_word_214'):
            self.assertEqual(fields[key][4], '0x0')
        for key in list(fields):
            if not key.startswith('poll_'):
                self.assertEqual(fields[key][3:], fields['poll_' + key][3:])
        constants = {r[2]: r[3] for r in self.rows('cleanup-reset-values.tsv')}
        self.assertEqual(constants['0x20c240'], '01' + '00' * 15)
        self.assertEqual(constants['0x20c250'], '00' * 16)
        with n.TARGET.open('rb') as handle:
            with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_COPY) as altered:
                offset, _ = n.va_offset(altered, self.secs, 0x2256d8e, 1, True)
                altered[offset] ^= 1
                spec = next(x for x in n.WINDOWS if x[0] == 'future_cleanup_full_fde')
                frames = {'future_cleanup': {'start': 0x22569c0, 'end': 0x2257080}}
                with self.assertRaisesRegex(ValueError, 'pattern mismatch'):
                    n.window_rows(altered, self.secs, frames, [spec])

    def test_cleanup_indirect_release_guard_boundaries(self):
        self.assertFalse(n.cleanup_release_guard(0, 1))
        self.assertFalse(n.cleanup_release_guard(1, 0))
        self.assertFalse(n.cleanup_release_guard(1, 1 << 63))
        for value in (1, 2, (1 << 63) - 1, (1 << 63) + 1, n.MASK64):
            self.assertTrue(n.cleanup_release_guard(1, value))
            self.assertTrue(n.cleanup_release_guard(255, value))
        for bad in (-1, 256):
            with self.assertRaises(ValueError):
                n.cleanup_release_guard(bad, 1)
        for bad in (-1, 1 << 64):
            with self.assertRaises(ValueError):
                n.cleanup_release_guard(1, bad)
        # NEG sets CF for every nonzero operand and OF only at signed minimum.
        for value in list(range(4096)) + [1 << 63, n.MASK64]:
            expected = value != 0 and value != 1 << 63
            self.assertEqual(n.cleanup_release_guard(1, value), expected)
        for flag, word, selected in self.rows('cleanup-guards.tsv'):
            self.assertEqual(selected, int(n.cleanup_release_guard(flag, int(word, 16))))

    def test_literal_contents_are_bounded_and_bound(self):
        messages = {r[0]: r[-1] for r in self.rows('literals.tsv')}
        self.assertEqual(messages['notified_assertion'], 'assertion failed: next.is_notified()')
        self.assertEqual(messages['running_assertion'], 'assertion failed: curr.is_running()')
        self.assertEqual(messages['parent_unwrap_literal'], 'called `Result::unwrap()` on an `Err` value')
        for row in self.rows('literals.tsv'):
            self.assertEqual(len(bytes.fromhex(row[4])), row[3])

    def test_raw_scheduler_branch_examples_and_u64_boundaries(self):
        c = self.constants
        self.assertEqual(n.model_constants(self.data, self.secs, 'a'), c)
        with self.assertRaises(ValueError):
            n.model_constants(self.data, self.secs, 'unknown')
        pre = {
            0: ('notified_assertion', None, None),
            4: ('cas', 1, 0),
            5: ('reference_count_assertion', None, None),
            36: ('cas', 33, 1),
            0x45: ('cas', 5, 3),
            0x85: ('cas', 0x45, 2),
        }
        post = {
            0: ('running_assertion', None, None),
            1: ('reference_count_assertion', None, None),
            5: ('cas', 0x44, 1),
            0x21: ('no_cas', None, 3),
            0x41: ('cas', 0, 2),
            0x81: ('cas', 0x40, 0),
            (1 << 63) + 5: ('signed_bound_assertion', None, None),
        }
        for word, expected in pre.items():
            self.assertEqual(n.model_pre(word, c), expected, hex(word))
        for word, expected in post.items():
            self.assertEqual(n.model_post(word, c), expected, hex(word))
        for bad in (-1, 1 << 64):
            with self.assertRaises(ValueError):
                n.model_pre(bad, c)
            with self.assertRaises(ValueError):
                n.model_post(bad, c)

    def test_scheduler_model_invariants_for_all_low_words(self):
        c = self.constants
        observed_pre, observed_post = set(), set()
        for word in range(4096):
            action, new, index = n.model_pre(word, c)
            observed_pre.add((action, index))
            if not word & 4:
                self.assertEqual(action, 'notified_assertion')
            if action == 'cas':
                self.assertTrue(0 <= new <= n.MASK64)
                self.assertIn(index, range(4))
            action, new, index = n.model_post(word, c)
            observed_post.add((action, index))
            if not word & 1:
                self.assertEqual(action, 'running_assertion')
            if action == 'cas':
                self.assertTrue(0 <= new <= n.MASK64)
                self.assertIn(index, range(4))
            if action == 'no_cas':
                self.assertEqual(index, 3)
                self.assertIsNone(new)
        for index in range(4):
            self.assertTrue(any(i == index for _, i in observed_pre))
            self.assertTrue(any(i == index for _, i in observed_post))
        mutated = dict(c, post_add=c['post_add'] - 1)
        self.assertNotEqual(n.model_post(5, c), n.model_post(5, mutated))

    def test_mapping_rejects_fileless_ambiguous_and_outside_ranges(self):
        data = b'abcdef'
        section = {'name': '.text', 'type': 1, 'flags': 6, 'address': 0x1000, 'offset': 0, 'size': 6}
        self.assertEqual(n.read_va(data, [section], 0x1001, 3, True), b'bcd')
        with self.assertRaises(ValueError):
            n.read_va(data, [section], 0xfff, 1)
        with self.assertRaises(ValueError):
            n.read_va(data, [section], 0x1005, 2)
        with self.assertRaises(ValueError):
            n.read_va(data, [section], 0x1000, 0)
        fileless = dict(section, type=8)
        with self.assertRaises(ValueError):
            n.read_va(data, [fileless], 0x1000, 1)
        with self.assertRaises(ValueError):
            n.read_va(data, [section, dict(section)], 0x1000, 1)
        with self.assertRaises(ValueError):
            n.section_named([section, dict(section)], '.text')

    def test_actual_window_rejects_mutated_byte(self):
        name, address, expected = next(x for x in n.WINDOWS if x[0] == 'poll_bridge_entry')
        actual = n.read_va(self.data, self.secs, address, len(bytes.fromhex(expected)), True)
        image = bytearray(actual)
        sec = {'name': '.text', 'type': 1, 'flags': 6, 'address': address, 'offset': 0, 'size': len(image)}
        frames = {'selected': {'start': address, 'end': address + len(image)}}
        self.assertEqual(len(n.window_rows(image, [sec], frames, [(name, address, expected)])), 1)
        image[2] ^= 1
        with self.assertRaisesRegex(ValueError, 'pattern mismatch'):
            n.window_rows(image, [sec], frames, [(name, address, expected)])
        with self.assertRaisesRegex(ValueError, 'unique selected FDE'):
            n.window_rows(actual, [sec], {'x': {'start': address, 'end': address + len(actual) - 1}},
                          [(name, address, expected)])

    def test_transfer_and_conditional_corruption(self):
        raw = bytes.fromhex('e807ac2900')
        self.assertEqual(n.checked_rel32(raw, 0x2013c94, 0xe8, 0x22ae8a0)[1], 0x22ae8a0)
        for broken in (b'\xe9' + raw[1:], raw[:4], raw[:1] + b'\0' * 4):
            with self.assertRaises(ValueError):
                n.checked_rel32(broken, 0x2013c94, 0xe8, 0x22ae8a0)
        self.assertEqual(n.checked_branch(bytes.fromhex('75db00000000'), 0x1000, 0xfdd)[:2], (2, 'ne'))
        with self.assertRaises(ValueError):
            n.checked_branch(bytes.fromhex('75da00000000'), 0x1000, 0xfdd)
        with self.assertRaises(ValueError):
            n.checked_branch(b'\x90' * 6, 0x1000, 0x1002)
        with self.assertRaises(ValueError):
            n.checked_lea(b'\x48\x8d\x05\0\0\0\0', 0x1000, 0x1008)

    def test_relocation_corruption_and_ambiguity(self):
        expect = {0x100: 0x200}
        good = (0x100, 8, 0, 0x200, 0x10)
        self.assertEqual(n.select_relocations([good], expect)[0x100], [good])
        for rows in ([], [good, good], [(0x100, 7, 0, 0x200, 0x10)],
                     [(0x100, 8, 1, 0x200, 0x10)], [(0x100, 8, 0, 0x201, 0x10)]):
            with self.assertRaises(ValueError):
                n.select_relocations(rows, expect)

    def test_table_corruption_and_signed_offsets(self):
        base = 0x1000
        raw = struct.pack('<ii', -4, 8)
        self.assertEqual(n.table_targets(raw, base, (0xffc, 0x1008)), (0xffc, 0x1008))
        with self.assertRaises(ValueError):
            n.table_targets(raw[:-1], base, (0xffc, 0x1008))
        with self.assertRaises(ValueError):
            n.table_targets(struct.pack('<ii', -3, 8), base, (0xffc, 0x1008))

    def test_fde_index_mismatch_and_fileless_section(self):
        function_rows = self.rows('functions.tsv')
        records = [{'start': int(r[1], 16), 'end': int(r[2], 16), 'fde': int(r[5], 16)} for r in function_rows]
        headers = [{'start': int(r[1], 16), 'fde': int(r[5], 16)} for r in function_rows]
        self.assertEqual(len(n.selected_frames(self.secs, headers, records)), len(n.FUNCTIONS))
        bad = copy.deepcopy(headers)
        bad[0]['fde'] += 1
        with self.assertRaises(ValueError):
            n.selected_frames(self.secs, bad, records)
        with self.assertRaises(ValueError):
            n.selected_frames(self.secs, headers, records + [records[0]])
        no_text = [dict(s, type=8) if s['name'] == '.text' else s for s in self.secs]
        with self.assertRaises(ValueError):
            n.selected_frames(no_text, headers, records)

    def test_real_image_cow_relocation_and_branch_corruption(self):
        with n.TARGET.open('rb') as handle:
            with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_COPY) as altered:
                wanted = {0x5693650: 0x22a4460, 0x5693668: 0x229f710}
                selected = n.select_relocations(n.relocation_rows(altered, self.secs), wanted)
                row_offset = selected[0x5693650][0][4]
                struct.pack_into('<q', altered, row_offset + 16, 0x22a4461)
                with self.assertRaisesRegex(ValueError, 'relocation differs'):
                    n.select_relocations(n.relocation_rows(altered, self.secs), wanted)
                with self.assertRaisesRegex(ValueError, 'SHA-256'):
                    n.require_identity(altered)
        with n.TARGET.open('rb') as handle:
            with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_COPY) as altered:
                offset, _ = n.va_offset(altered, self.secs, 0x1d7c9a6, 6, True)
                altered[offset + 2] ^= 1
                with self.assertRaisesRegex(ValueError, 'branch target mismatch'):
                    n.checked_branch(bytes(altered[offset:offset + 6]), 0x1d7c9a6, 0x1d7cb03)
                expected = next(x for x in n.WINDOWS if x[0] == 'scheduler_b_poll')
                frames = {'scheduler_b': {'start': 0x1d7c8f0, 'end': 0x1d7cce6}}
                with self.assertRaisesRegex(ValueError, 'pattern mismatch'):
                    n.window_rows(altered, self.secs, frames, [expected])

    def test_real_image_cow_duplicate_relocation_and_fde_range(self):
        with n.TARGET.open('rb') as handle:
            with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_COPY) as altered:
                rel = n.section_named(self.secs, '.rela.dyn')
                last = rel['offset'] + rel['size'] - 24
                struct.pack_into('<Q', altered, last, 0x5693650)
                with self.assertRaisesRegex(ValueError, 'duplicate'):
                    n.select_relocations(n.relocation_rows(altered, self.secs), {0x5693650: 0x22a4460})
        with n.TARGET.open('rb') as handle:
            with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_COPY) as altered:
                fde_offset, _ = n.va_offset(altered, self.secs, 0x1072bdc, 16)
                struct.pack_into('<i', altered, fde_offset + 12, 0x80)
                secs, headers = n.unwind_index(altered)
                _, records = n.eh_frame_records(altered, secs)
                frames = n.selected_frames(secs, headers, records)
                with self.assertRaisesRegex(ValueError, 'unique selected FDE'):
                    n.window_rows(altered, secs, frames)

    def test_byte_scan_keeps_unaligned_candidates(self):
        base, dest = 0x229ebc0, 0x229ec10
        image = bytearray(b'\x90' * 32)
        image[1:6] = b'\xe8' + struct.pack('<i', dest - (base + 1 + 5))
        image[10:15] = b'\xe9' + struct.pack('<i', dest - (base + 10 + 5))
        sec = {'name': '.text', 'type': 1, 'flags': 6, 'address': base, 'offset': 0, 'size': len(image)}
        frames = {'fixture': {'start': base, 'end': base + len(image)}}
        found = n.selected_candidate_scan(image, [sec], frames)
        self.assertEqual([(r[0], r[1], r[2]) for r in found],
                         [(base + 1, 0xe8, dest), (base + 10, 0xe9, dest)])
        image[2] ^= 1
        self.assertEqual(len(n.selected_candidate_scan(image, [sec], frames)), 1)


if __name__ == '__main__':
    unittest.main()
