"""Static and corruption controls for the node 94 slow-worker handoff."""
import contextlib
import hashlib
import mmap
import struct
import unittest

from tools import abci_slow_worker94 as p


class SlowWorker94Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.handle = p.TARGET.open('rb')
        cls.data = mmap.mmap(cls.handle.fileno(), 0, access=mmap.ACCESS_COPY)
        p.authenticate(cls.data)
        cls.image = p.Image(cls.data)
        cls.functions = p.select_functions(cls.image)
        cls.worker = next(row for name, row, _, _ in cls.functions if name == 'slow_callback')
        cls.relocations = p.selected_relocations(cls.image)
        cls.refs = {row[0]: int(row[-1], 16)
                    for row in (p.reference_row(cls.image, *spec) for spec in p.REFERENCES)}
        cls.values = {row[0]: int(row[-2])
                      for row in (p.constant_row(cls.image, *spec) for spec in p.CONSTANTS)}

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.handle.close()

    @contextlib.contextmanager
    def changed(self, file_offset, replacement):
        old = bytes(self.data[file_offset:file_offset + len(replacement)])
        self.data[file_offset:file_offset + len(replacement)] = replacement
        try:
            yield
        finally:
            self.data[file_offset:file_offset + len(replacement)] = old

    def test_target_digest_rejects_corruption(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), p.SHA256)
        with self.changed(0, bytes([self.data[0] ^ 1])):
            with self.assertRaisesRegex(p.EvidenceError, 'SHA-256'):
                p.authenticate(self.data)
        p.authenticate(self.data)

    def test_fde_and_window_extents(self):
        self.assertEqual(len(self.functions), 10)
        self.assertEqual((self.worker['start'], self.worker['end'], self.worker['lsda']),
                         (0x433a350, 0x433a5e1, 0xb29cb0))
        extents = {(start, end) for _, start, end, _ in p.FUNCTIONS}
        self.assertEqual({(start, end) for _, start, end, _ in p.WINDOWS}, extents)
        self.assertEqual(len(p.capture_windows(self.image)), len(extents))

    def test_fde_range_corruption(self):
        at = self.image.where(self.worker['fde'], 16)[1] + 12
        with self.changed(at, bytes([self.data[at] ^ 1])):
            with self.assertRaises(ValueError):
                p.select_functions(self.image)

    def test_every_window_rejects_a_mutated_byte(self):
        self.assertEqual(len(p.WINDOWS), 10)
        for label, start, _, _ in p.WINDOWS:
            with self.subTest(window=label):
                at = self.image.where(start, 1)[1]
                with self.changed(at, bytes([self.data[at] ^ 1])):
                    with self.assertRaises(p.EvidenceError):
                        p.capture_windows(self.image)

    def test_branch_opcode_and_displacement_mutations(self):
        self.assertEqual(len(p.BRANCHES), 111)
        for site, expected in p.BRANCHES:
            row = p.branch_row(self.image, site, expected)
            owners = [(start, end) for _, start, end, _ in p.FUNCTIONS if start <= site < end]
            self.assertEqual(len(owners), 1)
            self.assertTrue(owners[0][0] <= int(row[-1], 16) < owners[0][1])
            for index in (0, len(bytes.fromhex(expected)) - 1):
                with self.subTest(site=hex(site), byte=index):
                    at = self.image.where(site, len(bytes.fromhex(expected)))[1] + index
                    with self.changed(at, bytes([self.data[at] ^ 1])):
                        with self.assertRaises(p.EvidenceError):
                            p.branch_row(self.image, site, expected)

    def test_guarded_decisions_and_corruption(self):
        self.assertEqual(len(p.DECISIONS), 21)
        rows = {row[0]: p.decision_row(self.image, *row) for row in p.DECISIONS}
        self.assertEqual(rows['slow_builder_result_zero'][-1], '0x474b003')
        self.assertEqual(rows['adapter_low_bit_clear'][-1], '0x433248f')
        self.assertEqual(rows['thread_create_zero'][-1], '0x4ee4bb2')
        self.assertEqual(rows['exception_previous_completion_nonzero'][-1], '0x433a4a7')
        self.assertEqual(rows['dispatch_lock_contended'][-1], '0x4528c59')
        self.assertEqual(rows['replace_old_min_sentinel'][-1], '0x4527b80')
        for row in p.DECISIONS:
            label, va, raw, _, _ = row
            at = self.image.where(va, len(bytes.fromhex(raw)))[1]
            with self.subTest(guard=label), self.changed(at, bytes([self.data[at] ^ 1])):
                with self.assertRaises(p.EvidenceError):
                    p.decision_row(self.image, *row)
        label, va, raw, branch_va, branch_raw = p.DECISIONS[0]
        with self.assertRaises(p.EvidenceError):
            p.decision_row(self.image, label, va, raw, branch_va + 1, branch_raw)

    def test_every_reference_rejects_displacement_mutation(self):
        self.assertEqual(len(p.REFERENCES), 31)
        for label, site, expected, displacement_offset in p.REFERENCES:
            with self.subTest(reference=label):
                p.reference_row(self.image, label, site, expected, displacement_offset)
                at = self.image.where(site, len(bytes.fromhex(expected)))[1] + displacement_offset
                with self.changed(at, bytes([self.data[at] ^ 1])):
                    with self.assertRaises(p.EvidenceError):
                        p.reference_row(self.image, label, site, expected, displacement_offset)

    def test_immediate_values_and_mutation(self):
        self.assertEqual(len(p.CONSTANTS), 11)
        self.assertEqual(self.values['worker_payload_size'], 168)
        self.assertEqual(self.values['worker_envelope_size'], 24)
        self.assertEqual(self.values['worker_method_offset'], 24)
        self.assertEqual(self.values['stack_size_retry_error'], 22)
        self.assertEqual(self.values['stack_size_floor'], 16384)
        self.assertEqual(self.values['stack_size_page_selector'], 30)
        for label, site, expected, offset, size in p.CONSTANTS:
            at = self.image.where(site, len(bytes.fromhex(expected)))[1] + offset
            with self.subTest(constant=label), self.changed(at, bytes([self.data[at] ^ 1])):
                with self.assertRaises(p.EvidenceError):
                    p.constant_row(self.image, label, site, expected, offset, size)

    def test_relocation_bindings(self):
        self.assertEqual(len(self.relocations), 13)
        self.assertEqual(self.relocations[0x5773b60]['addend'], 0x474abe0)
        self.assertEqual(self.relocations[0x576f5d0]['addend'], 0x4ee4ab0)
        self.assertEqual(self.relocations[0x5776600]['addend'], 0x432e4d0)
        self.assertEqual(self.relocations[0x57773c0]['symbol_name'], 'pthread_create')
        self.assertEqual(self.relocations[0x57773b8]['symbol_name'], 'pthread_attr_setstacksize')
        self.assertEqual(self.relocations[0x57708a8]['symbol_name'], 'sysconf')
        self.assertEqual(self.relocations[0x576dfe0]['symbol_name'], 'memcpy')

    def test_relocation_type_symbol_and_addend_corruption(self):
        relative = self.relocations[0x5773b60]['file_offset']
        for at in (relative + 8, relative + 12, relative + 16):
            with self.subTest(offset=at - relative):
                with self.changed(at, bytes([self.data[at] ^ 1])):
                    with self.assertRaises(p.EvidenceError):
                        p.selected_relocations(self.image)
        dynamic = self.relocations[0x57773c0]['file_offset']
        with self.changed(dynamic + 8, struct.pack('<Q', (0xffffffff << 32) | 6)):
            with self.assertRaises(p.EvidenceError):
                p.selected_relocations(self.image)

    def test_duplicate_selected_relocation(self):
        rel = self.image.by_name['.rela.dyn']
        for pos in range(rel['offset'], rel['offset'] + rel['size'], 24):
            if struct.unpack_from('<Q', self.data, pos)[0] not in p.SLOTS:
                break
        else:
            self.fail('no distinct relocation record available for control')
        with self.changed(pos, struct.pack('<Q', 0x5773b60)):
            with self.assertRaises(p.EvidenceError):
                p.selected_relocations(self.image)

    def test_dynamic_symbol_name_corruption(self):
        index = self.relocations[0x57773c0]['symbol']
        sym = self.image.by_name['.dynsym']
        strings = self.image.by_name['.dynstr']
        name_offset = struct.unpack_from('<I', self.data, sym['offset'] + index * 24)[0]
        at = strings['offset'] + name_offset
        with self.changed(at, bytes([self.data[at] ^ 1])):
            with self.assertRaises(p.EvidenceError):
                p.selected_relocations(self.image)

    def test_constructor_to_worker_call_chain(self):
        self.assertEqual(self.refs['boundary_slow_call'], 0x5773b60)
        self.assertEqual(self.refs['slow_thread_builder'], 0x43320f0)
        self.assertEqual(self.refs['worker_thread_start_slot'], 0x576f5d0)
        self.assertEqual(self.refs['pthread_entry_ref'], 0x4ee48b0)
        self.assertEqual(self.refs['pthread_create_slot'], 0x57773c0)
        table = p.worker_table_rows(self.image, self.relocations, self.refs['worker_table_ref'])
        self.assertEqual([row[-1] for row in table], ['0x4340ae0', '', '', '0x433a350'])
        self.assertEqual(self.refs['worker_loop_slot'], 0x5776600)
        self.assertEqual(self.image.read(0x433a48e, 5), bytes.fromhex('488d7c2410'))
        self.assertEqual(self.image.read(0x4ee49e7, 4), bytes.fromhex('41ff5718'))

    def test_worker_vtable_mutations(self):
        for va in (0x571cb70, 0x571cb78):
            at = self.image.where(va, 8)[1]
            with self.changed(at, bytes([self.data[at] ^ 1])):
                with self.assertRaises(p.EvidenceError):
                    p.worker_table_rows(self.image, self.relocations, 0x571cb68)
        with self.assertRaises(p.EvidenceError):
            p.worker_table_rows(self.image, self.relocations, 0x571cb60)

    def test_every_worker_layout_instruction_rejects_corruption(self):
        self.assertEqual(len(p.thread_layout_rows(self.image)), 34)
        for label, va, raw in p.THREAD_LAYOUT:
            at = self.image.where(va, len(bytes.fromhex(raw)))[1]
            with self.subTest(site=label), self.changed(at, bytes([self.data[at] ^ 1])):
                with self.assertRaises(p.EvidenceError):
                    p.thread_layout_rows(self.image)

    def test_protected_layout_and_all_instruction_corruptions(self):
        rows = {row[0]: row for row in p.protected_layout_rows(self.image)}
        self.assertEqual(len(rows), 56)
        self.assertEqual(rows['replace_payload_address'][-1], '4d8db770050000')
        self.assertEqual(rows['normal_copy_store_tail'][-1], rows['cleanup_copy_store_tail'][-1])
        self.assertEqual(rows['normal_copy_store_middle'][-1], rows['cleanup_copy_store_middle'][-1])
        self.assertEqual(rows['normal_copy_store_first'][-1], rows['cleanup_copy_store_first'][-1])
        for part in ('tail', 'middle', 'first'):
            self.assertEqual(rows['wrapper_plain_store_' + part][-1], rows['wrapper_tls_store_' + part][-1])
        for label, va, raw in p.PROTECTED_LAYOUT:
            at = self.image.where(va, len(bytes.fromhex(raw)))[1]
            with self.subTest(site=label), self.changed(at, bytes([self.data[at] ^ 1])):
                with self.assertRaises(p.EvidenceError):
                    p.protected_layout_rows(self.image)

    def test_processing_chain_and_distinct_input_bases(self):
        self.assertEqual(self.refs['prior_loop_process_call'], 0x474a0f0)
        self.assertEqual(self.refs['prior_loop_no_result_branch'], 0x432e729)
        self.assertEqual(self.refs['prior_loop_replace_call'], 0x4527ab0)
        self.assertEqual(self.refs['wrapper_dispatch_plain'], 0x4528a00)
        self.assertEqual(self.refs['wrapper_dispatch_tls'], 0x4528a00)
        self.assertEqual(self.refs['protected_dispatch_tls_match'], 0x4677fd0)
        self.assertEqual(self.refs['protected_dispatch_tls_empty'], 0x46a7ee0)
        self.assertEqual(self.refs['protected_dispatch_tls_other'], 0x46b8350)
        rows = {row[0]: row[-1] for row in p.protected_layout_rows(self.image)}
        self.assertEqual(rows['loop_dispatch_base'], '498b7570')
        self.assertEqual(rows['loop_replace_base'], '498b7d78')

    def test_constructor_argument_origins_and_corruption(self):
        layout, operands = p.origin_rows(self.image)
        self.assertEqual((len(layout), len(operands)), (23, 17))
        values = {row[0]: int(row[-2]) for row in operands}
        self.assertEqual(values['constructor_second_stack'], 0x110)
        self.assertEqual(values['constructor_third_stack'], 0x118)
        self.assertEqual(values['builder_pair_input'], 0x70)
        self.assertEqual(values['loop_second_offset'], 0x70)
        self.assertEqual(values['loop_third_offset'], 0x78)
        for label, va, raw in p.ORIGIN_LAYOUT:
            at = self.image.where(va, len(bytes.fromhex(raw)))[1]
            with self.subTest(site=label), self.changed(at, bytes([self.data[at] ^ 1])):
                with self.assertRaises(p.EvidenceError):
                    p.origin_rows(self.image)

    def test_constructor_argument_copy_model(self):
        _, operands = p.origin_rows(self.image)
        v = {row[0]: int(row[-2]) for row in operands}
        second, third = 0x123456789abcdef0, 0xfedcba9876543210
        constructor = bytearray(0x200)
        struct.pack_into('<Q', constructor, v['constructor_second_stack'], second)
        struct.pack_into('<Q', constructor, v['constructor_third_stack'], third)
        src = v['constructor_pair_load_stack']
        dst = v['constructor_pair_store_stack']
        constructor[dst:dst + 16] = constructor[src:src + 16]
        record = constructor[v['constructor_record_base']:v['constructor_record_base'] + 128]
        builder = bytearray(0x200)
        start = v['builder_payload_stack'] + v['worker_record_offset']
        builder[start:start + len(record)] = record
        payload = builder[v['builder_payload_stack']:v['builder_payload_stack'] + v['builder_payload_copy_size']]
        worker = payload[v['worker_record_offset']:]
        actual = (struct.unpack_from('<Q', worker, v['loop_second_offset'])[0],
                  struct.unpack_from('<Q', worker, v['loop_third_offset'])[0])
        self.assertEqual(actual, (second, third))
        self.assertNotEqual(actual, (third, second))

    def test_processing_lsda_and_corruption(self):
        rows, details = p.processing_lsda_rows(self.image, self.functions)
        self.assertEqual(len(rows), 39)
        self.assertEqual(details['protected_dispatch']['lsda_va'], '0xb4a81c')
        self.assertIn(('protected_replace', '0x4527b63', '0x4527b69',
                       '0x4527ca8', '0', '0xb4a6cb', 'b30106f80300'), rows)
        self.assertIn(('protected_dispatch', '0x4528b2c', '0x4528b3b',
                       '0x4528cb8', '0', '0xb4a82a', 'ac020fb80500'), rows)
        for va in (0xb7192c, 0xb71952, 0xb4a81c, 0xb4a82d, 0xb4a6bc, 0xb4a6ce):
            with self.subTest(va=hex(va)):
                at = self.image.where(va, 1)[1]
                with self.changed(at, bytes([self.data[at] ^ 1])):
                    with self.assertRaises(ValueError):
                        p.processing_lsda_rows(self.image, self.functions)

    def test_signed_minimum_sentinel_boundaries(self):
        # For the pinned zero-minus-memory CMP, x86 overflow is set only for
        # the minimum signed word. This models the arithmetic, not execution.
        def zero_sub_overflow(word):
            mask = (1 << 64) - 1
            result = (-word) & mask
            return bool((word & result) & (1 << 63))
        for word in (0, 1, (1 << 63) - 1, 1 << 63, (1 << 63) + 1, (1 << 64) - 1):
            self.assertEqual(zero_sub_overflow(word), word == 1 << 63)
        row = next(row for row in p.DECISIONS if row[0] == 'replace_old_min_sentinel')
        self.assertEqual(p.decision_row(self.image, *row)[-1], '0x4527b80')

    def test_worker_literals_and_lengths(self):
        rows = p.literal_rows(self.image, self.refs, self.values)
        self.assertEqual([(r[0], r[-1]) for r in rows], [
            ('slow_block', 'slow abci block'),
            ('slow_state_driver', 'node slow abci_state driver'),
            ('spawn_failure', 'failed to spawn thread')])
        for row in rows:
            at = int(row[2], 16)
            with self.changed(at, bytes([self.data[at] ^ 1])):
                with self.assertRaises(p.EvidenceError):
                    p.literal_rows(self.image, self.refs, self.values)
        with self.assertRaises(p.EvidenceError):
            p.literal_rows(self.image, self.refs, dict(self.values, slow_driver_name_length=28))

    def test_worker_lsda_and_mutations(self):
        rows, details = p.worker_lsda_rows(self.image, self.worker)
        self.assertEqual(len(rows), 8)
        selected = next(r for r in rows if r['start'] <= 0x433a493 < r['end'])
        self.assertEqual((selected['start'], selected['end'], selected['landing'], selected['action']),
                         (0x433a48e, 0x433a499, 0x433a586, 7))
        self.assertEqual((details['worker_call_action_bytes'], details['worker_call_type_filter'],
                          details['worker_call_next_action'], details['worker_call_type_entry_bytes']),
                         ('0100', 1, 0, '00000000'))
        for va in (0xb29cb0, 0xb29cc3, 0xb29cc5, 0xb29ce9, 0xb29cec):
            with self.subTest(va=hex(va)):
                at = self.image.where(va, 1)[1]
                with self.changed(at, bytes([self.data[at] ^ 1])):
                    with self.assertRaises(ValueError):
                        p.worker_lsda_rows(self.image, self.worker)

    def test_pthread_result_model_boundaries(self):
        self.assertEqual(self.values['pthread_error_shift'], 32)
        self.assertEqual(self.values['pthread_error_tag'], 2)
        self.assertEqual(p.pthread_result(0, 0), (0, 0))
        self.assertEqual(p.pthread_result(0, 0xffffffffffffffff), (0, 0xffffffffffffffff))
        self.assertEqual(p.pthread_result(11, 5), (1, 0x0000000b00000002))
        self.assertEqual(p.pthread_result(0xffffffff, 5), (1, 0xffffffff00000002))
        for error, handle in ((-1, 0), (1 << 32, 0), (0, -1), (0, 1 << 64)):
            with self.assertRaises(p.EvidenceError):
                p.pthread_result(error, handle)

    def test_spawn_failure_and_success_signatures(self):
        self.assertEqual(int(p.branch_row(self.image, 0x474af2e, '0f84cf000000')[-1], 16), 0x474b003)
        self.assertEqual(int(p.branch_row(self.image, 0x4ee4b93, '741d')[-1], 16), 0x4ee4bb2)
        self.assertEqual(self.image.read(0x4ee4ba3, 8), bytes.fromhex('49c1e6204983ce02'))
        self.assertEqual(self.image.read(0x474b045, 2), bytes.fromhex('0f0b'))

    def test_file_mapping_rejects_nobits_ambiguity_and_bad_ranges(self):
        data = b'\x00' * 32
        section = {'type': 1, 'flags': 2, 'address': 0x1000, 'size': 16, 'offset': 0}
        self.assertEqual(p.map_file(data, [section], 0x1004, 4)[1], 4)
        nobits = dict(section, type=8)
        for secs, va, size in (([nobits], 0x1000, 1), ([section, dict(section)], 0x1000, 1),
                               ([section], 0xfff, 1), ([section], 0x100f, 2),
                               ([section], 0x1000, 0), ([section], -1, 1),
                               ([section], (1 << 64) - 1, 2)):
            with self.subTest(va=va, size=size, sections=len(secs)):
                with self.assertRaises(p.EvidenceError):
                    p.map_file(data, secs, va, size)


if __name__ == '__main__':
    unittest.main()
