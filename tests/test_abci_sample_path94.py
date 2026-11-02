"""Target-backed and negative controls for the selected ABCI sample path."""
import contextlib
import csv
import hashlib
import io
import mmap
import struct
import unittest

from tools import abci_sample_path94 as subject


class SamplePathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = subject.BINARY.open('rb')
        cls.image_bytes = mmap.mmap(cls.source.fileno(), 0, access=mmap.ACCESS_COPY)
        cls.image = subject.Image(cls.image_bytes)

    @classmethod
    def tearDownClass(cls):
        cls.image_bytes.close()
        cls.source.close()

    @contextlib.contextmanager
    def change(self, offset, replacement):
        saved = self.image_bytes[offset:offset + len(replacement)]
        self.image_bytes[offset:offset + len(replacement)] = replacement
        self.image._rels = None
        try:
            yield
        finally:
            self.image_bytes[offset:offset + len(saved)] = saved
            self.image._rels = None

    def mutation_at_va(self, va, size=1, position=0):
        _, offset, raw = self.image.read(va, size)
        altered = bytes([raw[position] ^ 1])
        return self.change(offset + position, altered)

    def test_digest_matches_artifact(self):
        self.assertEqual(hashlib.sha256(self.image_bytes).hexdigest(),
                         '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f')
        self.assertEqual(subject.Image(self.image_bytes).fde(0x4523150)['end'], 0x45234de)

    def test_reject_corrupt_digest_before_parsing(self):
        with self.change(0, b'X'):
            with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
                subject.Image(self.image_bytes)

    def test_all_selected_fde_and_boundary_pins_reject_corruption(self):
        targets = [(name, addr) for name, addr in subject.FUNCTIONS]
        targets += [(name, start) for name, start, _ in subject.BOUNDARIES]
        for name, addr in targets:
            with self.subTest(name=name):
                with self.mutation_at_va(addr):
                    with self.assertRaisesRegex(ValueError, 'bytes changed'):
                        subject.pinned_windows(self.image)
        subject.pinned_windows(self.image)

    def test_missing_or_disagreeing_fde_rejected(self):
        with self.assertRaisesRegex(ValueError, 'missing or duplicate'):
            self.image.fde(0x4523151)
        original = self.image.index[0x4523150]
        self.image.index[0x4523150] ^= 4
        try:
            with self.assertRaisesRegex(ValueError, 'index disagree'):
                self.image.fde(0x4523150)
        finally:
            self.image.index[0x4523150] = original

    def test_nobits_unmapped_and_ambiguous_ranges_rejected(self):
        with self.assertRaises(ValueError):
            self.image.read((1 << 64) - 1, 8)
        bss = dict(name='.bss', type=8, flags=3, address=0x1000, offset=0, size=64)
        with self.assertRaises(ValueError):
            subject.unique_mapping([bss], 0x1000, 8)
        file_section = dict(name='.data', type=1, flags=3, address=0x1000, offset=64, size=64)
        with self.assertRaises(ValueError):
            subject.unique_mapping([file_section, dict(file_section)], 0x1000, 8)
        with self.assertRaises(ValueError):
            subject.unique_mapping([file_section], 0x103f, 2)
        with self.assertRaises(ValueError):
            subject.unique_mapping([file_section], 0x1000, 0)

    def test_each_selected_branch_opcode_and_displacement_corruption(self):
        for name, _, branch in subject.DECISIONS:
            with self.subTest(name=name, kind='opcode'):
                _, offset, head = self.image.read(branch, 2, executable=True)
                with self.change(offset, b'\x90'):
                    with self.assertRaises(ValueError):
                        subject.decode_branch(self.image, branch)
            with self.subTest(name=name, kind='displacement'):
                _, raw, _, _, _, _ = subject.decode_branch(self.image, branch)
                with self.mutation_at_va(branch, len(raw), len(raw) - 1):
                    with self.assertRaisesRegex(ValueError, 'bytes changed'):
                        subject.pinned_windows(self.image)

    def test_selected_edge_destinations_and_relocation(self):
        rows = subject.edge_rows(self.image)
        by_name = {row[0]: row for row in rows}
        self.assertEqual(by_name['startup_to_save_boundary'][5:7], ('0x5773b68', '0x474ba90'))
        self.assertEqual(by_name['callback_to_prior_loop'][5:7], ('0x5776608', '0x432e930'))
        self.assertEqual(by_name['line_to_existing_sink'][6], '0x13d12a0')
        self.assertEqual(by_name['lag_adapter_tail'][4:7], ('jump_rel32', '', '0x4a7c270'))

    def test_branch_and_call_target_changes_rejected(self):
        _, off, raw = self.image.read(0x45b59b4, 5, executable=True)
        with self.change(off + 1, bytes([raw[1] ^ 1])):
            with self.assertRaisesRegex(ValueError, 'target changed'):
                subject.edge_rows(self.image)
        _, off, raw = self.image.read(0x46a913f, 7, executable=True)
        with self.change(off + 3, bytes([raw[3] ^ 1])):
            with self.assertRaisesRegex(ValueError, 'reference target changed'):
                subject.reference_rows(self.image)

    def test_relocation_type_symbol_target_and_duplicate_controls(self):
        slot = 0x5773b68
        typ, symbol, addend, _, record_offset = self.image.relative_reloc(slot)
        self.assertEqual((typ, symbol, addend), (8, 0, 0x474ba90))
        _, info = struct.unpack_from('<QQ', self.image_bytes, record_offset)
        for replacement in (info ^ 1, info | (1 << 32)):
            with self.subTest(info=replacement):
                with self.change(record_offset + 8, struct.pack('<Q', replacement)):
                    with self.assertRaises(ValueError):
                        self.image.relative_reloc(slot)
        with self.change(record_offset + 16, struct.pack('<q', addend + 1)):
            with self.assertRaisesRegex(ValueError, 'target changed'):
                subject.edge_rows(self.image)
        self.image.relocations()
        previous = self.image._rels[slot]
        self.image._rels[slot] = previous + previous
        try:
            with self.assertRaisesRegex(ValueError, 'duplicate'):
                self.image.relative_reloc(slot)
        finally:
            self.image._rels = None

    def test_descriptor_matches_callback_and_rejects_size_corruption(self):
        descriptor = subject.descriptor_rows(self.image)
        self.assertEqual([r[6] for r in descriptor], ['0x0', '0x30', '0x8', '0x0'])
        self.assertEqual(descriptor[0][9], '0x4341050')
        self.assertEqual(descriptor[3][9], '0x433a7c0')
        with self.mutation_at_va(0x571cb50):
            with self.assertRaisesRegex(ValueError, 'size or alignment changed'):
                subject.descriptor_rows(self.image)

    def test_field_order_offsets_and_pinned_text(self):
        fields = subject.field_rows(self.image)
        self.assertEqual([(r[12], r[4]) for r in fields], [
            ('initial_height', 0x20), ('height', 0x28), ('scheduled_freeze_height', 0),
            ('consensus_time', 0x30), ('wall_clock_time', 0x3c), ('reference_lag', 0x10)])
        self.assertEqual(fields[2][-1], '0x4a9b850')
        self.assertEqual(fields[5][-1], '0x4a7c270')
        with self.mutation_at_va(0x701e1d):
            with self.assertRaisesRegex(ValueError, 'selected field changed'):
                subject.field_rows(self.image)

    def test_three_sample_routes_use_matching_exchange_offsets(self):
        rows = {r[0]: r[5] for r in subject.operand_rows(self.image)}
        base = rows['sample_state_offset']
        for suffix in ('initial', 'height', 'freeze_tag', 'freeze_value', 'time_head', 'time_tail'):
            self.assertEqual(rows['null_callback_' + suffix], rows['other_callback_' + suffix])
        for source, suffix in (('sample_initial_source', 'initial'),
                               ('sample_height_source', 'height'),
                               ('sample_freeze_source', 'freeze_tag'),
                               ('sample_time_head_source', 'time_head'),
                               ('sample_time_tail_source', 'time_tail')):
            self.assertEqual(rows[source] - base, rows['null_callback_' + suffix])
        self.assertEqual(rows['null_callback_freeze_value'], 0xb98)
        self.assertEqual(rows['sample_lag_zero_stack'] - rows['sample_freeze_stack'], 0x10)
        self.assertEqual(rows['sample_initial_stack'] - rows['sample_freeze_stack'], 0x20)
        self.assertEqual(rows['sample_height_stack'] - rows['sample_freeze_stack'], 0x28)
        self.assertEqual(rows['sample_last_output'] + 8, 72)

    def test_queue_entry_layout_and_ticket_boundaries(self):
        for index in range(63):
            self.assertEqual(subject.queue_slot_layout(self.image, index),
                             (8 + 24 * index, 16 + 24 * index, 24 + 24 * index))
        for ticket, outcome in ((0, ('normal', 0)), (122, ('normal', 61)),
                                (124, ('rotate', 62)), (126, ('retry', 63)),
                                (128, ('normal', 0))):
            self.assertEqual(subject.queue_ticket_case(self.image, ticket), outcome)
        for index in (-1, 63, True):
            with self.assertRaises(ValueError):
                subject.queue_slot_layout(self.image, index)
        for ticket in (-1, 1 << 64, True):
            with self.assertRaises(ValueError):
                subject.queue_ticket_case(self.image, ticket)
        with self.mutation_at_va(0x4e19da7):
            with self.assertRaisesRegex(ValueError, 'stride'):
                subject.queue_slot_layout(self.image, 0)

    def test_queue_publishes_and_invokes_callback_context_pair(self):
        expected = ((0x4e19db2, '488b4c240849894cc708'),
                    (0x4e19dbc, '488b4c241049894cc710'),
                    (0x4e19dc6, 'f049834cc71801'),
                    (0x4e19f5a, '4b8d04644d8d3cc64983c708498b44c618'),
                    (0x4e19fba, '410f1007'),
                    (0x4e1a044, '0f114308b801000000'),
                    (0x4e15bff, '4c8b7c2448488b6c2450'),
                    (0x4e15cdc, '4889ef41ffd7'))
        for va, encoded in expected:
            raw = bytes.fromhex(encoded)
            self.assertEqual(self.image.read(va, len(raw), executable=True)[2], raw)
        rows = {row[0]: row for row in subject.edge_rows(self.image)}
        self.assertEqual(rows['queue_run_to_pop'][6], '0x4e19e50')
        self.assertEqual(rows['queue_run_to_callback'][4:7], ('call_reg_r15', '', ''))
        operands = {row[0]: row[5] for row in subject.operand_rows(self.image)}
        self.assertEqual(operands['queue_push_tail'], operands['queue_pop_tail'])
        self.assertEqual(operands['queue_run_owner'], 0x110)
        adjust = struct.unpack('<b', bytes([operands['queue_run_negated_adjust']]))[0]
        self.assertEqual(-adjust, operands['sample_queue_adjust'])

    def test_decimal_formatter_u64_boundaries_and_table_corruption(self):
        formatter = subject.DecimalModel(self.image)
        self.assertEqual([formatter.digits[2 * i:2 * i + 2] for i in range(100)],
                         [f'{i:02}'.encode('ascii') for i in range(100)])
        values = list(range(10000))
        for exponent in range(1, 20):
            pivot = 10 ** exponent
            values.extend(value for value in (pivot - 1, pivot, pivot + 1) if value < 1 << 64)
        values.extend((0xffffffffffffffff, 0xfffffffffffffffe))
        state = 0x8598acfc7c9e7d6b
        for _ in range(10000):
            state = (state * 6364136223846793005 + 1442695040888963407) & ((1 << 64) - 1)
            values.append(state)
        for value in values:
            self.assertEqual(formatter.format(value), str(value).encode('ascii'), value)
        for value in (-1, 1 << 64, True):
            with self.assertRaises(ValueError):
                formatter.format(value)
        with self.mutation_at_va(0x704d88):
            with self.assertRaisesRegex(ValueError, 'digit table changed'):
                subject.DecimalModel(self.image)

    def test_stack_argument_and_closure_layout(self):
        rows = {r[0]: r[5] for r in subject.operand_rows(self.image)}
        self.assertEqual(rows['slow_worker_parent_field'], rows['save_worker_parent_field'])
        self.assertEqual(rows['builder_stack_argument'], rows['builder_frame_size'] + 6 * 8 + 8)
        self.assertEqual(rows['builder_payload_argument'] - rows['builder_payload_load']
                         + rows['builder_payload_store'], rows['callback_payload_field'])
        self.assertEqual(rows['builder_closure_size'], 0x30)
        self.assertEqual(self.image.read(0x474bbe7, 4, executable=True)[2], b'\x48\x89\x1c\x24')

    def test_conditional_constructor_return_parent_slot_arithmetic(self):
        rows = {r[0]: r[5] for r in subject.operand_rows(self.image)}
        self.assertEqual(rows['constructor_return_allocation'], 0x4170)
        self.assertEqual(rows['constructor_return_saved'], rows['constructor_return_reloaded'])
        relative = rows['constructor_parent_slot'] - rows['constructor_parent_address']
        self.assertEqual(relative, 0x668)
        self.assertLessEqual(relative + 8, rows['constructor_parent_size'])
        self.assertEqual(rows['constructor_parent_size'], rows['outer_parent_size'])
        self.assertEqual(rows['outer_parent_address'] + relative,
                         rows['save_worker_parent_field'])

    def test_acquire_lock_boundaries_and_cas_failure(self):
        case = lambda word, cas: subject.read_lock_case(self.image, word, cas)
        self.assertEqual(case(0, True), ('fast', 16))
        self.assertEqual(case(7, True), ('fast', 23))
        self.assertEqual(case(8, True), ('slow', 8))
        self.assertEqual(case(0, False), ('slow', 0))
        self.assertEqual(case(0xffffffffffffffe7, True), ('fast', 0xfffffffffffffff7))
        self.assertEqual(case(0xfffffffffffffff0, True), ('slow', 0xfffffffffffffff0))
        for bad in (-1, 1 << 64, True):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                case(bad, True)
        with self.assertRaises(ValueError):
            case(0, 1)

    def test_release_lock_wake_mask(self):
        self.assertTrue(subject.release_wakes(self.image, 0x12))
        self.assertTrue(subject.release_wakes(self.image, 0x13))
        self.assertFalse(subject.release_wakes(self.image, 0x10))
        self.assertFalse(subject.release_wakes(self.image, 0x22))
        with self.assertRaises(ValueError):
            subject.release_wakes(self.image, -1)

    def test_freeze_option_raw_low_bit_not_discriminant_equality(self):
        for tag, kind in ((0, 'null'), (1, 'number'), (2, 'null'), (3, 'number'),
                          (0xffffffffffffffff, 'number')):
            with self.subTest(tag=tag):
                self.assertEqual(subject.freeze_case(self.image, tag), kind)
        with self.assertRaises(ValueError):
            subject.freeze_case(self.image, 1 << 64)
        with self.mutation_at_va(0x4a9b906):
            with self.assertRaises(ValueError):
                subject.freeze_case(self.image, 1)

    def test_lag_ieee754_finite_and_nonfinite_controls(self):
        for bits in (0, 0x8000000000000000, 0x3ff0000000000000,
                     0x7fefffffffffffff, 0xffefffffffffffff):
            with self.subTest(bits=bits):
                self.assertEqual(subject.lag_case(self.image, 1, bits), 'number')
                self.assertEqual(subject.lag_case(self.image, 0, bits), 'null')
        for bits in (0x7ff0000000000000, 0xfff0000000000000,
                     0x7ff8000000000000, 0xfff0000000000001):
            with self.subTest(bits=bits):
                self.assertEqual(subject.lag_case(self.image, 1, bits), 'null')
        self.assertEqual(subject.lag_case(self.image, 2, 0), 'null')
        self.assertEqual(subject.lag_case(self.image, 3, 0), 'number')
        for bad in (-1, 1 << 64):
            with self.assertRaises(ValueError):
                subject.lag_case(self.image, 1, bad)

    def test_literal_and_punctuation_bytes(self):
        literals = {r[0]: r[-1] for r in subject.literal_rows(self.image)}
        self.assertEqual(literals['thread_label'], 'node save visor_abci_state')
        self.assertEqual(literals['spawn_failure'], 'failed to spawn thread')
        self.assertEqual(literals['closing_brace'], '}')
        for va, expected in ((0x45b5950, b'\xc6\x00['),
                             (0x45b59a0, b'\xc6\x04\x30,'),
                             (0x45b5a02, b'\xc6\x04\x30]'),
                             (0x45b5a3b, b'\x41\xc6\x04\x07\x0a'),
                             (0x48fe6d0, b'\xc6\x04\x01{'),
                             (0x4a9b95b, b'\xc7\x04\x30null')):
            self.assertEqual(self.image.read(va, len(expected), executable=True)[2], expected)

    def test_lsda_sample_release_and_writer_cleanup_are_covered(self):
        fdes = [(name, self.image.fde(start)) for name, start in subject.FUNCTIONS]
        rows = subject.lsda_rows(self.image, fdes)
        def covering(name, addr):
            return [r for r in rows if r[0] == name and int(r[3], 16) <= addr < int(r[4], 16)]
        self.assertEqual(covering('sample_guard', 0x4523454)[0][5], '0x4523478')
        self.assertEqual(covering('sample_guard', 0x452346e)[0][5], '0x4523478')
        self.assertEqual(covering('line_writer', 0x45b59b4)[0][5], '0x45b5aec')
        self.assertEqual(covering('thread_callback', 0x433a81f)[0][5], '0x433a827')
        sample = self.image.fde(0x4523150)
        _, offset, raw = self.image.read(sample['lsda'], 1)
        with self.change(offset, bytes([raw[0] ^ 1])):
            with self.assertRaisesRegex(ValueError, 'LSDA landing'):
                subject.lsda_rows(self.image, [('sample_guard', sample)])

    def test_output_set_summary_and_no_missing_evidence(self):
        output = subject.generate(self.image_bytes)
        self.assertEqual(set(output), set(subject.OUTPUTS))
        self.assertTrue(all(data.endswith(b'\n') for data in output.values()))
        fields = list(csv.DictReader(io.StringIO(output['fields.tsv'].decode()), delimiter='\t'))
        self.assertEqual(len(fields), 6)
        self.assertEqual(fields[-1]['name_text'], 'reference_lag')


if __name__ == '__main__':
    unittest.main()
