"""Target-grounded and corruption controls for the node #94 handoff packet."""
from contextlib import contextmanager
import mmap
from pathlib import Path
import struct
import tempfile
import unittest

from tools import abci_fast_handoff94 as packet

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'research/work-items/RE-017-abci-fast-handoff-94'
FILES = ('fdes.tsv', 'boundaries.tsv', 'branches.tsv', 'calls.tsv',
         'relocations.tsv', 'labels.tsv', 'lsda.tsv', 'lsda-headers.tsv',
         'comparison-paths.tsv', 'summary.json')


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.file = packet.ARTIFACT.open('rb')
        cls.data = mmap.mmap(cls.file.fileno(), 0, access=mmap.ACCESS_COPY)
        packet.authenticate(cls.data)
        cls.secs, cls.index = packet.unwind_index(cls.data)
        _, cls.fdes = packet.eh_frame_records(cls.data, cls.secs)
        cls.by_start = {fde['start']: fde for fde in cls.fdes}
        cls.image = packet.Image(cls.data, cls.secs)
        cls.record = packet.inspect(cls.data)

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.file.close()

    @contextmanager
    def corrupt_offset(self, off, replacement):
        before = self.data[off:off + len(replacement)]
        self.data[off:off + len(replacement)] = replacement
        try:
            yield
        finally:
            self.data[off:off + len(before)] = before

    @contextmanager
    def corrupt_va(self, va, replacement, executable=True):
        off, _ = packet.file_offset(self.secs, len(self.data), va, len(replacement), executable)
        with self.corrupt_offset(off, replacement):
            yield

    def test_identity_and_extent_counts(self):
        self.assertEqual(packet.authenticate(self.data),
                         '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f')
        self.assertEqual(len(self.record['owned']), 9)
        self.assertEqual(len(self.record['boundaries']), 35)
        self.assertEqual(len(self.record['branches']), 74)
        self.assertEqual(len(self.record['calls']), 21)
        self.assertEqual(len(self.record['relocations']), 9)
        self.assertEqual(len(self.record['labels']), 7)
        self.assertEqual(sum(len(t['entries']) for t in self.record['lsdas']), 71)
        owned = {row['name']: row for row in self.record['owned']}
        self.assertEqual((owned['two_tree_last_words']['start'], owned['two_tree_last_words']['end']),
                         ('0x4b31790', '0x4b31a67'))
        self.assertEqual((owned['worker_constructor']['start'], owned['worker_constructor']['end']),
                         ('0x4548b40', '0x4548cb6'))

    def test_tree_input_and_constructor_register_outputs(self):
        x = self.record['layout']
        self.assertEqual(x['tree_one'], {'root': 0x28, 'depth': 0x30, 'count': 0x38})
        self.assertEqual(x['tree_two'], {'root': 0x08, 'depth': 0x10, 'count': 0x18})
        self.assertEqual((x['constructor_first_tree_word_offset'], x['constructor_second_tree_word_offset']),
                         (0x2d0, 0x2d8))
        self.assertEqual((x['constructor_tag_offset'], x['constructor_clock_marker_offset']), (0x260, 0x280))
        self.assertEqual((x['constructor_identifier_offset'], x['constructor_identifier_bytes']), (0x261, 20))
        self.assertEqual(x['constructor_float_bits'], '0x403e000000000000')
        self.assertEqual(struct.unpack('<d', struct.pack('<Q', int(x['constructor_float_bits'], 16)))[0], 30.0)

    def test_parent_and_closure_transfer_lengths(self):
        x = self.record['layout']
        self.assertEqual((x['state_copy_bytes'], x['state_body_copy_bytes']), (0x3ae8, 0x3ae0))
        self.assertEqual((x['object_copy_bytes'], x['aggregate_copy_bytes']), (0x2e0, 0x3dc0))
        self.assertEqual(x['object_stack_base'] - x['state_body_stack_base'], 0x3ae0)
        self.assertEqual((x['worker_parent_relative_offset'], x['worker_callee_relative_offset']), (0x260, 0x260))
        self.assertEqual((x['outer_parent_save_offset'], x['outer_parent_spawn_offset']), (0xe8, 0xe8))
        self.assertEqual((x['outer_parent_copy_bytes'], x['outer_spawn_copy_bytes']), (0x698, 0x698))
        self.assertEqual((x['launch_copy_bytes'], x['closure_input_copy_bytes']), (0x6f0, 0x6f0))
        self.assertEqual((x['callback_prefix_copy_bytes'], x['callback_tail_copy_bytes']), (0x10, 0x6e0))
        self.assertEqual(x['closure_bytes'], 0x718)
        self.assertEqual((x['closure_input_offset'], x['thread_stack_fallback_bytes']), (0x28, 0x200000))

    def test_closure_descriptor_relative_relocation(self):
        d = self.record['descriptor']
        self.assertEqual((d['address'], d['size'], d['alignment']), ('0x56924a8', 0x718, 8))
        self.assertEqual((d['callback_slot']['slot'], d['callback_slot']['type'],
                          d['callback_slot']['symbol_index'], d['callback_slot']['addend']),
                         ('0x56924c0', 8, 0, '0x1f9a9f0'))
        self.assertEqual(bytes.fromhex(d['bytes_before_relocation'])[:8], bytes(8))

    def test_selected_call_chain(self):
        calls = {r['name']: r for r in self.record['calls']}
        expected = {
            'two_tree_call': '0x4b31790', 'constructor_call': '0x4548b40',
            'bridge_builder': '0x1f85740',
            'closure_adapter': '0x432f5f0', 'adapter_worker_boundary': '0x474bfa0',
            'guard_update_boundary': '0x4548cc0',
            'compare_boundary': '0x4526490', 'replace_boundary': '0x4523e00',
            'list_boundary': '0x4527d40',
        }
        self.assertEqual({name: calls[name]['target'] for name in expected}, expected)
        self.assertEqual(calls['constructor_call']['slot'], '0x5773af0')
        self.assertEqual(calls['closure_adapter']['relocation']['symbol_index'], 0)

    def test_binary_pointer_length_labels(self):
        labels = {row['name']: row['text'] for row in self.record['labels']}
        self.assertEqual(labels['outer_launch_label'], 'node handle client blocks')
        self.assertEqual(labels['worker_read_label'], 'run_node_send_execution_state')
        self.assertEqual(labels['refresh_label'], 'firewall_ips_maybe_update')
        self.assertEqual(labels['compare_label'], 'check_computed_ips')
        self.assertEqual(labels['replace_label'], 'update_computed_ips')
        self.assertEqual(labels['thread_stack_setting'], 'RUST_MIN_STACK')

    def test_tree_empty_and_missing_parent_branches(self):
        branches = {r['name']: r for r in self.record['branches']}
        self.assertEqual(branches['tree_one_null_root']['target'], '0x4b318d0')
        self.assertEqual(branches['tree_one_zero_count']['target'], '0x4b318d0')
        self.assertEqual(branches['tree_two_null_root']['target'], '0x4b31a08')
        self.assertEqual(branches['tree_two_zero_count']['target'], '0x4b31a08')
        self.assertEqual(branches['tree_one_missing_parent']['target'], '0x4b31a45')
        self.assertEqual(branches['tree_two_missing_parent']['target'], '0x4b31a54')
        self.assertEqual(self.image.read(0x4b31a61, 2), bytes.fromhex('0f0b'))

    def test_update_tag_and_timer_branch_targets(self):
        branches = {r['name']: r for r in self.record['branches']}
        self.assertEqual((branches['update_tag_nonzero']['condition'], branches['update_tag_nonzero']['target']),
                         ('ne', '0x45492c6'))
        self.assertEqual((branches['timer_zero_marker']['condition'], branches['timer_zero_marker']['target']),
                         ('e', '0x4548de1'))
        self.assertEqual((branches['timer_below_or_unordered']['condition'], branches['timer_below_or_unordered']['target']),
                         ('be', '0x4548ec6'))

    def test_comparison_examples_include_short_circuit_and_noncanonical_bytes(self):
        rows = self.record['comparison_paths']
        self.assertEqual([(r['first_al'], r['second_al'], r['third_al'], r['helpers_called'],
                           r['stored_byte'], r['zero_test_would_skip_replace']) for r in rows], [
            (0, None, None, 1, 1, 0), (1, 0, None, 2, 1, 0),
            (1, 1, 0, 3, 1, 0), (1, 1, 1, 3, 0, 1),
            (1, 1, 2, 3, 3, 0), (1, 1, 255, 3, 254, 0),
        ])

    def test_guarded_offsets_and_replacement_stores(self):
        x = self.record['layout']
        self.assertEqual((x['read_lock_offset'], x['write_lock_offset']), (0x568, 0x568))
        self.assertEqual((x['read_lock_exclusion_mask'], x['read_lock_unsigned_limit']),
                         (8, '0xfffffffffffffff0'))
        self.assertEqual(x['compared_field_offsets'], [0x570, 0x588, 0x5a0])
        self.assertEqual(x['replacement_span_bytes'], 0x48)
        self.assertEqual((x['list_lock_offset'], x['list_value_offset'], x['list_deallocation_multiplier']),
                         (0x2a0, 0x2a8, 5))
        self.assertEqual((x['list_copy_bytes'], x['list_source_stride'], x['list_destination_stride']),
                         (0x20, 0x50, 5))
        self.assertEqual(self.image.read(0x4524023, 0x2a), self.image.read(0x45241cb, 0x2a))

    def test_lsda_links_drop_calls_to_exception_landings(self):
        tables = {t['function']: t['entries'] for t in self.record['lsdas']}
        rows = tables['replace_three_fields']
        def landing_for(site):
            found = [row for row in rows if int(row['start'], 16) <= site < int(row['end'], 16)]
            self.assertEqual(len(found), 1)
            return found[0]['landing_pad'], found[0]['action']
        self.assertEqual(landing_for(0x4523e4d), ('0x4524175', 0))
        self.assertEqual(landing_for(0x4523f16), ('0x45241ad', 0))
        self.assertEqual(landing_for(0x4523f96), ('0x45241a8', 0))
        self.assertEqual(landing_for(0x4524016), ('0x45241a3', 0))
        reader = tables['compare_three_fields']
        row = next(r for r in reader if int(r['start'], 16) <= 0x4526548 < int(r['end'], 16))
        self.assertEqual((row['landing_pad'], row['action']), ('0x4526697', 0))

    def test_authentication_rejects_corrupt_capture_before_output(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / 'out'
            with self.corrupt_offset(0, b'\x00'):
                with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
                    packet.generate(self.data, out)
            self.assertFalse(out.exists())

    def test_owned_body_pin_rejects_corruption(self):
        with self.corrupt_va(0x4524023, b'\x90'):
            with self.assertRaisesRegex(ValueError, 'selected FDE bytes differ'):
                packet.validate_pins(self.image, self.fdes, self.index)

    def test_boundary_pin_rejects_corruption(self):
        with self.corrupt_va(0x2278155, b'\x90'):
            with self.assertRaisesRegex(ValueError, 'boundary bytes differ'):
                packet.validate_pins(self.image, self.fdes, self.index)

    def test_literal_corruption_rejected(self):
        spec = next(row for row in packet.LABELS if row[0] == 'compare_label')
        with self.corrupt_va(0x6f6030, b'X', executable=False):
            with self.assertRaisesRegex(ValueError, 'label bytes differ'):
                packet.decode_label(self.image, spec)

    def test_malformed_branch_opcode_rejected(self):
        with self.corrupt_va(0x4526552, b'\x90'):
            with self.assertRaisesRegex(ValueError, 'unsupported branch opcode'):
                packet.decode_branch(self.image, 0x4526552)

    def test_branch_target_outside_executable_rejected(self):
        with self.corrupt_va(0x4523e44, struct.pack('<i', 0x7fffffff)):
            with self.assertRaises(ValueError):
                packet.decode_branch(self.image, 0x4523e42)

    def test_malformed_call_opcode_rejected(self):
        with self.corrupt_va(0x2236c2c, b'\x90'):
            with self.assertRaisesRegex(ValueError, 'unsupported call opcode'):
                packet.decode_call(self.image, {}, 0x2236c2c)

    def test_callback_relocation_addend_corruption_rejected(self):
        rel = self.record['descriptor']['callback_slot']
        off = int(rel['file_offset'], 16) + 16
        with self.corrupt_offset(off, struct.pack('<q', 0x1f9aa00)):
            with self.assertRaisesRegex(ValueError, 'unexpected closure descriptor relocation'):
                packet.inspect(self.data)

    def test_missing_callback_relocation_rejected(self):
        rel = self.record['descriptor']['callback_slot']
        off = int(rel['file_offset'], 16)
        with self.corrupt_offset(off, struct.pack('<Q', 0x56924c1)):
            with self.assertRaisesRegex(ValueError, 'missing relocation'):
                packet.inspect(self.data)

    def test_lsda_encoding_corruption_rejected(self):
        fde = self.by_start[0x4523e00]
        with self.corrupt_va(fde['lsda'] + 1, b'\x00', executable=False):
            with self.assertRaisesRegex(ValueError, 'unsupported LSDA type encoding'):
                packet.parse_lsda(self.image, 'replace_three_fields', fde)

    def test_lsda_well_formed_action_tamper_rejected(self):
        fde = self.by_start[0x4523e00]
        lsda = packet.parse_lsda(self.image, 'replace_three_fields', fde)
        off = int(lsda['file_offset'], 16) + lsda['size'] - 1
        with self.corrupt_offset(off, b'\x00'):
            with self.assertRaisesRegex(ValueError, 'LSDA header or call-site bytes differ'):
                packet.parse_lsda(self.image, 'replace_three_fields', fde)

    def test_fde_length_corruption_rejected(self):
        fde = self.by_start[0x4523e00]
        range_va = fde['fde'] + 12
        old = self.image.read(range_va, 4, executable=False)
        bad = struct.pack('<I', struct.unpack('<I', old)[0] + 1)
        with self.corrupt_va(range_va, bad, executable=False):
            with self.assertRaisesRegex(ValueError, 'FDE or index mismatch'):
                packet.inspect(self.data)

    def test_unwind_index_pointer_corruption_rejected(self):
        entry = next(row for row in self.index if row['start'] == 0x4523e00)
        hdr = next(sec for sec in self.secs if sec['name'] == '.eh_frame_hdr')
        off = hdr['offset'] + 12 + entry['index'] * 8 + 4
        old = struct.unpack_from('<i', self.data, off)[0]
        with self.corrupt_offset(off, struct.pack('<i', old + 1)):
            with self.assertRaisesRegex(ValueError, 'FDE or index mismatch'):
                packet.inspect(self.data)

    def test_unmapped_and_empty_ranges_rejected(self):
        for va, size in ((0xffffffffffff, 8), (0x4523e00, 0), (-1, 1)):
            with self.subTest(va=va, size=size):
                with self.assertRaises(ValueError):
                    packet.file_offset(self.secs, len(self.data), va, size, True)

    def test_nobits_section_has_no_file_backing(self):
        bss = next(sec for sec in self.secs if sec['name'] == '.bss')
        self.assertEqual(bss['type'], 8)
        with self.assertRaises(ValueError):
            packet.file_offset(self.secs, len(self.data), bss['address'], 1, False)

    def test_ambiguous_file_mappings_rejected(self):
        sec = next(sec for sec in self.secs if sec['name'] == '.text')
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            packet.file_offset([sec, dict(sec)], len(self.data), 0x4523e00, 1, True)

    def test_retained_generated_files_reproduce(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / 'generated'
            summary = packet.generate(self.data, out)
            self.assertEqual(summary['counts']['lsda_call_sites'], 71)
            self.assertEqual(sorted(p.name for p in out.iterdir()), sorted(FILES))
            for name in FILES:
                with self.subTest(file=name):
                    self.assertEqual((out / name).read_bytes(), (EVIDENCE / name).read_bytes())


if __name__ == '__main__':
    unittest.main()
