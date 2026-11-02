"""Static boundary and negative controls for the node 115 freeze-state packet."""
import json
import contextlib
import io
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import abci_freeze_snapshot115 as packet
import elf_index


class TargetEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = packet.TARGET.read_bytes()
        cls.evidence = packet.build_evidence(cls.data)
        cls.sections = elf_index.sections(cls.data)
        cls.relocations = packet.relative_relocations(cls.data, cls.sections)
        cls.constants = cls.evidence['constants']

    def read(self, va, size, **kwargs):
        return packet.read_va(self.data, self.sections, va, size, **kwargs)

    def test_digest_is_authenticated_and_bad_inputs_rejected(self):
        self.assertEqual(packet.digest(self.data), packet.SHA115)
        packet.authenticate(self.data)
        for bad in (b'', b'not the node', self.data[:4096]):
            with self.subTest(size=len(bad)):
                with self.assertRaisesRegex(ValueError, 'SHA-256'):
                    packet.authenticate(bad)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            packet.authenticate(self.data, packet.SHA94)

    def test_bad_digest_creates_no_evidence_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bad = root / 'bad-node'
            bad.write_bytes(b'not the expected executable')
            output = root / 'evidence'
            with mock.patch.object(packet, 'TARGET', bad), \
                 mock.patch.object(sys, 'argv', ['extractor', '--out', str(output)]), \
                 contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(ValueError, 'SHA-256'):
                    packet.main()
            self.assertFalse(output.exists())

    def test_selected_frame_ranges_reconcile_with_unwind_index(self):
        frames = self.evidence['frames']
        self.assertEqual(len(frames), len(packet.FUNCTIONS))
        for f in frames:
            self.assertEqual(packet.containing_frame(frames, f['start'], 1), f)
            self.assertEqual(packet.containing_frame(frames, f['end'] - 1, 1), f)
            self.assertEqual(packet.digest(self.data[f['offset']:f['offset'] +
                                                     f['end'] - f['start']]), f['sha256'])
        f = frames[0]
        with self.assertRaises(ValueError):
            packet.containing_frame([f], f['end'], 1)
        with self.assertRaises(ValueError):
            packet.containing_frame([f, f], f['start'], 1)

    def test_file_backed_address_boundaries_and_nobits(self):
        frames = self.evidence['frames']
        self.assertEqual(packet.mapping(self.sections, frames[0]['start'], 1, executable=True),
                         frames[0]['offset'])
        for address, size in ((-1, 1), (0, 0), (1 << 63, 1)):
            with self.subTest(address=address, size=size):
                with self.assertRaises(ValueError):
                    packet.mapping(self.sections, address, size, executable=True)
        nobits = [dict(type=8, flags=6, address=100, size=4, offset=1)]
        with self.assertRaises(ValueError):
            packet.mapping(nobits, 100, 1)
        filebacked = [dict(type=1, flags=6, address=100, size=4, offset=1)]
        self.assertEqual(packet.mapping(filebacked, 103, 1), 4)
        with self.assertRaises(ValueError):
            packet.mapping(filebacked, 103, 2)
        with self.assertRaises(ValueError):
            packet.mapping(filebacked * 2, 100, 1)

    def test_every_checked_window_rejects_a_changed_byte(self):
        self.assertEqual(len(self.evidence['windows']), len(packet.WINDOWS))
        for spec in packet.WINDOWS:
            name, va, size, _ = spec
            original = self.read(va, size, executable=True)
            damaged = bytearray(original)
            damaged[len(damaged) // 2] ^= 0x01
            with self.subTest(window=name):
                with mock.patch.object(packet, 'read_va', return_value=bytes(damaged)):
                    with self.assertRaisesRegex(ValueError, 'window changed'):
                        packet.verify_window(self.data, self.sections, spec)

    def test_selected_transfer_decoding_and_corruption(self):
        self.assertEqual(len(self.evidence['edges']), len(packet.EDGES))
        for edge in self.evidence['edges']:
            kind, size, target = packet.decode_transfer(bytes.fromhex(edge['raw']), edge['va'])
            self.assertEqual((kind, size, target),
                             (edge['kind'], len(bytes.fromhex(edge['raw'])), edge['target']))
            broken = bytearray.fromhex(edge['raw'])
            broken[-1] ^= 1
            with self.subTest(edge=edge['label']):
                with self.assertRaisesRegex(ValueError, 'destination changed'):
                    packet.decode_transfer(broken, edge['va'], edge['target'])
        for raw in (b'', b'\xe8', b'\x90\x90', b'\x0f\x80\x00'):
            with self.subTest(raw=raw.hex()):
                with self.assertRaises(ValueError):
                    packet.decode_transfer(raw, 0x100)

    def test_locations_and_relocation_controls(self):
        locs = self.evidence['locations']
        self.assertEqual([(x['line'], x['column']) for x in locs],
                         [(201, 9), (201, 32), (193, 56), (195, 17), (195, 64)])
        slot = locs[0]['va']
        current = self.relocations[slot][0]
        for altered in ([], [current, current], [(1, current[1], current[2], current[3])],
                        [(8, 1, current[2], current[3])]):
            with self.subTest(relocations=altered):
                with self.assertRaises(ValueError):
                    packet.location(self.data, self.sections, {slot: altered}, slot)
        original = packet.read_va
        def corrupt_location(data, secs, va, size, **kwargs):
            raw = original(data, secs, va, size, **kwargs)
            if va == slot and size == 24:
                raw = raw[:8] + struct.pack('<Q', 0) + raw[16:]
            return raw
        with mock.patch.object(packet, 'read_va', side_effect=corrupt_location):
            with self.assertRaisesRegex(ValueError, 'malformed Location'):
                packet.location(self.data, self.sections, self.relocations, slot)

    def test_root_capture_shape_and_descriptor_are_connected(self):
        captures, root = self.evidence['captures'], self.evidence['root_info']
        self.assertEqual((len(captures), root['descriptor_count'], root['slot_size']), (74, 59, 24))
        selected = captures[root['selected_capture_index']]
        self.assertEqual((selected['state_offset'], selected['stack_offset']), (0x10e8, 0x208))
        self.assertEqual(selected['stack_offset'] - root['capture_stack_base'],
                         root['descriptor_input_offset'])
        self.assertEqual(root['descriptor_index'], 13)
        self.assertEqual(root['allocation_bytes'], 59 * 24)
        self.assertEqual(root['slot_offsets'], list(range(0, 59 * 24, 24)))
        self.assertEqual(root['table']['words'], [0, 16, 8, 0, 0])
        self.assertEqual([r['addend'] for r in root['table']['relocations']],
                         [0x22a0fa0, 0x22a0b60])
        self.assertEqual(root['visitor_one']['hex'], '0100000000000000')
        self.assertEqual(root['visitor_zero']['hex'], '0000000000000000')
        self.assertEqual(root['visitor_constructor_bytes'], 2 * root['slot_size'])

    def test_capture_pair_decoder_rejects_damage_and_missing_slot(self):
        start = 0x269a1ed
        raw = self.read(start, 30, executable=True)
        rows = packet.decode_capture_pairs(raw, start, 0x138)
        self.assertEqual([r['stack_offset'] for r in rows], [0x138, 0x140])
        for index in (0, 7, 11, 15, 22, 26):
            damaged = bytearray(raw)
            damaged[index] ^= 1
            with self.subTest(index=index):
                with self.assertRaises(ValueError):
                    packet.decode_capture_pairs(damaged, start, 0x138)
        with self.assertRaises(ValueError):
            packet.decode_capture_pairs(raw[:-1], start, 0x138)

    def test_slot_decoder_rejects_changed_offsets_opcodes_and_truncation(self):
        start, end = 0x269a643, 0x269a7cd
        raw = self.read(start, end - start, executable=True)
        self.assertEqual(packet.decode_slot_stores(raw), list(range(0, 59 * 24, 24)))
        for index in (0, 3, 6, len(raw) - 1):
            damaged = bytearray(raw)
            damaged[index] ^= 1
            with self.subTest(index=index):
                with self.assertRaises(ValueError):
                    packet.decode_slot_stores(damaged)
        with self.assertRaises(ValueError):
            packet.decode_slot_stores(raw[:-1])

    def test_root_descriptor_rejects_wrong_or_duplicate_relocation(self):
        root = self.evidence['root_info']
        slot = root['table']['relocations'][0]['slot']
        old = self.relocations[slot][0]
        for changed in ([], [old, old], [(old[0], old[1], old[2] + 1, old[3])],
                        [(old[0] + 1, old[1], old[2], old[3])]):
            relocs = dict(self.relocations)
            relocs[slot] = changed
            with self.subTest(relocations=changed):
                with self.assertRaises(ValueError):
                    packet.root_capture_evidence(self.data, self.sections, relocs, self.constants)

    def test_root_descriptor_and_mutation_operands_reject_corruption(self):
        original = packet.read_va
        for site, method in ((0x2b7f702, 'root'), (0x644b4b0, 'root'),
                             (0x22a0fb3, 'constants'), (0x2d25960, 'mutations')):
            def corrupt(data, secs, va, size, **kwargs):
                raw = original(data, secs, va, size, **kwargs)
                if va == site:
                    raw = bytes([raw[0] ^ 1]) + raw[1:]
                return raw
            with self.subTest(site=hex(site)):
                with mock.patch.object(packet, 'read_va', side_effect=corrupt):
                    with self.assertRaises(ValueError):
                        if method == 'root':
                            packet.root_capture_evidence(self.data, self.sections, self.relocations,
                                                         self.constants)
                        elif method == 'constants':
                            packet.extract_constants(self.data, self.sections)
                        else:
                            packet.context_mutations(self.data, self.sections)

    def test_context_writes_are_separate_guarded_paths(self):
        changes = self.evidence['mutations']
        self.assertEqual([(x['context_offset'], x['size'], x['value'])
                          for x in changes['small_sentinel_path']],
                         [(0x408, 8, 0), (0x418, 8, 0)])
        self.assertEqual([(x['context_offset'], x['size'], x['value'])
                          for x in changes['replacement_path']],
                         [(0x400, 8, 0), (0x408, 8, 8), (0x410, 16, 0)])
        self.assertEqual((changes['sentinel'], changes['small_limit_exclusive'],
                          changes['replacement_limit_inclusive']), (1 << 63, 32, 64))

    def test_context_write_guard_neighbors(self):
        c = self.evidence['mutations']
        sentinel = c['sentinel']
        cases = [(sentinel, 31, 0, 'small_sentinel_stores'),
                 (sentinel, 32, 1, 'other_or_unresolved'),
                 (sentinel, 64, 1, 'other_or_unresolved'),
                 (0, 63, 1, 'other_or_unresolved'),
                 (0, 64, 0, 'other_or_unresolved'),
                 (0, 64, 1, 'replacement_stores')]
        for header, count, lookup, expected in cases:
            with self.subTest(header=header, count=count, lookup=lookup):
                self.assertEqual(packet.mutation_choice(header, count, lookup, c), expected)
        with self.assertRaises(ValueError):
            packet.mutation_choice(0, -1, 1, c)

    def test_upper_pointer_and_result_joins(self):
        upper = self.evidence['upper']
        self.assertEqual(upper['input_state_pointer_offset'], 0x360)
        self.assertEqual(upper['constructor_input_pointer_offset'], 0x420)
        self.assertEqual(upper['context_state_offset'], 0x450)
        self.assertEqual(upper['context_stack'] + upper['context_state_offset'],
                         upper['context_state_stack'])
        self.assertEqual(upper['constructor_context_copy_size'], 0x450)
        self.assertEqual(upper['constructor_return_copy_size'], 0x470)
        self.assertEqual(upper['end_result_stack'] - upper['result_stack'], 0x78)
        self.assertEqual(upper['change_byte_offset'], 0xf8)
        self.assertEqual(upper['external_copy']['symbol_name'], 'memcpy')
        self.assertEqual(upper['external_copy']['relocation_type'], 6)

    def test_upper_pointer_copy_and_symbol_controls(self):
        original = packet.read_va
        for site in (0x2b1e18c, 0x2b1e1bf, 0x2d275e2, 0x2d27612, 0x2b1e3d0,
                     0x2d24fea):
            def corrupt(data, secs, va, size, **kwargs):
                raw = original(data, secs, va, size, **kwargs)
                if va == site:
                    raw = raw[:-1] + bytes([raw[-1] ^ 1])
                return raw
            with self.subTest(site=hex(site)):
                with mock.patch.object(packet, 'read_va', side_effect=corrupt):
                    with self.assertRaises(ValueError):
                        packet.upper_join_evidence(self.data, self.sections, self.relocations)
        slot = self.evidence['upper']['external_copy']['slot']
        original_row = self.relocations[slot][0]
        for changed in ([], [original_row, original_row],
                        [(8, original_row[1], 0, original_row[3])],
                        [(6, 0, 0, original_row[3])],
                        [(6, 8, 0, original_row[3])]):
            relocs = dict(self.relocations)
            relocs[slot] = changed
            with self.subTest(relocations=changed):
                with self.assertRaises(ValueError):
                    packet.upper_join_evidence(self.data, self.sections, relocs)

    def test_task_construction_maps_input_to_dispatch_object(self):
        task, upper = self.evidence['task'], self.evidence['upper']
        self.assertEqual(task['input_state_pointer_offset'], 0x320)
        self.assertEqual(task['task_state_pointer_offset'], upper['input_state_pointer_offset'])
        self.assertEqual(task['vtable_pointer_offset'], 0x10)
        self.assertEqual(task['final_copy']['size'], 0x400)
        self.assertEqual(task['dispatch_slot']['type'], 8)
        self.assertEqual(task['dispatch_slot']['addend'], 0x2b1df60)

    def test_task_construction_rejects_copy_and_dispatch_damage(self):
        original = packet.read_va
        upper = self.evidence['upper']
        for site in (0x2b3ac28, 0x2b3ac3c, 0x2b3ac5e, 0x2b3ac9a,
                     0x2b3aca2, 0x2b3ad1d):
            def corrupt(data, secs, va, size, **kwargs):
                raw = original(data, secs, va, size, **kwargs)
                if va == site:
                    raw = bytes([raw[0] ^ 1]) + raw[1:]
                return raw
            with self.subTest(site=hex(site)):
                with mock.patch.object(packet, 'read_va', side_effect=corrupt):
                    with self.assertRaises(ValueError):
                        packet.task_evidence(self.data, self.sections, self.relocations, upper)
        slot = self.evidence['task']['dispatch_slot']['va']
        old = self.relocations[slot][0]
        for changed in ([], [old, old], [(8, 0, old[2] + 1, old[3])],
                        [(6, 0, old[2], old[3])]):
            relocs = dict(self.relocations)
            relocs[slot] = changed
            with self.subTest(relocations=changed):
                with self.assertRaises(ValueError):
                    packet.task_evidence(self.data, self.sections, relocs, upper)

    def test_collection_stride_and_size_witnesses(self):
        c = self.evidence['collection']
        self.assertEqual((c['reserve_element_bytes'], c['left_span_stride'],
                          c['right_span_stride'], c['output_stride']), (32, 40, 24, 64))
        self.assertEqual(c['output_byte_limit'], (1 << 63) - 8)
        self.assertEqual(c['max_output_items'], ((1 << 63) - 8) // 64)
        original = packet.read_va
        for site in (0x2ccdc37, 0x2ccdcb5, 0x26a1ebf, 0x26a1ece,
                     0x231b3d8, 0x231b3e6, 0x26a1f39):
            def corrupt(data, secs, va, size, **kwargs):
                raw = original(data, secs, va, size, **kwargs)
                if va == site:
                    raw = bytes([raw[0] ^ 1]) + raw[1:]
                return raw
            with self.subTest(site=hex(site)):
                with mock.patch.object(packet, 'read_va', side_effect=corrupt):
                    with self.assertRaises(ValueError):
                        packet.collection_evidence(self.data, self.sections)

    def test_collection_reserve_growth_and_failure_controls(self):
        self.assertEqual(packet.reserve_decision(10, 3, 7, 7), 'advance_length')
        self.assertEqual(packet.reserve_decision(10, 3, 7), 'producer_required')
        self.assertEqual(packet.reserve_decision(10, 3, 8), 'grow_required')
        self.assertEqual(packet.reserve_decision(10, 3, 8, 8, grown_capacity=20,
                                                 grown_length=3), 'advance_length')
        self.assertEqual(packet.reserve_decision(10, 3, 8, 8, grown_capacity=10,
                                                 grown_length=3), 'insufficient_capacity')
        self.assertEqual(packet.reserve_decision(3, 10, 0, 0), 'capacity_underflow')
        self.assertEqual(packet.reserve_decision(10, 3, 7, 6), 'produced_count_mismatch')
        with self.assertRaises(ValueError):
            packet.reserve_decision(10, 3, 8, grown_capacity=20)

    def test_collection_join_count_and_allocation_boundaries(self):
        c = self.evidence['collection']
        bound = c['max_output_items']
        self.assertEqual(packet.join_decision(0, 0, c), 'empty_output')
        self.assertEqual(packet.join_decision(1, 0, c), 'length_mismatch')
        self.assertEqual(packet.join_decision(bound, bound, c), 'allocation_required')
        self.assertEqual(packet.join_decision(bound + 1, bound + 1, c),
                         'allocation_size_failure')
        self.assertEqual(packet.join_decision(packet.MASK64, packet.MASK64, c),
                         'allocation_size_failure')
        with self.assertRaises(ValueError):
            packet.join_decision(-1, 0, c)

    def test_repeat_generation_same_bytes(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            packet.write_evidence(Path(a), self.evidence)
            packet.write_evidence(Path(b), self.evidence)
            first, second = Path(a), Path(b)
            names = sorted(p.name for p in first.iterdir())
            self.assertEqual(names, sorted(p.name for p in second.iterdir()))
            self.assertEqual(len(names), 16)
            for name in names:
                with self.subTest(name=name):
                    self.assertEqual((first / name).read_bytes(), (second / name).read_bytes())
            summary = json.loads((first / 'summary.json').read_text(encoding='utf-8'))
            self.assertEqual(summary['target_sha256'], packet.SHA115)
            self.assertEqual(summary['root_captures'], 74)


class SyntheticModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        data = packet.TARGET.read_bytes()
        packet.authenticate(data)
        cls.c = packet.extract_constants(data, elf_index.sections(data))

    def test_periodic_formula_matches_integer_modulus_and_wrap_boundaries(self):
        self.assertEqual((self.c['inverse'], self.c['period']), (625, 10000))
        self.assertEqual(self.c['threshold_exclusive'], packet.MASK64 // 10000 + 1)
        for height in list(range(20001)) + [packet.MASK64, packet.MASK64 - 1,
                      (packet.MASK64 // 10000) * 10000,
                      (packet.MASK64 // 10000) * 10000 - 1]:
            self.assertEqual(packet.is_periodic(height, self.c), height % 10000 == 0)
        state = 0x123456789abcdef0
        for _ in range(20000):
            state = (state * 6364136223846793005 + 1442695040888963407) & packet.MASK64
            self.assertEqual(packet.is_periodic(state, self.c), state % 10000 == 0)

    def test_entry_order_and_tag_width(self):
        examples = [(0, 1, 2, 'continue'), (1, 1, 2, 'past_failure'),
                    (1, 2, 2, 'equal_failure'), (1, 3, 2, 'continue'),
                    (0x100000001, 1, 2, 'continue')]
        for tag, target, height, result in examples:
            with self.subTest(tag=tag, target=target, height=height):
                self.assertEqual(packet.entry_decision(tag, target, height), result)

    def test_end_order_mode_snapshot_and_divisor(self):
        cases = [
            ((1, 9998, 9999, 2, 10), 'first_past_failure'),
            ((1, 9999, 10000, 2, 10), 'mode_sentinel'),
            ((1, 9999, 10000, 0, 10), 'second_past_failure'),
            ((1, 10000, 10000, 0, 10), 'write_freeze'),
            ((1, 10001, 10000, 0, 10), 'write_periodic'),
            ((0, 0, 10000, 0, 10), 'write_periodic'),
            ((1, 9999, 9999, 0, 10), 'write_freeze'),
            ((0, 0, 9999, 0, 3), 'interval_path_no_snapshot'),
            ((0, 0, 9999, 0, 10), 'skip_snapshot'),
            ((0, 0, 9999, 0, 0), 'division_by_zero'),
            ((0x100000001, 9999, 9999, 0, 10), 'write_freeze'),
            ((0, 0, 9999, 0x100000002, 0), 'mode_sentinel'),
        ]
        for args, expected in cases:
            with self.subTest(args=args):
                self.assertEqual(packet.end_decision(*args, self.c), expected)

    def test_integer_wire_boundaries_and_noncanonical_tag(self):
        vectors = [(0, '00'), (127, '7f'), (128, 'cc80'), (255, 'ccff'),
                   (256, 'cd0100'), (65535, 'cdffff'), (65536, 'ce00010000'),
                   (0xffffffff, 'ceffffffff')]
        for value, expected in vectors:
            with self.subTest(value=value):
                self.assertEqual(packet.field_bytes(1, value, self.c).hex(), expected)
        self.assertIsNone(packet.field_bytes(1, 0x100000000, self.c))
        self.assertIsNone(packet.field_bytes(1, packet.MASK64, self.c))
        self.assertEqual(packet.field_hex(1, packet.MASK64, self.c), 'unresolved')
        self.assertEqual(packet.field_bytes(0, 123, self.c).hex(), 'c0')
        self.assertEqual(packet.field_bytes(0x100000001, 123, self.c).hex(), 'c0')
        self.assertEqual(packet.root_choice(0x100000001, self.c), 'payload_then_one')
        self.assertEqual(packet.root_choice(0x100000000, self.c), 'zero_only')
        self.assertEqual(packet.entry_decision(0x100000001, 1, 2), 'continue')
        self.assertEqual(packet.end_decision(0x100000001, 1, 2, 0, 1, self.c),
                         'first_past_failure')

    def test_change_byte_canonical_and_synthetic_noncanonical_inputs(self):
        cases = [(0, 10, 0, 20, 0), (0, 10, 1, 20, 1), (1, 10, 0, 20, 1),
                 (1, 10, 1, 10, 0), (1, 10, 1, 20, 1),
                 (2, 10, 0, 20, 2), (2, 10, 2, 10, 0), (2, 10, 2, 20, 1),
                 (0x100, 10, 0, 20, 0), (0x100000001, 10, 1, 20, 1),
                 (0x100000000, 10, 0x100000000, 20, 0)]
        for old_tag, old_value, new_tag, new_value, expected in cases:
            with self.subTest(old_tag=old_tag, new_tag=new_tag):
                self.assertEqual(packet.change_byte(old_tag, old_value, new_tag, new_value), expected)

    def test_out_of_range_model_inputs_are_rejected(self):
        for invalid in (-1, packet.MASK64 + 1, True, 1.0, '1'):
            with self.subTest(value=invalid):
                for operation in (lambda: packet.is_periodic(invalid, self.c),
                                  lambda: packet.entry_decision(1, invalid, 0),
                                  lambda: packet.end_decision(1, 0, 0, invalid, 1, self.c),
                                  lambda: packet.root_choice(invalid, self.c),
                                  lambda: packet.change_byte(0, 0, invalid, 0),
                                  lambda: packet.field_bytes(1, invalid, self.c)):
                    with self.assertRaises(ValueError):
                        operation()


if __name__ == '__main__':
    unittest.main()
