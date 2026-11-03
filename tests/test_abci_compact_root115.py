"""Target-grounded and corruption controls for the selected ABCI result path."""
import csv
import io
import json
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import abci_compact_root115 as subject


class CompactRootEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT / 'artifacts/node/115/hl-node').read_bytes()
        subject.verify_digest(cls.data)
        cls.secs = subject.sections(cls.data)
        cls.outputs = subject.generate(cls.data)

    def read(self, address, length):
        return subject.read_va(self.data, self.secs, address, length, True)

    def patched(self, address, replacement):
        def read(start, length):
            result = bytearray(self.read(start, length))
            for i, byte in enumerate(replacement):
                if start <= address + i < start + length:
                    result[address + i - start] = byte
            return bytes(result)
        return read

    @staticmethod
    def rows(data):
        return list(csv.DictReader(io.StringIO(data.decode('ascii')), delimiter='\t'))

    def test_target_digest_and_mutation(self):
        subject.verify_digest(self.data)
        altered = bytearray(self.data)
        altered[128] ^= 1
        with self.assertRaises(ValueError):
            subject.verify_digest(altered)

    def test_historical_wrong_digest_fails_before_parse(self):
        with self.assertRaises(ValueError):
            subject.validate_historical(b'not the authenticated historical node')

    def test_generated_metrics_and_target_identity(self):
        summary = json.loads(self.outputs['summary.json'])
        self.assertEqual(summary['artifact_sha256'], subject.TARGET)
        self.assertEqual(summary['new_unwind_extents'], 16)
        self.assertEqual(summary['compact_pointer_captures'], 74)
        self.assertEqual(summary['descriptor_tag_stores'], 59)
        self.assertEqual(summary['joined_result_slices'], 3)
        location = json.loads(self.outputs['location.json'])
        self.assertEqual((location['name'], location['line'], location['column']),
                         ('l1/src/abci/state.rs', 123, 37))

    def test_real_location_and_literal_association(self):
        literals = {r['label']: r['text'] for r in self.rows(self.outputs['literals.tsv'])}
        self.assertEqual(literals['task_name'], 'node slow abci_state driver')
        self.assertEqual(literals['callback_operation'], 'hardfork_hashes')
        self.assertEqual(literals['owner_increment_label'], 'slow_abci_engine_read_increment')
        self.assertEqual(literals['apply_block_operation'], 'spawn_slow_abci_driver_apply_block')
        self.assertEqual(literals['write_greeting_operation'], 'spawn_slow_abci_driver_write_greeting')

    def test_file_mapping_rejects_unmapped_and_cross_section(self):
        with self.assertRaises(ValueError):
            subject.mapping(self.secs, 0, 16, True)
        sec = next(s for s in self.secs if s['name'] == '.text')
        with self.assertRaises(ValueError):
            subject.mapping([sec], sec['address'] + sec['size'] - 1, 2, True)
        with self.assertRaises(ValueError):
            subject.mapping([sec], sec['address'], 0, True)

    def test_mapping_excludes_nobits_and_ambiguity(self):
        fake = {'name': 'fixture', 'type': 8, 'flags': 6, 'address': 10, 'offset': 0, 'size': 8}
        with self.assertRaises(ValueError):
            subject.mapping([fake], 10, 1, True)
        fake = dict(fake, type=1)
        self.assertEqual(subject.mapping([fake], 10, 1, True)[1], 0)
        with self.assertRaises(ValueError):
            subject.mapping([fake, fake], 10, 1, True)
        with self.assertRaises(ValueError):
            subject.mapping([dict(fake, flags=2)], 10, 1, True)

    def test_fde_overlap_and_boundary(self):
        chosen = {'start': 10, 'end': 20}
        subject.ensure_no_fde_overlap(chosen, [chosen, {'start': 20, 'end': 25}])
        with self.assertRaises(ValueError):
            subject.ensure_no_fde_overlap(chosen, [chosen, {'start': 19, 'end': 25}])
        with self.assertRaises(ValueError):
            subject.ensure_no_fde_overlap(chosen, [chosen, {'start': 9, 'end': 11}])

    def test_selected_direct_transfers_and_each_bad_displacement(self):
        for name, site, opcode, target in subject.TRANSFERS:
            with self.subTest(name=name):
                _, _, raw = subject.checked_transfer(self.read, site, opcode, target)
                broken = self.patched(site + len(raw) - 1, bytes([raw[-1] ^ 1]))
                with self.assertRaises(ValueError):
                    subject.checked_transfer(broken, site, opcode, target)

    def test_bad_transfer_opcode_rejected(self):
        with self.assertRaises(ValueError):
            subject.checked_transfer(self.patched(0x5a34472, b'\x90'), 0x5a34472,
                                     'call', 0x5647720)

    def test_each_selected_pattern_rejects_a_changed_opcode(self):
        for row in self.rows(self.outputs['patterns.tsv']):
            with self.subTest(label=row['label']):
                site = int(row['site_va'], 16)
                raw = bytes.fromhex(row['raw_hex'])
                subject.require_bytes(self.read, site, raw)
                changed = self.patched(site, bytes([raw[0] ^ 1]))
                with self.assertRaises(ValueError):
                    subject.require_bytes(changed, site, raw)

    def test_rip_reference_and_opcode_corruption(self):
        target, raw = subject.rip_target(self.read, 0x5a6ce58, b'\x48\x8d\x0d')
        self.assertEqual(target, 0x64b8a00)
        self.assertEqual(len(raw), 7)
        with self.assertRaises(ValueError):
            subject.rip_target(self.patched(0x5a6ce58, b'\x90'), 0x5a6ce58, b'\x48\x8d\x0d')

    @staticmethod
    def relocation_fixture(*entries):
        data = b''.join(struct.pack('<QQq', *row) for row in entries)
        sec = {'name': '.rela.dyn', 'type': 4, 'flags': 2, 'address': 0,
               'offset': 0, 'size': len(data)}
        return data, [sec]

    def test_relocation_positive_and_bad_type(self):
        data, secs = self.relocation_fixture((0x1234, 8, 0x5678))
        self.assertEqual(subject.relative_relocations(data, secs, [0x1234])[0x1234][0], 0x5678)
        data, secs = self.relocation_fixture((0x1234, 1, 0x5678))
        with self.assertRaises(ValueError):
            subject.relative_relocations(data, secs, [0x1234])

    def test_relocation_duplicate_missing_and_truncated(self):
        data, secs = self.relocation_fixture((0x1234, 8, 1), (0x1234, 8, 2))
        with self.assertRaises(ValueError):
            subject.relative_relocations(data, secs, [0x1234])
        with self.assertRaises(ValueError):
            subject.relative_relocations(data, secs, [0x1111])
        secs[0]['size'] -= 1
        with self.assertRaises(ValueError):
            subject.relative_relocations(data, secs, [0x1234])

    def test_capture_offsets_and_key_indices(self):
        start, end = 0x4e34d06, 0x4e35155
        rows = subject.parse_captures(self.read(start, end - start))
        self.assertEqual(len(rows), 74)
        self.assertEqual((rows[0][2], rows[0][3]), (0x128, 0))
        self.assertEqual((rows[28][2], rows[28][3]), (0x208, 0x10e8))
        self.assertEqual((rows[41][2], rows[41][3]), (0x270, 0x10f8))
        self.assertEqual((rows[-1][2], rows[-1][3]), (0x370, 0x3908))

    def test_capture_opcode_truncation_and_slot_corruption(self):
        raw = bytearray(self.read(0x4e34d06, 0x4e35155 - 0x4e34d06))
        broken = bytearray(raw)
        broken[23] ^= 1
        with self.assertRaises(ValueError):
            subject.parse_captures(broken)
        broken = bytearray(raw)
        broken[23 + 11] ^= 8
        with self.assertRaises(ValueError):
            subject.parse_captures(broken)
        with self.assertRaises(ValueError):
            subject.parse_captures(raw[:-1])

    def test_descriptor_count_stride_and_corruption(self):
        raw = bytearray(self.read(0x4e35173, 0x4e352fd - 0x4e35173))
        rows = subject.parse_descriptor_stores(raw)
        self.assertEqual((len(rows), rows[-1][2]), (59, 0x570))
        broken = bytearray(raw)
        broken[6] ^= 1
        with self.assertRaises(ValueError):
            subject.parse_descriptor_stores(broken)
        with self.assertRaises(ValueError):
            subject.parse_descriptor_stores(raw[:-1])

    def test_pointer_copy_boundaries(self):
        self.assertEqual(subject.map_copy(0xf8, 0x80, 0, 0xb8, 8), 0x78)
        with self.assertRaises(ValueError):
            subject.map_copy(0x137, 0x80, 0, 0xb8, 2)
        with self.assertRaises(ValueError):
            subject.map_copy(0x7f, 0x80, 0, 0xb8, 1)
        with self.assertRaises(ValueError):
            subject.map_copy(0x80, 0x80, 0, 0xb8, 0)

    def test_context_parent_return_to_owner_slot(self):
        fields = {row['label']: int(row['value'], 16)
                  for row in self.rows(self.outputs['immediates.tsv'])}
        fields['parent_copy_source_2'] = fields['parent_copy_destination_1']
        steps = subject.project_parent_owner(fields)
        self.assertEqual([row[-1] for row in steps], [0x38b0, 0x2de0, 0x25f0, 0x840])
        with self.assertRaises(ValueError):
            subject.project_parent_owner(dict(fields, parent_copy_size_3=0x10))
        with self.assertRaises(ValueError):
            subject.project_parent_owner(dict(fields, parent_return_load_stack=0x40))

    def test_result_record_projection(self):
        copies = subject.selected_copies(self.read)
        self.assertEqual(subject.track_projection(copies, 0xd0, 0xc8, 0x2b8,
                                                  0x38, 8, 'height_chunk'), 0)
        self.assertEqual(subject.track_projection(copies, 0xd0, 0xc8, 0x2b8,
                                                  0x40, 16, 'mix_first'), 8)
        self.assertEqual(subject.track_projection(copies, 0xd0, 0xc8, 0x2b8,
                                                  0x50, 16, 'mix_second'), 24)
        rows = self.rows(self.outputs['projection.tsv'])
        self.assertEqual([r['record_offset'] for r in rows], ['0x0', '0x8', '0x18'])

    def test_projection_opcode_and_out_of_range_controls(self):
        with self.assertRaises(ValueError):
            subject.selected_copies(self.patched(0x4fc37b0, b'\x90'))
        copies = subject.selected_copies(self.read)
        changed = list(copies['gate_mix_first'])
        changed[1] += 1
        copies['gate_mix_first'] = tuple(changed)
        with self.assertRaises(ValueError):
            subject.track_projection(copies, 0xd0, 0xc8, 0x2b8, 0x40, 16, 'mix_first')
        with self.assertRaises(ValueError):
            subject.track_projection(subject.selected_copies(self.read), 0xd0, 0xc8, 0x2b8,
                                     0x3f, 16, 'mix_first')

    def test_queue_geometry_and_negative_controls(self):
        self.assertEqual(subject.queue_geometry(self.read, 0x1f, 0x500), (32, 40))
        with self.assertRaises(ValueError):
            subject.queue_geometry(self.read, 0x1e, 0x500)
        with self.assertRaises(ValueError):
            subject.queue_geometry(self.patched(0x581a683, b'\x9a'), 0x1f, 0x500)
        with self.assertRaises(ValueError):
            subject.queue_geometry(self.patched(0x581a68b, b'\x82'), 0x1f, 0x500)

    def test_distinct_work_queue_geometry_and_bad_control(self):
        self.assertEqual(subject.work_queue_geometry(0x1f, 0x58, 0xb00), (32, 88))
        with self.assertRaises(ValueError):
            subject.work_queue_geometry(0x1f, 0x28, 0xb00)
        with self.assertRaises(ValueError):
            subject.work_queue_geometry(0x1e, 0x58, 0xb00)
        with self.assertRaises(ValueError):
            subject.work_queue_geometry(0x1f, 0, 0)

    def test_loader_owner_to_block_boundary_projection(self):
        fields = {row['label']: int(row['value'], 16)
                  for row in self.rows(self.outputs['immediates.tsv'])}
        context = {row['label']: int(row['value'], 16)
                   for row in self.rows(self.outputs['context_operands.tsv'])}
        self.assertEqual(subject.check_apply_projection(fields, context), (0x58, 0x58, 0xb00))
        bad_fields = dict(fields, apply_callback_body_stack=0xa0)
        with self.assertRaises(ValueError):
            subject.check_apply_projection(bad_fields, context)
        bad_fields = dict(fields, apply_callback_owner_pointer=0x70)
        with self.assertRaises(ValueError):
            subject.check_apply_projection(bad_fields, context)
        bad_context = dict(context, existing_context_state_slot=0x458)
        with self.assertRaises(ValueError):
            subject.check_apply_projection(fields, bad_context)
        with self.assertRaises(ValueError):
            subject.immediate(self.patched(0x5a34e8f, b'\x90'), 0x5a34e8f,
                              bytes.fromhex('48898424'), '<I')

    def test_same_owner_mode_controls_direct_root_and_apply_arms(self):
        fields = {row['label']: int(row['value'], 16)
                  for row in self.rows(self.outputs['immediates.tsv'])}
        root_mode = fields['root_wrapper_dispatch_base'] + fields['root_dispatch_mode_offset']
        apply_mode = fields['apply_wrapper_dispatch_base'] + fields['apply_dispatch_mode_offset']
        self.assertEqual((root_mode, apply_mode), (0x150, 0x150))
        for site in (0x4f21aa9, 0x4f152bf):
            subject.require_bytes(self.read, site, bytes.fromhex('807e2000'))
            with self.assertRaises(ValueError):
                subject.require_bytes(self.patched(site + 3, b'\x01'), site,
                                      bytes.fromhex('807e2000'))

    def test_write_owner_capture_slot_is_distinct_and_joined(self):
        fields = {row['label']: int(row['value'], 16)
                  for row in self.rows(self.outputs['immediates.tsv'])}
        self.assertEqual(subject.check_write_capture(fields), (0xa8, 0x28))
        self.assertNotEqual(fields['callback_owner_slot'], fields['callback_write_owner_slot'])
        with self.assertRaises(ValueError):
            subject.check_write_capture(dict(fields, constructor_write_arg_load=0x40))
        with self.assertRaises(ValueError):
            subject.check_write_capture(dict(fields, callback_write_body_stack=0x70))
        with self.assertRaises(ValueError):
            subject.check_write_capture(dict(fields, callback_write_owner_slot=0xa0))

    def test_apply_result_to_second_owner_slot_and_corruption(self):
        copies = subject.selected_copies(self.read)
        rows = subject.check_write_projection(copies, 0xc0, 0x40)
        self.assertEqual([(r[1], r[2], r[3]) for r in rows], [(0, 16, 0), (16, 16, 16), (32, 8, 32)])
        damaged = dict(copies)
        altered = list(damaged['write_stage_second'])
        altered[1] += 1
        damaged['write_stage_second'] = tuple(altered)
        with self.assertRaises(ValueError):
            subject.check_write_projection(damaged, 0xc0, 0x40)
        with self.assertRaises(ValueError):
            subject.selected_copies(self.patched(0x4fcc092, b'\x90'))

    def test_sentinel_subtraction_overflow_boundaries(self):
        sign, mask = 1 << 63, (1 << 64) - 1
        for value in (0, 1, sign - 1, sign, sign + 1, mask):
            result = (0 - value) & mask
            overflow = bool((0 ^ value) & (0 ^ result) & sign)
            self.assertEqual(overflow, value == sign)
        with self.assertRaises(ValueError):
            subject.require_bytes(self.patched(0x5a3448b, b'\x70'), 0x5a3448b, b'\x71\x0d')

    @staticmethod
    def lsda_fixture(raw):
        sec = {'name': '.gcc_except_table', 'type': 1, 'flags': 2,
               'address': 0x200, 'offset': 0, 'size': len(raw)}
        return bytes(raw), [sec], {'lsda': 0x200, 'start': 0x100, 'end': 0x120}

    def test_lsda_bounds_and_unwind_link(self):
        data, secs, fde = self.lsda_fixture(b'\xff\xff\x01\x04\x02\x05\x10\x00')
        rows = subject.parse_lsda(data, secs, fde)
        self.assertEqual((rows[0][1], rows[0][2], rows[0][3]), (0x102, 0x107, 0x110))
        self.assertEqual(subject.callsite_witness(rows, 0x102, 5), rows[0])
        self.assertIsNone(subject.callsite_witness(rows, 0x108, 1))
        with self.assertRaises(ValueError):
            subject.callsite_witness(rows, 0x106, 2)
        with self.assertRaises(ValueError):
            subject.callsite_witness(rows + rows, 0x102, 5)
        actual = self.rows(self.outputs['unwind_links.tsv'])
        self.assertEqual(len(actual), 33)
        self.assertTrue(all(row['status'] == 'covered' for row in actual))

    def test_lsda_rejects_truncation_and_outside_extent(self):
        data, secs, fde = self.lsda_fixture(b'\xff\xff\x01\x04\x1f\x04\x00\x00')
        with self.assertRaises(ValueError):
            subject.parse_lsda(data, secs, fde)

    def test_lsda_pointer_must_belong_to_exception_section(self):
        data, secs, fde = self.lsda_fixture(b'\xff\xff\x01\x04\x02\x05\x10\x00')
        other = dict(secs[0], name='another_section', address=0x300)
        fde['lsda'] = 0x300
        with self.assertRaises(ValueError):
            subject.parse_lsda(data, secs + [other], fde)
        data, secs, fde = self.lsda_fixture(b'\xff\xff\x01\x04\x02\x05\x10')
        with self.assertRaises(ValueError):
            subject.parse_lsda(data, secs, fde)
        data, secs, fde = self.lsda_fixture(b'\xfe\xff\x01\x00')
        with self.assertRaises(ValueError):
            subject.parse_lsda(data, secs, fde)


if __name__ == '__main__':
    unittest.main()
