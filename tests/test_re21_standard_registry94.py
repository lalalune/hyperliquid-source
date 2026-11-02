"""Static, artifact-bound controls for the standard-precompile path."""
import contextlib
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import re21_standard_registry94 as tool


class StandardRegistryEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = tool.TARGET.read_bytes()
        cls.image = tool.Image(cls.data)
        cls.evidence = tool.extract(cls.data)
        cls.records = tool.relas(cls.image)
        cls.providers = {va: tool.provider(cls.image, va) for va in tool.PROVIDERS}
        cls.mutable = bytearray(cls.data)

    @contextlib.contextmanager
    def changed_byte(self, va, xor=1):
        off = self.image.offset(va, 1)
        self.mutable[off] ^= xor
        try:
            yield tool.Image(self.mutable, self.image.secs)
        finally:
            self.mutable[off] ^= xor

    def test_authenticated_input_and_one_bit_mismatch(self):
        tool.authenticate(self.data)
        with self.changed_byte(0x44bc793) as bad:
            with self.assertRaises(ValueError):
                tool.authenticate(bad.data)
        with self.assertRaises(ValueError):
            tool.authenticate(b'')

    def test_selected_ranges_are_distinct_and_nonempty(self):
        rows = self.evidence['functions']
        self.assertEqual(len(rows), 19)
        self.assertEqual(len({r['start_va'] for r in rows}), len(rows))
        for row in rows:
            self.assertGreater(row['end_va'], row['start_va'])
            self.assertEqual(row['end_va'] - row['start_va'], row['size'])
            self.assertEqual(self.image.offset(row['start_va'], row['size'], True), row['file_offset'])

    def test_prior_owned_runtime_is_not_selected(self):
        starts = {row['start_va'] for row in self.evidence['functions']}
        for boundary in (0x4dd6ea0, 0x4e91cb0, 0x4e99f30, 0x4e9d2a0, 0x4e9a8a0):
            self.assertNotIn(boundary, starts)

    def test_all_revision_modes_and_canonical_bytes(self):
        rows = self.evidence['revision_cases']
        self.assertEqual([r['raw_revision'] for r in rows], list(range(256)))
        expected_modes = [0]*6 + [1]*3 + [2]*2 + [3]*6 + [4] + [5]*238
        self.assertEqual([r['provider_mode'] for r in rows], expected_modes)
        expected_canonical = [0, 0, 2, 2, 4, 5, 6, 8, 8, 9, 9, 11, 12, 12, 12, 15, 16, 17, 18, 19]
        self.assertEqual([r['canonical'] for r in rows], expected_canonical + [255]*236)

    def test_revision_boundaries_and_descriptor_binding(self):
        rows = self.evidence['revision_cases']
        for raw in (11, 12, 13, 14, 15, 16):
            self.assertEqual(rows[raw]['provider_va'], 0x4473710)
        self.assertEqual(rows[12]['case_va'], rows[14]['case_va'])
        self.assertEqual(rows[12]['provider_descriptor_va'], 0x5721448)
        self.assertEqual(rows[12]['constructor_va'], 0x4dde9b0)
        self.assertEqual(rows[19]['canonical'], 19)
        self.assertEqual(rows[20]['canonical'], 255)
        self.assertEqual(rows[255]['case_va'], rows[20]['case_va'])

    def test_revision_guard_corruption(self):
        with self.changed_byte(0x44bc796) as image:
            with self.assertRaises(ValueError):
                tool.parse_revision_cases(image, self.records, self.providers)

    def test_revision_table_displacement_corruption(self):
        with self.changed_byte(0x6f2a8c + 4*12) as image:
            with self.assertRaises(ValueError):
                tool.parse_revision_cases(image, self.records, self.providers)

    def test_revision_canonical_byte_corruption(self):
        with self.changed_byte(0x44bc9e6) as image:
            with self.assertRaises(ValueError):
                tool.parse_revision_cases(image, self.records, self.providers)

    def test_revision_descriptor_displacement_corruption(self):
        with self.changed_byte(0x44bc98f) as image:
            with self.assertRaises(ValueError):
                tool.parse_revision_cases(image, self.records, self.providers)

    def test_provider_six_modes_and_nobits_cache(self):
        self.assertEqual({r['mode'] for r in self.providers.values()}, set(range(6)))
        for row in self.providers.values():
            self.assertEqual(row['cache_section'], '.bss')
            self.assertEqual(row['mode'], tool.PRIOR_CONSTRUCTORS[row['constructor_va']])
            with self.assertRaises(ValueError):
                self.image.read(row['cache_va'], 1)

    def test_provider_prefix_corruption(self):
        with self.changed_byte(0x4473710) as image:
            with self.assertRaises(ValueError):
                tool.provider(image, 0x4473710)

    def test_provider_target_corruption(self):
        with self.changed_byte(0x447371c) as image:
            with self.assertRaises(ValueError):
                tool.provider(image, 0x4473710)

    def test_provider_borrow_tag_store_corruption(self):
        with self.changed_byte(0x4473723) as image:
            with self.assertRaises(ValueError):
                tool.provider(image, 0x4473710)

    def test_callback_pair_and_all_three_relocations(self):
        rows = self.evidence['execution_pairs']
        self.assertEqual(len(rows), 11)
        self.assertEqual([r['output_pointer_offset'] for r in rows], list(range(8, 0xa9, 16)))
        selected = rows[2]
        self.assertEqual(selected['descriptor_va'], 0x57462b0)
        self.assertEqual([m['addend'] for m in selected['methods']], [0x4daa200, 0x4da7da0, 0x4da4e20])

    def test_callback_descriptor_pointer_corruption(self):
        with self.changed_byte(0x4ddec6f) as image:
            with self.assertRaises(ValueError):
                tool.execution_pairs(image, self.records)

    def test_callback_output_offset_corruption(self):
        with self.changed_byte(0x4ddec76) as image:
            with self.assertRaises(ValueError):
                tool.execution_pairs(image, self.records)

    def test_callback_relocation_target_corruption(self):
        records = dict(self.records)
        info, addend, off = records[0x57462d8]
        records[0x57462d8] = (info, addend + 1, off)
        with self.assertRaises(ValueError):
            tool.execution_pairs(self.image, records)

    def test_context_and_handler_copy_arithmetic(self):
        flow = self.evidence['flow']
        self.assertEqual(flow['handler_in_engine_offset'], 0x110)
        self.assertEqual((flow['provider_in_engine_data'], flow['provider_in_engine_descriptor']), (0x158, 0x160))
        self.assertEqual((flow['callback_in_engine_data'], flow['callback_in_engine_descriptor']), (0x218, 0x220))
        self.assertEqual(flow['environment_pointer_in_context'], 0xd8)
        self.assertEqual((flow['target_tag_offset'], flow['target_first_offset'], flow['target_last_offset']), (0x294, 0x295, 0x2a5))
        self.assertEqual(flow['target_tag_value'], 1)

    def test_context_copy_displacement_corruption(self):
        with self.changed_byte(0x4463b21) as image:
            with self.assertRaises(ValueError):
                tool.flow_facts(image, self.evidence['execution_pairs'])

    def test_target_last_lane_displacement_corruption(self):
        with self.changed_byte(0x4463a58) as image:
            with self.assertRaises(ValueError):
                tool.flow_facts(image, self.evidence['execution_pairs'])

    def test_environment_pointer_displacement_corruption(self):
        with self.changed_byte(0x44638fe) as image:
            with self.assertRaises(ValueError):
                tool.flow_facts(image, self.evidence['execution_pairs'])

    def test_provider_dispatch_displacement_corruption(self):
        with self.changed_byte(0x47f30fb) as image:
            with self.assertRaises(ValueError):
                tool.flow_facts(image, self.evidence['execution_pairs'])

    def test_creation_callback_and_full_key_probe(self):
        selected = self.evidence['execution_pairs'][5]
        self.assertEqual(selected['descriptor_va'], 0x57462e0)
        self.assertEqual(selected['methods'][2]['addend'], 0x4da6ff0)
        flow = self.evidence['flow']
        self.assertEqual((flow['creation_in_engine_data'], flow['creation_in_engine_descriptor']), (0x248, 0x250))
        edges = {r['name']: r for r in self.evidence['transfers']}
        for name in ('create_owned_contains', 'create_borrowed_contains'):
            self.assertEqual(edges[name]['target_va'], 0x488d0b0)
        self.assertEqual(edges['create_borrowed_match']['target_va'], 0x4dd881c)
        self.assertEqual(edges['contains_full_key_match']['target_va'], 0x488d1be)

    def test_creation_callback_relocation_corruption(self):
        records = dict(self.records)
        slot = self.evidence['execution_pairs'][5]['methods'][2]['slot_va']
        info, addend, off = records[slot]
        records[slot] = (info, addend + 1, off)
        with self.assertRaises(ValueError):
            tool.execution_pairs(self.image, records)

    def test_creation_callback_offset_corruption(self):
        with self.changed_byte(0x47f3488) as image:
            with self.assertRaises(ValueError):
                tool.flow_facts(image, self.evidence['execution_pairs'])

    def test_nested_callback_offset_corruption(self):
        with self.changed_byte(0x47f39ee) as image:
            with self.assertRaises(ValueError):
                tool.flow_facts(image, self.evidence['execution_pairs'])

    def test_constructor_allocation_checks(self):
        rows = self.evidence['allocations']
        self.assertEqual(len(rows), 11)
        self.assertEqual(len({r['failure_va'] for r in rows}), 11)
        self.assertTrue(all((r['size'], r['failure_alignment'], r['failure_size']) == (16, 8, 16) for r in rows))

    def test_constructor_allocation_pattern_corruption(self):
        with self.changed_byte(0x4dde9c5) as image:
            with self.assertRaises(ValueError):
                tool.allocation_checks(image)

    def test_constructor_failure_target_corruption(self):
        with self.changed_byte(0x4ddea42) as image:
            with self.assertRaises(ValueError):
                tool.allocation_checks(image)

    def test_constructor_failure_size_corruption(self):
        with self.changed_byte(0x4dded4b) as image:
            with self.assertRaises(ValueError):
                tool.allocation_checks(image)

    def test_relocation_kind_and_missing(self):
        records = dict(self.records)
        _, addend, off = records[0x57462d8]
        records[0x57462d8] = (6, addend, off)
        with self.assertRaises(ValueError):
            tool.relative_relocation(records, 0x57462d8)
        del records[0x57462d8]
        with self.assertRaises(ValueError):
            tool.relative_relocation(records, 0x57462d8)

    def test_copy_symbol_and_nobits_relocation(self):
        rows = {r['slot_va']: r for r in self.evidence['relocations']}
        self.assertEqual((rows[0x576dfe0]['type'], rows[0x576dfe0]['symbol']), (6, 'memcpy'))
        self.assertEqual((rows[0x576e3e0]['addend_va'], rows[0x576e3e0]['target_section']), (0x5788348, '.bss'))

    def test_copy_symbol_name_corruption(self):
        sec = next(s for s in self.image.secs if s['name'] == '.dynstr')
        off = self.data.find(b'memcpy\0', sec['offset'], sec['offset'] + sec['size'])
        self.assertGreaterEqual(off, sec['offset'])
        va = sec['address'] + off - sec['offset']
        with self.changed_byte(va) as image:
            with self.assertRaises(ValueError):
                tool.relocation_boundaries(image, self.records)

    def test_copy_relocation_type_corruption(self):
        records = dict(self.records)
        info, addend, off = records[0x576dfe0]
        records[0x576dfe0] = (info - 1, addend, off)
        with self.assertRaises(ValueError):
            tool.relocation_boundaries(self.image, records)

    def test_duplicate_relocation_rejected(self):
        record = struct.pack('<QQq', 0x1200, 8, 0x3100)
        class MockImage:
            data = record + record
            secs = [{'name': '.rela.dyn', 'type': 4, 'offset': 0, 'size': len(record)*2}]
        with self.assertRaises(ValueError):
            tool.relas(MockImage())

    def test_prior_address_and_callable_boundary(self):
        boundary = self.evidence['prior_boundaries']
        self.assertEqual(bytes.fromhex(boundary['address_bytes']), bytes(19) + b'\x09')
        self.assertEqual(boundary['wrapper_addend'], 0x4e9d2a0)
        self.assertEqual(boundary['frame_addend'], 0x4e91cb0)

    def test_all_transfer_destinations_are_encoded(self):
        for name, va, target, kind in tool.EDGES:
            with self.subTest(name=name):
                self.assertEqual(tool.transfer(self.image, va)[:2], (kind, target))

    def test_selected_branch_displacement_corruption(self):
        with self.changed_byte(0x47f31bf) as image:
            actual = tool.transfer(image, 0x47f31bc)[1]
            with self.assertRaises(ValueError):
                tool.must_equal(actual, 0x47f32c7, 'branch')

    def test_selected_transfer_opcode_corruption(self):
        with self.changed_byte(0x4da4e30) as image:
            kind, _, _ = tool.transfer(image, 0x4da4e30)
            with self.assertRaises(ValueError):
                tool.must_equal(kind, 'call', 'transfer kind')

    def test_every_window_has_fixed_endpoints(self):
        for name, va, expected in tool.PINS:
            raw = self.image.read(va, len(bytes.fromhex(expected)), True)
            self.assertEqual(raw.hex(), expected, name)
            for pos in (0, len(raw)-1):
                mutated = bytearray(raw)
                mutated[pos] ^= 1
                with self.assertRaises(ValueError, msg=name):
                    tool.must_equal(mutated.hex(), expected, name)

    def test_zero_and_out_of_range_file_mapping(self):
        for va, length in ((-1, 1), (0, 0), (2**64, 1), (2**64-1, 2)):
            with self.assertRaises(ValueError):
                self.image.offset(va, length)
        with self.assertRaises(ValueError):
            self.image.offset(0x574f0c0, 20, executable=True)

    def test_nobits_overlap_and_section_crossing_rejected(self):
        # NOBITS must never resolve to bytes, even if its offset happens to be in file.
        fake = [{'type': 8, 'flags': 6, 'address': 100, 'size': 20, 'offset': 0}]
        with self.assertRaises(ValueError):
            tool.Image(b'0123456789', fake).read(100, 1)
        sec = {'type': 1, 'flags': 6, 'address': 100, 'size': 10, 'offset': 0}
        with self.assertRaises(ValueError):
            tool.Image(b'0123456789', [sec, dict(sec)]).read(100, 1)
        with self.assertRaises(ValueError):
            tool.Image(b'0123456789', [sec]).read(109, 2)

    def test_unwind_records_selected_and_raw(self):
        records = self.evidence['unwind']
        self.assertEqual(len(records), 19)
        for row in records:
            self.assertTrue(row['fde_bytes'])
            self.assertTrue(row['cie_bytes'])

    def test_selected_fde_start_corruption(self):
        va = next(x['fde_va'] for x in self.evidence['unwind'] if x['start_va'] == 0x4da4e20)
        with self.changed_byte(va + 8) as image:
            with self.assertRaises(ValueError):
                tool.checked_functions(image)

    def test_selected_unwind_index_pointer_corruption(self):
        _, index = tool.unwind_index(self.data)
        selected = next(x for x in index if x['start'] == 0x4da4e20)
        header = next(s for s in self.image.secs if s['name'] == '.eh_frame_hdr')
        pointer = header['address'] + 12 + selected['index'] * 8 + 4
        with self.changed_byte(pointer) as image:
            with self.assertRaises(ValueError):
                tool.checked_functions(image)

    def test_malformed_frame_record_length(self):
        va = next(x['fde_va'] for x in self.evidence['unwind'] if x['start_va'] == 0x4da4e20)
        off = self.image.offset(va, 4)
        original = self.mutable[off:off+4]
        self.mutable[off:off+4] = b'\x00'*4
        try:
            with self.assertRaises(ValueError):
                tool.raw_frame_record(tool.Image(self.mutable, self.image.secs), va)
        finally:
            self.mutable[off:off+4] = original

    def test_exception_call_sites_cover_distinct_cleanup_lands(self):
        adapter = next(x for x in self.evidence['exceptions'] if x['function_va'] == 0x4da4e20)
        def landing(site):
            return next(x['landing_va'] for x in adapter['entries'] if x['start_va'] <= site < x['start_va'] + x['length'])
        self.assertEqual(landing(0x4da4e30), 0x4da4e7e)
        self.assertEqual(landing(0x4da4e45), 0x4da4e63)
        executor = next(x for x in self.evidence['exceptions'] if x['function_va'] == 0x47f3090)
        def executor_landing(site):
            return next(x['landing_va'] for x in executor['entries'] if x['start_va'] <= site < x['start_va'] + x['length'])
        self.assertEqual(executor_landing(0x47f312b), 0x47f4e47)
        self.assertEqual(executor_landing(0x47f3158), 0x47f4e14)

    def test_malformed_exception_encoding(self):
        _, frames = tool.eh_frame_records(self.data, self.image.secs)
        frame = next(x for x in frames if x['start'] == 0x4da4e20)
        with self.changed_byte(frame['lsda'] + 3, 2) as image:
            with self.assertRaises(ValueError):
                tool.lsda_record(image, frame)

    def test_exception_call_range_outside_fde(self):
        _, frames = tool.eh_frame_records(self.data, self.image.secs)
        frame = next(x for x in frames if x['start'] == 0x4da4e20)
        with self.changed_byte(frame['lsda'] + 6, 0x74) as image:
            with self.assertRaises(ValueError):
                tool.lsda_record(image, frame)

    def test_full_key_equality_and_all_bit_changes(self):
        key = bytes(19) + b'\x09'
        self.assertTrue(tool.lane_equal(key, key))
        for bit in range(160):
            different = bytearray(key)
            different[bit // 8] ^= 1 << (bit % 8)
            self.assertFalse(tool.lane_equal(key, different))
        for n in (0, 19, 21):
            with self.assertRaises(ValueError):
                tool.lane_equal(key, bytes(n))

    def test_synthetic_membership_probe_and_empty_order(self):
        address = bytes(19) + b'\x09'
        altered = address[:-1] + b'\x08'
        hashed = (0x35 << 57) | 29
        controls, keys = [0xff] * 64, [None] * 64
        controls[29], keys[29] = 0x35, altered
        controls[30], keys[30] = 0x35, address
        self.assertTrue(tool.membership_probe(controls, keys, address, hashed))
        controls[30], keys[30] = 0xff, None
        self.assertFalse(tool.membership_probe(controls, keys, address, hashed))
        controls, keys = [0x80] * 64, [None] * 64
        controls[13], keys[13] = 0x35, address
        controls[14] = 0xff
        self.assertTrue(tool.membership_probe(controls, keys, address, hashed))
        keys[13] = altered
        self.assertFalse(tool.membership_probe(controls, keys, address, hashed))

    def test_synthetic_membership_rejects_corruption(self):
        address = bytes(20)
        controls, keys = [0x80] * 32, [None] * 32
        with self.assertRaises(ValueError):
            tool.membership_probe(controls, keys, address, 0)
        for bad in (-1, 2**64, True):
            with self.assertRaises(ValueError):
                tool.membership_probe(controls, keys, address, bad)
        with self.assertRaises(ValueError):
            tool.membership_probe([0xff] * 15, [None] * 15, address, 0)
        controls[0] = 0
        with self.assertRaises(ValueError):
            tool.membership_probe(controls, keys, address, 0)

    def test_reserve_hint_boundaries(self):
        self.assertEqual(tool.reserve_hint(0, 0), 0)
        self.assertEqual(tool.reserve_hint(7, 0), 7)
        self.assertEqual(tool.reserve_hint(7, 1), 4)
        self.assertEqual(tool.reserve_hint(8, 1), 4)
        self.assertEqual(tool.reserve_hint(2**64 - 1, 1), 0)
        self.assertEqual(tool.reserve_hint(2**64 - 1, 0), 2**64 - 1)
        for value in (-1, 2**64, True):
            with self.assertRaises(ValueError):
                tool.reserve_hint(value, 1)
            with self.assertRaises(ValueError):
                tool.reserve_hint(1, value)


if __name__ == '__main__':
    unittest.main()
