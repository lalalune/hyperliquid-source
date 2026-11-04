"""Static and synthetic controls for the node 115 ring growth packet."""

import hashlib
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

from tools import abci_ring_growth115 as growth


class ByteEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = bytearray(growth.TARGET.read_bytes())
        cls.secs = growth.sections(cls.data)
        cls.functions, cls.insertion_fde = growth.select_fdes(cls.data, cls.secs)
        cls.relocs = growth.relocation_records(cls.data, cls.secs, growth.SLOTS)

    def test_target_sha(self):
        self.assertEqual(growth.authenticate(self.data, growth.TARGET_SHA), growth.TARGET_SHA)

    def test_same_size_mutated_target_hash_rejected(self):
        self.data[-1] ^= 1
        try:
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                growth.authenticate(self.data, growth.TARGET_SHA)
        finally:
            self.data[-1] ^= 1

    def test_wrong_digest_rejected(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            growth.authenticate(self.data, '0' * 64)

    def test_bad_input_cannot_create_output_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / 'out'
            with mock.patch.object(growth, 'TARGET_SHA', '0' * 64):
                with self.assertRaisesRegex(ValueError, 'SHA-256'):
                    growth.main(['--out', str(out)])
            self.assertFalse(out.exists())

    def test_each_selected_window_is_anchored_and_detects_corruption(self):
        for label, scope, va, expected in growth.WINDOWS:
            with self.subTest(label=label, scope=scope):
                actual = growth.read_va(self.data, self.secs, va, len(expected) // 2)
                growth.check_window(actual, expected)
                bad = bytearray(actual)
                for index in range(len(bad)):
                    bad[index] ^= 1
                    with self.assertRaises(ValueError):
                        growth.check_window(bad, expected)
                    bad[index] ^= 1

    def test_every_selected_transfer_and_corrupt_opcode(self):
        lengths = {'call_slot': 6, 'jmp_slot': 6, 'call': 5, 'jbe8': 2,
                   'jne8': 2, 'je8': 2, 'ja32': 6, 'lea_rdx': 7}
        for label, _, va, kind, target in growth.TRANSFERS:
            with self.subTest(label=label):
                raw = bytes(growth.read_va(self.data, self.secs, va, lengths[kind]))
                self.assertEqual(growth.checked_transfer(raw, va, kind, target), target)
                bad = bytearray(raw)
                bad[0] ^= 1
                with self.assertRaises(ValueError):
                    growth.checked_transfer(bad, va, kind, target)

    def test_every_displacement_corruption_is_rejected(self):
        lengths = {'call_slot': 6, 'jmp_slot': 6, 'call': 5, 'jbe8': 2,
                   'jne8': 2, 'je8': 2, 'ja32': 6, 'lea_rdx': 7}
        for label, _, va, kind, target in growth.TRANSFERS:
            with self.subTest(label=label):
                raw = bytearray(growth.read_va(self.data, self.secs, va, lengths[kind]))
                width = 1 if kind.endswith('8') else 4
                for index in range(len(raw) - width, len(raw)):
                    raw[index] ^= 1
                    with self.assertRaises(ValueError):
                        growth.checked_transfer(raw, va, kind, target)
                    raw[index] ^= 1

    def test_short_and_unknown_transfer_forms_rejected(self):
        with self.assertRaises(ValueError):
            growth.decode_transfer(b'\xe8\x00', 0x100, 'call')
        with self.assertRaises(ValueError):
            growth.decode_transfer(b'\xe8\0\0\0\0', 0x100, 'unknown')

    def test_complete_selected_fdes_are_indexed_and_byte_pinned(self):
        self.assertEqual(set(self.functions), {row[0] for row in growth.OWNED})
        for role, start, end, expected_sha in growth.OWNED:
            fde, index, body = self.functions[role]
            self.assertEqual((fde['start'], fde['end'], fde['fde']),
                             (start, end, index['fde']))
            self.assertEqual(hashlib.sha256(body).hexdigest(), expected_sha)
            self.assertIsNone(fde['lsda'])

    def test_new_windows_partition_both_fdes_and_reject_gaps_or_overlap(self):
        growth.check_window_partition(growth.WINDOWS)
        first = next(item for item in growth.WINDOWS if item[1] == 'new')
        with self.assertRaises(ValueError):
            growth.check_window_partition(tuple(item for item in growth.WINDOWS if item != first))
        with self.assertRaises(ValueError):
            growth.check_window_partition(growth.WINDOWS + (first,))
        with self.assertRaises(ValueError):
            growth.check_window_partition(growth.WINDOWS + (('outside', 'new', 0x100, '90'),))

    def test_fde_byte_corruption_fails(self):
        va = growth.OWNED[0][1]
        offset = growth.file_offset(self.data, self.secs, va, 1)
        self.data[offset] ^= 1
        try:
            with self.assertRaisesRegex(ValueError, 'body changed'):
                growth.select_fdes(self.data, self.secs)
        finally:
            self.data[offset] ^= 1

    def test_fde_header_corruption_fails(self):
        fde = self.functions['reposition_after_grow'][0]
        offset = growth.file_offset(self.data, self.secs, fde['fde'] + 12, 4)
        self.data[offset] ^= 1
        try:
            with self.assertRaises(ValueError):
                growth.select_fdes(self.data, self.secs)
        finally:
            self.data[offset] ^= 1

    def test_file_mapping_rejects_invalid_and_cross_section_ranges(self):
        for va, size in ((0, 1), (-1, 1), (0x5800d70, 0), (0x5800e08, -1)):
            with self.subTest(va=va, size=size), self.assertRaises(ValueError):
                growth.file_offset(self.data, self.secs, va, size)
        sec = next(s for s in self.secs if s['name'] == '.text')
        with self.assertRaises(ValueError):
            growth.file_offset(self.data, self.secs, sec['address'] + sec['size'] - 1, 2)

    def test_file_mapping_rejects_nobits_and_nonallocated(self):
        fake = b'abcdefgh'
        for section in (
            dict(name='.bss', type=8, flags=2, address=0x100, offset=0, size=8),
            dict(name='.debug', type=1, flags=0, address=0x100, offset=0, size=8),
        ):
            with self.subTest(section=section['name']), self.assertRaises(ValueError):
                growth.file_offset(fake, [section], 0x100, 1)

    def test_file_mapping_rejects_overlaps_and_outside_file(self):
        a = dict(name='a', type=1, flags=2, address=0x100, offset=0, size=8)
        b = dict(name='b', type=1, flags=2, address=0x100, offset=0, size=8)
        with self.assertRaises(ValueError):
            growth.file_offset(b'abcdefgh', [a, b], 0x100, 1)
        with self.assertRaises(ValueError):
            growth.file_offset(b'ab', [a], 0x100, 4)

    def test_relocation_targets_and_external_names(self):
        by_label = {row[0]: row for row in self.relocs}
        self.assertEqual(by_label['capacity_grow'][6], 0x5962d20)
        self.assertEqual(by_label['tail_memmove'][7], 'memmove')
        self.assertEqual(by_label['prefix_memcpy'][7], 'memcpy')
        self.assertEqual(by_label['prior_insertion_grow'][6], 0x5800d70)

    def test_relocation_type_corruption_fails(self):
        row = next(row for row in self.relocs if row[0] == 'capacity_grow')
        off = row[3] + 8
        self.data[off] ^= 1
        try:
            with self.assertRaises(ValueError):
                growth.relocation_records(self.data, self.secs, growth.SLOTS)
        finally:
            self.data[off] ^= 1

    def test_relocation_addend_corruption_fails(self):
        row = next(row for row in self.relocs if row[0] == 'capacity_grow')
        off = row[3] + 16
        self.data[off] ^= 1
        try:
            with self.assertRaises(ValueError):
                growth.relocation_records(self.data, self.secs, growth.SLOTS)
        finally:
            self.data[off] ^= 1

    def test_relocation_target_corruption_fails(self):
        row = next(row for row in self.relocs if row[0] == 'capacity_grow')
        off = row[3]
        self.data[off] ^= 1
        try:
            with self.assertRaises(ValueError):
                growth.relocation_records(self.data, self.secs, growth.SLOTS)
        finally:
            self.data[off] ^= 1

    def test_relocation_duplicate_request_fails(self):
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            growth.relocation_records(self.data, self.secs, (growth.SLOTS[0], growth.SLOTS[0]))

    def test_duplicate_relocation_in_elf_fails(self):
        row = next(row for row in self.relocs if row[0] == 'capacity_grow')
        off = row[3] + 24
        original = self.data[off:off + 8]
        struct.pack_into('<Q', self.data, off, row[2])
        try:
            with self.assertRaisesRegex(ValueError, 'duplicate target'):
                growth.relocation_records(self.data, self.secs, growth.SLOTS)
        finally:
            self.data[off:off + 8] = original

    def test_wrong_section_type_and_duplicate_name_fail(self):
        changed = [dict(section) for section in self.secs]
        next(section for section in changed if section['name'] == '.rela.dyn')['type'] = 1
        with self.assertRaises(ValueError):
            growth.relocation_records(self.data, changed, growth.SLOTS)
        with self.assertRaises(ValueError):
            growth.unique_section(self.secs + [next(s for s in self.secs if s['name'] == '.dynstr')], '.dynstr')

    def test_external_symbol_name_corruption_fails(self):
        dynsym = growth.unique_section(self.secs, '.dynsym')
        dynstr = growth.unique_section(self.secs, '.dynstr')
        row = next(row for row in self.relocs if row[0] == 'tail_memmove')
        name = struct.unpack_from('<I', self.data, dynsym['offset'] + row[5] * 24)[0]
        off = dynstr['offset'] + name
        self.data[off] ^= 1
        try:
            with self.assertRaises(ValueError):
                growth.relocation_records(self.data, self.secs, growth.SLOTS)
        finally:
            self.data[off] ^= 1

    def test_location_bytes_and_corruption(self):
        result = growth.checked_location(self.data, self.secs, self.relocs, 0x64767a8, 123, 37)
        self.assertEqual(result[2:], (123, 37, 'l1/src/abci/state.rs'))
        off = growth.file_offset(self.data, self.secs, 0x64767a8 + 16, 1)
        self.data[off] ^= 1
        try:
            with self.assertRaises(ValueError):
                growth.checked_location(self.data, self.secs, self.relocs, 0x64767a8, 123, 37)
        finally:
            self.data[off] ^= 1

    def test_growth_call_has_prior_unwind_landing(self):
        rows = growth.read_exception_rows(self.data, self.secs, self.insertion_fde)
        selected = [r for r in rows if r[1] <= 0x57ea3a9 and 0x57ea3af <= r[2]]
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0][1:],
                         (0x57ea3a6, 0x57ea494, 0x57ea496, 0, '26ee01960200'))

    def test_prior_out_of_range_index_reaches_diagnostic_and_ud2(self):
        raw = bytes(growth.read_va(self.data, self.secs, 0x57ea392, 6))
        self.assertEqual(growth.checked_transfer(raw, 0x57ea392, 'ja32', 0x57ea47b), 0x57ea47b)
        self.assertEqual(bytes(growth.read_va(self.data, self.secs, 0x57ea494, 2)), b'\x0f\x0b')

    def test_exception_header_corruption_fails(self):
        off = growth.file_offset(self.data, self.secs, self.insertion_fde['lsda'], 1)
        self.data[off] ^= 1
        try:
            with self.assertRaises(ValueError):
                growth.read_exception_rows(self.data, self.secs, self.insertion_fde)
        finally:
            self.data[off] ^= 1

    def test_exception_pointer_outside_its_section_fails(self):
        damaged = dict(self.insertion_fde, lsda=0x5800d70)
        with self.assertRaises(ValueError):
            growth.read_exception_rows(self.data, self.secs, damaged)

    def test_failure_path_branches_before_publishing_pointer_or_capacity(self):
        check = bytes(growth.read_va(self.data, self.secs, 0x5962d5a, 6))
        self.assertEqual(check, bytes.fromhex('833c24017414'))
        self.assertEqual(growth.checked_transfer(check[4:], 0x5962d5e, 'je8', 0x5962d74), 0x5962d74)
        fail = bytes(growth.read_va(self.data, self.secs, 0x5962d74, 16))
        self.assertEqual(fail[:10], bytes.fromhex('488b7c2408488b742410'))
        self.assertEqual(bytes(growth.read_va(self.data, self.secs, 0x5962d84, 1)), b'\xcc')

    def test_old_digest_is_distinct(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            growth.verify_historical(self.data)


class RingModelTests(unittest.TestCase):
    def test_capacity_boundaries_and_machine_width_wrap(self):
        self.assertEqual([growth.capacity_after_growth(x) for x in (0, 1, 2, 3, 31, 32, 63)],
                         [4, 4, 4, 6, 62, 64, 126])
        self.assertEqual(growth.capacity_after_growth((1 << 63) - 1), (1 << 64) - 2)
        self.assertEqual(growth.capacity_after_growth(1 << 63), 4)
        with self.assertRaises(ValueError):
            growth.model_growth(1 << 63, 0, 0)
        with self.assertRaisesRegex(ValueError, 'model allocation'):
            growth.model_growth(1 << 62, 0, 0)
        for cap in (-1, 1 << 64):
            with self.subTest(cap=cap), self.assertRaises(ValueError):
                growth.capacity_after_growth(cap)

    def test_both_move_arms_and_equal_tie(self):
        self.assertEqual(growth.branch_plan(8, 0, 8, 16)[0], 'contiguous')
        self.assertEqual(growth.branch_plan(8, 3, 8, 16)[0], 'prefix')
        self.assertEqual(growth.branch_plan(8, 4, 8, 16)[0], 'tail')
        self.assertEqual(growth.branch_plan(8, 5, 8, 16)[0], 'tail')

    def test_counterfactual_short_extra_space_uses_tail(self):
        branch, head, src, dst, size, tail, prefix = growth.branch_plan(8, 3, 8, 10)
        self.assertEqual((branch, head, src, dst, size, tail, prefix),
                         ('tail', 5, 3, 5, 5, 5, 3))
        # A mutant forcing prefix would write outside the 10-row buffer.
        self.assertGreater(8 + prefix, 10)

    def test_generic_smaller_growth_preserves_rows_and_copy_bounds(self):
        cases = insufficient = 0
        for capacity in range(1, 25):
            for new_capacity in range(capacity, 2 * capacity + 1):
                for head in range(capacity):
                    for length in range(capacity + 1):
                        logical = [(i, i ^ 0x5a) for i in range(length)]
                        rows = [None] * new_capacity
                        for i, row in enumerate(logical):
                            rows[(head + i) % capacity] = row
                        kind, new_head, source, destination, count, tail, prefix = growth.branch_plan(
                            capacity, head, length, new_capacity)
                        self.assertLessEqual(destination + count, new_capacity)
                        if kind == 'prefix':
                            self.assertLessEqual(source + count, destination)
                        if head + length > capacity and new_capacity - capacity < prefix:
                            insufficient += 1
                            self.assertEqual(kind, 'tail')
                        rows[destination:destination + count] = list(rows[source:source + count])
                        self.assertEqual([rows[(new_head + i) % new_capacity] for i in range(length)], logical)
                        cases += 1
        self.assertEqual(cases, 100100)
        self.assertGreater(insufficient, 0)

    def test_invalid_storage_is_not_treated_as_supported(self):
        for case in ((0, 1, 0, 4), (0, 0, 1, 4), (8, -1, 2, 16),
                     (8, 8, 2, 16), (8, 2, 9, 16), (8, 2, 4, 7)):
            with self.subTest(case=case), self.assertRaises(ValueError):
                growth.branch_plan(*case)

    def test_sweep_and_independent_shorter_side_oracle(self):
        counts = {'contiguous': 0, 'tail': 0, 'prefix': 0}
        full_count = 0
        for cap in range(64):
            for head in (range(cap) if cap else (0,)):
                for length in range(cap + 1):
                    new_cap = max(4, 2 * cap)
                    plan = growth.branch_plan(cap, head, length, new_cap)
                    if head + length <= cap:
                        expected = 'contiguous'
                    else:
                        expected = 'tail' if cap - head <= length - (cap - head) else 'prefix'
                    self.assertEqual(plan[0], expected)
                    counts[expected] += 1
                    full_count += length == cap
        sweep, _, _ = growth.make_models(4, 64)
        self.assertEqual(sweep['all_branch_counts'], counts)
        self.assertEqual(sweep['full_descriptors'], full_count)
        self.assertEqual(sweep['valid_descriptors'], sum(counts.values()))
        self.assertEqual(sweep['logical_mismatches'], 0)

    def test_full_ring_byte_rows_preserve_order_in_all_head_positions(self):
        for cap in range(1, 64):
            for head in range(cap):
                with self.subTest(cap=cap, head=head):
                    new_cap = max(4, 2 * cap)
                    before = [bytes((i + 17 * j) & 255 for j in range(64)) for i in range(cap)]
                    physical = [None] * new_cap
                    for i, row in enumerate(before):
                        physical[(head + i) % cap] = row
                    kind, new_head, src, dst, count, _, _ = growth.branch_plan(cap, head, cap, new_cap)
                    copied = list(physical[src:src + count])
                    physical[dst:dst + count] = copied
                    after = [physical[(new_head + i) % new_cap] for i in range(cap)]
                    self.assertEqual(after, before, kind)

    def test_all_valid_small_rings_produce_preserved_models(self):
        sweep, examples, forced = growth.make_models(4, 64)
        self.assertEqual(sweep['valid_descriptors'], 87361)
        self.assertEqual(sweep['full_descriptors'], 2017)
        self.assertTrue(all(row['preserved'] for row in examples))
        self.assertEqual(forced['branch'], 'tail')

    def test_empty_ring_and_wrapped_examples(self):
        empty = growth.model_growth(0, 0, 0)
        self.assertEqual((empty['new_capacity'], empty['new_head'], empty['branch']),
                         (4, 0, 'contiguous'))
        prefix = growth.model_growth(8, 3, 8)
        self.assertEqual((prefix['source'], prefix['destination'], prefix['moved_rows']), (0, 8, 3))
        tail = growth.model_growth(8, 5, 8)
        self.assertEqual((tail['source'], tail['destination'], tail['moved_rows']), (5, 13, 3))

    def test_descending_lifecycle_replaces_at_64_and_converts_on_miss(self):
        keys = list(range(63, -1, -1)) + [32, 64]
        trace = growth.model_history(keys, 4, 64)
        self.assertEqual(len(trace), 66)
        grows = [row for row in trace if row[7] != 'none']
        self.assertEqual([row[9] for row in grows], [4, 8, 16, 32, 64])
        self.assertIn('tail', [row[7] for row in grows])
        self.assertEqual(trace[-2][6:10], ('replace', 'none', 64, 64))
        self.assertEqual(trace[-1][6:10], ('convert_boundary', 'none', 64, 64))

    def test_mixed_lifecycles_match_an_independent_list_oracle(self):
        inputs = [list(range(64)), list(range(63, -1, -1)),
                  [value for i in range(32) for value in (i, 63 - i)],
                  [value for i in range(64) for value in (i, i)]]
        for sequence in inputs:
            with self.subTest(first=sequence[:4]):
                expected_keys = []
                for row in growth.model_history(sequence + [64], 4, 64):
                    _, key, old_len, _, _, position, operation, _, new_len, _, _ = row
                    self.assertEqual(old_len, len(expected_keys))
                    self.assertEqual(position, sum(existing < key for existing in expected_keys))
                    if key in expected_keys:
                        self.assertEqual(operation, 'replace')
                    elif len(expected_keys) == 64:
                        self.assertEqual(operation, 'convert_boundary')
                    else:
                        self.assertEqual(operation, 'insert')
                        expected_keys.append(key)
                        expected_keys.sort()
                    self.assertEqual(new_len, len(expected_keys))


if __name__ == '__main__':
    unittest.main()
