import csv
import io
import json
from pathlib import Path
import struct
import unittest
from unittest import mock

from tools import rest_index_growth94 as r


class RestIndexGrowth94Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = r.verified_data(r.BIN.read_bytes())
        cls.secs = r.sections(cls.data)
        cls.relocs = r.relative_relocations(cls.data, cls.secs)
        cls.generated = r.generate(cls.data)

    def test_binary_identity(self):
        self.assertEqual(r.digest(self.data), r.TARGET)
        self.assertIs(r.verified_data(self.data), self.data)

    def test_wrong_digest_rejected(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            r.verified_data(self.data, '0' * 64)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            r.verified_data(self.data[:-1])

    def test_selected_extents_and_unmasked_bytes(self):
        evidence = json.loads(self.generated['functions.json'])
        rows = evidence['functions']
        self.assertEqual(len(rows), 3)
        self.assertEqual(sum(row['length'] for row in rows), 1989)
        self.assertEqual(evidence['target_sha256'], r.TARGET)
        for row in rows:
            start, end, sha = r.SELECTED[row['role']]
            self.assertEqual((int(row['start_va'], 16), int(row['end_va'], 16)), (start, end))
            self.assertEqual(r.digest(bytes.fromhex(row['raw_hex'])), sha)
            self.assertIsInstance(row['unwind_index'], int)

    def test_unwind_header_membership_and_mismatch(self):
        table = [{'start': 0x1234, 'fde': 0x5678}]
        self.assertEqual(r.verify_indexed({'index': 0, 'start': 0x1234, 'fde': 0x5678}, table), 0)
        for frame in ({'start': 0x1234, 'fde': 0x5678},
                      {'index': 1, 'start': 0x1234, 'fde': 0x5678},
                      {'index': 0, 'start': 0x1235, 'fde': 0x5678},
                      {'index': 0, 'start': 0x1234, 'fde': 0x5679}):
            with self.subTest(frame=frame), self.assertRaises(ValueError):
                r.verify_indexed(frame, table)

    def test_each_witness_is_byte_sensitive(self):
        changed = bytearray(self.data)
        for label, (va, expected) in r.WINDOWS.items():
            with self.subTest(label=label):
                pos = r.offset_for(self.secs, va, len(bytes.fromhex(expected)), executable=True)
                changed[pos] ^= 1
                with self.assertRaisesRegex(ValueError, 'witness'):
                    r.check_window(changed, self.secs, va, expected)
                changed[pos] ^= 1
                r.check_window(changed, self.secs, va, expected)

    def test_fde_body_corruption_does_not_match_pinned_hash(self):
        va, end, expected = r.SELECTED['oid_table_grow']
        raw = bytearray(r.read_va(self.data, self.secs, va, end - va, executable=True))
        raw[-1] ^= 1
        self.assertNotEqual(r.digest(raw), expected)

    def test_corrupt_selected_unwind_extent_rejected_after_identity_gate(self):
        row = next(row for row in json.loads(self.generated['functions.json'])['functions']
                   if row['role'] == 'oid_table_grow')
        pos = r.offset_for(self.secs, int(row['fde_va'], 16), 16)
        changed = bytearray(self.data)
        changed[pos + 12] ^= 1
        # Bypass only the first guard to test the later, independent FDE check.
        with mock.patch.object(r, 'verified_data', side_effect=lambda data: data):
            with self.assertRaisesRegex(ValueError, 'unwind extent mismatch'):
                r.generate(changed)

    def test_address_must_be_file_backed(self):
        bss = next(s for s in self.secs if s['name'] == '.bss')
        self.assertEqual(bss['type'], 8)
        with self.assertRaisesRegex(ValueError, 'file backed'):
            r.read_va(self.data, self.secs, bss['address'], 1)
        with self.assertRaisesRegex(ValueError, 'file backed'):
            r.read_va(self.data, self.secs, 0xffffffffffffffff, 1)
        with self.assertRaises(ValueError):
            r.read_va(self.data, self.secs, -1, 1)
        with self.assertRaises(ValueError):
            r.read_va(self.data, self.secs, 0, 0)

    def test_section_boundary_and_ambiguity_rejected(self):
        sec = next(s for s in self.secs if s['name'] == '.text')
        with self.assertRaises(ValueError):
            r.read_va(self.data, [sec], sec['address'] + sec['size'] - 1, 2)
        with self.assertRaises(ValueError):
            r.offset_for([sec, sec.copy()], sec['address'], 1)
        with self.assertRaises(ValueError):
            r.offset_for([dict(sec, flags=0)], sec['address'], 1, executable=True)

    def test_branch_decode_exact_edges(self):
        row = r.branch(self.data, self.secs, 0x357a718)
        self.assertEqual(row['taken'], 0x357a87c)
        self.assertEqual(row['fallthrough'], 0x357a71e)
        self.assertEqual(row['condition'], 6)
        row = r.branch(self.data, self.secs, 0x379d3e1)
        self.assertEqual((row['taken'], row['fallthrough'], row['condition']), (0x379d434, 0x379d3e3, 4))

    def test_branch_opcode_and_displacement_corruption(self):
        changed = bytearray(self.data)
        site = 0x357a718
        pos = r.offset_for(self.secs, site, 6, executable=True)
        changed[pos] = 0x90
        with self.assertRaisesRegex(ValueError, 'conditional branch'):
            r.branch(changed, self.secs, site)
        changed[pos] = self.data[pos]
        changed[pos + 2] ^= 1
        self.assertNotEqual(r.branch(changed, self.secs, site)['taken'], 0x357a87c)
        changed[pos + 2] ^= 1
        changed[pos + 1] ^= 1
        self.assertEqual(r.branch(changed, self.secs, site)['condition'], 7)
        anchor, expected = r.WINDOWS['grow_capacity_decision']
        with self.assertRaisesRegex(ValueError, 'witness'):
            r.check_window(changed, self.secs, anchor, expected)

    def test_branch_inventory_is_bounded(self):
        rows = list(csv.DictReader(io.StringIO(self.generated['branches.tsv'].decode()), delimiter='\t'))
        self.assertEqual(len(rows), 38)
        for row in rows:
            start, end, _ = r.SELECTED[row['role']]
            self.assertTrue(start <= int(row['taken'], 16) < end)
            self.assertTrue(start <= int(row['fallthrough'], 16) < end)

    def test_direct_edges(self):
        site, kind, target = r.CALLS['counter_to_tracker_entry']
        got = r.call_edge(self.data, self.secs, self.relocs, site, kind, target)
        self.assertIsNone(got['slot'])
        self.assertEqual(got['target'], 0x3597020)
        with self.assertRaisesRegex(ValueError, 'target'):
            r.call_edge(self.data, self.secs, self.relocs, site, kind, target + 1)

    def test_indirect_edges_and_relocation(self):
        site, kind, target = r.CALLS['book_to_growth']
        got = r.call_edge(self.data, self.secs, self.relocs, site, kind, target)
        self.assertEqual((got['slot'], got['target']), (0x5773758, 0x357a6d0))
        altered = dict(self.relocs)
        altered[got['slot']] += 1
        with self.assertRaisesRegex(ValueError, 'target'):
            r.call_edge(self.data, self.secs, altered, site, kind, target)
        del altered[got['slot']]
        with self.assertRaisesRegex(ValueError, 'missing'):
            r.call_edge(self.data, self.secs, altered, site, kind, target)

    def test_call_opcode_and_displacement_corruption(self):
        changed = bytearray(self.data)
        site, kind, target = r.CALLS['rest_to_book_oid_put']
        pos = r.offset_for(self.secs, site, 5, executable=True)
        changed[pos] = 0x90
        with self.assertRaisesRegex(ValueError, 'direct call'):
            r.call_edge(changed, self.secs, self.relocs, site, kind, target)
        changed[pos] = self.data[pos]
        changed[pos + 1] ^= 1
        with self.assertRaisesRegex(ValueError, 'target'):
            r.call_edge(changed, self.secs, self.relocs, site, kind, target)

    def test_bad_relocation_sections_rejected(self):
        duplicate = struct.pack('<QQq', 0x1000, 8, 0x2000) * 2
        sec = {'name': '.rela.dyn', 'type': 4, 'offset': 0, 'address': 0, 'size': len(duplicate)}
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            r.relative_relocations(duplicate, [sec])
        with self.assertRaises(ValueError):
            r.relative_relocations(duplicate, [dict(sec, size=47)])
        with self.assertRaises(ValueError):
            r.relative_relocations(duplicate[:-1], [sec])
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            r.relocation_records(duplicate, [sec], {0x1000})
        with self.assertRaisesRegex(ValueError, 'missing'):
            r.relocation_records(duplicate[:24], [dict(sec, size=24, address=0)], {0x3000})

    def test_selected_relocation_raw_bytes(self):
        rows = list(csv.DictReader(io.StringIO(self.generated['relocations.tsv'].decode()), delimiter='\t'))
        self.assertEqual(len(rows), 8)
        for row in rows:
            raw = bytes.fromhex(row['raw_hex'])
            slot, info, addend = struct.unpack('<QQq', raw)
            self.assertEqual(info, 8)
            self.assertEqual(slot, int(row['slot'], 16))
            self.assertEqual(addend, int(row['relative_addend'], 16))
            pos = int(row['file_offset'], 16)
            self.assertEqual(raw, self.data[pos:pos + 24])

    def test_copy_comparison_masks_only_operands(self):
        source = r.read_va(self.data, self.secs, 0x379d360, 398, executable=True)
        for va in r.COPIES.values():
            target = r.read_va(self.data, self.secs, va, 398, executable=True)
            self.assertEqual(r.normalized(source), r.normalized(target))
        changed = bytearray(source)
        changed[0x116] ^= 1
        self.assertEqual(r.normalized(source), r.normalized(changed))
        changed[0x50] ^= 1
        self.assertNotEqual(r.normalized(source), r.normalized(changed))
        rows = list(csv.DictReader(io.StringIO(self.generated['context-copies.tsv'].decode()), delimiter='\t'))
        self.assertEqual([row['classification'] for row in rows], ['normalized_only', 'normalized_only'])
        for row in rows:
            self.assertEqual(r.digest(bytes.fromhex(row['raw_hex'])), row['raw_sha256'])
            self.assertEqual(r.digest(r.normalized(bytes.fromhex(row['raw_hex']))), row['masked_sha256'])

    def test_mask_cannot_exceed_body(self):
        with self.assertRaises(ValueError):
            r.normalized(b'\0' * 16)

    def test_masked_shuffle_operands_resolve_to_same_literal(self):
        for va in (0x379d360, *r.COPIES.values()):
            self.assertEqual(r.shuffle_target(self.data, self.secs, va + 0x112), 0x203480)
        changed = bytearray(self.data)
        pos = r.offset_for(self.secs, 0x379d472, 9, executable=True)
        changed[pos + 4] ^= 1
        self.assertNotEqual(r.shuffle_target(changed, self.secs, 0x379d472), 0x203480)
        changed[pos] ^= 1
        with self.assertRaises(ValueError):
            r.shuffle_target(changed, self.secs, 0x379d472)

    def test_failure_span_operand_and_length(self):
        self.assertEqual(r.lea_target(self.data, self.secs, 0x357ab72), 0x280866)
        rows = list(csv.DictReader(io.StringIO(self.generated['literals.tsv'].decode()), delimiter='\t'))
        diagnostic = next(row for row in rows if row['label'] == 'capacity_failure_span')
        self.assertEqual(int(diagnostic['length']), 57)
        self.assertTrue(bytes.fromhex(diagnostic['raw_hex']).startswith(b'Hash table capacity overflow'))
        changed = bytearray(self.data)
        pos = r.offset_for(self.secs, 0x357ab72, 7, executable=True)
        changed[pos] ^= 1
        with self.assertRaises(ValueError):
            r.lea_target(changed, self.secs, 0x357ab72)

    def test_hash_known_boundaries(self):
        k, rot = 0xf1357aea2e62a9c5, 20
        self.assertEqual(r.hash_key(0, k, rot), 0)
        self.assertEqual(r.hash_key(1, k, rot), 0xaea2e62a9c5f1357)
        self.assertEqual(r.hash_key(2, k, rot), 0x5d45cc5538ae26af)
        self.assertEqual(r.hash_key(1 << 63, k, rot), 0x80000)
        self.assertEqual(r.hash_key(r.U64, k, rot), 0x515d19d563b0eca8)

    def test_hash_rejects_out_of_range_keys_and_shifts(self):
        for key in (-1, 1 << 64, True):
            with self.subTest(key=key), self.assertRaises(ValueError):
                r.hash_key(key, 1, 20)
        for shift in (0, 64):
            with self.assertRaises(ValueError):
                r.hash_key(1, 1, shift)

    def test_growth_threshold_boundaries(self):
        self.assertEqual(r.growth_decision(15, 6, 1), ('rehash_in_place', 14, 7))
        self.assertEqual(r.growth_decision(15, 7, 1), ('allocate', 14, 8))
        self.assertEqual(r.growth_decision(31, 13, 1), ('rehash_in_place', 28, 14))
        self.assertEqual(r.growth_decision(31, 14, 1), ('allocate', 28, 15))
        self.assertEqual(r.growth_decision(0, 0, 1), ('allocate', 0, 1))

    def test_growth_invalid_input_and_overflow(self):
        self.assertEqual(r.growth_decision(15, r.U64, 1), ('overflow', None, None))
        for args in ((8, 0, 1), (4, 0, 1), (-1, 0, 1), (15, -1, 1), (15, 0, 1 << 64)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                r.growth_decision(*args)

    def test_tracker_counter_saturates(self):
        self.assertEqual(r.counter_after_rest(0), 1)
        self.assertEqual(r.counter_after_rest(r.U64 - 1), r.U64)
        self.assertEqual(r.counter_after_rest(r.U64), r.U64)
        for value in (-1, r.U64 + 1, True):
            with self.assertRaises(ValueError):
                r.counter_after_rest(value)

    def test_tracker_lookup_precedes_growth(self):
        self.assertEqual(r.tracker_route(True, False, False, False), ('existing', 'none', 'increment'))
        self.assertEqual(r.tracker_route(False, False, False, True), ('vacant', 'called', 'growth_failure'))
        self.assertEqual(r.tracker_route(False, False, True, False), ('vacant', 'called', 'date_failure'))
        self.assertEqual(r.tracker_route(False, True, False, True), ('vacant', 'none', 'insert_and_increment'))
        with self.assertRaises(ValueError):
            r.tracker_route(1, True, True, True)

    def test_tracker_bucket_store_geometry(self):
        rows = list(csv.DictReader(io.StringIO(self.generated['tracker-stores.tsv'].decode()), delimiter='\t'))
        actual = [(int(row['bucket_offset'], 16), int(row['width'])) for row in rows]
        self.assertEqual(actual, [(0, 8), (8, 8), (16, 4), (20, 16), (36, 16),
                                  (52, 16), (68, 4), (72, 4), (76, 8), (84, 2)])
        touched = {i for start, width in actual for i in range(start, start + width)}
        self.assertEqual(touched, set(range(86)))
        self.assertNotIn(86, touched)
        self.assertNotIn(87, touched)

    def test_constant_extraction_and_operand_corruption(self):
        rows = list(csv.DictReader(io.StringIO(self.generated['constants.tsv'].decode()), delimiter='\t'))
        values = {row['label']: int(row['value_decimal']) for row in rows}
        self.assertEqual(len(values), 18)
        self.assertEqual(values['hash_multiplier'], 0xf1357aea2e62a9c5)
        self.assertEqual(values['tracker_default_day'], 719163)
        self.assertEqual(values['book_oid_table_offset'], 0x28)
        self.assertEqual(values['state_tracker_table_offset'], 0x11c0)
        self.assertEqual(values['tracker_bucket_stride'], 0x58)
        changed = bytearray(self.data)
        for label, (site, expected, field, width) in r.CONSTANTS.items():
            with self.subTest(label=label):
                pos = r.offset_for(self.secs, site, len(bytes.fromhex(expected)), executable=True) + field
                changed[pos] ^= 1
                with self.assertRaisesRegex(ValueError, 'witness'):
                    r.check_window(changed, self.secs, site, expected)
                changed[pos] ^= 1

    def test_tracker_each_store_displacement_corruption(self):
        changed = bytearray(self.data)
        for label, (site, expected, width, displacement_index) in r.TRACKER_STORES.items():
            with self.subTest(label=label):
                raw_len = len(bytes.fromhex(expected))
                pos = r.offset_for(self.secs, site, raw_len, executable=True) + displacement_index
                changed[pos] ^= 1
                with self.assertRaisesRegex(ValueError, 'witness'):
                    r.check_window(changed, self.secs, site, expected)
                changed[pos] ^= 1

    def test_synthetic_collisions_and_replacements(self):
        multiplier, rotate = 0xf1357aea2e62a9c5, 20
        table = r.LogicalIndex(multiplier, rotate)
        keys = [k for k in range(256) if r.hash_key(k, multiplier, rotate) & 15 == 15][:4]
        self.assertEqual(len(keys), 4)
        for i, key in enumerate(keys):
            self.assertIsNone(table.put(key, 100 + i))
        self.assertEqual(table.items, 4)
        self.assertEqual(table.put(keys[1], 999), 101)
        self.assertEqual(table.logical_pairs(), {keys[0]: 100, keys[1]: 999, keys[2]: 102, keys[3]: 103})
        self.assertEqual(table.items, 4)

    def test_synthetic_full_duplicate_allocates_before_lookup(self):
        table = r.LogicalIndex(0xf1357aea2e62a9c5, 20)
        for key in range(14):
            table.put(key, key + 10)
        self.assertEqual(table.available, 0)
        self.assertEqual(table.put(0, 777), 10)
        self.assertEqual((table.buckets, table.items, table.available), (32, 14, 14))
        self.assertEqual(table.events, ['allocate'])

    def test_synthetic_tombstone_rebuild_preserves_live_pairs(self):
        table = r.LogicalIndex(0xf1357aea2e62a9c5, 20)
        for key in range(14):
            table.put(key, key + 10)
        for key in range(8):
            table.force_tombstone(key)
        self.assertEqual((table.items, table.available), (6, 0))
        table.put(42, 1000)
        expected = {key: key + 10 for key in range(8, 14)}
        expected[42] = 1000
        self.assertEqual(table.logical_pairs(), expected)
        self.assertEqual(table.events, ['rehash_in_place'])
        with self.assertRaises(ValueError):
            table.force_tombstone(0)

    def test_synthetic_many_updates_against_dictionary(self):
        table = r.LogicalIndex(0xf1357aea2e62a9c5, 20)
        expected = {}
        for key in list(range(64)) + list(range(63, -1, -1)):
            value = key * 11 + len(expected)
            previous = expected.get(key)
            self.assertEqual(table.put(key, value), previous)
            expected[key] = value
            self.assertEqual(table.logical_pairs(), expected)
        self.assertEqual(table.items, len(expected))
        for invalid in (-1, r.U64 + 1, True, None):
            with self.subTest(value=invalid), self.assertRaises(ValueError):
                table.put(0, invalid)

    def test_synthetic_rehash_exercises_all_three_arms(self):
        table = r.rehash_trial(0, 0xf1357aea2e62a9c5, 20)
        self.assertEqual((table.buckets, table.items, table.available), (64, 28, 28))
        self.assertEqual(table.rehash_counts, {'same_group': 19, 'move': 4, 'swap': 4})
        for seed in range(1, 16):
            trial = r.rehash_trial(seed, 0xf1357aea2e62a9c5, 20)
            self.assertEqual((trial.buckets, trial.items, trial.available), (64, 28, 28))
            trial.validate()

    def test_synthetic_rehash_control_and_pair_corruption(self):
        table = r.rehash_trial(0, 0xf1357aea2e62a9c5, 20)
        live = next(i for i, ctrl in enumerate(table.control) if ctrl < 0x80)
        old = table.control[live]
        table.control[live] ^= 1
        with self.assertRaisesRegex(ValueError, 'fingerprint'):
            table.validate()
        table.control[live] = old
        pair = table.pairs[live]
        table.pairs[live] = None
        with self.assertRaisesRegex(ValueError, 'fingerprint'):
            table.validate()
        table.pairs[live] = pair
        table.validate()

    def test_generated_file_names_and_fixtures(self):
        self.assertEqual(len(self.generated), 16)
        table = list(csv.DictReader(io.StringIO(self.generated['capacity-projections.tsv'].decode()), delimiter='\t'))
        self.assertEqual(len(table), 28)
        self.assertEqual(table[-1]['decision'], 'overflow')
        self.assertEqual(len(list(csv.DictReader(io.StringIO(self.generated['hash-projections.tsv'].decode()), delimiter='\t'))), 8)
        logical = list(csv.DictReader(io.StringIO(self.generated['logical-projections.tsv'].decode()), delimiter='\t'))
        self.assertEqual([row['growth_decision'] for row in logical], ['-', '-', 'allocate', 'rehash_in_place'])
        routes = list(csv.DictReader(io.StringIO(self.generated['tracker-projections.tsv'].decode()), delimiter='\t'))
        self.assertEqual(len(routes), 16)
        rehash = list(csv.DictReader(io.StringIO(self.generated['rehash-projections.tsv'].decode()), delimiter='\t'))
        self.assertEqual(len(rehash), 16)
        self.assertEqual((rehash[0]['same_group'], rehash[0]['moves'], rehash[0]['swaps']), ('19', '4', '4'))

    def test_generated_output_matches_retained_evidence(self):
        folder = r.ROOT / 'research/work-items/RE-006-rest-index-growth-94'
        for name, expected in self.generated.items():
            with self.subTest(name=name):
                self.assertEqual((folder / name).read_bytes(), expected)


if __name__ == '__main__':
    unittest.main()
