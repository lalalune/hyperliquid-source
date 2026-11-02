"""Offline positive and negative controls for node 115 registry refresh."""
import copy
import csv
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import re21_registry_refresh115 as evidence


class RegistryRefreshTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = evidence.TARGET.read_bytes()
        cls.image = evidence.Image(cls.data)
        cls.outputs = evidence.project(cls.image)

    def corrupt_read(self, address, xor=1):
        altered = copy.copy(self.image)
        original = self.image.read

        def read(va, size):
            raw = bytearray(original(va, size))
            if va <= address < va + size:
                raw[address - va] ^= xor
            return bytes(raw)

        altered.read = read
        return altered

    def altered_relocation(self, slot, *, info=None, addend=None, duplicate=False):
        altered = copy.copy(self.image)
        altered._relocations = dict(self.image.relocations())
        old_info, old_addend, offset, raw = altered._relocations[slot][0]
        row = (old_info if info is None else info,
               old_addend if addend is None else addend, offset, raw)
        altered._relocations[slot] = [row, row] if duplicate else [row]
        return altered

    def test_target_digest_and_truncation(self):
        evidence.check_digest(self.data)
        for data in (self.data[:128], b'not the authenticated target'):
            with self.subTest(size=len(data)), self.assertRaisesRegex(ValueError, 'SHA-256'):
                evidence.check_digest(data)

    def test_fde_index_join_and_full_body(self):
        rows = self.outputs['functions.json']
        self.assertEqual(len(rows), 10)
        self.assertEqual(len({x['start_va'] for x in rows}), 10)
        for row in rows:
            self.assertEqual(len(bytes.fromhex(row['body_bytes'])), row['size'])
            self.assertTrue(row['fde_bytes'])
            self.assertTrue(row['cie_bytes'])

    def test_missing_and_duplicate_fde_rejected(self):
        for mode in ('missing', 'duplicate'):
            altered = copy.copy(self.image)
            altered.fdes = dict(self.image.fdes)
            if mode == 'missing':
                altered.fdes.pop(0x2a6b7a0)
            else:
                altered.fdes[0x2a6b7a0] = altered.fdes[0x2a6b7a0] * 2
            with self.subTest(mode=mode), self.assertRaisesRegex(ValueError, 'FDE'):
                altered.functions()

    def test_wrong_fde_end_rejected(self):
        altered = copy.copy(self.image)
        altered.fdes = dict(self.image.fdes)
        record = dict(altered.fdes[0x2a6b7a0][0])
        record['end'] += 1
        altered.fdes[0x2a6b7a0] = [record]
        with self.assertRaisesRegex(ValueError, 'FDE/index'):
            altered.functions()

    def test_changed_body_byte_rejected(self):
        with self.assertRaisesRegex(ValueError, 'body digest'):
            self.corrupt_read(0x2a6b7f4).functions()

    def test_unbacked_cross_section_and_invalid_ranges_rejected(self):
        bss = next(s for s in self.image.sections if s['name'] == '.bss')
        code = next(s for s in self.image.sections if s['name'] == '.text')
        for va, size in ((bss['address'], 1), (code['address'] + code['size'] - 1, 2),
                         (0xffffffffffffffff, 2), (code['address'], 0), (-1, 1)):
            with self.subTest(va=va, size=size), self.assertRaises(ValueError):
                self.image.locate(va, size)

    def test_ambiguous_mapping_rejected(self):
        altered = copy.copy(self.image)
        code = next(s for s in self.image.sections if s['name'] == '.text')
        altered.sections = self.image.sections + [dict(code)]
        with self.assertRaisesRegex(ValueError, 'uniquely'):
            altered.locate(0x2a6b7a0, 1)

    def test_relocation_type_addend_and_duplicates(self):
        for altered in (self.altered_relocation(0x64e7158, info=7),
                        self.altered_relocation(0x64e7158, duplicate=True)):
            with self.assertRaises(ValueError):
                altered.relative_relocation(0x64e7158)
        with self.assertRaisesRegex(ValueError, 'relocation addend'):
            evidence.project(self.altered_relocation(0x64e7158, addend=1))
        with self.assertRaises(ValueError):
            self.image.relative_relocation(0xffffffffffffffff)

    def test_record_anchor_corruption_rejected(self):
        with self.assertRaisesRegex(ValueError, 'address-09 record'):
            evidence.project(self.corrupt_read(0x64c0730))
        with self.assertRaisesRegex(ValueError, 'address-09 record'):
            evidence.project(self.corrupt_read(0x64c0730 + 32))
        with self.assertRaisesRegex(ValueError, 'address-09 record'):
            evidence.project(self.altered_relocation(0x64c0730 + 24, addend=0))

    def test_selector_table_and_equal_mode_transition(self):
        rows = self.outputs['mode-cases.tsv']
        self.assertEqual(len(rows), 15)
        self.assertEqual([r['entry_byte'] for r in rows],
                         [0, 0, 0, 0, 1, 1, 2, 3, 3, 3, 3, 4, 5, 6, 6])
        self.assertEqual(rows[7]['entry_byte'], rows[8]['entry_byte'])
        self.assertEqual(evidence.refresh_decision(7, 8, 1)['rebuild_projection'], 1)
        self.assertEqual(evidence.refresh_decision(7, 7, 1)['rebuild_projection'], 0)
        self.assertEqual(evidence.refresh_decision(7, 7, 0)['rebuild_projection'], 1)

    def test_selector_data_corruption_rejected(self):
        with self.assertRaisesRegex(ValueError, 'selector-table'):
            evidence.project(self.corrupt_read(0x606f1f + 7))

    def test_selector_address_copy_threshold(self):
        self.assertEqual(evidence.refresh_decision(9, 9, 1)['copy_extra_address'], 0)
        self.assertEqual(evidence.refresh_decision(9, 10, 1)['copy_extra_address'], 1)
        for args in ((-1, 0, 0), (0, 256, 0), (0, 0, -1)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                evidence.refresh_decision(*args)

    def test_replacement_builder_values_and_call_targets(self):
        rows = evidence.set_calls(self.image)
        self.assertEqual(len(rows), 21)
        self.assertEqual([int(r['key_hex'], 16) for r in rows],
                         [0x800, 0x813] + list(range(0x801, 0x813)) + [0x814])
        self.assertTrue(all(r['callee_va'] == '0x3ed7620' for r in rows))
        self.assertNotIn(9, [int(r['key_hex'], 16) for r in rows])

    def test_builder_instruction_and_source_corruption_rejected(self):
        with self.assertRaises(ValueError):
            evidence.set_calls(self.corrupt_read(0x38be4d8 + 29))
        with self.assertRaises(ValueError):
            evidence.set_calls(self.corrupt_read(0x38be4d8 + 2))
        with self.assertRaises(ValueError):
            evidence.project(self.corrupt_read(0x646e4e0 + 19))

    def test_small_key_boundary(self):
        for number in (0, 9, 299):
            self.assertEqual(evidence.small_key(number.to_bytes(20, 'big'), 300), number)
        for number in (300, 0x800, 0x814, 65535):
            self.assertIsNone(evidence.small_key(number.to_bytes(20, 'big'), 300))
        self.assertIsNone(evidence.small_key(b'\x01' + bytes(18) + b'\x09', 300))
        for key, limit in ((bytes(19), 300), (bytes(21), 300), (bytes(20), -1)):
            with self.subTest(size=len(key), limit=limit), self.assertRaises(ValueError):
                evidence.small_key(key, limit)

    def test_every_address_09_bit_matters_for_full_key(self):
        key = (9).to_bytes(20, 'big')
        controls = [255] * 32
        keys = [None] * 32
        controls[31] = 0
        keys[31] = key
        self.assertEqual(evidence.probe20(controls, keys, 31, key), 31)
        for bit in range(160):
            changed = bytearray(key)
            changed[bit // 8] ^= 1 << (bit % 8)
            self.assertIsNone(evidence.probe20(controls, keys, 31, bytes(changed)), bit)

    def test_probe_wraparound_tombstones_and_fingerprint_collision(self):
        key, other = bytes(19) + b'\x09', bytes(19) + b'\x08'
        controls = [0x80] * 32
        keys = [None] * 32
        controls[30] = 0
        keys[30] = other
        controls[2] = 0
        keys[2] = key
        controls[3] = 0xff
        self.assertEqual(evidence.probe20(controls, keys, 30, key), 2)
        self.assertIsNone(evidence.probe20(controls, keys, 30, bytes(20)))
        controls[3] = 0x80
        with self.assertRaisesRegex(ValueError, 'no reachable empty'):
            evidence.probe20(controls, keys, 30, bytes(20))

    def test_probe_rejects_bad_tables_and_hashes(self):
        cases = [([255] * 15, [None] * 15, 0, bytes(20)),
                 ([255] * 16, [None] * 15, 0, bytes(20)),
                 ([256] * 16, [None] * 16, 0, bytes(20)),
                 ([255] * 16, [None] * 16, -1, bytes(20)),
                 ([255] * 16, [None] * 16, 0, bytes(19))]
        for args in cases:
            with self.subTest(args=args), self.assertRaises(ValueError):
                evidence.probe20(*args)

    def test_hash_fold_arithmetic_and_bad_inputs(self):
        mask = (1 << 64) - 1
        self.assertEqual(evidence.fold64(mask, mask), mask)
        self.assertEqual(evidence.fold64(0, mask), 0)
        self.assertEqual(evidence.hash20(bytes(20), 0, 0), 0)
        for a, b in ((-1, 0), (0, 1 << 64)):
            with self.assertRaises(ValueError):
                evidence.fold64(a, b)
        with self.assertRaises(ValueError):
            evidence.hash20(bytes(19), 0, 0)

    def test_hash_word_arithmetic_against_bitwise_multiply(self):
        def slow_fold(a, b):
            product = sum((a << i) for i in range(64) if (b >> i) & 1)
            return (product & ((1 << 64) - 1)) ^ (product >> 64)

        key = bytes(range(20))
        seed = 0x0123456789abcdef
        secret = 0xfedcba9876543210
        a = int.from_bytes(key[:8], 'little')
        b = int.from_bytes(key[8:16], 'little')
        c = int.from_bytes(key[16:], 'little')
        expected = slow_fold(slow_fold(a ^ seed, b ^ secret) ^ c, secret)
        self.assertEqual(evidence.hash20(key, seed, secret), expected)
        self.assertNotEqual(evidence.hash20(key, seed, secret),
                            evidence.hash20(key, seed, secret ^ 1))

    def test_prior_pr_boundaries_are_not_selected_bodies(self):
        selected = {start for start, _, _, _ in evidence.FUNCTIONS}
        self.assertNotIn(0x3ec4290, selected)
        self.assertNotIn(0x3ed7620, selected)
        self.assertEqual(self.outputs['runtime-boundary.json']['target_section'], '.bss')
        self.assertIsNone(self.outputs['runtime-boundary.json']['runtime_secret_value'])

    def test_foreign_transfer_and_window_rejected(self):
        with patch.object(evidence, 'EDGES', evidence.EDGES + (('foreign', 0x3ed7620),)):
            with self.assertRaisesRegex(ValueError, 'outside the selected FDEs'):
                evidence.project(self.image)
        with patch.object(evidence, 'WINDOWS', evidence.WINDOWS + (('foreign', 0x3ed7620, 0x3ed7621),)):
            with self.assertRaisesRegex(ValueError, 'outside the selected FDEs'):
                evidence.project(self.image)

    def test_nested_growth_guards_are_on_opposite_sides_of_lookup(self):
        edges = {row['name']: row for row in self.outputs['edges.tsv']}
        self.assertEqual(edges['map_miss_growth']['target_va'], '0x2a319fd')
        self.assertLess(int(edges['map_empty']['site_va'], 16), int(edges['map_miss_growth']['site_va'], 16))
        self.assertEqual(edges['nested_growth']['target_va'], '0x2a32c61')
        self.assertLess(int(edges['nested_growth']['site_va'], 16), int(edges['nested_duplicate']['site_va'], 16))

    def test_nested_key_byte_order_and_length_controls(self):
        self.assertEqual(self.image.read(0x2668d4f, 12), bytes.fromhex('480fce480fca480fc9480fc8'))
        key = bytes(range(32))
        self.assertEqual(evidence.nested_key32(key), key[::-1])
        changed = key[:-1] + b'\xff'
        self.assertEqual(evidence.nested_key32(changed)[0], 0xff)
        for bad in (bytes(31), bytes(33)):
            with self.assertRaisesRegex(ValueError, 'not 32 bytes'):
                evidence.nested_key32(bad)

    def test_reserve_sizes_against_capacity_oracle(self):
        for requested in range(1, 100):
            result = evidence.model_reserve(0, 0, requested)
            candidate = 4
            while (candidate - 1 if candidate < 8 else candidate - candidate // 8) < requested:
                candidate *= 2
            self.assertEqual(result['buckets'], candidate, requested)
            self.assertEqual(result['bytes'], ((20 * candidate + 15) // 16) * 16 + candidate + 16)
        self.assertEqual(evidence.model_reserve(7, 3, 0), {'action': 'in_place'})
        self.assertEqual(evidence.model_reserve(7, 3, 1),
                         {'action': 'allocate', 'buckets': 16, 'bytes': 352})
        self.assertEqual(evidence.model_reserve(15, 7, 1),
                         {'action': 'allocate', 'buckets': 32, 'bytes': 688})

    def test_reserve_overflow_and_bad_mask_controls(self):
        for args in ((0, (1 << 64) - 1, 1), (0, 0, 1 << 61),
                     (0, 0, 1 << 58), (0, 0, 1 << 59), (5, 0, 1),
                     (-1, 0, 0), (0, -1, 0), (0, 0, 1 << 64)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                evidence.model_reserve(*args)

    def test_transfer_decoder_rejects_wrong_shape_and_range(self):
        with self.assertRaises(ValueError):
            evidence.transfer(self.corrupt_read(0x2a6b7f4, xor=0xff), 0x2a6b7f4)
        with self.assertRaises(ValueError):
            evidence.transfer(self.image, 0xffffffffffffffff)

    def test_lsda_ranges_and_builder_cleanup(self):
        headers, rows = evidence.exception_tables(self.image)
        self.assertEqual(len(headers), 4)
        self.assertEqual(len(rows), 15)
        calls = {r['name']: r for r in self.outputs['selected-call-sites.tsv']}
        for index in range(21):
            self.assertEqual(calls[f'set_insert_0x38be4a0_{index}']['landing_va'], '0x38be7e1')
        self.assertEqual(calls['nested_insert']['landing_va'], '0x2668e65')
        self.assertEqual(calls['set_builder']['coverage'], 'no selected table entry')

    def test_lsda_header_corruption_rejected(self):
        for address in (0x2d0034, 0x22a454):
            with self.subTest(va=address), self.assertRaises(ValueError):
                evidence.exception_tables(self.corrupt_read(address))

    def test_lsda_overlapping_ranges_rejected(self):
        rows = self.outputs['lsda-call-sites.tsv']
        selected = next(r for r in rows if r['entry_va'] == '0x2d003c')
        with self.assertRaisesRegex(ValueError, 'overlapping'):
            evidence.correlate_calls(self.outputs['edges.tsv'], self.outputs['set-copies.tsv'],
                                     rows + [selected])

    def test_evidence_regenerates_byte_for_byte(self):
        saved = ROOT / 'research/work-items/RE-021-precompile-refresh-115'
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            evidence.write_outputs(output, self.outputs)
            self.assertEqual(set(p.name for p in output.iterdir()), set(self.outputs))
            for name in self.outputs:
                with self.subTest(name=name):
                    self.assertEqual((output / name).read_bytes(), (saved / name).read_bytes())

    def test_generated_tables_are_parseable(self):
        saved = ROOT / 'research/work-items/RE-021-precompile-refresh-115'
        for name, rows in self.outputs.items():
            if name.endswith('.tsv'):
                with (saved / name).open(newline='', encoding='ascii') as source:
                    self.assertEqual(len(list(csv.DictReader(source, delimiter='\t'))), len(rows))


if __name__ == '__main__':
    unittest.main()
