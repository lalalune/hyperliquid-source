import hashlib
import unittest

from tools import book_match_result_ownership94 as m


class OwnershipEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = bytearray(m.TARGET.read_bytes())
        cls.image = m.Image(cls.data)
        cls.result = m.collect(cls.data)

    def flip(self, offset, check):
        self.data[offset] ^= 1
        try:
            check()
        finally:
            self.data[offset] ^= 1

    def test_identity_and_selected_extents(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), m.SHA256)
        self.assertEqual(len(self.result['functions']), 4)
        self.assertEqual([x['length'] for x in self.result['functions']], [707, 100, 707, 100])
        self.assertEqual(len(self.result['windows']), 26)
        self.assertEqual(len(self.result['branches']), 46)
        self.assertEqual(len(self.result['calls']), 50)
        self.assertEqual(len(self.result['relocations']), 7)
        self.assertEqual([len(x['rows']) for x in self.result['lsdas']], [5, 5, 69, 61])

    def test_bad_target_digest_is_refused(self):
        self.flip(0, lambda: self.assertRaises(m.EvidenceError, m.authenticate, self.data))

    def test_every_selected_window_rejects_corruption(self):
        for record in self.result['windows']:
            with self.subTest(record['label']):
                off = int(record['file_offset'], 16) + len(bytes.fromhex(record['raw_hex'])) // 2
                self.flip(off, lambda: self.assertRaises(m.EvidenceError, m.selected_windows, self.image))

    def test_every_selected_body_rejects_corruption(self):
        for record in self.result['functions']:
            off = int(record['file_offset'], 16) + record['length'] // 2
            with self.subTest(function=record['start_va']):
                self.flip(off, lambda: self.assertRaises(m.EvidenceError, m.validate_bodies, self.image))

    def test_every_direct_and_indirect_call_rejects_changed_displacement(self):
        for record in self.result['calls']:
            site = int(record['site_va'], 16)
            off, raw = self.image.read(site, 6 if record['kind'] == 'rip-slot' else 5)
            with self.subTest(site=hex(site)):
                self.flip(off + len(raw) - 1,
                          lambda: self.assertRaises(m.EvidenceError, m.selected_edges, self.image))

    def test_every_selected_branch_rejects_changed_displacement(self):
        for record in self.result['branches']:
            site = int(record['site_va'], 16)
            raw = bytes.fromhex(record['raw_hex'])
            off, _ = self.image.read(site, len(raw))
            with self.subTest(site=hex(site)):
                self.flip(off + len(raw) - 1,
                          lambda: self.assertRaises(m.EvidenceError, m.selected_branches, self.image))

    def test_every_selected_branch_rejects_changed_predicate(self):
        for record in self.result['branches']:
            site = int(record['site_va'], 16)
            raw = bytes.fromhex(record['raw_hex'])
            off, _ = self.image.read(site, len(raw))
            with self.subTest(site=hex(site)):
                self.flip(off + (1 if len(raw) == 6 else 0),
                          lambda: self.assertRaises(m.EvidenceError, m.selected_branches, self.image))

    def test_every_selected_relocation_rejects_changed_addend(self):
        for record in self.result['relocations']:
            off = int(record['rela_file_offset'], 16)
            with self.subTest(slot=record['slot_va']):
                self.flip(off + 16, lambda: self.assertRaises(m.EvidenceError, self.image.relocations))

    def test_dynamic_symbols_are_bound(self):
        dynsym = next(x for x in self.image.sections if x['name'] == '.dynsym')
        dynstr = next(x for x in self.image.sections if x['name'] == '.dynstr')
        for name, slot in (('memcpy', '0x576dfe0'), ('_Unwind_Resume', '0x5778db0')):
            record = next(x for x in self.result['relocations'] if x['symbol_name'] == name)
            self.assertEqual(record['slot_va'], slot)
            start = dynsym['offset'] + record['symbol_index'] * 24
            name_off = int.from_bytes(self.data[start:start+4], 'little')
            self.flip(dynstr['offset'] + name_off,
                      lambda: self.assertRaises(m.EvidenceError, self.image.relocations))

    def test_unwind_plt_slot_and_corruption(self):
        self.assertEqual(self.result['plt_binding']['slot_va'], '0x5778db0')
        off, _ = self.image.read(0x5660110, 6)
        self.flip(off + 2, lambda: self.assertRaises(m.EvidenceError, m.plt_binding, self.image))

    def test_invalid_call_and_branch_opcodes_rejected(self):
        off, _ = self.image.read(0x32d5eb5, 5)
        self.flip(off, lambda: self.assertRaises(m.EvidenceError, m.call_target, self.image, 0x32d5eb5))
        off, _ = self.image.read(0x277b233, 2)
        self.flip(off, lambda: self.assertRaises(m.EvidenceError, m.selected_branches, self.image))

    def test_unbacked_and_invalid_ranges_rejected(self):
        bss = next(s for s in self.image.sections if s['name'] == '.bss' and s['type'] == 8)
        for addr, length in ((-1, 1), (0, 0), (1 << 63, 8), (bss['address'], 1)):
            with self.subTest(address=addr, length=length):
                with self.assertRaises(m.EvidenceError):
                    self.image.read(addr, length)

    def test_lsda_header_corruption_rejected(self):
        frames = {x['function_va']: x for x in self.result['lsdas']}
        for start in (0x277b220, 0x433f6a0, 0x26ebdc0, 0x430d610):
            lsda = frames[hex(start)]
            frame = {'start': start, 'end': (m.SELECTED[start][0] if start in m.SELECTED else m.CONTEXT[start]),
                     'lsda': int(lsda['lsda_va'], 16)}
            off = int(lsda['file_offset'], 16)
            with self.subTest(frame=hex(start)):
                self.flip(off, lambda: self.assertRaises(m.EvidenceError, m.decode_lsda, self.image, frame))

    def test_lsda_covers_growth_and_cleanup_calls(self):
        def landing(function, site):
            table = next(x for x in self.result['lsdas'] if x['function_va'] == hex(function))
            rows = [r for r in table['rows'] if int(r['start_va'], 16) <= site < int(r['end_va'], 16)]
            self.assertEqual(len(rows), 1)
            return rows[0]['landing_va']
        self.assertEqual(landing(0x26ebdc0, 0x26ed2e5), '0x26efdc6')
        self.assertEqual(landing(0x430d610, 0x430f206), '0x4311027')
        self.assertEqual(landing(0x277b220, 0x277b296), '0x277b44e')
        self.assertEqual(landing(0x277b220, 0x277b316), '0x277b449')
        self.assertEqual(landing(0x433f6a0, 0x433f716), '0x433f8ce')
        self.assertEqual(landing(0x433f6a0, 0x433f796), '0x433f8c9')

    def test_comparison_masks_are_explicit_and_local(self):
        comparisons = self.result['masked_comparisons']
        self.assertEqual([len(x['different_byte_offsets']) for x in comparisons], [7, 56])
        self.assertEqual([len(x['masks']) for x in comparisons], [3, 17])
        off, _ = self.image.read(0x277b220, 1)
        self.flip(off, lambda: self.assertRaises(m.EvidenceError, m.compare_masked, self.image,
                                                0x277b220, 0x433f6a0, 0x2c3, m.DROP_MASKS))
        # A masked displacement is deliberately ignored by this comparison alone.
        masked_off, _ = self.image.read(0x277b220 + 0x77, 1)
        self.flip(masked_off, lambda: m.compare_masked(self.image, 0x277b220, 0x433f6a0,
                                                       0x2c3, m.DROP_MASKS))

    def test_stride_and_growth_boundaries(self):
        self.assertEqual(self.result['derived_operands'], {
            'minimum_capacity': 4, 'double_threshold': 5,
            'wide_record_size': 568, 'narrow_record_size': 552,
            'vector20_element_size': 32, 'vector50_element_size': 40,
            'nested_element_size': 8})
        self.assertEqual(self.result['narrow_record_stores'], {
            'prefix_copy_bytes': 0x1f0, 'first_qword_store': 0x1f0,
            'second_qword_store': 0x1f8, 'third_qword_store': 0x200,
            'first_simd_store': 0x208, 'second_simd_store': 0x218})
        cases = [(0, 4), (1, 4), (2, 4), (3, 6), (4, 8),
                 ((1 << 63) - 1, (1 << 64) - 2), (1 << 63, 4),
                 ((1 << 64) - 1, (1 << 64) - 2)]
        for capacity, expected in cases:
            with self.subTest(capacity=capacity):
                self.assertEqual(m.growth(capacity, 4, 5), expected)
        for capacity in (-1, 1 << 64, True):
            with self.assertRaises(m.EvidenceError):
                m.growth(capacity, 4, 5)

    def test_cleanup_order_and_zero_controls(self):
        self.assertEqual(m.drop_projection(0, (0, 0, 0), (), 0x238),
                         ['visit-first-tree', 'visit-last-tree'])
        self.assertEqual(m.drop_projection(2, (1, 2, 3), (0, 1, 3), 0x238),
                         ['visit-first-tree', 'visit-optional-tree', 'vector-20:release:32',
                          'vector-38:release:1136', 'vector-50:release:120', 'visit-last-tree',
                          'inner:release:8', 'inner:release:24'])
        self.assertIn('vector-38:release:1104', m.drop_projection(1, (0, 2, 0), (), 0x228))
        for args in ((-1, (0, 0, 0), (), 0x238), (1, (4, 0, 0), (), 0x238),
                     (1, (0, 0, 0), (), 0x230), (1, (0, 0), (), 0x238)):
            with self.assertRaises(m.EvidenceError):
                m.drop_projection(*args)

    def test_output_transfer_and_partial_cleanup_are_pinned(self):
        self.assertEqual(self.result['derived_layout'], {
            'first_tree': 0x78, 'first_tree_second_word': 0x80, 'first_tree_third_word': 0x88,
            'optional_tree_root': 0x08,
            'vector20_capacity': 0x20, 'vector20_pointer': 0x28,
            'vector38_capacity': 0x38, 'vector38_pointer': 0x40,
            'vector50_capacity': 0x50, 'vector50_pointer': 0x58,
            'last_tree': 0x90, 'last_tree_second_word': 0x98, 'last_tree_third_word': 0xa0})
        self.assertEqual(self.result['success_transfer'], {
            'source_vector_header': 0x38, 'source_vector_length': 0x48,
            'source_last_tree_header': 0x90, 'source_last_tree_third_word': 0xa0,
            'result_vector_length': 0x10, 'result_tree_first_word': 0x18,
            'result_tree_second_word': 0x20, 'result_tree_third_word': 0x28})
        windows = {x['label']: bytes.fromhex(x['raw_hex']) for x in self.result['windows']}
        # Two unaligned SIMD stores publish the three-qword result groups.
        self.assertIn(bytes.fromhex('f3410f7f00'), windows['success-transfer-wide'])
        self.assertIn(bytes.fromhex('49895018'), windows['success-transfer-wide'])
        # Success releases the +0x20 and +0x50 vectors using 0x20 and 0x28 widths.
        self.assertIn(bytes.fromhex('48c1e605'), windows['success-cleanup-wide'])
        self.assertIn(bytes.fromhex('488d3480'), windows['success-cleanup-wide'])
        # Full cleanup separately uses the matching per-variant vector widths.
        self.assertIn(bytes.fromhex('4869f038020000'), windows['drop-wide-vectors'])
        self.assertIn(bytes.fromhex('4869f028020000'), windows['drop-narrow-vectors'])


if __name__ == '__main__':
    unittest.main()
