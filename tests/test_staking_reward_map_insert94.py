"""Target-grounded controls for the staking reward-map insertion packet."""
import hashlib
import unittest

from tools import staking_reward_map_insert94 as m


class RewardMapInsertionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = m.load_image()

    def test_input_digest(self):
        self.assertEqual(hashlib.sha256(self.image.blob).hexdigest(), m.SHA256)

    def test_wrong_digest_fails_closed(self):
        with self.assertRaisesRegex(m.EvidenceError, 'SHA-256 mismatch'):
            m.load_image(expected='0' * 64)

    def test_selected_fdes_and_exact_bodies(self):
        m.validate_image(self.image)
        self.assertEqual(self.image.exact_fde(m.FUNCTIONS['stage']), (0x2f3f5d0, 0x2f40166))
        self.assertEqual(self.image.exact_fde(m.FUNCTIONS['compound']), (0x2f46550, 0x2f47169))

    def test_non_fde_address_rejected(self):
        with self.assertRaises(m.EvidenceError):
            self.image.exact_fde(m.FUNCTIONS['stage'] + 1)

    def test_unmapped_address_rejected(self):
        with self.assertRaises(m.EvidenceError):
            m.at(self.image, 0xffffffffffffffff, 1)

    def test_range_crossing_section_rejected(self):
        text = m.unique_section(self.image, '.text')
        with self.assertRaises(m.EvidenceError):
            m.at(self.image, text['address'] + text['size'] - 1, 2)

    def test_caller_transfers_and_zero_value(self):
        m.validate_context(self.image)
        for site, role in m.CALL_SITES:
            self.assertEqual(m.call_target(self.image, site), m.FUNCTIONS[role])
        for site, pattern in m.POST_SITES:
            self.assertEqual(m.at(self.image, site, len(bytes.fromhex(pattern))), bytes.fromhex(pattern))

    def test_non_call_bytes_rejected(self):
        with self.assertRaisesRegex(m.EvidenceError, 'not a direct'):
            m.call_target(self.image, m.FUNCTIONS['stage'])

    def test_import_relocations(self):
        rel = m.relocation_records(self.image)
        self.assertEqual(rel[m.SLOT_MEMCPY][3], 'memcpy')
        self.assertEqual(rel[m.SLOT_MEMMOVE][3], 'memmove')
        self.assertEqual(rel[m.SLOT_ALLOC][0], 8)

    def test_linear_decode_ends_at_fde(self):
        for addr in m.FUNCTIONS.values():
            start, end = self.image.exact_fde(addr)
            rows = m.decode_range(self.image, start, end)
            self.assertEqual(rows[-1].next, end)
            self.assertTrue(all(start <= r.va < end for r in rows))
            row_starts = {r.va for r in rows}
            for row in rows:
                if row.op in ('jcc', 'jmp'):
                    self.assertIn(row.target, row_starts)

    def test_stage_all_leaf_gaps(self):
        for count in range(12):
            for gap in range(count + 1):
                with self.subTest(count=count, gap=gap):
                    r = m.evaluate(self.image, m.FUNCTIONS['stage'], (), (), count, gap)
                    self.assertEqual(r['keys'], count+1)
                    self.assertEqual(r['depth'], int(count == 11))

    def test_compound_all_leaf_gaps(self):
        for count in range(12):
            for gap in range(count + 1):
                with self.subTest(count=count, gap=gap):
                    r = m.evaluate(self.image, m.FUNCTIONS['compound'], (), (), count, gap)
                    self.assertEqual(r['keys'], count+1)
                    self.assertEqual(r['depth'], int(count == 11))

    def test_promotion_and_root_allocation(self):
        for name, leaf, internal in (('stage', 0x140, 0x1a0), ('compound', 0x150, 0x1b0)):
            for gap in range(12):
                with self.subTest(role=name, gap=gap):
                    r = m.evaluate(self.image, m.FUNCTIONS[name], (), (), 11, gap)
                    self.assertEqual(r['pivot'], 4 if gap < 5 else 5 if gap <= 6 else 6)
                    self.assertEqual(r['allocations'], [leaf, internal])
                    self.assertEqual(r['left_count'] + r['right_count'], 11)

    def test_parent_absorbs_promotion(self):
        for name, leaf in (('stage', 0x140), ('compound', 0x150)):
            r = m.evaluate(self.image, m.FUNCTIONS[name], (10,), (5,), 11, 7)
            self.assertEqual(r['allocations'], [leaf])
            self.assertEqual(r['depth'], 1)

    def test_three_ancestor_cascade(self):
        for name, leaf, internal in (('stage', 0x140, 0x1a0), ('compound', 0x150, 0x1b0)):
            r = m.evaluate(self.image, m.FUNCTIONS[name], (11,11,11), (0,5,11), 11, 6)
            self.assertEqual(r['depth'], 4)
            self.assertEqual(r['allocations'], [leaf, internal, internal, internal, internal])

    def test_compound_key_kinds_and_amount_bounds(self):
        for kind in (0, 1):
            for amount in (0, (1 << 64)-1):
                for gap in (0, 4, 5, 6, 7, 11):
                    with self.subTest(kind=kind, amount=amount, gap=gap):
                        m.evaluate(self.image, m.FUNCTIONS['compound'], (11,), (6,), 11, gap,
                                   kind=kind, inserted_value=amount)

    def test_compound_same_address_different_kinds(self):
        for gap in (1, 5, 6, 11):
            result = m.evaluate(self.image, m.FUNCTIONS['compound'], (11,), (6,), 11, gap,
                                kind=1, inserted_value=m.MASK[8], same_address=True)
            old = bytes.fromhex(result['related_existing'])
            new = bytes.fromhex(result['inserted_key'])
            self.assertEqual(old[:20], new[:20])
            self.assertEqual((old[20], new[20]), (0, 1))

    def test_stage_amount_bounds(self):
        for amount in (0, (1 << 64)-1):
            m.evaluate(self.image, m.FUNCTIONS['stage'], (11,), (6,), 11, 5, inserted_value=amount)

    def test_invalid_fixture_arguments(self):
        with self.assertRaises(ValueError):
            m.evaluate(self.image, m.FUNCTIONS['compound'], (), (), 1, 2)
        with self.assertRaises(ValueError):
            m.evaluate(self.image, m.FUNCTIONS['compound'], (), (), 0, 0, kind=2)
        with self.assertRaises(ValueError):
            m.evaluate(self.image, m.FUNCTIONS['stage'], (), (), 0, 0, inserted_value=1 << 64)

    def test_allocation_failure_paths(self):
        for addr in m.FUNCTIONS.values():
            for fail, counts, edges in ((1, (), ()), (2, (), ()), (2, (11,), (6,)), (3, (11,), (6,))):
                with self.subTest(addr=addr, fail=fail, counts=counts):
                    r = m.evaluate(self.image, addr, counts, edges, 11, 5,
                                   fail_alloc_at=fail, expect_panic=True)
                    self.assertIn('failure sink reached', r['panic'])

    def test_corrupt_node_count_and_root(self):
        for addr in m.FUNCTIONS.values():
            for opts in (dict(corrupt_leaf_count=22), dict(null_root=True),
                         dict(root_height_override=m.MASK[8]), dict(root_height_override=1)):
                with self.subTest(addr=addr, opts=opts):
                    r = m.evaluate(self.image, addr, (), (), 11, 5, expect_panic=True, **opts)
                    self.assertIn('failure sink reached', r['panic'])
            m.evaluate(self.image, addr, (11,), (0,), 11, 5,
                       corrupt_parent_count=22, expect_panic=True)

    def test_capacity_pivot_key_and_branch_corruption(self):
        for name, start in m.FUNCTIONS.items():
            for label, off, byte, count, gap in m.MUTATIONS[name]:
                with self.subTest(role=name, mutation=label):
                    with self.assertRaises((m.Halt, m.Panicked, m.EvidenceError)):
                        m.evaluate(self.image, start, (), (), count, gap, patches={start+off:byte})

    def test_mutated_body_hash_rejected(self):
        # Alter one selected opcode without changing the ELF metadata.
        original = self.image.blob
        off = self.image.offset(m.FUNCTIONS['stage'])
        try:
            self.image.blob = original[:off] + bytes((original[off] ^ 1,)) + original[off+1:]
            with self.assertRaisesRegex(m.EvidenceError, 'unexpected function body'):
                m.validate_image(self.image)
        finally:
            self.image.blob = original

    def test_context_byte_corruption_rejected(self):
        original = self.image.blob
        off = self.image.offset(m.CONTEXT_SITES[0][1])
        try:
            self.image.blob = original[:off] + bytes((original[off] ^ 1,)) + original[off+1:]
            with self.assertRaisesRegex(m.EvidenceError, 'anchor mismatch'):
                m.validate_context(self.image)
        finally:
            self.image.blob = original

    def test_overlapping_memcpy_is_rejected(self):
        f = m.Fixture(self.image, layout=m.LAYOUT_STAGE)
        f.machine.regs[m.RDI] = m.ARENA
        f.machine.regs[m.RSI] = m.ARENA + 1
        f.machine.regs[m.RDX] = 8
        with self.assertRaisesRegex(m.Halt, 'overlapping memcpy'):
            f.on_memcpy(f.machine)
        # The distinct memmove hook explicitly permits overlap.
        f.on_copy(f.machine)

    def test_model_detects_unsorted_corruption(self):
        f = m.Fixture(self.image, layout=m.LAYOUT_STAGE)
        root, _ = f.build((), (), 2, 1)
        first = root + f.layout['key']
        f.put(first, bytes([255])*f.layout['key_width'])
        with self.assertRaisesRegex(m.Halt, 'key order'):
            f.inspect(root, 0)


if __name__ == '__main__':
    unittest.main()
