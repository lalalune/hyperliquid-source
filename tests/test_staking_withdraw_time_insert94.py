"""Target-bound controls for the withdrawal time-index insertion study."""
import struct
import unittest
from pathlib import Path

from tools import staking_withdraw_time_insert94 as study


class WithdrawalTimeInsertTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = study.load_image()

    def test_target_digest_rejected(self):
        with self.assertRaisesRegex(study.EvidenceError, 'SHA-256 mismatch'):
            study.load_image(expected='0' * 64)

    def test_fde_bounds(self):
        self.assertEqual(self.image.exact_fde(study.SUBJECT), (study.SUBJECT, study.END))
        with self.assertRaises(study.EvidenceError):
            self.image.exact_fde(study.SUBJECT + 1)

    def test_bad_address_and_nobits_rejected(self):
        with self.assertRaises(study.EvidenceError):
            study.at(self.image, 0xffffffffffffffff, 1)
        bss = next(s for s in self.image.sections if s['type'] == 8 and s['name'] == '.bss')
        with self.assertRaises(study.EvidenceError):
            study.at(self.image, bss['address'], 1)

    def test_body_and_context_pins(self):
        rows = study.validate_image(self.image)
        self.assertEqual(rows[0].va, study.SUBJECT)
        self.assertEqual(rows[-1].next, study.END)
        self.assertEqual(study.call_target(self.image, 0x33bffcd), study.SUBJECT)

    def corrupt_pin_and_reject(self, address):
        original = self.image.blob
        try:
            patched = bytearray(original)
            patched[self.image.offset(address)] ^= 1
            self.image.blob = patched
            with self.assertRaises(study.EvidenceError):
                study.validate_image(self.image)
        finally:
            self.image.blob = original

    def test_corrupt_function_byte_rejected(self):
        self.corrupt_pin_and_reject(study.SUBJECT + 3)

    def test_corrupt_caller_byte_rejected(self):
        self.corrupt_pin_and_reject(0x33bffcd + 1)

    def test_corrupt_append_site_rejected(self):
        self.corrupt_pin_and_reject(0x3c13344)

    def test_nonfull_leaf_all_gaps(self):
        for count in (0, 1, 5, 10):
            for gap in range(count + 1):
                result = study.evaluate(self.image, study.SUBJECT, (), (), count, gap)
                self.assertEqual((result['keys'], result['depth'], result['allocations']),
                                 (count+1, 0, []))
                self.assertEqual(result['returned_slot'], gap)

    def test_split_pivots_all_gaps(self):
        for gap in range(12):
            result = study.evaluate(self.image, study.SUBJECT, (), (), 11, gap)
            pivot = 4 if gap < 5 else 5 if gap <= 6 else 6
            self.assertEqual(result['pivot'], pivot)
            self.assertEqual(result['depth'], 1)
            self.assertEqual(result['allocations'], [0x198, 0x1f8])

    def test_cascading_split_and_parent_links(self):
        result = study.evaluate(self.image, study.SUBJECT, (11, 11), (6, 7), 11, 6)
        self.assertEqual(result['depth'], 3)
        self.assertEqual(result['allocations'], [0x198, 0x1f8, 0x1f8, 0x1f8])

    def test_sequential_insertions_preserve_rows(self):
        n, height, allocations, _, _ = study.sequence(
            self.image, [study.KEY_BASE + 2*i for i in range(180, 0, -1)])
        self.assertEqual(n, 180)
        self.assertEqual(height, 2)
        self.assertGreater(allocations, 2)

    def test_mixed_time_components_survive_split(self):
        times = study.varied_times()
        n, height, _, _, _ = study.sequence(self.image, [study.rank_time(*row) for row in times])
        self.assertEqual((n, height), (16, 1))

    def test_time_width_boundaries_are_checked(self):
        self.assertLess(study.rank_time(-1, 0xffffffff, 0xffffffff), study.rank_time(0, 0, 0))
        for components in ((-(1 << 31)-1, 0, 0), (1 << 31, 0, 0), (0, -1, 0), (0, 0, 1 << 32)):
            with self.assertRaises(ValueError):
                study.rank_time(*components)

    def test_duplicate_sequence_is_not_a_vacant_cursor(self):
        with self.assertRaisesRegex(ValueError, 'duplicate key'):
            study.sequence(self.image, [study.KEY_BASE + 2, study.KEY_BASE + 2])

    def test_leaf_allocation_failure(self):
        result = study.evaluate(self.image, study.SUBJECT, (), (), 11, 5,
                                fail_alloc_at=1, expect_panic=True)
        self.assertIn('0x2f51292', result['panic'])

    def test_parent_allocation_failure(self):
        result = study.evaluate(self.image, study.SUBJECT, (11,), (6,), 11, 5,
                                fail_alloc_at=2, expect_panic=True)
        self.assertIn('0x2f51241', result['panic'])

    def test_corrupt_cursor_reaches_failure_boundary(self):
        result = study.evaluate(self.image, study.SUBJECT, (1,), (0,), 11, 5,
                                bad_cursor_depth=True, expect_panic=True)
        self.assertIn('0x2f511eb', result['panic'])

    def test_mutated_split_threshold_is_detected(self):
        with self.assertRaises(study.Halt):
            study.evaluate(self.image, study.SUBJECT, (), (), 10, 5,
                           patches={study.SUBJECT + 0x29: 10})

    def test_mutated_pivot_is_detected(self):
        with self.assertRaises(study.Halt):
            study.evaluate(self.image, study.SUBJECT, (), (), 11, 0,
                           patches={study.SUBJECT + 0x52: 3})

    def test_corrupt_key_tail_is_detected(self):
        with self.assertRaises(study.Halt):
            study.evaluate(self.image, study.SUBJECT, (), (), 4, 4,
                           patches={study.SUBJECT + 0x82: 9})

    def test_branch_outside_fde_is_refused(self):
        jump = b'\xe9' + struct.pack('<i', study.END + 16 - (study.SUBJECT + 5))
        with self.assertRaisesRegex(study.Halt, 'control left selected FDE'):
            study.evaluate(self.image, study.SUBJECT, (), (), 0, 0,
                           patches={study.SUBJECT+i: byte for i, byte in enumerate(jump)})

    def test_lsda_decodes_and_binds_landing_instructions(self):
        records = study.lsda_records(self.image)
        self.assertEqual(len(records), 13)
        self.assertEqual(records[0][2], study.SUBJECT)
        self.assertEqual(records[-1][3], study.END)
        self.assertTrue(all(record[5] == 0 for record in records))
        self.assertEqual(next(record[4] for record in records
                              if record[2] <= 0x2f51292 < record[3]), 0x2f51321)

    def test_unwind_symbol_resolves_through_relocation(self):
        plt, stub, slot, kind, index, addend, name = study.unwind_symbol(self.image)
        self.assertEqual((plt, slot, kind, name), (0x5660110, 0x5778db0, 7, '_Unwind_Resume'))
        self.assertEqual(stub[:2], b'\xff\x25')

    def test_corrupt_unwind_plt_is_rejected(self):
        self.corrupt_pin_and_reject(0x5660110)

    def test_corrupt_lsda_header_is_rejected(self):
        self.corrupt_pin_and_reject(0xa5c89c)

    def test_lsda_landing_inside_instruction_is_rejected(self):
        original = self.image.blob
        try:
            patched = bytearray(original)
            patched[self.image.offset(0xa5c89c) + 7] = 2
            self.image.blob = patched
            with self.assertRaisesRegex(study.EvidenceError, 'landing inside an instruction'):
                study.validate_image(self.image)
        finally:
            self.image.blob = original

    def test_landing_cleanup_order_with_two_live_descriptors(self):
        terminal, events = study.cleanup_case(self.image, 0x2f51332, 2, 3)
        self.assertEqual(terminal, 'resume')
        self.assertEqual(events, [(0x77700020, 96), (0x77700030, 0x198),
                                  (0x77700010, 64), ('resume', 0x77700050)])

    def test_landing_skips_empty_descriptors(self):
        terminal, events = study.cleanup_case(self.image, 0x2f51374, 0, 0)
        self.assertEqual(terminal, 'resume')
        self.assertEqual(events, [(0x77700040, 0x1f8), ('resume', 0x77700050)])

    def test_landing_trap_path_releases_internal_node(self):
        terminal, events = study.cleanup_case(self.image, 0x2f512fe, 2, 3)
        self.assertEqual((terminal, events), ('trap', [(0x77700030, 0x1f8)]))

    def test_values_are_three_word_descriptors(self):
        value = study.value_for_key(study.KEY_BASE + 4, 24)
        self.assertEqual(value & ((1 << 64)-1), 4)
        self.assertGreater((value >> 64) & ((1 << 64)-1), 1)
        with self.assertRaises(ValueError):
            study.value_for_key(study.KEY_BASE, 16)


if __name__ == '__main__':
    unittest.main()
