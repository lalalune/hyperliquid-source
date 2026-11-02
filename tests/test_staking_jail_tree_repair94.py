"""Target-bound static controls for jailed-signer tree deletion."""
import pathlib
import tempfile
import unittest

from tools import staking_jail_tree_repair94 as work


class JailTreeRepairTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = work.load_image()

    def test_selected_fdes_and_body_hashes(self):
        rows = work.verify_subjects(self.image)
        self.assertEqual(len(rows), 4)
        self.assertEqual(sum(row[4] for row in rows), 4097)
        self.assertEqual(len(work.verify_pins(self.image)), 18)

    def test_wrong_digest_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate = pathlib.Path(directory) / 'bad-node'
            candidate.write_bytes(b'not the target')
            with self.assertRaisesRegex(work.EvidenceError, 'SHA-256 mismatch'):
                work.load_image(candidate)

    def test_corrupted_subject_body_and_context_refused(self):
        start = work.FUNCTIONS['jail_leaf']
        byte = work.file_bytes(self.image, start, 1)[0][0]
        with self.assertRaisesRegex(work.EvidenceError, 'subject body mismatch'):
            work.verify_subjects(self.image, {start: byte ^ 1})
        name, address, expected = work.PINS[0]
        with self.assertRaisesRegex(work.EvidenceError, 'pin mismatch'):
            work.verify_pins(self.image, {address: bytes.fromhex(expected)[0] ^ 1})

    def test_non_file_backed_and_invalid_ranges_rejected(self):
        bss = next(sec for sec in self.image.sections if sec['name'] == '.bss' and sec['type'] == 8 and sec['size'])
        with self.assertRaises(work.EvidenceError):
            work.file_bytes(self.image, bss['address'], 1)
        with self.assertRaises(work.EvidenceError):
            work.file_bytes(self.image, (1 << 64)-1, 1)
        with self.assertRaises(work.EvidenceError):
            work.file_bytes(self.image, work.FUNCTIONS['jail_cursor'], -1)

    def test_fde_rejects_interior_address(self):
        with self.assertRaises(work.EvidenceError):
            self.image.exact_fde(work.FUNCTIONS['jail_cursor'] + 1)

    def test_leaf_first_middle_last_and_stale_tail(self):
        for n in (1, 5, 11):
            for index in sorted({0, n // 2, n - 1}):
                with self.subTest(n=n, index=index):
                    result = work.run_case(self.image, 'jail', ('single', n, 0, 'leaf', index))
                    self.assertEqual(result['removed'], 10 + index)
                    self.assertEqual(result['next'], 11 + index if index + 1 < n else None)
                    self.assertEqual(result['rows_after'], n - 1)
                    self.assertEqual((result['root_flag'], result['frees']), (0, 0))

    def test_predecessor_and_cursor_successor(self):
        result = work.run_case(self.image, 'jail', ('pair', 6, 5, 'root', 0))
        self.assertEqual((result['removed'], result['next']), (80, 110))
        self.assertEqual((result['root_flag'], result['frees']), (0, 0))

    def test_merge_boundary_and_root_flag(self):
        merge = work.run_case(self.image, 'jail', ('pair', 5, 6, 'left', 0))
        borrow = work.run_case(self.image, 'jail', ('pair', 5, 7, 'left', 0))
        self.assertEqual((merge['root_flag'], merge['frees']), (1, 1))
        self.assertEqual((borrow['root_flag'], borrow['frees']), (0, 0))
        self.assertIn('jail_merge', merge['reached'])
        self.assertIn('jail_borrow_right', borrow['reached'])

    def test_left_transfer_stops_at_prior_work_boundary(self):
        with self.assertRaises(work.PriorWorkBoundary):
            work.run_case(self.image, 'jail', ('pair', 7, 5, 'right', 0))

    def test_right_transfer_leaf_and_internal(self):
        for height in (0, 1):
            with self.subTest(height=height):
                result = work.transfer_case(self.image, ('jail', 'right', height, 5, 10, 3))
                self.assertEqual((result['left_after'], result['right_after']), (8, 7))
                self.assertGreater(result['separator_after'], result['separator_before'])

    def test_invalid_transfer_request_refused(self):
        with self.assertRaises(ValueError):
            work.transfer_case(self.image, ('jail', 'right', 0, 10, 6, 3))

    def test_borrow_failure_guards_before_tree_writes(self):
        for failure, site in (('capacity', 0x2fa9292), ('donor', 0x2fa92ab)):
            with self.subTest(failure=failure):
                seen = work.guard_case(self.image, 'jail', 'right', failure)
                self.assertIn(site, seen)

    def test_merge_failure_guards_before_tree_writes(self):
        self.assertEqual(work.merge_guard(self.image, 'index')[0], 0x2faec20)
        self.assertEqual(work.merge_guard(self.image, 'capacity')[0], 0x2faec3d)

    def test_flag_preservation_and_empty_root(self):
        for flag in (0, 1, 2, 255):
            self.assertEqual(work.flag_case(self.image, 'jail', ('single', 1, 0, 'leaf', 0), flag), flag)
            self.assertEqual(work.flag_case(self.image, 'jail', ('pair', 5, 5, 'left', 2), flag), 1)

    def test_targeted_instruction_corruptions_are_detected(self):
        for mutant in work.MUTATIONS:
            with self.subTest(mutation=mutant[0]):
                self.assertIn(work.mutation_case(self.image, *mutant),
                              ('EvidenceError', 'Halt', 'Panicked', 'prior-work boundary reached unexpectedly'))

    def test_transfer_instruction_corruptions_are_detected(self):
        for mutant in work.TRANSFER_MUTATIONS:
            with self.subTest(mutation=mutant[0]):
                self.assertIn(work.transfer_mutation_case(self.image, *mutant),
                              ('EvidenceError', 'Halt', 'Panicked'))


if __name__ == '__main__':
    unittest.main()
