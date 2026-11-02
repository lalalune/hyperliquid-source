"""Target-grounded controls for RE-006 spot level deletion evidence."""
import pathlib
import tempfile
import unittest
from unittest import mock

from tools import spot_level_erase94 as re


class SpotLevelEraseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = re.load_image()

    def run_named(self, name, patches=None):
        case = next(c for c in re.fixtures() if c[0] == name)
        return re.Harness(self.image, patches).run(case)

    def test_digest_rejects_corruption_before_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            bad = pathlib.Path(directory) / 'node'
            bad.write_bytes(b'\x7fELF\x02\x01broken')
            with self.assertRaisesRegex(re.EvidenceError, 'SHA-256 mismatch'):
                re.load_image(bad)

    def test_unmapped_and_cross_section_reads_fail(self):
        with self.assertRaises(re.EvidenceError):
            re.raw_at(self.image, 0, 8)
        section = self.image.named['.text']
        with self.assertRaises(re.EvidenceError):
            re.raw_at(self.image, section['address'] + section['size'] - 1, 2)
        with self.assertRaises(re.EvidenceError):
            re.raw_at(self.image, section['address'], -1)
        h = re.Harness(self.image)
        with self.assertRaises(re.Halt):
            h.m.memory.bytes_at(section['address'] + section['size'] - 1, 2)

    def test_duplicate_fde_starts_rejected(self):
        cies, fdes = re.eh_frame_records(self.image.blob, self.image.sections)
        with mock.patch.object(re, 'eh_frame_records', return_value=(cies, fdes + [fdes[0]])):
            with self.assertRaisesRegex(re.EvidenceError, 'duplicate FDE start'):
                re.Image(self.image.blob)

    def test_all_selected_functions_decode_through_fde_end(self):
        rows = re.instruction_rows(self.image)
        self.assertEqual(sum(map(len, rows.values())), 1221)
        for label, start in re.FUNCTIONS:
            _, end = self.image.exact_fde(start)
            self.assertEqual(rows[label][0].va, start)
            self.assertEqual(rows[label][-1].next, end)
            self.assertEqual(len(re.raw_at(self.image, start, end-start)), end-start)

    def test_corrupt_body_bytes_and_wrong_extent_are_rejected(self):
        start = 0x28666e0
        _, end = self.image.exact_fde(start)
        body = bytearray(re.raw_at(self.image, start, end-start))
        re.validate_body(start, end, body)
        body[0] ^= 1
        with self.assertRaises(re.EvidenceError):
            re.validate_body(start, end, body)
        with self.assertRaises(re.EvidenceError):
            re.validate_body(start, end+1, body)
        with self.assertRaises(re.EvidenceError):
            re.validate_body(0, end, body)

    def test_absence_does_not_change_tree(self):
        result = self.run_named('leaf-5-missing--101')
        self.assertFalse(result['found'])
        self.assertEqual(result['before_count'], result['after_count'])
        self.assertEqual(result['return_hex'][:16], '0200000000000000')
        self.assertEqual(result['freed'], 0)

    def test_signed_key_boundaries(self):
        for key in (-(1 << 63), -1, 0, (1 << 63) - 1):
            with self.subTest(key=key):
                result = self.run_named('signed-' + str(key))
                self.assertTrue(result['found'])
                self.assertNotIn(key, result['keys'])
                self.assertEqual(result['return_hex'], re.payload(key).hex())

    def test_empty_root_and_single_leaf(self):
        self.assertIsNone(self.run_named('empty')['shape'])
        result = self.run_named('leaf-1-0')
        self.assertEqual(result['shape'], [[], []])
        self.assertEqual(result['freed'], 0)

    def test_merge_then_root_shrink(self):
        case = next(c for c in re.fixtures() if c[0] == 'pair-5-5-left')
        original_keys = re.tree_keys(case[1])
        result = re.Harness(self.image).run(case)
        self.assertEqual(result['shape'], [original_keys[1:], []])
        self.assertEqual(result['height_after'], 0)
        self.assertEqual(result['freed'], 2)
        self.assertCountEqual(result['freed_sizes'], [0x1c8, 0x228])

    def test_borrow_from_right_and_left(self):
        case = next(c for c in re.fixtures() if c[0] == 'pair-5-7-left')
        root = case[1]
        expected = [[root.children[1].keys[0]], [
            [root.children[0].keys[1:] + [root.keys[0]], []],
            [root.children[1].keys[1:], []]]]
        result = re.Harness(self.image).run(case)
        self.assertEqual(result['shape'], expected)
        self.assertEqual(result['freed'], 0)
        case = next(c for c in re.fixtures() if c[0] == 'pair-7-5-right')
        root = case[1]
        expected = [[root.children[0].keys[-1]], [
            [root.children[0].keys[:-1], []],
            [[root.keys[0]] + root.children[1].keys[1:], []]]]
        self.assertEqual(re.Harness(self.image).run(case)['shape'], expected)

    def test_internal_predecessor_swap_preserves_value(self):
        case = next(c for c in re.fixtures() if c[0] == 'deep-internal-7-7-root')
        removed_key = case[2]
        result = re.Harness(self.image).run(case)
        self.assertEqual(result['return_hex'], re.payload(removed_key).hex())
        self.assertNotIn(removed_key, result['keys'])
        self.assertEqual(result['after_count'], result['before_count'] - 1)

    def test_realistic_repair_fixtures(self):
        harness = re.Harness(self.image)
        cases = re.fixtures()
        self.assertEqual(len(cases), 262)
        for case in cases:
            with self.subTest(case=case[0]):
                harness.run(case)

    def test_synthetic_multi_entry_rotation(self):
        self.assertEqual(len(re.rotation_cases(self.image)), 20)

    def test_tracked_edges_and_internal_merges(self):
        self.assertEqual(len(re.merge_cases(self.image)), 72)
        address = 0x1b00ac3
        original = re.raw_at(self.image, address, 1)[0]
        with self.assertRaises((re.Halt, re.Panicked)):
            re.merge_cases(self.image, {address: original ^ 1})

    def test_direct_cursor_contract_and_mutations(self):
        self.assertEqual(len(re.cursor_cases(self.image)), 6)
        for address in (0x1b21d40, 0x1b21d54, 0x1b21d70):
            with self.subTest(address=hex(address)):
                original = re.raw_at(self.image, address, 1)[0]
                with self.assertRaises((re.Halt, re.Panicked)):
                    re.cursor_cases(self.image, {address: original ^ 1})

    def test_all_focused_controls_are_detected(self):
        controls = re.instruction_controls(self.image)
        self.assertEqual(len(controls), 14)
        self.assertTrue(all(row['outcome'] == 'killed' for row in controls))

    def test_repeated_removals_keep_tree_valid(self):
        rows = re.sequential_cases(self.image)
        self.assertEqual(len(rows), 424)
        for name in {row['sequence'] for row in rows}:
            last = [row for row in rows if row['sequence'] == name][-1]
            self.assertEqual(last['after_count'], 0)
        self.assertTrue(any(not row['found'] for row in rows))

    def test_caller_gates_require_both_tags_zero(self):
        rows = re.caller_gate_cases(self.image)
        self.assertEqual(len(rows), 32)
        self.assertEqual(sum(row['outcome'] == 'call' for row in rows), 2)
        for address in (0x26df218, 0x26e02d5):
            with self.subTest(address=hex(address)):
                byte = re.raw_at(self.image, address, 1)[0]
                with self.assertRaises(re.Halt):
                    re.caller_gate_cases(self.image, {address: byte ^ 1})

    def test_sparse_descent_loop_boundaries(self):
        results = re.descent_fragments(self.image)
        self.assertEqual(len(results), 17)
        self.assertEqual({r['depth'] for r in results if r['direction'] == 'predecessor'},
                         {1, 2, 7, 8, 9, 10, 16, 17})
        for address in (0x1b21c7c, 0x1b21dff):
            with self.subTest(address=hex(address)):
                original = re.raw_at(self.image, address, 1)[0]
                with self.assertRaises(re.Halt):
                    re.descent_fragments(self.image, {address: original ^ 1})

    def test_invalid_helper_inputs_reach_distinct_error_arms(self):
        results = {item['case']: item for item in re.failure_cases(self.image)}
        self.assertEqual(len(results), 10)
        self.assertIn('old_right_len + count', results['left-capacity']['message'])
        self.assertIn('old_left_len >= count', results['left-donor']['message'])
        self.assertIn('new_left_len', results['merge-capacity']['message'])
        self.assertIn('track_edge_idx', results['merge-track-index']['message'])
        self.assertIn('unreachable code', results['right-height']['message'])
        self.assertTrue(results['empty-internal-parent']['message'].startswith(
            'internal error: entered unreachable code: empty internal node'))

    def test_branch_byte_mutation_is_detected(self):
        address = 0x286675b
        original = re.raw_at(self.image, address, 1)[0]
        self.assertEqual(original, 0x74)
        with self.assertRaises((re.Halt, re.Panicked, re.EvidenceError)):
            self.run_named('leaf-1-missing--101', {address: original ^ 1})

    def test_parent_pointer_corruption_is_rejected(self):
        h = re.Harness(self.image)
        root = re.shallow(5, 5)
        re.assign_keys(root, [-10])
        nodes = h.write_tree(root)
        h.m.memory.write(root.children[0].address + 0x160, 8, 0)
        with self.assertRaisesRegex(re.Halt, 'wrong parent pointer'):
            h.view(nodes)

    def test_overlapping_memcpy_is_rejected(self):
        h = re.Harness(self.image)
        m = h.m
        m.call_target = re.FAKE_COPY
        m.regs[re.RDI], m.regs[re.RSI], m.regs[re.RDX] = re.NODES + 1, re.NODES, 8
        with self.assertRaisesRegex(re.Halt, 'overlapping memcpy'):
            h.copy(m)
        m.call_target = re.FAKE_MOVE
        h.copy(m)

    def test_imported_copy_symbols_are_elf_relocations(self):
        rows = re.rows_for_slots(self.image, (0x576dfe0, 0x576e0e0))
        self.assertEqual([r['symbol'] for r in rows], ['memcpy', 'memmove'])
        self.assertTrue(all(r['type'] == 6 for r in rows))
        with self.assertRaises(re.EvidenceError):
            re.rows_for_slots(self.image, (0,))


if __name__ == '__main__':
    unittest.main()
