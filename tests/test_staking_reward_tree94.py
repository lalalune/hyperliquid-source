"""Target-grounded controls for the reward-stage sort and bulk builder."""
import hashlib
import itertools
import unittest

from tools import staking_reward_tree94 as subject


class RewardTreeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = subject.load_image()
        subject.checked_pins(cls.image)

    def run_rows(self, rows):
        runner = subject.Runner(self.image)
        ordered, tree, height, nodes = runner.run(rows)
        return runner, ordered, tree, height, nodes

    def test_target_digest(self):
        self.assertEqual(hashlib.sha256(self.image.blob).hexdigest(), subject.SHA256)

    def test_wrong_digest_is_refused(self):
        with self.assertRaises(subject.EvidenceError):
            subject.load_image(subject.BINARY, "0" * 64)

    def test_unmapped_address_is_refused(self):
        with self.assertRaises(subject.EvidenceError):
            self.image.offset(1 << 63)

    def test_nobits_has_no_file_mapping(self):
        bss = next(s for s in self.image.sections if s["name"] == ".bss")
        with self.assertRaises(subject.EvidenceError):
            self.image.offset(bss["address"])

    def test_range_must_not_cross_section_end(self):
        text = self.image.named[".text"]
        with self.assertRaises(subject.EvidenceError):
            self.image.offset(text["address"] + text["size"] - 1, 2, executable=True)

    def test_non_function_address_is_refused(self):
        with self.assertRaises(subject.EvidenceError):
            self.image.exact_fde(0x33879D1)

    def test_each_fde_decodes_to_its_end(self):
        for start in subject.FUNCTIONS:
            with self.subTest(start=start):
                _, end = self.image.exact_fde(start)
                rows = subject.decode_range(self.image, start, end)
                self.assertEqual(rows[-1].next, end)

    def test_host_selector_pin_detects_corruption(self):
        altered = bytearray(self.image.blob)
        altered[self.image.offset(0x3373C6F) + 3] ^= 1
        with self.assertRaises(subject.EvidenceError):
            subject.checked_pins(subject.Image(altered))

    def test_sort_relocation_is_bound(self):
        self.assertEqual(self.image.relative()[subject.INDIRECT_SORT], subject.INDIRECT_SORT_TARGET)

    def test_corrupt_sort_relocation_is_refused(self):
        changed = subject.damaged_relocation(self.image, subject.INDIRECT_SORT)
        with self.assertRaises(subject.EvidenceError):
            subject.checked_pins(changed)

    def test_memory_import_symbols_are_checked(self):
        rels = {r[0]: r for r in subject.selected_relocations(self.image)}
        self.assertEqual(rels["compare"][-1], "memcmp")
        self.assertEqual(rels["copy"][-1], "memcpy")
        self.assertEqual(rels["move"][-1], "memmove")

    def test_empty_host_path_does_not_build(self):
        runner, ordered, tree, height, nodes = self.run_rows([])
        self.assertEqual((ordered, tree, height, nodes, runner.m.steps), ([], [], 0, 0, 0))

    def test_one_row_keeps_none_tag_and_payload(self):
        runner, ordered, tree, height, nodes = self.run_rows([subject.row(7, 0, 25)])
        self.assertEqual(tree, [(bytes(19) + b"\x07", 0, 25)])
        self.assertEqual((height, nodes), (0, 1))
        self.assertNotIn(0x33879D0, runner.m.seen)

    def test_key_order_uses_all_twenty_bytes(self):
        values = [subject.row(1 << 152, 1, 1), subject.row(256, 1, 2), subject.row(1, 1, 3)]
        _, ordered, tree, _, _ = self.run_rows(values)
        self.assertEqual([int.from_bytes(r[:20], "big") for r in ordered], [1, 256, 1 << 152])
        self.assertEqual([x[2] for x in tree], [3, 2, 1])

    def test_small_sort_is_stable_for_equal_keys(self):
        values = [subject.row(2, 1, 10, 0), subject.row(1, 1, 11, 1), subject.row(2, 0, 12, 2)]
        _, ordered, tree, _, _ = self.run_rows(values)
        self.assertEqual(ordered, [values[1], values[0], values[2]])
        self.assertEqual(tree, [(bytes(19) + b"\x01", 1, 11), (bytes(19) + b"\x02", 0, 12)])

    def test_small_and_long_sort_threshold(self):
        for count, entry in ((20, 0x33879D0), (21, 0x3BC1610)):
            with self.subTest(count=count):
                values = [subject.row(i, 1, i) for i in range(count, 0, -1)]
                runner, ordered, tree, _, _ = self.run_rows(values)
                self.assertIn(entry, runner.m.seen)
                self.assertEqual([x[2] for x in tree], list(range(1, count + 1)))

    def test_long_sort_keeps_duplicate_order(self):
        values = [subject.row(i % 7, i & 1, i, i) for i in range(205)]
        _, ordered, tree, _, _ = self.run_rows(values)
        self.assertEqual(ordered, sorted(values, key=lambda item: item[:20]))
        self.assertEqual([v for _, _, v in tree], [203, 204, 198, 199, 200, 201, 202])

    def test_equal_rows_keep_last_tag_not_sum(self):
        values = [subject.row(5, 1, 9), subject.row(5, 1, 12), subject.row(5, 0, 45)]
        _, _, tree, _, _ = self.run_rows(values)
        self.assertEqual(tree, [(bytes(19) + b"\x05", 0, 45)])

    def test_all_four_key_permutations(self):
        for keys in itertools.permutations(range(4)):
            with self.subTest(keys=keys):
                values = [subject.row(key, i & 1, i, i) for i, key in enumerate(keys)]
                _, ordered, tree, _, _ = self.run_rows(values)
                self.assertEqual([int.from_bytes(x[:20], "big") for x in ordered], [0, 1, 2, 3])
                self.assertEqual([int.from_bytes(x[0], "big") for x in tree], [0, 1, 2, 3])

    def test_eleven_rows_fit_and_twelve_split(self):
        for count, height, nodes in ((11, 0, 1), (12, 1, 3)):
            with self.subTest(count=count):
                _, _, tree, actual_height, actual_nodes = self.run_rows([subject.row(i, 1, i) for i in range(count)])
                self.assertEqual((len(tree), actual_height, actual_nodes), (count, height, nodes))

    def test_long_sort_stack_to_heap_boundary(self):
        for count, allocations in ((102, []), (103, [4120])):
            with self.subTest(count=count):
                runner, _, tree, _, _ = self.run_rows([subject.row(1, i & 1, i, i) for i in range(count)])
                self.assertEqual(runner.allocations, allocations)
                self.assertEqual(tree[0][2], count - 1)

    def test_multi_level_tree_has_all_values(self):
        count = 1728
        _, _, tree, height, nodes = self.run_rows([subject.row(i, i & 1, i) for i in range(count - 1, -1, -1)])
        self.assertGreaterEqual(height, 2)
        self.assertGreater(nodes, 12)
        self.assertEqual([v for _, _, v in tree], list(range(count)))

    def test_allocator_fill_does_not_change_result_or_topology(self):
        values = [subject.row((i * 17) % 29, i & 1, i, i) for i in range(103)]
        outcomes = []
        for fill in (0, 0xA5, 0xFF):
            runner = subject.Runner(self.image, fresh_byte=fill)
            outcomes.append((runner.run(values), runner.topology))
        self.assertEqual(outcomes[0], outcomes[1])
        self.assertEqual(outcomes[0], outcomes[2])

    def test_comparison_magnitude_does_not_change_result(self):
        values = [subject.row((i * 17) % 29, i & 1, i, i) for i in range(103)]
        outcomes = []
        for magnitude in (1, 255, 0x7FFFFFFF):
            runner = subject.Runner(self.image, compare_magnitude=magnitude)
            outcomes.append((runner.run(values), runner.topology))
        self.assertEqual(outcomes[0], outcomes[1])
        self.assertEqual(outcomes[0], outcomes[2])

    def test_sort_context_does_not_change_tested_result(self):
        values = [subject.row((i * 17) % 29, i & 1, i, i) for i in range(103)]
        outcomes = []
        for pointer in (0, subject.ITER):
            runner = subject.Runner(self.image, sort_context=pointer)
            outcomes.append((runner.run(values), runner.topology))
        self.assertEqual(outcomes[0], outcomes[1])

    def test_full_two_level_tree_grows_at_1728(self):
        for count, expected in ((1727, 2), (1728, 3)):
            with self.subTest(count=count):
                values = [subject.row(i, 1, i) for i in range(count)]
                _, _, tree, height, _ = self.run_rows(values)
                self.assertEqual((len(tree), height), (count, expected))

    def test_fixture_limit_is_enforced(self):
        with self.assertRaises(ValueError):
            subject.Runner(self.image).run([subject.row(0, 0, 0)] * 4097)

    def test_out_of_order_bulk_input_is_detected(self):
        with self.assertRaises(subject.Halt):
            subject.Runner(self.image).run([subject.row(2, 1, 0), subject.row(1, 1, 0)], presorted=True)

    def test_invalid_input_tag_is_refused(self):
        with self.assertRaises(ValueError):
            subject.row(1, 2, 0)

    def test_bad_row_length_is_refused(self):
        with self.assertRaises(ValueError):
            subject.Runner(self.image).run([bytes(39)])

    def test_sort_allocation_failure_reaches_failure_sink(self):
        runner = subject.Runner(self.image, fail_at=1)
        with self.assertRaises(subject.Panicked):
            runner.run([subject.row(i, 1, i) for i in range(103)])

    def test_tree_allocation_failure_reaches_failure_sink(self):
        runner = subject.Runner(self.image, fail_at=1)
        with self.assertRaises(subject.Panicked):
            runner.run([subject.row(i, 1, i) for i in range(12)])

    def test_conditional_flip_breaks_sort(self):
        values = [subject.row(i, 1, i) for i in (3, 2, 1)]
        with self.assertRaises(subject.Halt):
            subject.Runner(self.image, patches={0x3387A58: 0x78}).run(values)

    def test_conditional_flip_breaks_duplicate_handling(self):
        values = [subject.row(5, 1, 1), subject.row(5, 0, 2)]
        with self.assertRaises(subject.Halt):
            subject.Runner(self.image, patches={0x2FBE28C: 0x74}).run(values)

    def test_reduced_node_capacity_changes_shape(self):
        values = [subject.row(i, 1, i) for i in range(11)]
        _, _, _, height, nodes = self.run_rows(values)
        mutant = subject.Runner(self.image, patches={0x2FBE2E2: 10}).run(values)
        self.assertEqual((height, nodes), (0, 1))
        self.assertNotEqual(mutant[2:], (height, nodes))


if __name__ == "__main__":
    unittest.main()
