"""Target-free controls for the independent #115 nested-map specification."""

import hashlib
import unittest

from tools import re007_oracle_sum_115 as subject


def key(number):
    return number.to_bytes(20, "big")


def decode_bytes(data, start=0x1000):
    blob = bytes(data) + bytes(32)

    def read(address, count):
        offset = address - start
        if offset < 0:
            raise ValueError("address below test buffer")
        return blob[offset:offset + count]

    row = subject.decode(read, start)
    row.data = blob[:row.size]
    return row


class DigestAndRangeTests(unittest.TestCase):
    def test_digest_accepts_exact_bytes(self):
        image = b"small synthetic input"
        digest = hashlib.sha256(image).hexdigest()
        self.assertEqual(subject.check_digest(image, digest), digest)

    def test_digest_rejects_corrupted_byte(self):
        image = b"small synthetic input"
        digest = hashlib.sha256(image).hexdigest()
        with self.assertRaises(subject.EvidenceError):
            subject.check_digest(image[:-1] + b"x", digest)

    def test_digest_rejects_wrong_expected_hash(self):
        with self.assertRaises(subject.EvidenceError):
            subject.check_digest(b"abc", "0" * 64)

    def test_file_backed_address_boundaries(self):
        image = object.__new__(subject.Image)
        image.mapped = [{"address": 0x1000, "size": 16, "offset": 0x80}]
        self.assertEqual(image.offset(0x1000), 0x80)
        self.assertEqual(image.offset(0x100F), 0x8F)
        for address in (0xFFF, 0x1010, 0, 0xFFFFFFFF):
            with self.subTest(address=address), self.assertRaises(subject.EvidenceError):
                image.offset(address)

    def test_fde_interior_is_not_an_exact_start(self):
        image = object.__new__(subject.Image)
        image.starts = [0x1000, 0x2000]
        image.fde_ends = {0x1000: 0x1010, 0x2000: 0x2008}
        self.assertEqual(image.fde(0x100F), (0x1000, 0x1010))
        self.assertEqual(image.exact_fde(0x2000), (0x2000, 0x2008))
        for address in (0x1001, 0x1010, 0x2008):
            with self.subTest(address=address), self.assertRaises(subject.EvidenceError):
                image.exact_fde(address)

    def test_unmapped_memory_write_fails(self):
        image = object.__new__(subject.Image)
        image.mapped = []
        memory = subject.Memory(image)
        for address in (0, subject.HEAP_BASE - 1, subject.HEAP_BASE + subject.HEAP_SIZE):
            with self.subTest(address=address), self.assertRaises(subject.Halt):
                memory.write(address, 1, 7)


class DecoderTests(unittest.TestCase):
    def test_short_conditional_branch_has_signed_relative_target(self):
        row = decode_bytes(b"\x75\xf9")
        self.assertEqual((row.op, row.size, row.target), ("jcc", 2, 0xFFB))

    def test_near_conditional_branch_has_signed_relative_target(self):
        row = decode_bytes(b"\x0f\x84\x10\x00\x00\x00")
        self.assertEqual((row.op, row.size, row.target), ("jcc", 6, 0x1016))

    def test_call_has_resolved_target_and_operand_range(self):
        row = decode_bytes(b"\xe8\x04\x00\x00\x00")
        self.assertEqual((row.op, row.target, row.imm_at, row.imm_size), ("call", 0x1009, 1, 4))

    def test_fixed_call_pattern_rejects_opcode_and_truncation(self):
        self.assertEqual(subject.direct_call_target(0x1000, b"\xe8\xfb\xff\xff\xff"), 0x1000)
        for malformed in (b"\xe9\x00\x00\x00\x00", b"\xe8\x00", b"", b"\xe8" + bytes(5)):
            with self.subTest(malformed=malformed), self.assertRaises(subject.EvidenceError):
                subject.direct_call_target(0x1000, malformed)

    def test_branch_controls_flip_only_reached_condition(self):
        first = decode_bytes(b"\x75\x02", 0x1000)
        second = decode_bytes(b"\x0f\x84\x02\x00\x00\x00", 0x1010)
        bodies = {0x1000: (0x1000, 0x1016, [first, second])}
        selected = list(subject.branch_mutations(bodies, {0x1010}))
        self.assertEqual(selected, [(0x1000, 0x1010, 0x1011, 0x84, 0x85)])

    def test_corrupt_branch_encoding_is_not_accepted_as_conditional(self):
        row = decode_bytes(b"\x90")
        self.assertEqual(row.op, "nop")
        self.assertNotEqual(row.op, "jcc")


class SaturatingSumTests(unittest.TestCase):
    def test_empty_retains_initial_value(self):
        self.assertEqual(subject.saturating_sum([], 19), 19)
        self.assertEqual(subject.saturating_sum([], subject.U64), subject.U64)

    def test_unsigned_overflow_saturates(self):
        self.assertEqual(subject.saturating_sum([subject.U64 - 2, 1], 1), subject.U64)
        self.assertEqual(subject.saturating_sum([subject.U64 - 2, 2], 1), subject.U64)
        self.assertEqual(subject.saturating_sum([subject.U64, 1], 0), subject.U64)
        self.assertNotEqual(subject.saturating_sum([subject.U64, 1], 0), (subject.U64 + 1) & subject.U64)

    def test_input_domain_is_u64(self):
        for value in (-1, subject.U64 + 1):
            with self.subTest(value=value), self.assertRaises(ValueError):
                subject.saturating_sum([value])
            with self.subTest(initial=value), self.assertRaises(ValueError):
                subject.saturating_sum([], value)

    def test_split_ring_uses_both_segments(self):
        rows = ((key(1), 5), (key(2), 7), (key(3), 11))
        case = subject.Case("split", 3, rows[:1], rows[1:])
        self.assertEqual(case.expected(), 26)
        self.assertNotEqual(case.expected(), subject.saturating_sum([5], 3))
        self.assertEqual(tuple(case.entries()), rows)

    def test_flat_and_tree_models_agree(self):
        rows = ((key(0), 2), (key(1), 3), (key(2), 4))
        tree = subject.Node((rows[1],), (subject.Node((rows[0],)), subject.Node((rows[2],))))
        flat = subject.Case("flat", 7, rows[:2], rows[2:])
        nested = subject.Case("tree", 7, tree=tree, tree_mode=True)
        self.assertEqual(tuple(nested.entries()), rows)
        self.assertEqual(nested.expected(), flat.expected())


class TreeModelTests(unittest.TestCase):
    def test_leaf_cursor_moves_past_returned_entry(self):
        leaf = subject.Node(((key(0), 4), (key(1), 9)))
        steps = list(subject.tree_steps(leaf))
        self.assertEqual([step[0][1] for step in steps], [4, 9])
        self.assertEqual([step[1] for step in steps], [leaf, leaf])
        self.assertEqual([step[2] for step in steps], [1, 2])

    def test_internal_entry_points_cursor_at_next_leaf(self):
        left = subject.Node(((key(0), 1),))
        right = subject.Node(((key(2), 3),))
        root = subject.Node(((key(1), 2),), (left, right))
        steps = list(subject.tree_steps(root))
        self.assertEqual([step[0][1] for step in steps], [1, 2, 3])
        self.assertIs(steps[1][1], right)
        self.assertEqual(steps[1][2], 0)

    def test_height_eight_has_511_rows(self):
        root = subject.make_tree(8, 1, subject.SmallSequence())
        self.assertEqual(subject.node_height(root), 8)
        self.assertEqual(sum(1 for _ in subject.tree_entries(root)), 511)

    def test_invalid_nodes_are_rejected(self):
        with self.assertRaises(ValueError):
            subject.Node(())
        with self.assertRaises(ValueError):
            subject.Node(((b"short", 1),))
        with self.assertRaises(ValueError):
            subject.Node(((key(0), 1),), (subject.Node(((key(1), 1),)),))

    def test_unequal_tree_depths_are_rejected(self):
        leaf = subject.Node(((key(0), 1),))
        branch = subject.Node(((key(2), 1),), (leaf, leaf))
        root = subject.Node(((key(1), 1),), (leaf, branch))
        with self.assertRaises(ValueError):
            subject.node_height(root)


class NestedSpecificationTests(unittest.TestCase):
    def sample_case(self):
        child_a = subject.InnerCollection("ring", (2, 4), capacity=3, head=2)
        child_b = subject.InnerCollection("ring", (9,), capacity=1, head=0)
        supplement_a = subject.InnerCollection("ring", (21,), capacity=2, head=1)
        supplement_b = subject.InnerCollection("ring", (), capacity=1, head=0)
        outer_a = subject.OuterCollection("ring", ((key(1), child_a), (key(2), child_b)), capacity=3, head=2)
        outer_b = subject.OuterCollection("ring", ((key(3), child_b),), capacity=1, head=0)
        return subject.NestedCase("example", subject.NestedPhase(outer_a, supplement_a, key(8)),
                                  subject.NestedPhase(outer_b, supplement_b, key(9)))

    def test_nested_order_and_supplement(self):
        case = self.sample_case()
        self.assertEqual(list(case.items()), [(key(1), 2), (key(1), 4), (key(2), 9), (key(8), 21), (key(3), 9)])
        self.assertEqual(case.count(), 5)
        self.assertEqual([phase.outer_count() for phase in case.phases], [3, 1])

    def test_phase_and_group_positions_are_explicit(self):
        events = list(self.sample_case().events())
        self.assertEqual([(e[0], e[3], e[4], e[5]) for e in events],
                         [(0, 0, 0, False), (0, 0, 1, False), (0, 1, 0, False),
                          (0, 2, 0, True), (1, 0, 0, False)])

    def test_ring_validation_rejects_duplicate_keys_and_bad_capacity(self):
        with self.assertRaises(ValueError):
            subject.InnerCollection("ring", (1, 1), capacity=2)
        with self.assertRaises(ValueError):
            subject.InnerCollection("ring", (1, 2), capacity=1)
        with self.assertRaises(ValueError):
            subject.InnerCollection("ring", (1,), capacity=2, head=2)

    def test_outer_key_order_and_width_are_checked(self):
        child = subject.InnerCollection("ring", (), capacity=1)
        with self.assertRaises(ValueError):
            subject.OuterCollection("ring", ((key(2), child), (key(1), child)), capacity=2)
        with self.assertRaises(ValueError):
            subject.OuterCollection("ring", ((b"bad", child),), capacity=1)

    def test_tree_entry_keys_must_match_tree(self):
        tree = subject.Node(((key(1), 0),))
        child = subject.InnerCollection("ring", (), capacity=1)
        with self.assertRaises(ValueError):
            subject.OuterCollection("tree", ((key(2), child),), tree=tree)

    def test_fixture_matrix_is_deterministic(self):
        for index in range(64):
            first = subject.nested_fixture(index, True)
            second = subject.nested_fixture(index, True)
            with self.subTest(index=index):
                self.assertEqual(list(first.events()), list(second.events()))
                self.assertGreater(first.count(), 0)

    def test_terminal_ring_swaps_only_two_empty_ranges(self):
        state = bytearray(0x210)
        state[0x108:0x110] = (2).to_bytes(8, "little")
        state[0x110:0x120] = b"A" * 16
        state[0x120:0x130] = b"B" * 16
        result = subject.terminal_after_call(state)
        self.assertEqual(result[0x110:0x120], b"B" * 16)
        self.assertEqual(result[0x120:0x130], b"A" * 16)
        self.assertEqual(subject.terminal_after_call(result), bytes(state))
        self.assertNotEqual(result, bytes(state))

    def test_terminal_tree_state_is_unchanged(self):
        state = bytearray(0x210)
        state[0x108:0x110] = (1).to_bytes(8, "little")
        self.assertEqual(subject.terminal_after_call(state), bytes(state))
        with self.assertRaises(ValueError):
            subject.terminal_after_call(state[:-1])


class FilteredSpecificationTests(unittest.TestCase):
    def test_filter_compares_payload_and_preserves_order(self):
        inner = subject.InnerCollection("ring", (0, 1, 8, 33), capacity=5, head=4)
        outer = subject.OuterCollection("ring", ((key(3), inner),), capacity=2, head=1)
        empty = subject.InnerCollection("ring", (), capacity=1)
        phase = subject.NestedPhase(outer, empty, key(5))
        zero = subject.FilteredCase("zero", phase, 0)
        self.assertEqual([(item[0], item[1]) for item in zero.events()],
                         [(key(3), 0), (key(3), 8), (key(3), 33)])
        self.assertEqual(zero.count(), 3)
        self.assertNotEqual(subject.filter_word(33), 33)

    def test_filter_can_match_no_rows(self):
        inner = subject.InnerCollection("ring", (1, 2), capacity=3)
        outer = subject.OuterCollection("ring", ((key(0), inner),), capacity=2)
        empty = subject.InnerCollection("ring", (), capacity=1)
        case = subject.FilteredCase("absent", subject.NestedPhase(outer, empty, key(9)), 9)
        self.assertEqual(case.count(), 0)
        with self.assertRaises(ValueError):
            subject.FilteredCase("negative", case.phase, -1)

    def test_same_key_can_have_different_filter_payloads(self):
        first = subject.InnerCollection("ring", (33,), capacity=1, salt=0)
        second = subject.InnerCollection("ring", (33,), capacity=1, salt=7)
        outer = subject.OuterCollection("ring", ((key(1), first), (key(2), second)), capacity=2)
        empty = subject.InnerCollection("ring", (), capacity=1)
        phase = subject.NestedPhase(outer, empty, key(9))
        a = subject.FilteredCase("a", phase, first.filter_of(33))
        b = subject.FilteredCase("b", phase, second.filter_of(33))
        self.assertEqual([(e[0], e[1]) for e in a.events()], [(key(1), 33)])
        self.assertEqual([(e[0], e[1]) for e in b.events()], [(key(2), 33)])
        self.assertNotEqual(first.filter_of(33), second.filter_of(33))

    def test_filtered_terminal_swaps_only_outer_ring_ranges(self):
        state = bytearray(0x120)
        state[:8] = (2).to_bytes(8, "little")
        state[8:24], state[24:40] = b"A" * 16, b"B" * 16
        result = subject.filtered_terminal_after_call(state)
        self.assertEqual(result[8:24], b"B" * 16)
        self.assertEqual(result[24:40], b"A" * 16)
        self.assertEqual(subject.filtered_terminal_after_call(result), bytes(state))
        with self.assertRaises(ValueError):
            subject.filtered_terminal_after_call(state[:-1])


class SizeHintSpecificationTests(unittest.TestCase):
    def test_current_and_supplement_form_the_lower_bound(self):
        self.assertEqual(subject.phase_hint(False, 1, 7, 11), (18, None))
        self.assertEqual(subject.phase_hint(False, 0, 7, 11), (18, 18))

    def test_done_phase_contributes_nothing(self):
        self.assertEqual(subject.phase_hint(True, 1, subject.U64, subject.U64), (0, 0))

    def test_overflow_saturates_lower_and_removes_upper(self):
        self.assertEqual(subject.phase_hint(False, 0, subject.U64, 1), (subject.U64, None))
        self.assertEqual(subject.combine_hints((subject.U64, subject.U64), (1, 1)),
                         (subject.U64, None))
        self.assertNotEqual(subject.phase_hint(False, 0, subject.U64, 1)[0], 0)

    def test_unknown_upper_bound_propagates(self):
        self.assertEqual(subject.combine_hints((3, None), (2, 2)), (5, None))
        self.assertEqual(subject.combine_hints((3, 3), (2, 2)), (5, 5))

    def test_hint_input_ranges_and_boundary_matrix(self):
        with self.assertRaises(ValueError):
            subject.phase_hint(False, 0, -1, 0)
        cases = tuple(subject.hint_cases())
        self.assertEqual(len(cases), 4096)
        self.assertEqual(cases[0].expected(), (0, 0))
        self.assertTrue(any(case.expected()[1] is None for case in cases))

    def test_hint_matrix_varies_all_six_container_representations(self):
        cases = tuple(subject.mixed_hint_cases())
        self.assertEqual(len(cases), 1024)
        self.assertEqual(len({case.ring_modes for case in cases}), 64)
        for case in cases:
            lower, upper = case.expected()
            self.assertGreaterEqual(lower, 0)
            if upper is not None:
                self.assertEqual(lower, upper)

    def test_deep_inner_tree_has_one_logical_row_per_key(self):
        case = next(subject.deep_nested_cases())
        self.assertEqual(case.count(), 511)
        self.assertEqual(case.phases[0].outer_count(), 511)


if __name__ == "__main__":
    unittest.main()
