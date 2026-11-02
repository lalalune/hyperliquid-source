"""Checks of the bounded delegation teardown evidence, without node execution."""
import hashlib
import struct
import unittest

from tools import staking_delegation_drop94 as d


class DelegationDropEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = d.load_image()

    def test_digest_is_target_bound(self):
        self.assertEqual(hashlib.sha256(self.image.blob).hexdigest(), d.SHA256)

    def test_wrong_digest_is_rejected(self):
        with self.assertRaisesRegex(d.EvidenceError, 'SHA-256 mismatch'):
            d.load_image(expected='0' * 64)

    def test_selected_fdes_and_exclusive_ends(self):
        expected = {
            'inner_drop': (0x33f91a0, 0x33f94ed),
            'user_book_drop': (0x33fa7b0, 0x33fa87e),
            'member_book_drop': (0x33fbde0, 0x33fbeae),
            'user_unwind_cleanup': (0x3378990, 0x33789f2),
            'member_unwind_cleanup': (0x3378360, 0x33783c2),
            'both_books_unwind': (0x37644c0, 0x37644fc),
        }
        for name, pair in expected.items():
            with self.subTest(name=name):
                self.assertEqual(self.image.exact_fde(d.FUNCTIONS[name]), pair)
                rows = d.decode_range(self.image, *pair)
                self.assertEqual(rows[-1].next, pair[1])

    def test_inner_fde_rejects_interior_address(self):
        with self.assertRaises(d.EvidenceError):
            self.image.exact_fde(d.FUNCTIONS['inner_drop']+1)

    def test_outside_file_backed_section_rejected(self):
        with self.assertRaises(d.EvidenceError):
            d.file_bytes(self.image, 0xffffffffffff, 1)

    def test_nobits_is_not_file_backed(self):
        sec = next(s for s in self.image.sections if s['name'] == '.bss')
        with self.assertRaises(d.EvidenceError):
            d.file_bytes(self.image, sec['address'], 1)

    def test_cross_section_and_empty_ranges_rejected(self):
        sec = next(s for s in self.image.sections if s['name'] == '.text')
        with self.assertRaises(d.EvidenceError):
            d.file_bytes(self.image, sec['address']+sec['size']-1, 2)
        with self.assertRaises(d.EvidenceError):
            d.file_bytes(self.image, sec['address'], 0)

    def test_context_binds_both_staking_fields(self):
        pins = d.context_pins(self.image)
        self.assertEqual(len(pins), 5)
        self.assertEqual([r[0] for r in pins[:2]],
                         ['state_user_field_and_call', 'state_member_field_and_call'])
        for _, va, _, raw in pins[:2]:
            bytecode = bytes.fromhex(raw)
            target = int(va, 16) + 12 + struct.unpack('<i', bytecode[8:12])[0]
            self.assertIn(target, (d.FUNCTIONS['user_book_drop'], d.FUNCTIONS['member_book_drop']))

    def test_corrupt_context_fails_closed(self):
        va = d.CONTEXT['state_user_field_and_call'][0]
        old = d.file_bytes(self.image, va, 1)[0][0]
        with self.assertRaisesRegex(d.EvidenceError, 'changed context'):
            d.context_pins(self.image, {va: old ^ 1})

    def test_null_root_does_not_call_free(self):
        self.assertEqual(d.run_inner(self.image, None).events, [])
        self.assertEqual(d.run_inner(self.image, None, length_override=9).events, [])

    def test_empty_allocated_leaf_is_freed(self):
        h = d.run_inner(self.image, d.leaf(0))
        self.assertEqual([(s, a) for _, s, a in h.events], [(496, 0)])

    def test_populated_leaf_freed_once_at_capacity(self):
        for count in (1, 5, 11):
            with self.subTest(count=count):
                h = d.run_inner(self.image, d.leaf(count))
                self.assertEqual([size for _, size, _ in h.events], [496])
                self.assertFalse(h.live)

    def test_height_one_child_first_order(self):
        h = d.run_inner(self.image, d.uniform_tree(1, 1, 5))
        self.assertEqual([size for _, size, _ in h.events], [496, 496, 592])
        self.assertEqual(len(set(a for a, _, _ in h.events)), 3)

    def test_height_two_child_first_order(self):
        h = d.run_inner(self.image, d.uniform_tree(2, 1, 5))
        self.assertEqual([size for _, size, _ in h.events],
                         [496, 496, 592, 496, 496, 592, 592])

    def test_uneven_sibling_sizes_are_released_in_order(self):
        tree = (2, (d.leaf(5), d.leaf(6), d.leaf(11)))
        h = d.run_inner(self.image, tree)
        self.assertEqual([size for _, size, _ in h.events], [496, 496, 496, 592])
        self.assertFalse(h.live)

    def test_deep_valid_tree(self):
        h = d.run_inner(self.image, d.uniform_tree(3, 5, 5))
        self.assertEqual(sum(size == 496 for _, size, _ in h.events), 216)
        self.assertEqual(sum(size == 592 for _, size, _ in h.events), 43)
        self.assertFalse(h.live)

    def test_noncanonical_height_exercises_eight_step_unrolling(self):
        tree = d.leaf(5)
        for _ in range(9):
            tree = (0, (tree,))
        h = d.run_inner(self.image, tree)
        self.assertEqual([s for _,s,_ in h.events], [496]+[592]*9)
        self.assertIn(0x33f9270, h.machine.seen)

    def test_both_books_normal_and_unwind_agree(self):
        users = [d.leaf(5), d.uniform_tree(1, 5, 5)]
        members = [d.leaf(2), None, d.leaf(11)]
        normal = d.run_books(self.image, users, members)
        unwind = d.run_books(self.image, users, members, mode='unwind')
        self.assertEqual(normal.events, unwind.events)
        self.assertEqual(normal.calls, unwind.calls)
        self.assertEqual(normal.calls, [('user', 0), ('user', 1), ('user', 'end'),
                                        ('member', 0), ('member', 1), ('member', 2), ('member', 'end')])

    def test_cleanup_continues_after_consumed_prefix(self):
        trees = [d.leaf(5), d.uniform_tree(1, 5, 5), d.leaf(11)]
        for kind in ('user', 'member'):
            for consumed, nfree in ((0, 9), (1, 8), (2, 1), (3, 0)):
                with self.subTest(kind=kind, consumed=consumed):
                    h = d.run_cleanup(self.image, kind, trees, consumed)
                    self.assertEqual(len(h.events), nfree)
                    self.assertEqual(h.calls[-1], (kind, 'end'))

    def test_bad_parent_reaches_panic_after_one_free(self):
        h = d.broken_parent(self.image)
        self.assertEqual(len(h.events), 1)
        self.assertIn(0x33f94e3, h.machine.seen)

    def test_lsda_bindings_for_cleanup_calls(self):
        rows = {
            'user_book_drop': (0x33fa841, 0x33fa863, 0),
            'member_book_drop': (0x33fbe71, 0x33fbe93, 0),
            'both_books_unwind': (0x37644c7, 0x37644df, 0),
        }
        for name, (site, landing, action) in rows.items():
            with self.subTest(name=name):
                records = d.lsda_records(self.image, d.FUNCTIONS[name])['records']
                matches = [r for r in records if r[2] <= site < r[3]]
                self.assertEqual([(r[4], r[5]) for r in matches], [(landing, action)])

    def test_lsda_corruption_is_rejected(self):
        start = d.FUNCTIONS['user_book_drop']
        addr = self.image.fde_records[start]['lsda']
        with self.assertRaises(d.EvidenceError):
            d.lsda_records(self.image, start, {addr: 0})

    def test_injected_landing_boundaries(self):
        for kind, outcome, frees in (('user', 'resume', 8), ('member', 'resume', 8),
                                     ('both', 'resume', 8), ('double', 'double_unwind', 0)):
            with self.subTest(kind=kind):
                h, result = d.run_landing(self.image, kind)
                self.assertEqual(result, outcome)
                self.assertEqual(len(h.events), frees)

    def test_both_books_rejects_unknown_entry(self):
        with self.assertRaises(ValueError):
            d.run_books(self.image, None, None, mode='other')

    def test_invalid_shape_rejected_by_fixture(self):
        with self.assertRaises(ValueError):
            d.run_inner(self.image, (2, (d.leaf(5),)))
        with self.assertRaises(ValueError):
            d.run_inner(self.image, d.leaf(12))

    def test_mutations_change_observed_results(self):
        for name in ('root_condition', 'free_size_choice', 'user_stride',
                     'member_stride', 'second_book_offset'):
            with self.subTest(name=name):
                self.assertEqual(d.run_mutation(self.image, name)[0], name)

    def test_branch_sweep_preserves_survivors_and_faults(self):
        decoded = {name: d.decode_range(self.image, start, self.image.exact_fde(start)[1])
                   for name, start in d.FUNCTIONS.items()}
        controls = d.conditional_mutations(self.image, decoded)
        self.assertEqual(len(controls), 39)
        by_site = {row[1]: row[5] for row in controls}
        self.assertEqual(by_site['0x33f9223'], 'survived')
        self.assertEqual(by_site['0x33f91f7'], 'interpreter_or_hook_fault')
        self.assertNotIn('no_witness', by_site.values())

    def test_free_hook_rejects_double_free_and_wrong_size(self):
        h = d.DropFixture(self.image)
        desc = h.alloc(24)
        h.descriptor(desc, d.leaf(5))
        root = h.mem.read(desc, 8)
        h.machine.regs[d.RDI] = root
        h.machine.regs[d.RSI] = 592
        h.machine.regs[d.RDX] = 0
        with self.assertRaises(d.Halt):
            h.free(h.machine)
        self.assertIn(root, h.live)
        h.machine.regs[d.RSI] = 496
        h.free(h.machine)
        with self.assertRaises(d.Halt):
            h.free(h.machine)

    def test_slots_are_exact_relative_relocations(self):
        found = {slot: (kind, addend, sym) for slot, kind, addend, sym in self.image.relocations()
                 if slot in (0x576e010, 0x576e470, 0x576e128)}
        self.assertEqual(found, {0x576e010: (8, 0x54c8cb0, 0),
                                 0x576e470: (8, 0x157a9f0, 0),
                                 0x576e128: (8, 0x157b63b, 0)})


if __name__ == '__main__':
    unittest.main()
