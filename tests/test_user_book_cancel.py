import hashlib
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import user_book_cancel as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-006-user-book-cancel-94"
FAMILY_A, FAMILY_B, FAMILY_C, FAMILY_D = tool.FAMILIES
USER = tool.user_bytes(5)
OTHER = tool.user_bytes(6)
BIG = tool.MASK[8]


def patched_image(image, changes):
    """A second Image with changed bytes; the digest check is bypassed on purpose."""
    blob = bytearray(image.blob)
    for va, data in changes.items():
        at = image.offset(va)
        blob[at:at + len(data)] = data
    return tool.Image(bytes(blob))


def keys_of(trace):
    return [row[0] for row in trace["removes"]]


class Base(unittest.TestCase):
    def set_up_class(cls):
        cls.image = tool.load_image()
        cls.harness = tool.Harness(cls.image, FAMILY_A)

    setUpClass = classmethod(set_up_class)

    def run_case(self, slab, first=(), second=(), target=USER, **fields):
        entry = tool.simple_entry(USER, first, second)
        return self.harness.run(tool.Case("t", target, [entry], slab, **fields))


class IdentityTests(Base):
    def test_wrong_digest_is_rejected(self):
        with self.assertRaisesRegex(tool.EvidenceError, "SHA-256 mismatch"):
            tool.load_image(expected="0" * 64)

    def test_non_elf_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Expected ELF64"):
            tool.Image(b"\0" * 128)

    def test_interior_address_is_not_a_function_start(self):
        with self.assertRaisesRegex(tool.EvidenceError, "not an FDE start"):
            self.image.exact_fde(FAMILY_A.wrapper + 1)

    def test_address_past_an_fde_end_is_rejected(self):
        with self.assertRaisesRegex(tool.EvidenceError, "outside every FDE"):
            self.image.fde(0x4303DA4 + 3)

    def test_nobits_address_has_no_file_offset(self):
        bss = self.image.named[".bss"]["address"]
        with self.assertRaisesRegex(tool.EvidenceError, "outside file-backed"):
            self.image.offset(bss + 0x10)

    def test_every_function_decodes_to_its_fde_end(self):
        for start, (_, end, rows) in tool.decode_functions(self.image).items():
            self.assertEqual(rows[-1].next, end, hex(start))

    def test_family_pairs_share_one_shape(self):
        decoded = tool.decode_functions(self.image)

        def shape(start):
            return tool.normalized_hash(self.image, start, decoded[start][2])

        self.assertEqual(shape(FAMILY_A.wrapper), shape(FAMILY_B.wrapper))
        self.assertEqual(shape(FAMILY_C.wrapper), shape(FAMILY_D.wrapper))
        self.assertNotEqual(shape(FAMILY_A.wrapper), shape(FAMILY_C.wrapper))
        self.assertEqual(shape(FAMILY_A.collect), shape(FAMILY_C.collect))
        self.assertEqual(shape(FAMILY_A.single), shape(FAMILY_C.single))

    def test_shape_hash_sees_a_changed_instruction(self):
        rows = tool.decode_range(self.image, *self.image.exact_fde(FAMILY_A.wrapper))
        clean = tool.normalized_hash(self.image, FAMILY_A.wrapper, rows)
        bent = bytearray(self.image.blob)
        bent[self.image.offset(FAMILY_A.wrapper + 0x11)] ^= 1
        image = tool.Image.__new__(tool.Image)
        image.__dict__.update(self.image.__dict__)
        image.blob = bytes(bent)
        self.assertNotEqual(clean, tool.normalized_hash(image, FAMILY_A.wrapper, rows))


class LookupTests(Base):
    def test_empty_map_makes_no_call(self):
        trace = self.harness.run(tool.Case("t", USER, [], tool.plain_slab(2)))
        self.assertEqual((trace["removes"], trace["unmapped"], trace["first_alloc"]), ([], [], None))

    def test_absent_user_makes_no_call(self):
        trace = self.harness.run(tool.Case("t", OTHER, [tool.simple_entry(USER, [0])], tool.plain_slab(2)))
        self.assertEqual((trace["removes"], trace["unmapped"]), ([], []))

    def test_key_past_a_node_length_is_not_found(self):
        case = tool.Case("t", OTHER, [tool.simple_entry(USER, [0])], tool.plain_slab(2), stale_target=True)
        self.assertEqual(self.harness.run(case)["removes"], [])

    def test_user_in_an_inner_node_and_in_a_leaf(self):
        users = [tool.user_bytes(index * 2 + 1) for index in range(30)]
        entries = [tool.simple_entry(user, [0]) for user in users]
        for user in users:
            case = tool.Case("t", user, entries, tool.plain_slab(1), map_height=1)
            self.assertEqual(self.harness.run(case)["unmapped"], [user])

    def test_all_twenty_bytes_are_compared(self):
        near = USER[:19] + bytes([USER[19] ^ 1])
        trace = self.harness.run(tool.Case("t", near, [tool.simple_entry(USER, [0])], tool.plain_slab(1)))
        self.assertEqual(trace["removes"], [])


class CollectionTests(Base):
    def test_removals_run_in_ascending_unsigned_key_order(self):
        slab = [(0, 0, tool.NONE_WORD), (0, 0, 1), (0, 0, BIG), (0, 0, 7)]
        self.assertEqual(keys_of(self.run_case(slab, range(4))), [1, 7, tool.NONE_WORD, BIG])

    def test_same_key_is_removed_once(self):
        self.assertEqual(keys_of(self.run_case([(0, 0, 9), (0, 0, 9), (0, 0, 8)], range(3), [9, 3])), [3, 8, 9])

    def test_second_tree_keys_need_no_slab_slot(self):
        self.assertEqual(keys_of(self.run_case([], (), [BIG, 4])), [4, BIG])

    def test_stale_vacant_and_flagged_slots(self):
        slab = [(0, 0, 10), (2, 0, 20), (0x100000002, 0, 30), (0x200000000, 0, 40), (0, 1, 50), (0, 2, 60)]
        self.assertEqual(keys_of(self.run_case(slab, list(range(6)) + [6, BIG])), [10, 40, 50, 60])
        self.assertEqual(keys_of(self.run_case(slab, list(range(6)) + [6, BIG], flag=0)), [10, 40, 60])

    def test_flag_is_one_low_byte(self):
        slab = [(0, 1, 5), (0, 0, 6)]
        self.assertEqual(keys_of(self.run_case(slab, [0, 1], [9], flag=0x100)), [6])
        self.assertEqual(keys_of(self.run_case(slab, [0, 1], [9], flag=0x180)), [5, 6, 9])

    def test_flag_zero_ignores_the_second_tree_and_keeps_the_entry(self):
        trace = self.run_case(tool.plain_slab(2), [0], [9], flag=0)
        self.assertEqual(keys_of(trace), [tool.order_key(1)])
        self.assertEqual((trace["unmapped"], trace["dropped"]), ([], []))

    def test_reason_is_one_low_byte_and_context_passes_through(self):
        trace = self.run_case(tool.plain_slab(1), [0], reason=0xABCD1202, rcx=11, r8=22)
        self.assertEqual(trace["removes"], [(tool.order_key(1), USER, 11, 22, 2)])

    def test_the_driver_sort_starts_at_twenty_one_keys(self):
        for count, sorts in ((20, 0), (21, 1)):
            trace = self.run_case(tool.plain_slab(count), range(count))
            self.assertEqual(trace["sorts"], sorts)
            self.assertEqual(keys_of(trace), sorted(tool.order_key(index + 1) for index in range(count)))

    def test_every_allocation_is_returned(self):
        trace = self.run_case(tool.plain_slab(40), range(40), list(range(30)))
        self.assertEqual((trace["leaked"], len(trace["removes"])), (0, 70))

    def test_keys_are_fixed_before_the_first_removal(self):
        slab = tool.plain_slab(5)
        clean = self.run_case(slab, range(5), [1])["removes"]
        self.assertEqual(self.run_case(slab, range(5), [1], clobber=True)["removes"], clean)

    def test_map_entry_removal_and_none_word(self):
        trace = self.run_case(tool.plain_slab(1), [0], unmapped=tool.NONE_WORD)
        self.assertEqual((trace["unmapped"], trace["dropped"]), ([USER], []))
        for word in (0, tool.NONE_WORD + 1, tool.NONE_WORD - 1):
            trace = self.run_case(tool.plain_slab(1), [0], unmapped=word)
            self.assertEqual(trace["dropped"], [word])

    def test_entry_is_removed_even_when_nothing_was_collected(self):
        trace = self.run_case([], (), ())
        self.assertEqual((trace["removes"], trace["unmapped"]), ([], [USER]))

    def test_length_past_the_tree_panics_before_any_removal(self):
        entry = tool.Entry(USER, range(3), (), first_len=4)
        trace = self.harness.run(tool.Case("t", USER, [entry], tool.plain_slab(5)))
        self.assertEqual((trace["panic"], trace["removes"]), (tool.LOCATION_UNWRAP_PARENT, []))

    def test_shorter_length_stops_early(self):
        entry = tool.Entry(USER, range(12), (), 1, 0, first_len=2)
        trace = self.harness.run(tool.Case("t", USER, [entry], tool.plain_slab(12)))
        self.assertEqual(len(trace["removes"]), 2)

    def test_all_families_agree_with_the_specification(self):
        cases = tool.argument_cases()[:30] + tool.filter_cases()[:30]
        for family in tool.FAMILIES:
            failures, _, _ = tool.run_family(self.image, family, cases)
            self.assertEqual(failures, [], family.name)


class ControlTests(Base):
    def patched_run(self, va, data):
        failures, _, _ = tool.run_family(self.image, FAMILY_A, tool.filter_cases() + tool.argument_cases(), True,
                                         {va + index: byte for index, byte in enumerate(data)})
        return failures

    def test_filter_constant_is_seen(self):
        self.assertTrue(self.patched_run(0x4871449 - 7 + 6, b"\x00"))

    def test_chain_filter_tag_is_seen(self):
        self.assertTrue(self.patched_run(0x48863B6 + 3, b"\x03"))

    def test_slab_stride_is_seen(self):
        self.assertTrue(self.patched_run(0x48863AF + 3, b"\xF0"))

    def test_second_arm_flag_compare_is_seen(self):
        self.assertTrue(self.patched_run(0x4303D2B, b"\x75"))

    def test_a_spinning_mutant_stops_at_its_limit(self):
        harness = tool.Harness(self.image, FAMILY_A, {0x48715B4: 0x74})
        harness.machine.step_limit = 50
        case = tool.Case("t", USER, [tool.simple_entry(USER, range(30))], tool.plain_slab(30))
        with self.assertRaisesRegex(tool.Halt, "step limit"):
            harness.run(case)

    def test_reset_refills_only_what_was_used_and_a_new_harness_refills_all(self):
        memory = tool.Memory(self.image)
        memory.heap[0x10] = 1
        memory.heap[0x20] = 1
        memory.reset(0x18)
        self.assertEqual((memory.heap[0x10], memory.heap[0x20]), (0xA5, 1))
        memory.reset()
        self.assertEqual(memory.heap[0x20], 0xA5)
        self.assertEqual(tool.Harness(self.image, FAMILY_A).brk, tool.HEAP_BASE + tool.HEAP_SIZE)

    def test_spec_rejects_a_changed_order(self):
        case = tool.Case("t", USER, [tool.simple_entry(USER, [0, 1])], tool.plain_slab(2))
        original = tool.spec
        try:
            tool.spec = lambda item: dict(original(item), removes=original(item)["removes"][::-1])
            self.assertIn("removes differs", tool.compare(self.harness, case))
        finally:
            tool.spec = original


class BuilderTests(Base):
    def set_up_class(cls):
        super().setUpClass()
        cls.builder = tool.builder_harness(cls.image)

    setUpClass = classmethod(set_up_class)

    def test_absent_user_gives_tag_two(self):
        case = tool.Case("t", OTHER, [tool.simple_entry(USER, [0])], tool.plain_slab(1))
        self.assertEqual(tool.run_builder(self.builder, case), ("absent",))
        self.assertEqual(tool.run_builder(self.builder, tool.Case("t", OTHER, [], [])), ("absent",))

    def test_flagged_slots_are_left_out(self):
        slab = [(0, 1, 5), (0, 0, 6), (2, 0, 7), (0, 2, 8)]
        case = tool.Case("t", USER, [tool.simple_entry(USER, range(5), [9])], slab)
        self.assertEqual(tool.run_builder(self.builder, case), ("found", 1, [6, 8], 2, tool.BOOK, USER))

    def test_nothing_left_gives_an_empty_iterator(self):
        case = tool.Case("t", USER, [tool.simple_entry(USER, [0])], [(0, 1, 5)])
        self.assertEqual(tool.run_builder(self.builder, case), ("found", 0, [], 0, tool.BOOK, USER))


class ClosureTests(Base):
    def outcome(self, start, wrapper, mode, key, books, post=0):
        return tool.ClosureRun(self.image, start, wrapper).run(tool.ClosureCase("t", mode, key, books, post, 5))

    def test_asset_closure_reduces_the_key_modulo_ten_thousand(self):
        calls, panic = self.outcome(0x4C63F20, 0x4303650, 1, 10003, 5)
        self.assertEqual(panic, None)
        self.assertEqual(calls[0][1], tool.CLOSURE_BOOKS + 3 * tool.BOOK_STRIDE)

    def test_index_closure_uses_the_key_as_is(self):
        self.assertEqual(self.outcome(0x4C64080, 0x4303B30, 1, 10003, 5), ([], tool.LOCATION_BOOKS))

    def test_other_modes_walk_every_book_with_flag_one(self):
        calls, _ = self.outcome(0x4C64080, 0x4303B30, 0, 0, 3)
        self.assertEqual([row[1] for row in calls], [tool.CLOSURE_BOOKS + index * tool.BOOK_STRIDE for index in range(3)])
        self.assertEqual({row[3] for row in calls}, {1})

    def test_post_call_needs_its_byte(self):
        self.assertEqual(self.outcome(0x4C64300, 0x4303DB0, 0, 0, 0), ([], None))
        calls, _ = self.outcome(0x4C64300, 0x4303DB0, 0, 0, 0, 1)
        self.assertEqual([row[0] for row in calls], ["post"])

    def test_modulo_constant_is_seen_at_an_exact_multiple(self):
        cases = tool.closure_mutant_cases()
        self.assertEqual(tool.compare_closures(self.image, 0x4C63F20, 0x4303650, cases), [])
        failed = tool.compare_closures(self.image, 0x4C63F20, 0x4303650, cases, {0x4C63F7E: 0x4A}, True)
        self.assertIn("key 10000", failed[0])

    def test_book_stride_is_seen(self):
        failed = tool.compare_closures(self.image, 0x4C64080, 0x4303B30, tool.closure_mutant_cases(), {0x4C640E9: 0xD9}, True)
        self.assertEqual(len(failed), 1)

    def test_wrong_wrapper_target_is_seen(self):
        with self.assertRaisesRegex(tool.Halt, "unmodelled call"):
            self.outcome(0x4C64080, 0x4303DB0, 0, 0, 1)


class CensusTests(Base):
    def set_up_class(cls):
        super().setUpClass()
        cls.calls, cls.edges = tool.census(cls.image)

    setUpClass = classmethod(set_up_class)

    def test_twenty_six_sites_all_pass_flag_one(self):
        self.assertEqual(len(self.calls), 26)
        self.assertEqual({row["flag"] for row in self.calls}, {1})
        self.assertEqual({row["opcode"] for row in self.calls}, {0xE8})

    def test_reasons(self):
        counts = {}
        for row in self.calls:
            counts[row["reason"]] = counts.get(row["reason"], 0) + 1
        self.assertEqual(counts, {2: 4, 0xC: 4, 0xD: 6, 0xE: 2, 0x10: 2, None: 8})

    def test_no_wrapper_has_its_address_taken(self):
        self.assertEqual({row["address_refs"] for row in self.edges}, {0})

    def test_filter_builder_a_b_has_one_caller(self):
        row = next(item for item in self.edges if item["role"] == "filter builder a b")
        self.assertEqual(row["fdes"], [0x431DB10])

    def test_literal_user_bytes_are_checked(self):
        site = 0x42E0B95
        self.assertEqual(tool.literal_user(self.image, site), "all 0xfe")
        bent = tool.Image.__new__(tool.Image)
        bent.__dict__.update(self.image.__dict__)
        blob = bytearray(self.image.blob)
        blob[self.image.offset(0x42E0B72 + 4)] ^= 1
        bent.blob = bytes(blob)
        with self.assertRaisesRegex(tool.EvidenceError, "literal user bytes differ"):
            tool.literal_user(bent, site)

    def test_a_flag_write_is_read_from_the_bytes(self):
        bent = tool.Image.__new__(tool.Image)
        bent.__dict__.update(self.image.__dict__)
        blob = bytearray(self.image.blob)
        blob[self.image.offset(0x4306F99 + 1)] = 0
        bent.blob = bytes(blob)
        self.assertEqual(tool.last_writer(bent, 0x4306FAE, tool.RDX), (0x4306F99, 0))


class PacketTests(Base):
    def test_manifest_matches_the_folder(self):
        names = set()
        for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ")
            names.add(name)
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)
        self.assertEqual(names, {path.name for path in FOLDER.iterdir()} - {"MANIFEST.sha256"})

    def test_static_files_regenerate(self):
        evidence = tool.analyse(self.image, full=False)
        files = tool.render(evidence)
        with tempfile.TemporaryDirectory() as folder:
            tool.write_outputs(folder, files)
            for name in ("callers.tsv", "edges.tsv", "closures.tsv"):
                self.assertEqual((pathlib.Path(folder) / name).read_bytes(), (FOLDER / name).read_bytes(), name)

    def test_no_mutant_survived_and_every_unreached_row_has_a_reason(self):
        rows = [line.split("\t") for line in (FOLDER / "mutations.tsv").read_text().splitlines()[1:]]
        self.assertEqual([row for row in rows if row[2] == "survived"], [])
        for row in rows:
            if row[2] == "unreached":
                self.assertEqual(row[4], tool.unreached_group(int(row[0], 16)))

    def test_unknown_unreached_row_is_refused(self):
        with self.assertRaisesRegex(tool.EvidenceError, "outside every known group"):
            tool.unreached_group(0x4303B30)

    def test_mutation_counts_match_the_evidence(self):
        rows = (FOLDER / "mutations.tsv").read_text().splitlines()[1:]
        document = tool.json.loads((FOLDER / "evidence.json").read_text())
        for result, count in document["mutations"].items():
            self.assertEqual(sum(1 for row in rows if row.split("\t")[2] == result), count, result)


if __name__ == "__main__":
    unittest.main()
