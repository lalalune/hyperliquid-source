import hashlib
import pathlib
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import top_order_clone as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-006-top-order-clone-94"
IMAGE = tool.load_image()


def patched(changes):
    return tool.Harness(IMAGE, changes)


def outcome(case, patches=None):
    return tool.Harness(IMAGE, patches).run(case)


class IdentityTests(unittest.TestCase):
    def test_wrong_digest_is_rejected(self):
        with self.assertRaisesRegex(tool.EvidenceError, "SHA-256 mismatch"):
            tool.load_image(expected="0" * 64)

    def test_non_elf_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Expected ELF64"):
            tool.Image(b"\0" * 128)

    def test_interior_address_is_not_a_function_start(self):
        with self.assertRaisesRegex(tool.EvidenceError, "not an FDE start"):
            IMAGE.exact_fde(tool.CLONE + 1)

    def test_address_past_the_fde_end_is_rejected(self):
        end = IMAGE.exact_fde(tool.CLONE)[1]
        with self.assertRaisesRegex(tool.EvidenceError, "outside every FDE"):
            IMAGE.fde(end + 1)

    def test_nobits_address_has_no_file_offset(self):
        bss = IMAGE.named[".bss"]["address"]
        with self.assertRaisesRegex(tool.EvidenceError, "outside file-backed"):
            IMAGE.offset(bss + 0x10)

    def test_both_functions_decode_to_their_fde_ends(self):
        for start in (tool.CLONE, tool.PAIR):
            begin, end = IMAGE.exact_fde(start)
            self.assertEqual(tool.decode_range(IMAGE, begin, end)[-1].next, end)


class CloneTests(unittest.TestCase):
    def test_all_cases_match_the_specification(self):
        harness = tool.Harness(IMAGE)
        self.assertEqual([row for row in map(lambda case: tool.compare(harness, case), tool.all_cases()) if row], [])

    def test_only_the_low_32_flag_bits_pick_the_side(self):
        for flag, index in ((0, 1), (1, 1), (0x100000000, 1)):
            case = tool.Case("t", flag, tool.Tree(index=index))
            self.assertEqual(outcome(case), tool.spec(case))
        wide = outcome(tool.Case("t", 0x100000000, tool.Tree(index=1)))
        self.assertEqual(wide["record"], tool.spec(tool.Case("t", 0, tool.Tree(index=1)))["record"])

    def test_the_other_side_is_not_read(self):
        case = tool.Case("t", 1, tool.Tree(root=False), other=tool.Tree(index=2))
        self.assertEqual(outcome(case), {"stop": ("panic", tool.LOCATION_EMPTY)})

    def test_empty_side_panics(self):
        for tree in (tool.Tree(root=False), tool.Tree(field=0), tool.Tree(root=False, field=9)):
            self.assertEqual(outcome(tool.Case("t", 1, tree)), {"stop": ("panic", tool.LOCATION_EMPTY)})

    def test_level_byte_and_slab_index_panic_at_their_own_locations(self):
        self.assertEqual(outcome(tool.Case("t", 1, tool.Tree(level_flag=0))), {"stop": ("panic", tool.LOCATION_LEVEL)})
        self.assertEqual(outcome(tool.Case("t", 1, tool.Tree(index=3), slab_len=3)), {"stop": ("panic", tool.LOCATION_SLOT)})
        self.assertIn("record", outcome(tool.Case("t", 1, tool.Tree(index=2), slab_len=3)))

    def test_vacant_tag_is_compared_as_64_bits(self):
        self.assertEqual(outcome(tool.Case("t", tag=2)), {"stop": ("panic", tool.LOCATION_SLOT)})
        self.assertIn("record", outcome(tool.Case("t", tag=0x100000002)))

    def test_climb_past_the_root_panics(self):
        tree = tool.Tree(1, lens=[0, 3], parents=[3, 0])
        self.assertEqual(outcome(tool.Case("t", 1, tree)), {"stop": ("panic", tool.LOCATION_NO_PARENT)})

    def test_upper_half_of_the_0x68_tag_is_not_kept(self):
        record = outcome(tool.Case("t", tag68=0x200000001))["record"]
        self.assertEqual(struct.unpack_from("<Q", record, 0x68)[0], 1)

    def test_absent_payloads_hold_stack_bytes_not_source_bytes(self):
        record = outcome(tool.Case("t", tag68=0, tagb1=0))["record"]
        self.assertEqual(record[0x70:0x90], bytes([tool.STACK_MARK]) * 0x20)
        self.assertEqual(record[0xB2:0xC2], bytes([tool.STACK_MARK]) * 0x10)

    def test_gaps_are_not_written(self):
        record = outcome(tool.Case("t"))["record"]
        self.assertEqual(record[0xC3:0xC8], bytes([tool.OUTPUT_MARK]) * 5)
        self.assertEqual(record[0xF6:0xF8], bytes([tool.OUTPUT_MARK]) * 2)

    def test_vector_boundaries(self):
        self.assertEqual(outcome(tool.Case("t", children=0))["pointer_empty"], True)
        for length, align, size in ((0x0FFFFFFFFFFFFFFF, 8, tool.VECTOR_LIMIT), (1 << 60, 0, 1 << 63), (1 << 61, 0, 0)):
            self.assertEqual(outcome(tool.Case("t", children=length)), {"stop": ("allocation", align, size)})

    def test_slot_map_covers_every_byte_once(self):
        at = 0
        for offset, size, _ in tool.SLOT_MAP:
            self.assertEqual(offset, at)
            at += size
        self.assertEqual(at, tool.SLOT_SIZE)

    def test_source_bytes_differ_at_every_field_edge(self):
        body = tool.slot_bytes(1, tool.Case("t"))
        self.assertGreater(len(set(body)), 200)


class ControlTests(unittest.TestCase):
    def failures(self, changes):
        harness = patched(changes)
        return [row for row in (tool.compare(harness, case) for case in tool.all_cases()) if row]

    def test_side_offset_is_seen(self):
        self.assertTrue(self.failures({0x49E3949: 0x90}))

    def test_level_stride_is_seen(self):
        self.assertTrue(self.failures({0x49E3A28: 0x04}))

    def test_slot_stride_is_seen(self):
        self.assertTrue(self.failures({0x49E3A49: 0xF0}))

    def test_vacant_constant_is_seen(self):
        self.assertTrue(self.failures({0x49E3A55: 0x03}))

    def test_copied_field_displacement_is_seen(self):
        self.assertTrue(self.failures({0x49E3B90: 0x98}))

    def test_a_vector_that_is_not_a_fresh_buffer_is_refused(self):
        harness = tool.Harness(IMAGE)
        harness.install(tool.Case("t"))
        harness.machine.memory.write(tool.OUTPUT + 0x58, 8, tool.HEAP_BASE + 0x100)
        harness.machine.memory.write(tool.OUTPUT + 0x60, 8, 1)
        with self.assertRaisesRegex(tool.Halt, "not a fresh allocation"):
            harness.read_record(tool.OUTPUT)

    def test_spec_rejects_a_changed_record(self):
        harness = tool.Harness(IMAGE)
        case = tool.Case("t")
        original = tool.spec
        try:
            tool.spec = lambda item: dict(original(item), record=b"\0" * tool.SLOT_SIZE)
            self.assertIn("differs", tool.compare(harness, case))
        finally:
            tool.spec = original

    def test_step_limit_stops_a_run(self):
        harness = tool.Harness(IMAGE)
        harness.machine.step_limit = 10
        with self.assertRaisesRegex(tool.Halt, "step limit"):
            harness.run(tool.Case("t", 1, tool.Tree(8)))


class PairTests(unittest.TestCase):
    def setUp(self):
        self.harness = tool.Harness(IMAGE)
        self.harness.machine.real = frozenset((tool.CLONE, tool.PAIR))

    def test_all_rows_match(self):
        self.assertEqual([row for row in (tool.compare_pair(self.harness, item) for item in tool.pair_cases()) if row], [])

    def test_zero_flag_tree_comes_first(self):
        result = tool.run_pair(self.harness, "t", tool.Tree(index=1), tool.Tree(index=2))
        self.assertEqual(result["first"]["record"][:16], tool.spec_pair(tool.Tree(index=1), tool.Tree(index=2))["first"]["record"][:16])
        self.assertNotEqual(result["first"]["record"], result["second"]["record"])

    def test_either_empty_side_panics(self):
        for left, right in ((tool.Tree(root=False), tool.Tree()), (tool.Tree(), tool.Tree(root=False))):
            self.assertEqual(tool.run_pair(self.harness, "t", left, right), {"stop": ("panic", tool.LOCATION_EMPTY)})

    def test_second_flag_constant_is_seen(self):
        harness = tool.Harness(IMAGE, {0x4A06F98: 0x00})
        harness.machine.real = frozenset((tool.CLONE, tool.PAIR))
        self.assertTrue(tool.compare_pair(harness, tool.pair_cases()[0]))


class CensusTests(unittest.TestCase):
    def load(cls):
        cls.calls, cls.refs = tool.census(IMAGE)

    setUpClass = classmethod(load)

    def test_clone_has_two_sites_with_flags_zero_and_one(self):
        rows = [row for row in self.calls if row["target"] == tool.CLONE]
        self.assertEqual([row["argument"] for row in rows], [0, 1])
        self.assertEqual({row["fde"] for row in rows}, {tool.PAIR})

    def test_pair_is_reached_only_from_the_two_self_checks(self):
        rows = [row for row in self.calls if row["target"] == tool.PAIR]
        self.assertEqual({row["fde"] for row in rows}, set(tool.CHECKS))

    def test_all_self_check_sites_pass_zero(self):
        rows = [row for row in self.calls if row["role"] == "self-check"]
        self.assertEqual(len(rows), 4)
        self.assertEqual({row["argument"] for row in rows}, {0})

    def test_no_address_is_taken(self):
        self.assertEqual(set(self.refs.values()), {0})

    def test_gate_is_read_from_bytes(self):
        self.assertEqual(tool.entry_gate(IMAGE, tool.CHECKS[0])["landing"], 0x42FD454)

    def test_changed_gate_is_refused(self):
        bent = tool.Image.__new__(tool.Image)
        bent.__dict__.update(IMAGE.__dict__)
        blob = bytearray(IMAGE.blob)
        blob[IMAGE.offset(0x42FC7A4)] = 0x85
        bent.blob = bytes(blob)
        with self.assertRaisesRegex(tool.EvidenceError, "another shape"):
            tool.entry_gate(bent, tool.CHECKS[0])

    def test_function_without_the_gate_is_refused(self):
        with self.assertRaisesRegex(tool.EvidenceError, "no esi gate"):
            tool.entry_gate(IMAGE, tool.CLONE)


class EquivalenceTests(unittest.TestCase):
    def test_shift_and_limit_flips_reject_the_same_lengths(self):
        lengths = [(top << 60) | low for top in range(16) for low in (0, 1, 7, (1 << 60) - 1)]

        def rejected(length, shift, limit):
            count = (length * 8) & tool.MASK[8]
            return bool(length >> shift) or count > limit

        for length in lengths:
            clean = rejected(length, 61, tool.VECTOR_LIMIT)
            self.assertEqual(rejected(length, 60, tool.VECTOR_LIMIT), clean)
            self.assertEqual(rejected(length, 61, tool.VECTOR_LIMIT | 1), clean)

    def test_every_survivor_has_a_written_reason(self):
        rows = [line.split("\t") for line in (FOLDER / "mutations.tsv").read_text().splitlines()[1:]]
        survivors = [row for row in rows if row[2] == "survived"]
        self.assertEqual({int(row[0], 16) for row in survivors}, set(tool.EQUIVALENT))
        self.assertTrue(all(row[4] for row in survivors))


class PacketTests(unittest.TestCase):
    def test_manifest_matches_the_folder(self):
        names = set()
        for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ")
            names.add(name)
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)
        self.assertEqual(names, {path.name for path in FOLDER.iterdir()} - {"MANIFEST.sha256"})

    def test_all_generated_files_regenerate(self):
        files = tool.render(tool.analyse(IMAGE))
        with tempfile.TemporaryDirectory() as folder:
            tool.write_outputs(folder, files)
            for name in files:
                self.assertEqual((pathlib.Path(folder) / name).read_bytes(), (FOLDER / name).read_bytes(), name)

    def test_mutation_counts_match_the_evidence(self):
        rows = (FOLDER / "mutations.tsv").read_text().splitlines()[1:]
        document = tool.json.loads((FOLDER / "evidence.json").read_text())
        for result, count in document["mutations"].items():
            self.assertEqual(sum(1 for row in rows if row.split("\t")[2] == result), count, result)


if __name__ == "__main__":
    unittest.main()
