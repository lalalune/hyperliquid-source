import copy as copying
import hashlib
import json
import pathlib
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import halt_book_sweep as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-006-halt-book-sweep-94"
IMAGE = tool.load_image()
HARNESS = tool.Harness(IMAGE)
MINE = 20003
OTHER = 20004


def patched(patches):
    return tool.Harness(IMAGE, patches)


def altered(va, data):
    """A view of the image with bytes changed at va, for the structural checks."""
    other = copying.copy(IMAGE)
    blob = bytearray(IMAGE.blob)
    at = IMAGE.offset(va)
    blob[at:at + len(data)] = data
    other.blob = bytes(blob)
    return other


def branch_flip(va):
    """Patch that inverts the conditional jump at va, short or near."""
    at = IMAGE.offset(va)
    byte = IMAGE.blob[at]
    if 0x70 <= byte <= 0x7F:
        return {va: byte ^ 1}
    return {va + 1: IMAGE.blob[at + 1] ^ 1}


def find_row(start, wanted):
    begin, end = IMAGE.exact_fde(start)
    for row in tool.decode_range(IMAGE, begin, end):
        if wanted(row):
            return row
    raise AssertionError("no such row")


def queue(copy=0, **options):
    case = tool.QueueCase("t", **options)
    return case, HARNESS.run_queue(copy, case)


class IdentityTests(unittest.TestCase):
    def test_wrong_digest_is_rejected(self):
        with self.assertRaisesRegex(tool.EvidenceError, "SHA-256 mismatch"):
            tool.load_image(expected="0" * 64)

    def test_non_elf_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Expected ELF64"):
            tool.Image(b"\0" * 128)

    def test_interior_address_is_not_a_function_start(self):
        with self.assertRaisesRegex(tool.EvidenceError, "not an FDE start"):
            IMAGE.exact_fde(tool.HALTS[0] + 1)

    def test_address_outside_every_fde(self):
        with self.assertRaisesRegex(tool.EvidenceError, "outside every FDE"):
            IMAGE.fde(0x10)

    def test_nobits_address_has_no_file_bytes(self):
        bss = IMAGE.named[".bss"]
        with self.assertRaisesRegex(tool.EvidenceError, "outside file-backed"):
            IMAGE.offset(bss["address"] + 8)

    def test_function_sizes(self):
        for pair, size in ((tool.GATES, 321), (tool.HALTS, 1207), (tool.QUEUES, 1958), (tool.BOOK_SWEEPS, 755)):
            for start in pair:
                begin, end = IMAGE.exact_fde(start)
                self.assertEqual(end - begin, size)
        begin, end = IMAGE.exact_fde(tool.UNHALT)
        self.assertEqual(end - begin, 288)

    def test_no_external_program(self):
        text = (ROOT / "tools" / "halt_book_sweep.py").read_text()
        for word in ("subprocess", "objdump", "readelf", "os.system"):
            self.assertNotIn(word, text.replace("No objdump or readelf output", ""))


class DecoderTests(unittest.TestCase):
    def test_sixteen_bit_move_takes_two_bytes(self):
        row = tool.decode(lambda va, count: bytes.fromhex("66b88601") + bytes(count), 0x1000)
        self.assertEqual((row.size, row.b, row.width), (4, ("i", 0x186), 2))

    def test_every_target_decodes_to_its_fde_end(self):
        for start in tool.GATES + tool.HALTS + tool.QUEUES + tool.BOOK_SWEEPS + (tool.UNHALT,):
            rows = tool.decode_range(IMAGE, *IMAGE.exact_fde(start))
            self.assertEqual(rows[-1].next, IMAGE.exact_fde(start)[1])

    def test_overrun_is_reported(self):
        with self.assertRaisesRegex(tool.EvidenceError, "overran"):
            tool.decode_range(IMAGE, tool.HALTS[0], tool.HALTS[0] + 4)


class StructureTests(unittest.TestCase):
    def test_copy_differences_are_fields_and_calls_only(self):
        self.assertEqual(len(tool.copy_differences(IMAGE, *tool.HALTS)), 12)
        self.assertEqual(len(tool.copy_differences(IMAGE, *tool.QUEUES)), 2)
        rows = tool.copy_differences(IMAGE, *tool.GATES)
        self.assertEqual(len(rows), 4)
        for row in rows:
            self.assertRegex(row["left"], r"0x(5c0|5c8|8f2|4cf0850)")

    def test_size_difference_is_rejected(self):
        with self.assertRaisesRegex(tool.EvidenceError, "differ in size"):
            tool.copy_differences(IMAGE, tool.GATES[0], tool.HALTS[0])

    def test_dispatch_reaches_the_halt(self):
        rows = [tool.dispatch_arm(IMAGE, copy) for copy in (0, 1)]
        self.assertEqual([row["halt_call"] for row in rows], ["0x4caf0f5", "0x4cb7a85"])
        self.assertEqual([row["flag_false_arm"] for row in rows], ["0x4cb001b", "0x4cb89ab"])

    def test_dispatch_entry_changed(self):
        bad = altered(tool.DISPATCH_TABLES[0] + tool.DISPATCH_FIELD * 4, struct.pack("<i", 0))
        with self.assertRaises(tool.EvidenceError):
            tool.dispatch_arm(bad, 0)

    def test_flag_true_call_changed(self):
        with self.assertRaisesRegex(tool.EvidenceError, "does not call the halt"):
            tool.dispatch_arm(altered(0x4CAF0F6, b"\0\0\0\0"), 0)

    def test_book_sweep_reason_is_delisted_canceled(self):
        rows = tool.book_sweep_sites(IMAGE)
        self.assertEqual({row["status_name"] for row in rows}, {"delistedCanceled"})
        self.assertEqual({row["reason"] for row in rows}, {0xC})

    def test_book_sweep_reason_changed(self):
        with self.assertRaisesRegex(tool.EvidenceError, "reason or flag"):
            tool.book_sweep_sites(altered(0x43080A8, b"\x0b"))

    def test_byte_pin_changed(self):
        with self.assertRaisesRegex(tool.EvidenceError, "pin changed"):
            tool.byte_pins(altered(0x49FF5ED, b"\x09"))

    def test_halt_stores_nothing_past_the_stack(self):
        self.assertEqual(tool.stores_outside_stack(IMAGE, tool.HALTS[0]), [])
        self.assertEqual(tool.stores_outside_stack(IMAGE, tool.HALTS[1]), [])
        self.assertEqual(len(tool.stores_outside_stack(IMAGE, tool.GATES[0])), 1)

    def test_delay_table(self):
        self.assertEqual(struct.unpack_from("<2d", IMAGE.blob, IMAGE.offset(tool.DELAY_TABLE)), (3600.0, 300.0))

    def test_callers(self):
        sites = tool.direct_sites(IMAGE, tool.HALTS + tool.GATES + (tool.UNHALT,))
        self.assertEqual([hex(va) for va, _ in sorted(sites[tool.HALTS[0]])], ["0x49ff655", "0x4caf0f5", "0x4cf3624"])
        self.assertEqual(len(sites[tool.UNHALT]), 4)
        self.assertEqual(len(sites[tool.GATES[0]]), 1)


class GateTests(unittest.TestCase):
    def word(self, **options):
        case = tool.GateCase("t", **options)
        result = HARNESS.run_gate(0, case)
        self.assertEqual(tool.compare(result, tool.spec_gate(0, case), "t"), "")
        return result

    def test_equal_time_passes(self):
        self.assertEqual(self.word()["word"], tool.STATUS_OK)

    def test_one_nanosecond_early_is_refused(self):
        result = self.word(deadline=(5, 6, 8))
        self.assertEqual(result["word"], tool.STATUS_TOO_SOON)
        self.assertFalse([row for row in result["events"] if row[0] == "halt"])

    def test_first_word_is_signed(self):
        self.assertEqual(self.word(deadline=(0xFFFFFFFF, 0, 0), now=(0, 0, 0))["word"], tool.STATUS_OK)
        self.assertEqual(self.word(deadline=(0, 0, 0), now=(0xFFFFFFFF, 0, 0))["word"], tool.STATUS_TOO_SOON)

    def test_other_words_are_unsigned(self):
        self.assertEqual(self.word(deadline=(0, 0x80000000, 0), now=(0, 1, 0))["word"], tool.STATUS_TOO_SOON)
        self.assertEqual(self.word(deadline=(0, 0, 0x80000000), now=(0, 0, 1))["word"], tool.STATUS_TOO_SOON)

    def test_delay_by_byte(self):
        for byte, seconds in ((0, 3600.0), (1, 300.0), (2, 300.0), (3, 3600.0), (255, 3600.0)):
            events = self.word(byte=byte)["events"]
            self.assertEqual(events[1][2], tool.to_bits(seconds))

    def test_status_three_skips_the_date(self):
        result = self.word(status=3, deadline=(9, 9, 9), now=(1, 1, 1))
        self.assertEqual([row[0] for row in result["events"]], ["drop", "halt"])

    def test_bound_panics_at_location(self):
        self.assertEqual(self.word(asset=30000)["stop"][1], tool.LOCATION_GATE)

    def test_changed_delay_index_is_seen(self):
        row = find_row(tool.GATES[0], lambda item: item.op == "cmp" and item.width == 1 and item.b == ("i", 2))
        harness = patched({row.va + row.imm_at: 1})
        self.assertIn("event", tool.compare_gate(harness, 0, tool.GateCase("byte", byte=2)))

    def test_inverted_gate_branch_is_seen(self):
        harness = patched(branch_flip(0x4CF3605))
        cases = [tool.GateCase("older", deadline=(4, 6, 7)), tool.GateCase("newer", deadline=(6, 6, 7))]
        self.assertTrue(any(tool.compare_gate(harness, 0, case) for case in cases))


class HaltTests(unittest.TestCase):
    def run_case(self, **options):
        case = tool.HaltCase("t", **options)
        for copy in (0, 1):
            result = HARNESS.run_halt(copy, case)
            self.assertEqual(tool.compare(result, tool.spec_halt(copy, case), "t"), "")
        return result

    def names(self, **options):
        return [row[0] for row in self.run_case(**options)["events"]]

    def test_full_order(self):
        self.assertEqual(self.names(), ["drop", "insert", "drop", "book", "queue", "finish", "drop", "rows", "record", "apply", "finish", "free"])

    def test_second_insert_does_nothing(self):
        self.assertEqual(self.names(keys=(MINE,)), ["drop"])

    def test_no_tag_means_no_record_call(self):
        result = self.run_case(tag=0)
        self.assertNotIn("record", [row[0] for row in result["events"]])
        apply_row = next(row for row in result["events"] if row[0] == "apply")
        self.assertEqual(apply_row[4], (1,) + (0,) * 32)

    def test_apply_kind(self):
        apply_row = next(row for row in self.run_case()["events"] if row[0] == "apply")
        self.assertEqual(apply_row[6], 0x30003)

    def test_set_grows_before_the_book_bound(self):
        result = self.run_case(asset=20000, collections=2)
        self.assertEqual(result["events"][-1][0], "insert")
        self.assertEqual(result["stop"][1], tool.LOCATION_COLLECTION)

    def test_book_bound_at_location(self):
        result = self.run_case(asset=20005)
        self.assertEqual(result["stop"], ("panic", tool.LOCATION_BOOK))

    def test_exact_multiple_splits(self):
        book = next(row for row in self.run_case(asset=20000)["events"] if row[0] == "book")
        self.assertEqual(book[1], tool.BOOKS)
        book = next(row for row in self.run_case(asset=19999, books=10000, keys=(1,))["events"] if row[0] == "book")
        self.assertEqual(book[1], tool.BOOKS + 9999 * tool.BOOK_STRIDE)

    def test_tree_paths(self):
        for keys, width in ((range(19980, 20030, 3), 3), (range(19900, 20100, 2), 2), (range(19993, 20004), 11)):
            present = MINE in keys
            self.assertEqual(len(self.names(keys=tuple(keys), width=width)) == 1, present)

    def test_vectors_move_to_the_finish(self):
        result = self.run_case(book_vector=(4, 0x70000, 2), queue_vector=(8, 0x71000, 5), apply_vector=(16, 0x72000, 3))
        finishes = [row[1] for row in result["events"] if row[0] == "finish"]
        self.assertEqual(finishes, [(8, 0x71000, 5), (16, 0x72000, 3)])

    def test_wrong_apply_constant_is_seen(self):
        row = find_row(tool.HALTS[0], lambda item: item.op == "mov" and item.b == ("i", tool.APPLY_KIND))
        harness = patched({row.va + row.imm_at: 4})
        self.assertIn("event", tool.compare_halt(harness, 0, tool.HaltCase("kind")))

    def test_inverted_present_branch_is_seen(self):
        harness = patched(branch_flip(0x4CF0905))
        self.assertTrue(tool.compare_halt(harness, 0, tool.HaltCase("present", keys=(MINE,))))

    def test_changed_market_stride_is_seen(self):
        row = find_row(tool.HALTS[0], lambda item: item.op == "imul3" and item.target == tool.MARKET_STRIDE)
        harness = patched({row.va + row.imm_at: 0xF1})
        self.assertTrue(tool.compare_halt(harness, 0, tool.HaltCase("stride")))


class UnhaltTests(unittest.TestCase):
    def word(self, **options):
        case = tool.UnhaltCase("t", **options)
        result = HARNESS.run_unhalt(case)
        self.assertEqual(tool.compare(result, tool.spec_unhalt(case), "t"), "")
        return result

    def test_present_and_absent_both_answer_ok(self):
        self.assertEqual(self.word(present=1)["word"], tool.STATUS_OK)
        self.assertEqual(self.word(present=0)["word"], tool.STATUS_OK)

    def test_status_one_and_two_are_blocked(self):
        for status in (1, 2, 4):
            result = self.word(status=status)
            self.assertEqual(result["word"], tool.STATUS_BLOCKED)
            self.assertEqual([row[0] for row in result["events"]], ["drop"])

    def test_status_three_removes(self):
        self.assertEqual([row[0] for row in self.word(status=3)["events"]], ["drop", "remove asset"])

    def test_bound(self):
        self.assertEqual(self.word(asset=30000)["stop"][1], tool.LOCATION_MARKET)

    def test_inverted_status_branch_is_seen(self):
        harness = patched(branch_flip(0x4CF0591))
        self.assertTrue(tool.compare_unhalt(harness, 0, tool.UnhaltCase("x", status=2)))


class QueueTests(unittest.TestCase):
    def check(self, **options):
        case, result = queue(**options)
        self.assertEqual(tool.compare(result, tool.spec_queue(0, case), "t"), "")
        return result

    def names(self, **options):
        return [row[0] for row in self.check(**options)["events"]]

    def test_match_emits_one_record(self):
        result = self.check(entries=[tool.Entry(1, 1)], users={1: {1: MINE, 2: OTHER}})
        self.assertEqual(len(result["records"]), 1)
        self.assertEqual(result["records"][0][0], (0, struct.pack("<Q", 4)))
        self.assertEqual(result["records"][0][2], (0x60, struct.pack("<Q", 0x8000000000000001)))

    def test_last_order_removes_the_user(self):
        self.assertIn("remove user", self.names(entries=[tool.Entry(1, 1)], users={1: {1: MINE}}))
        self.assertNotIn("remove user", self.names(entries=[tool.Entry(1, 1)], users={1: {1: MINE, 2: OTHER}}))

    def test_other_asset_goes_back_in_pop_order(self):
        result = self.check(entries=[tool.Entry(2, 1), tool.Entry(1, 1)], users={1: {1: OTHER, 2: OTHER}})
        pushed = [row[1] for row in result["events"] if row[0] == "push"]
        self.assertEqual(pushed, [tool.Entry(2, 1).bytes(), tool.Entry(1, 1).bytes()])

    def test_stale_entry_goes_back(self):
        self.assertEqual(self.names(entries=[tool.Entry(7, 1)], users={1: {1: MINE}}).count("push"), 1)

    def test_failed_removal_drops_the_entry(self):
        names = self.names(entries=[tool.Entry(1, 1, gone=True)], users={1: {1: MINE}})
        self.assertIn("drop failed", names)
        self.assertNotIn("push", names)
        self.assertNotIn("copy", names)

    def test_market_bound_only_at_a_match(self):
        self.assertNotIn("stop", self.check(markets=2, entries=[tool.Entry(1, 1)], users={1: {1: OTHER}}))
        self.assertEqual(self.check(markets=2, entries=[tool.Entry(1, 1)], users={1: {1: MINE}})["stop"][1], tool.LOCATION_GATE)

    def test_output_grows(self):
        result = self.check(out_capacity=1, entries=[tool.Entry(index, 1) for index in range(1, 7)], users={1: {index: MINE for index in range(1, 7)}})
        self.assertEqual(result["out_capacity"], 8)
        self.assertEqual(len(result["records"]), 6)

    def test_short_record_field_is_seen(self):
        row = find_row(tool.QUEUES[0], lambda item: item.op == "mov" and item.a[0] == "r" and item.b == ("i", 0x278))
        harness = patched({row.va + row.imm_at: 0x70})
        case = tool.QueueCase("size", entries=[tool.Entry(1, 1)], users={1: {1: MINE}})
        self.assertTrue(tool.compare_queue(harness, 0, case))

    def test_inverted_asset_test_is_seen(self):
        harness = patched(branch_flip(0x42F268D))
        case = tool.QueueCase("asset", entries=[tool.Entry(1, 1)], users={1: {1: MINE}})
        self.assertTrue(tool.compare_queue(harness, 0, case))

    def test_stale_memory_is_not_read_as_an_edge(self):
        harness = patched({0x42F264D: 0})
        case = tool.QueueCase("edge", entries=[tool.Entry(1, 1)], users={1: {5: MINE}})
        self.assertTrue(tool.compare_queue(harness, 0, case))


class TreeTests(unittest.TestCase):
    def test_depth_is_uniform(self):
        def depth(items, width, height):
            separators, children = tool.chunks(items, width, height)
            if children is None:
                return {0}
            self.assertLessEqual(len(separators), width)
            self.assertEqual(len(children), len(separators) + 1)
            return {1 + value for child in children for value in depth(child, width, height - 1)}

        for size in (1, 3, 4, 12, 40, 200):
            for width in (2, 3, 11):
                self.assertEqual(len(depth(list(range(size)), width, tool.tree_height(size, width))), 1)

    def test_height_grows_past_a_full_node(self):
        self.assertEqual(tool.tree_height(11, 11), 0)
        self.assertEqual(tool.tree_height(12, 11), 1)


class CompareTests(unittest.TestCase):
    def test_compare_reports_each_difference(self):
        base = {"events": [("a", 1)], "word": 5}
        self.assertEqual(tool.compare(base, dict(base), "t"), "")
        self.assertIn("stop", tool.compare(dict(base, stop=("x",)), base, "t"))
        self.assertIn("event 0", tool.compare(dict(base, events=[("a", 2)]), base, "t"))
        self.assertIn("events", tool.compare(dict(base, events=[]), base, "t"))
        self.assertIn("word", tool.compare(dict(base, word=6), base, "t"))

    def test_mutation_targets_cover_each_kind(self):
        rows = tool.decode_range(IMAGE, *IMAGE.exact_fde(tool.HALTS[0]))
        kinds = {kind for _, _, kind in tool.mutation_targets(IMAGE, rows)}
        self.assertTrue({"branch", "immediate", "offset"} <= kinds)

    def test_short_jump_patch_hits_the_opcode(self):
        rows = tool.decode_range(IMAGE, *IMAGE.exact_fde(tool.HALTS[0]))
        row = next(item for item in rows if item.op == "jcc" and item.size == 2)
        patch = tool.mutate_patch(IMAGE, row.va, 0)
        self.assertEqual(list(patch), [row.va])


class PacketTests(unittest.TestCase):
    def setup(cls):
        cls.evidence = tool.analyse(IMAGE, full=False)
        cls.files = tool.render(cls.evidence)

    setUpClass = classmethod(setup)

    def test_no_mismatch(self):
        self.assertEqual(self.evidence["mismatches"], 0)
        self.assertEqual(self.evidence["first_mismatch"], "")

    def test_static_files_regenerate(self):
        stored = json.loads((FOLDER / "evidence.json").read_text())
        built = json.loads(self.files["evidence.json"])
        for key in ("target", "field_sets", "constants", "delay_seconds", "node_shapes", "locations", "dispatch", "book_sweep_sites", "byte_pins",
                    "cases", "outcomes", "mismatches", "instructions_stepped", "reference_claims", "record_map"):
            self.assertEqual(stored[key], built[key], key)
        for name in ("call_sites.tsv", "copy_differences.tsv"):
            self.assertEqual((FOLDER / name).read_text(), self.files[name])

    def test_manifest_covers_every_file(self):
        lines = (FOLDER / "MANIFEST.sha256").read_text().splitlines()
        listed = {}
        for line in lines:
            digest, name = line.split("  ")
            listed[name] = digest
        expected = {path.name for path in FOLDER.iterdir() if path.name != "MANIFEST.sha256"}
        self.assertEqual(set(listed), expected)
        for name, digest in listed.items():
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)

    def test_every_survivor_has_a_reason(self):
        rows = [line.split("\t") for line in (FOLDER / "mutations.tsv").read_text().splitlines()[1:]]
        self.assertTrue(rows)
        for row in rows:
            if row[3] != "killed":
                self.assertTrue(row[5], row[1])

    def test_location_paths_are_relative(self):
        for row in self.evidence["locations"]:
            self.assertTrue(row["path"].startswith("l1/"), row["path"])

    def test_write_outputs(self):
        with tempfile.TemporaryDirectory() as folder:
            tool.write_outputs(folder, {"a.txt": "x\n"})
            self.assertEqual((pathlib.Path(folder) / "a.txt").read_text(), "x\n")


if __name__ == "__main__":
    unittest.main()
