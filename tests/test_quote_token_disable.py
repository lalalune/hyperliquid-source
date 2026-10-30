"""Tests for tools/quote_token_disable.py: quote token disable path of node #94."""

import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import quote_token_disable as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-006-quote-token-disable-94"
SHARED = {}
ONE = ((3, 7),)
TWO = ((3, 7), (4, 8), (5, 7))


def shared():
    if not SHARED:
        SHARED["image"] = tool.load_image()
        SHARED["harnesses"] = [tool.Harness(SHARED["image"], copy) for copy in tool.COPIES]
    return SHARED


def run(case, copy=0):
    return shared()["harnesses"][copy].run(case)


def names(result, kind):
    return [event for event in result["events"] if event[0] == kind]


def setUpModule():
    shared()


class IdentityTests(unittest.TestCase):
    def test_wrong_hash_is_refused(self):
        with self.assertRaisesRegex(tool.EvidenceError, "SHA-256 mismatch"):
            tool.load_image(expected="0" * 64)

    def test_hash_constant(self):
        self.assertEqual(tool.SHA256, "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f")

    def test_function_extents(self):
        image = shared()["image"]
        self.assertEqual(image.exact_fde(0x4D63950), (0x4D63950, 0x4D63BE0))
        self.assertEqual(image.exact_fde(0x42F3360), (0x42F3360, 0x42F39B0))
        self.assertEqual(image.exact_fde(0x4308160), (0x4308160, 0x4308453))
        self.assertEqual(image.exact_fde(0x2747D90), (0x2747D90, 0x274830C))

    def test_inside_a_function_is_refused(self):
        with self.assertRaisesRegex(tool.EvidenceError, "not an FDE start"):
            shared()["image"].exact_fde(0x4D63951)

    def test_nobits_never_resolves(self):
        image = shared()["image"]
        bss = image.named[".bss"]
        with self.assertRaisesRegex(tool.EvidenceError, "outside file-backed"):
            image.offset(bss["address"] + 8)

    def test_text_bytes(self):
        self.assertEqual(tool.read_constants(shared()["image"])["text"]["bytes"], "quote token is not currently enabled")

    def test_routes(self):
        rows = tool.read_routes(shared()["image"])
        self.assertEqual([(row["index"], row["arm"]) for row in rows], [(14, "0x4ad7afe"), (62, "0x4cacde3")])
        self.assertEqual(rows[1]["gate"]["zero_goes_to"], "0x4caf273")

    def test_edges_are_real_calls(self):
        self.assertEqual(len(tool.check_edges(shared()["image"])), 11)

    def test_a_wrong_edge_is_refused(self):
        image = shared()["image"]
        broken = dict(tool.COPIES[0], flush=0x432A990)
        saved = tool.COPIES
        tool.COPIES = (broken,)
        try:
            with self.assertRaisesRegex(tool.EvidenceError, "misses"):
                tool.check_edges(image)
        finally:
            tool.COPIES = saved

    def test_pin_count_is_enforced(self):
        image = shared()["image"]
        saved = tool.pin_rows
        tool.pin_rows = lambda: [(0x4D63950, "absent", b"\xde\xad\xbe\xef\x01", 1)]
        try:
            with self.assertRaisesRegex(tool.EvidenceError, "has 0 sites"):
                tool.read_pins(image)
        finally:
            tool.pin_rows = saved

    def test_route_table_is_read(self):
        saved = tool.ROUTES
        tool.ROUTES = (dict(saved[0], index=13),)
        try:
            with self.assertRaisesRegex(tool.EvidenceError, "arm"):
                tool.read_routes(shared()["image"])
        finally:
            tool.ROUTES = saved


class GateTests(unittest.TestCase):
    def test_token_zero(self):
        result = run(tool.Case("t", token=0, status={0: 0}))
        self.assertEqual(result["word"], 0xEF)
        self.assertEqual(result["events"], [])
        self.assertTrue(result["error_text"])

    def test_missing_token(self):
        for status in ({}, {5: 0}, {8: 0}, {5: 0, 9: 0}):
            result = run(tool.Case("t", status=status))
            self.assertEqual(result["word"], 0xDF)
            self.assertEqual(result["events"], [])

    def test_already_disabled(self):
        self.assertEqual(run(tool.Case("t", status={7: 1}))["word"], 0xDF)

    def test_any_other_value_passes(self):
        for value in (0, 2, 255):
            self.assertEqual(run(tool.Case("t", status={7: value}))["word"], 0x186)

    def test_status_byte_is_written_first(self):
        result = run(tool.Case("t", pairs=ONE, books=1))
        self.assertEqual(result["events"][0], ("write status", tool.EX + 0x2E0, 7, 1))

    def test_success_has_no_text(self):
        self.assertFalse(run(tool.Case("t"))["error_text"])


class SpotTests(unittest.TestCase):
    def test_only_the_quote_field_selects(self):
        result = run(tool.Case("t", pairs=((7, 8), (3, 7), (7, 9), (4, 7)), books=4))
        self.assertEqual([event[2] for event in names(result, "tree remove")], [1, 3])

    def test_list_growth(self):
        result = run(tool.Case("t", pairs=tuple((index, 7) for index in range(9)), books=9))
        self.assertEqual(names(result, "alloc"), [("alloc", 0x20)])
        self.assertEqual([event[1] for event in names(result, "grow list")], [4, 8])
        self.assertEqual(names(result, "free"), [("free", "list", 128, 0)])

    def test_tree_key_goes_first_and_book_bound_after(self):
        result = run(tool.Case("t", pairs=ONE, books=0))
        self.assertEqual(result["stop"], ("panic", "books"))
        self.assertEqual(names(result, "tree remove"), [("tree remove", tool.EX + 0x3A00, 0)])

    def test_second_copy_offsets(self):
        result = run(tool.Case("t", pairs=ONE, books=1), 1)
        self.assertEqual(names(result, "tree remove"), [("tree remove", tool.EX + 0x4480, 0)])

    def test_steps_run_spot_by_spot(self):
        case = tool.Case("t", pairs=TWO, books=3, users={0: [1], 2: [2]}, entries=[tool.row(1, 1), tool.row(2, 2)], twaps={1: {1: 0}, 2: {2: 2}}, book_rows=1)
        order = [event[0] for event in run(case)["events"] if event[0] in ("tree remove", "cancel", "remove", "flush")]
        self.assertEqual(order, ["tree remove", "cancel", "remove", "flush", "tree remove", "cancel", "remove", "flush"])


class BookTests(unittest.TestCase):
    def test_every_user_once_in_key_order(self):
        users = list(range(1, 40))
        result = run(tool.Case("t", pairs=ONE, books=1, users={0: users}, book_width=2))
        expected = [tool.user_id(user).hex() for user in sorted(users, key=tool.user_id)]
        self.assertEqual([event[2] for event in names(result, "cancel")], expected)

    def test_flag_one_reason_twelve(self):
        result = run(tool.Case("t", pairs=ONE, books=1, users={0: [1, 2]}))
        self.assertEqual({(event[3], event[4]) for event in names(result, "cancel")}, {(1, 0xC)})

    def test_zero_length_skips_the_clone(self):
        result = run(tool.Case("t", pairs=ONE, books=1, users={0: [1]}, claimed={0: 0}))
        self.assertEqual(names(result, "clone"), [])
        self.assertEqual(names(result, "clone drop"), [("clone drop", 0, 0)])

    def test_null_root_panics(self):
        self.assertEqual(run(tool.Case("t", pairs=ONE, books=1, users={0: [1]}, null_root=(0,)))["stop"], ("panic", "root"))

    def test_long_claim_panics_after_the_last_user(self):
        result = run(tool.Case("t", pairs=ONE, books=1, users={0: [1, 2]}, clone_extra={0: 1}))
        self.assertEqual(result["stop"], ("panic", "walk"))
        self.assertEqual(len(names(result, "cancel")), 2)

    def test_short_claim_stops_early(self):
        result = run(tool.Case("t", pairs=ONE, books=1, users={0: [1, 2, 3]}, clone_extra={0: -1}))
        self.assertEqual(len(names(result, "cancel")), 2)

    def test_tall_spines(self):
        for height in (8, 9, 16, 17):
            result = run(tool.Case("t", pairs=ONE, books=1, users={0: [1, 2, 3]}, book_width=1, book_height={0: height}))
            self.assertEqual(len(names(result, "cancel")), 3)


class SweepTests(unittest.TestCase):
    def test_only_the_matching_spot_ends(self):
        result = run(tool.Case("t", pairs=ONE, books=1, entries=[tool.row(1, 1), tool.row(2, 1)], twaps={1: {1: 0, 2: 9}}))
        self.assertEqual(names(result, "remove"), [("remove", 1, 1)])
        self.assertEqual(result["twaps"], {1: [2]})
        self.assertEqual(result["queue"], [tool.row(2, 1).bytes().hex()])

    def test_last_order_removes_the_user(self):
        result = run(tool.Case("t", pairs=ONE, books=1, entries=[tool.row(1, 1)], twaps={1: {1: 0}}))
        self.assertEqual(names(result, "remove user"), [("remove user", tool.user_id(1).hex())])
        self.assertEqual(result["twaps"], {})

    def test_row_fields(self):
        result = run(tool.Case("t", pairs=ONE, books=1, entries=[tool.row(9, 3)], twaps={3: {9: 0}}))
        rows = names(result, "flush")[0][2]
        self.assertEqual(rows[0][2:4], (0x8000000000000001, 9))
        self.assertEqual(rows[0][5], tool.user_id(3).hex())

    def test_rows_follow_book_rows(self):
        result = run(tool.Case("t", pairs=ONE, books=1, users={0: [1]}, book_rows=2, entries=[tool.row(1, 1)], twaps={1: {1: 0}}))
        self.assertEqual([row[0] for row in names(result, "flush")[0][2]], ["book", "book", "twap"])

    def test_entry_with_no_map_row_stays(self):
        result = run(tool.Case("t", pairs=ONE, books=1, entries=[tool.row(1, 1)], twaps={}))
        self.assertEqual(result["queue"], [tool.row(1, 1).bytes().hex()])

    def test_map_row_with_no_entry_stays(self):
        result = run(tool.Case("t", pairs=ONE, books=1, entries=[tool.row(1, 1)], twaps={1: {1: 0, 2: 0}}))
        self.assertEqual(result["twaps"], {1: [2]})

    def test_a_missed_removal_loses_the_entry(self):
        result = run(tool.Case("t", pairs=ONE, books=1, entries=[tool.row(1, 1), tool.row(2, 1)], twaps={1: {1: 0, 2: 0}}, remove_none=((1, 1),)))
        self.assertEqual(names(result, "error drop"), [("error drop", 0xCE)])
        self.assertEqual(result["queue"], [])
        self.assertEqual(result["twaps"], {1: [1]})

    def test_queue_order_survives(self):
        entries = [tool.row(index, 1 + index % 3, 40 - index) for index in range(1, 20)]
        twaps = {user: {index: index % 2 * 9 for index in range(1, 20) if 1 + index % 3 == user} for user in (1, 2, 3)}
        result = run(tool.Case("t", pairs=ONE, books=1, entries=entries, twaps=twaps))
        kept = sorted((entry for entry in entries if twaps[entry.user][entry.oid] != 0), key=tool.Entry.key)
        self.assertEqual(result["queue"], [entry.bytes().hex() for entry in kept])

    def test_time_comes_from_the_exchange(self):
        now = (tool.pack_date(2026, 7), 11, 22)
        result = run(tool.Case("t", pairs=ONE, books=1, entries=[tool.row(1, 1)], twaps={1: {1: 0}}, now=now))
        self.assertEqual(names(result, "flush")[0][2][0][4], tool.struct.pack("<III", *now).hex())


class SpecTests(unittest.TestCase):
    def test_the_comparison_can_fail(self):
        """A specification that expects another reason is refused by the same compare."""
        harness = shared()["harnesses"][0]
        case = tool.Case("t", pairs=ONE, books=1, users={0: [1]})
        saved = tool.REASON_DELISTED
        tool.REASON_DELISTED = 2
        try:
            self.assertIn("events differs", tool.compare_run(harness, case))
        finally:
            tool.REASON_DELISTED = saved

    def test_a_flipped_branch_is_seen(self):
        """je at 0x4d63969 (token zero) flipped: the zero token no longer gets word 0xef."""
        harness = tool.Harness(shared()["image"])
        harness.machine.patches = tool.mutate_patch(shared()["image"], 0x4D63969, 1)
        self.assertIsNotNone(tool.compare_run(harness, tool.Case("t", token=0, status={0: 0})))

    def test_a_flipped_field_is_seen(self):
        harness = tool.Harness(shared()["image"])
        row = next(row for row in tool.decode_range(shared()["image"], 0x42F3360, 0x42F39B0) if row.va == 0x42F3595)
        harness.machine.patches = tool.mutate_patch(shared()["image"], row.va, tool.displacement_at(shared()["image"], row), "offset")
        case = tool.Case("t", pairs=ONE, books=1, entries=[tool.row(1, 1)], twaps={1: {1: 0}})
        self.assertIsNotNone(tool.compare_run(harness, case))

    def test_all_cases_all_copies(self):
        for index in range(3):
            harness = shared()["harnesses"][index]
            for case in tool.all_cases()[:90]:
                self.assertIsNone(tool.compare_run(harness, case))


class PacketTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads((FOLDER / "evidence.json").read_text())

    def test_totals(self):
        self.assertEqual(self.document["mismatches"], 0)
        self.assertEqual(self.document["first_mismatch"], "")

    def test_every_survivor_has_a_reason(self):
        rows = [line.split("\t") for line in (FOLDER / "mutations.tsv").read_text().splitlines()[1:]]
        self.assertTrue(rows)
        for row in rows:
            self.assertEqual(bool(row[5]), row[3] != "killed", row)

    def test_mutation_counts_match(self):
        rows = [line.split("\t") for line in (FOLDER / "mutations.tsv").read_text().splitlines()[1:]]
        tally = {key: sum(1 for row in rows if row[3] == key) for key in ("killed", "survived", "unreached")}
        self.assertEqual(tally, self.document["mutations"])

    def test_structure_rows_regenerate(self):
        image = shared()["image"]
        self.assertEqual(self.document["pins"], tool.read_pins(image))
        self.assertEqual(self.document["routes"], tool.read_routes(image))
        self.assertEqual(self.document["edges"], tool.check_edges(image))

    def test_no_absolute_path_in_evidence(self):
        for row in self.document["locations"]:
            self.assertFalse(row["path"].startswith("/"), row)

    def test_manifest_lists_every_file(self):
        listed = {line.split("  ")[1] for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines()}
        self.assertEqual(listed, {path.name for path in FOLDER.iterdir() if path.name != "MANIFEST.sha256"})

    def test_write_outputs_is_ascii(self):
        with tempfile.TemporaryDirectory() as folder:
            tool.write_outputs(folder, {"a.txt": "x\n"})
            self.assertEqual((pathlib.Path(folder) / "a.txt").read_text(), "x\n")


if __name__ == "__main__":
    unittest.main()
