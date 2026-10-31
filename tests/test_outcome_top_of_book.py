import hashlib
import json
import pathlib
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import outcome_top_of_book as t  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-006-outcome-top-of-book-94"


def shared(cls):
    cls.image = t.load_image()
    cls.harness = t.Harness(cls.image)


class Base(unittest.TestCase):
    setUpClass = classmethod(shared)

    def answer(self, case):
        return self.harness.run(case)

    def same(self, case):
        self.assertIsNone(t.compare_run(self.harness, case))


class Identity(Base):
    def test_digest(self):
        self.assertEqual(hashlib.sha256(t.BINARY.read_bytes()).hexdigest(), t.SHA256)

    def test_wrong_digest_refused(self):
        with self.assertRaisesRegex(t.EvidenceError, "SHA-256 mismatch"):
            t.load_image(expected="0" * 64)

    def test_changed_byte_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "copy"
            data = bytearray(t.BINARY.read_bytes()[:4096])
            data[100] ^= 1
            path.write_bytes(bytes(data))
            with self.assertRaisesRegex(t.EvidenceError, "SHA-256 mismatch"):
                t.load_image(path=path)


class Static(Base):
    def test_exact_function_starts(self):
        for start, _ in t.GROUPS:
            self.assertEqual(self.image.exact_fde(start)[0], start)

    def test_inside_a_function_is_not_a_start(self):
        with self.assertRaisesRegex(t.EvidenceError, "not an FDE start"):
            self.image.exact_fde(t.LEG + 1)

    def test_address_outside_refused(self):
        with self.assertRaisesRegex(t.EvidenceError, "outside every FDE"):
            self.image.fde(0x10)

    def test_address_outside_file_refused(self):
        with self.assertRaisesRegex(t.EvidenceError, "outside file-backed"):
            self.image.offset(0x7FFFFFFFFF)

    def test_bss_never_resolves(self):
        section = self.image.named[".bss"]
        with self.assertRaisesRegex(t.EvidenceError, "outside file-backed"):
            self.image.offset(section["address"] + 8)

    def test_slots(self):
        relative = self.harness.relative
        self.assertEqual(relative[t.SLOT_MERGED], t.MERGED)
        self.assertEqual(relative[t.SLOT_CLASSIFY], t.CLASSIFY)
        self.assertEqual(relative[t.SLOT_MID], t.MID)
        self.assertEqual(relative[t.SLOT_GATE], t.GATE)

    def test_merged_call_sites(self):
        self.assertEqual(sorted(t.slot_sites(self.image, t.SLOT_MERGED)), [0x372A2EE, 0x372A316, 0x3730CFF])

    def test_leg_called_only_from_merge(self):
        sites = t.direct_sites(self.image, (t.LEG,))[t.LEG]
        self.assertEqual(sorted(va for va, _ in sites), [0x3727207, 0x3727224])

    def test_gate_sites_all_abort_on_a_byte(self):
        rows = t.read_gate_sites(self.image, t.slot_sites(self.image, t.SLOT_GATE))
        self.assertEqual(len(rows), 3)
        self.assertTrue(all(row["compare"] == "cmp al, 0x27" for row in rows))

    def test_gate_site_wrong_address_refused(self):
        with self.assertRaisesRegex(t.EvidenceError, "gate site bytes"):
            t.read_gate_sites(self.image, [t.GATE])

    def test_mid_sites_hold_the_limit_factors(self):
        rows = t.read_mid_sites(self.image, t.slot_sites(self.image, t.SLOT_MID))
        self.assertEqual(len(rows), 3)
        for row in rows:
            self.assertEqual(sorted(item["value"] for item in row["doubles_after_call"]), [0.97, 1.03])

    def test_locations(self):
        path, line, column = self.image.location(t.LOC_BOOK, self.harness.relative)
        self.assertEqual((path, line, column), ("l1/src/books.rs", 14, 16))
        path, line, _ = self.image.location(t.LOC_LIST, self.harness.relative)
        self.assertEqual((path, line), ("l1/src/spot_meta.rs", 565))

    def test_hash_is_siphash13(self):
        self.assertEqual(len(t.read_hash_check(self.harness)), 4)

    def test_hash_written_differs_when_key_differs(self):
        self.assertNotEqual(t.siphash13(1, 2, 3), t.siphash13(2, 1, 3))


class Spec(unittest.TestCase):
    def test_floor_mean(self):
        self.assertEqual(t.floor_mean(7, 8), 7)
        self.assertEqual(t.floor_mean(0, 8), 0)
        self.assertEqual(t.floor_mean(8, 0), 0)

    def test_abs_key(self):
        self.assertEqual(t.abs_key(-5), 5)
        self.assertEqual(t.abs_key(-(1 << 63)), 1 << 63)

    def test_first_key_climbs(self):
        tree = t.Tree(levels=[(0, [], 1), (2, [-1, -2], 0)])
        self.assertEqual(t.first_key(tree), 2)

    def test_first_key_past_root(self):
        with self.assertRaises(t.Stop):
            t.first_key(t.Tree(levels=[(0, [], 0)], count=1))

    def test_cases_have_unique_enough_kinds(self):
        kinds = {case.kind for case in t.all_cases()}
        self.assertEqual(kinds, {"merged", "leg", "sibling", "classify", "tops", "mid", "gate"})


class Leg(Base):
    def test_no_flip_reads_the_book(self):
        self.assertEqual(self.answer(t.Case("x", "leg", index=0, side=0))["answer"], ("ok", 60000000, 65000000))

    def test_flip_uses_the_sibling_value(self):
        world = t.books(b3=(30000000, 34000000))
        self.assertEqual(self.answer(t.Case("x", "leg", world, index=1, side=1))["answer"], ("ok", t.VALUE - 34000000, t.VALUE - 30000000))

    def test_flip_of_first_leg_uses_second_value(self):
        self.assertEqual(self.answer(t.Case("x", "leg", index=0, side=1))["answer"], ("ok", t.OTHER_VALUE - 65000000, t.OTHER_VALUE - 60000000))

    def test_side_two_is_no_flip(self):
        self.assertEqual(self.answer(t.Case("x", "leg", index=1, side=2))["answer"][1:], (30000000, 34000000))

    def test_wanted_book_decides_over_side(self):
        self.assertEqual(self.answer(t.Case("x", "leg", index=0, side=1, has=1, wanted=2))["answer"][1:], (60000000, 65000000))

    def test_price_at_value(self):
        world = t.books(b3=(t.VALUE, 0))
        self.assertEqual(self.answer(t.Case("x", "leg", world, index=1, side=1))["answer"], ("err", 9))

    def test_price_past_value(self):
        world = t.books(b3=(t.VALUE + 1, 0))
        self.assertEqual(self.answer(t.Case("x", "leg", world, index=1, side=1))["answer"], ("err", 8))

    def test_one_below_value(self):
        world = t.books(b3=(t.VALUE - 1, 0))
        self.assertEqual(self.answer(t.Case("x", "leg", world, index=1, side=1))["answer"], ("ok", 0, 1))

    def test_ask_at_value_on_second_turn(self):
        world = t.books(b3=(0, t.VALUE))
        self.assertEqual(self.answer(t.Case("x", "leg", world, index=1, side=1))["answer"], ("err", 9))

    def test_first_error_wins(self):
        world = t.books(b3=(t.VALUE + 1, t.VALUE))
        self.assertEqual(self.answer(t.Case("x", "leg", world, index=1, side=1))["answer"], ("err", 8))

    def test_empty_book_turns_to_nothing(self):
        world = t.books(b3=(0, 0))
        self.assertEqual(self.answer(t.Case("x", "leg", world, index=1, side=1))["answer"], ("ok", 0, 0))

    def test_two_books_row_refused(self):
        world = t.World()
        world.rows[t.TOKEN_YES] = [2, 3]
        self.assertEqual(self.answer(t.Case("x", "leg", world, index=0))["answer"], ("err", 0))


class Merge(Base):
    def test_best_of_both(self):
        world = t.books(b2=(60000000, 65000000), b3=(30000000, 34000000))
        self.assertEqual(self.answer(t.Case("x", "merged", world))["answer"], ("ok", 66000000, 65000000))

    def test_empty_leg_keeps_the_other(self):
        world = t.books(b2=(60000000, 65000000), b3=(0, 0))
        self.assertEqual(self.answer(t.Case("x", "merged", world))["answer"], ("ok", 60000000, 65000000))

    def test_no_record(self):
        self.assertEqual(self.answer(t.Case("x", "merged", record_id=11))["answer"], ("err", 4))

    def test_second_leg_panic_beats_first_error(self):
        world = t.World(row_count=t.TOKEN_NO)
        world.rows[t.TOKEN_YES] = []
        self.assertEqual(self.answer(t.Case("x", "merged", world))["stop"], ("panic", t.LOC_TOKEN))

    def test_first_error_reported_before_second(self):
        world = t.books(b3=(t.VALUE + 1, 0))
        world.rows[t.TOKEN_YES] = []
        self.assertEqual(self.answer(t.Case("x", "merged", world))["answer"], ("err", 0))

    def test_table_may_differ_from_owner(self):
        self.same(t.Case("x", "merged", split=True, has=1, wanted=3))

    def test_every_table_shape(self):
        for label, changes in t.table_worlds():
            self.same(t.Case(label, "merged", t.World(**changes)))


class Sibling(Base):
    def test_other_record(self):
        self.assertEqual(self.answer(t.Case("x", "sibling", book=2))["answer"], ("record", t.RECORD_ID, 1))
        self.assertEqual(self.answer(t.Case("x", "sibling", book=3))["answer"], ("record", t.RECORD_ID, 0))

    def test_errors(self):
        self.assertEqual(self.answer(t.Case("x", "sibling", book=5))["answer"], ("err", 3))
        self.assertEqual(self.answer(t.Case("x", "sibling", book=4))["answer"], ("err", 4))

    def test_list_bound(self):
        self.assertEqual(self.answer(t.Case("x", "sibling", t.World(list_len=3), book=3))["stop"], ("bounds", 3, 3, t.LOC_LIST))


class Classify(Base):
    def test_values(self):
        for key, value in ((2, 1), (t.TOKEN_YES, 2), (6, 1), (9, 0)):
            self.assertEqual(self.answer(t.Case("x", "classify", key=key))["answer"], value)

    def test_probe_past_a_full_group(self):
        self.same(t.Case("x", "classify", t.World(buckets=64, decoys=40), key=t.TOKEN_YES))


class Tops(Base):
    def test_heights(self):
        for height in (0, 1, 7, 8, 9, 16, 17):
            world = t.World()
            world.books[2] = (t.Tree([-1234], height=height), t.Tree([5678], height=height))
            self.assertEqual(self.answer(t.Case("x", "tops", world))["answer"], (1234, 5678))

    def test_walk_past_root(self):
        world = t.World()
        world.books[2] = (t.Tree(levels=[(0, [], 0)], count=2), t.Tree())
        self.assertEqual(self.answer(t.Case("x", "tops", world))["stop"], ("panic", t.LOC_LEVEL))


class Mid(Base):
    def test_plain(self):
        self.assertEqual(self.answer(t.Case("x", "mid", spot=0))["answer"], 51000000)

    def test_first_map_spot_gives_zero(self):
        self.assertEqual(self.answer(t.Case("x", "mid", spot=1))["answer"], 0)

    def test_outcome_mean_of_merged(self):
        world = t.books(b2=(60000000, 65000000), b3=(30000000, 34000000))
        self.assertEqual(self.answer(t.Case("x", "mid", world, spot=2))["answer"], 65500000)

    def test_failed_turn_gives_zero(self):
        world = t.books(b3=(t.VALUE + 5, 34000000))
        self.assertEqual(self.answer(t.Case("x", "mid", world, spot=2))["answer"], 0)

    def test_list_bound(self):
        self.assertEqual(self.answer(t.Case("x", "mid", spot=7))["stop"], ("bounds", 7, 7, t.LOC_LIST))

    def test_high_keys_do_not_wrap(self):
        self.assertEqual(self.answer(t.Case("x", "mid", t.high_book(), spot=0))["answer"], (1 << 63) - 1)


class Gate(Base):
    def test_plain_spot(self):
        self.assertEqual(self.answer(t.Case("x", "gate", spot=0))["answer"], 3)

    def test_clean_outcome(self):
        self.assertEqual(self.answer(t.Case("x", "gate"))["answer"], t.NONE_BYTE)

    def test_rejected_insert_still_runs_the_merge(self):
        world = t.books(b3=(t.VALUE + 5, 0))
        self.assertEqual(self.answer(t.Case("x", "gate", world, word=0xB7))["answer"], 8)

    def test_ok_word_tag(self):
        self.assertEqual(self.answer(t.Case("x", "gate", word=t.OK_WORD, tag=0))["answer"], 5)
        self.assertEqual(self.answer(t.Case("x", "gate", word=t.OK_WORD, tag=2))["answer"], 5)

    def test_tag_beats_a_missing_record(self):
        self.assertEqual(self.answer(t.Case("x", "gate", spot=4, word=t.OK_WORD, tag=0))["answer"], 5)

    def test_first_fill_chooses_the_frame(self):
        world = t.books(b2=(t.OTHER_VALUE + 1, 0), b3=(30000000, 34000000))
        self.assertEqual(self.answer(t.Case("x", "gate", world, word=t.OK_WORD, fills=((2, 1),)))["answer"], t.NONE_BYTE)
        self.assertEqual(self.answer(t.Case("x", "gate", world, word=t.OK_WORD, fills=((3, 1),)))["answer"], 8)

    def test_sum_recorder(self):
        run = self.answer(t.Case("x", "gate", word=t.OK_WORD, fills=((3, t.MASK[8]), (3, 1), (2, 5))))
        self.assertEqual(run["events"], [("recorder", 0, t.LOC_SUM)] * 2)

    def test_sum_exact_no_recorder(self):
        run = self.answer(t.Case("x", "gate", word=t.OK_WORD, fills=((3, t.MASK[8] - 1), (3, 1))))
        self.assertEqual(run["events"], [])


class Controls(Base):
    """A byte change at a named decision must be seen by the compare."""

    def flip(self, va, at, kind, case):
        machine = self.harness.machine
        machine.patches = t.mutate_patch(self.image, va, at, kind)
        machine.cache.clear()
        try:
            return t.compare_run(self.harness, case)
        finally:
            machine.patches = {}
            machine.cache.clear()

    def test_flip_of_borrow_branch(self):
        world = t.books(b3=(t.VALUE + 1, 0))
        self.assertIsNotNone(self.flip(0x3C01349, 1, "branch", t.Case("x", "leg", world, index=1, side=1)))

    def test_max_of_bids_changed(self):
        world = t.books(b2=(60000000, 65000000), b3=(30000000, 34000000))
        self.assertIsNotNone(self.flip(0x3727266, None, "cmov", t.Case("x", "merged", world)))

    def test_min_of_asks_changed(self):
        world = t.books(b2=(60000000, 65000000), b3=(30000000, 34000000))
        self.assertIsNotNone(self.flip(0x372727C, None, "cmov", t.Case("x", "merged", world)))

    def test_record_field_changed(self):
        self.assertIsNotNone(self.flip(0x3C01342, 3, "offset", t.Case("x", "leg", index=1, side=1)))

    def test_control_clean_without_patch(self):
        self.same(t.Case("x", "leg", index=1, side=1))


class Packet(unittest.TestCase):
    def test_manifest(self):
        lines = (FOLDER / "MANIFEST.sha256").read_text().splitlines()
        names = sorted(p.name for p in FOLDER.iterdir() if p.name != "MANIFEST.sha256")
        self.assertEqual(sorted(line.split("  ")[1] for line in lines), names)
        for line in lines:
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_evidence_counts(self):
        doc = json.loads((FOLDER / "evidence.json").read_text())
        self.assertEqual(doc["mismatches"], 0)
        self.assertEqual(doc["target"]["sha256"], t.SHA256)
        rows = (FOLDER / "mutations.tsv").read_text().splitlines()[1:]
        self.assertEqual(len(rows), sum(doc["mutations"].values()))
        self.assertTrue(all(row.split("\t")[3] == "killed" or row.split("\t")[5] for row in rows))

    def test_small_outputs_match_a_fresh_static_render(self):
        image = t.load_image()
        harness = t.Harness(image)
        text = (FOLDER / "turn.tsv").read_text().splitlines()[1:]
        self.assertEqual(["%d\t%d\t%d\t%s\t%s\t%s" % row for row in t.turn_rows(harness)], text)


if __name__ == "__main__":
    unittest.main()
