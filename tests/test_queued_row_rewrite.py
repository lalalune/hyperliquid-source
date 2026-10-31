import hashlib
import json
import pathlib
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import queued_row_rewrite as t  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-006-queued-row-rewrite-94"


def shared(cls):
    cls.image = t.load_image()
    cls.harness = t.Harness(cls.image)


class Base(unittest.TestCase):
    setUpClass = classmethod(shared)

    def rewrite(self, rows=(), copy="a", **change):
        case = self.case(rows, copy, **change)
        self.assertEqual(t.compare_run(self.harness, case), "")
        return self.harness.run(case)

    def case(self, rows=(), copy="a", **change):
        w = t.world(rows, **change)
        order = []
        for at, row in enumerate(w["rows"]):
            word = t.word(row, 0)
            if (word == 8 or word >= 11) and row[0x23A] != w["request"][0x30]:
                amount = t.word(row, 0x230)
                result = w["sibling_by_row"].get(at, w["sibling"])
                if amount and (result.get("error") is not None or result["token"] >= len(w["tokens"]) or w["tokens"][result["token"]]["count"] != 1 or result["value"] <= amount):
                    continue
                order.append(at)
        w["turn_order"] = order
        return t.Case("test", "rewrite", copy, w)

    def turn(self, **change):
        w = t.world()
        w.update({"class": 2, "pair": True, "legs": (1, 2, 0, 3), "image": t.turn_image()})
        w.update(change)
        case = t.Case("test", "turn", "", w)
        self.assertEqual(t.compare_run(self.harness, case), "")
        wanted = t.spec_run(case)
        return wanted

    def total(self, fills, copy="a"):
        case = t.Case("test", "total", copy, {"fills": fills})
        self.assertEqual(t.compare_run(self.harness, case), "")
        return self.harness.run(case)

    def mutant(self, va, offset, value, case):
        """One patched byte: the run must stop agreeing with the specification."""
        machine = self.harness.machine
        machine.patches = {va + offset: value}
        machine.cache.pop(va, None)
        try:
            return t.compare_run(self.harness, case)
        finally:
            machine.patches = {}
            machine.cache.pop(va, None)


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
    def test_functions_start_at_fdes(self):
        for start, _ in t.GROUPS:
            self.assertEqual(self.image.exact_fde(start)[0], start)

    def test_address_inside_a_function_refused(self):
        with self.assertRaises(t.EvidenceError):
            self.image.exact_fde(t.DRIVER_A + 1)

    def test_slots(self):
        self.assertEqual(self.harness.relative[t.SLOT_TURN], t.TURN)
        self.assertEqual(self.harness.relative[t.SLOT_CLASS], t.CLASS)

    def test_copies_differ_only_where_listed(self):
        row = t.twin_rows(self.image, t.DRIVER_B, t.DRIVER_C)
        self.assertEqual(row["call_targets_that_differ"], {"0x47f4fc0": "0x47f50d0"})
        self.assertEqual(sorted(row["field_words_that_differ"]), ["0x4329346", "0x43293b5"])
        self.assertEqual(t.twin_rows(self.image, t.ROW_TEST_B, t.ROW_TEST_C)["call_targets_that_differ"], {})
        self.assertEqual(t.twin_rows(self.image, t.TOTAL_A, t.TOTAL_B)["instructions"], 122)

    def test_twin_of_a_different_function_refused(self):
        with self.assertRaises(t.EvidenceError):
            t.twin_rows(self.image, t.DRIVER_B, t.TOTAL_A)

    def test_host_bytes(self):
        self.assertEqual(len(t.read_host_bytes(self.image)), len(t.HOST_BYTES))

    def test_changed_host_byte_refused(self):
        keep = t.HOST_BYTES
        t.HOST_BYTES = ((keep[0][0], "00" + keep[0][1][2:], keep[0][2]),) + keep[1:]
        try:
            with self.assertRaisesRegex(t.EvidenceError, "host bytes"):
                t.read_host_bytes(self.image)
        finally:
            t.HOST_BYTES = keep

    def test_locations(self):
        relative = self.harness.relative
        self.assertEqual(self.image.location(t.LOC_META, relative)[:2], ("l1/src/spot_meta.rs", 565))
        self.assertEqual(self.image.location(t.LOC_TOKEN, relative)[:2], ("l1/src/spot_meta.rs", 113))
        self.assertEqual(self.image.location(t.LOC_BOOK_A, relative)[:2], ("l1/src/books.rs", 14))
        self.assertEqual(self.image.location(t.LOC_SUM_FIRST, relative)[:2], ("l1/src/qtys/mod.rs", 827))

    def test_each_turn_slot_site(self):
        self.assertEqual(sorted(self.image.fde(va)[0] for va in t.slot_sites(self.image, t.SLOT_TURN)), [0x24F92E0, 0x2512AD0, 0x444D7D0, 0x4472550])


class Rows(Base):
    def test_all_cases_agree(self):
        bad = [line for line in (t.compare_run(self.harness, case) for case in t.all_cases()) if line]
        self.assertEqual(bad, [])

    def test_plain_kinds_stay(self):
        for tag in (0, 1, 2, 4, 5, 6, 7, 9, 10):
            row = t.make_row(tag, 0x43, {0xD0: (8, t.OLD_ID), 0x1C8: (8, t.OLD_ID), 0xA8: (8, t.OLD_ID)})
            for copy in "abc":
                self.assertEqual(t.scrub(self.rewrite([row], copy)["rows"]), t.scrub([row]))

    def test_old_record_takes_the_new_one_and_sums_size(self):
        for copy in "abc":
            row = self.rewrite([t.order_row(2, t.OLD_ID, 0, size=1.5)], copy, add=0.25)["rows"][0]
            self.assertEqual(struct.unpack_from("<d", row, 0x38 + 0x68)[0], 1.75)
            self.assertEqual(t.word(row, 0x38 + 0x70), t.NEW_ID)

    def test_record_offset_follows_the_inner_word(self):
        self.assertEqual(t.word(self.rewrite([t.order_row(3, t.OLD_ID, 0)])["rows"][0], 0x30 + 0x70), t.NEW_ID)
        self.assertEqual(t.word(self.rewrite([t.order_row(0, t.OLD_ID, 0)])["rows"][0], 0x30 + 0x70), t.NEW_ID)

    def test_flagged_row_goes_only_with_a_new_id(self):
        self.assertEqual(self.rewrite([t.order_row(2, t.OLD_ID, 1)])["length"], 0)
        self.assertEqual(self.rewrite([t.order_row(2, t.OLD_ID, 1)], new=(0, 0))["length"], 1)

    def test_row_already_on_the_new_id_goes_too(self):
        self.assertEqual(self.rewrite([t.order_row(2, t.NEW_ID, 1)])["length"], 0)

    def test_flag_two_stays(self):
        self.assertEqual(self.rewrite([t.order_row(2, t.OLD_ID, 2)])["length"], 1)

    def test_low_byte_of_the_tag_decides_the_removal(self):
        run = self.rewrite([t.order_row(2, t.OLD_ID, 1)], new=(0x100, t.NEW_ID))
        self.assertEqual(run["length"], 1)
        self.assertEqual(t.word(run["rows"][0], 0x38 + 0x70), t.NEW_ID)

    def test_without_a_new_id_the_record_keeps_the_old_id(self):
        self.assertEqual(t.word(self.rewrite([t.order_row(2, t.OLD_ID, 0)], new=(0, 9))["rows"][0], 0x38 + 0x70), t.OLD_ID)

    def test_later_rows_move_down(self):
        drop = t.order_row(2, t.OLD_ID, 1)
        keep = t.make_row(4, 0x1D)
        for copy in "abc":
            run = self.rewrite([drop, keep, drop, keep], copy)
            self.assertEqual(run["length"], 2)
            self.assertEqual(t.scrub(run["rows"]), t.scrub([keep, keep]))

    def test_leg_ids_move_on_either_side(self):
        for side in (0, 1):
            row = self.rewrite([t.fill_row(side, ids=(t.OLD_ID, 5))], turn={0: (2, {})})["rows"][0]
            self.assertEqual(t.word(row, 0xD0), t.NEW_ID)
            self.assertEqual(t.word(row, 0x1C8), 5)

    def test_same_side_fill_is_not_turned(self):
        self.assertFalse([event for event in self.rewrite([t.fill_row(0)])["events"] if event[0] == "turn"])

    def test_other_side_fill_is_handed_to_the_transform(self):
        self.assertTrue([event for event in self.rewrite([t.fill_row(1)], turn={0: (2, {})})["events"] if event[0] == "turn"])

    def test_turned_row_fields(self):
        row = self.rewrite([t.fill_row(1, amount=0x400)], turn={0: (0, {0x1F0: 0x60, 0x1F8: 3, 0x200: 9, 0x208: 0x360, 0x210: 0})})["rows"][0]
        self.assertEqual([t.word(row, at) for at in (0x1F8, 0x200, 0x208, 0x210, 0x218, 0x230)], [3, 0x60, 9, 0x360, 0, 0xC00])
        self.assertEqual(row[0x23A], 0)

    def test_amount_gate(self):
        for amount, turned in ((0xFFF, 1), (0x1000, 0), (0x1001, 0)):
            events = self.rewrite([t.fill_row(1, amount=amount)], turn={0: (2, {})})["events"]
            self.assertEqual(len([event for event in events if event[0] == "turn"]), turned)

    def test_token_panic(self):
        self.assertEqual(self.rewrite([t.fill_row(1, amount=5)], sibling={"value": 0x1000, "token": 4})["stop"], ("panic", t.LOC_TOKEN))

    def test_book_index_panic(self):
        self.assertEqual(self.rewrite(request=t.request(asset=3))["stop"], ("bounds", 3, 3, t.LOC_BOOK_A))
        self.assertEqual(self.rewrite(copy="b", request=t.request(asset=3))["stop"], ("bounds", 3, 3, t.LOC_BOOK_B))

    def test_view_gets_an_empty_child_list(self):
        view = self.rewrite()["events"][0]
        self.assertEqual(view[15:18], (0, 8, 0))

    def test_flipped_branch_is_seen(self):
        case = self.case([t.order_row(2, t.OLD_ID, 0)])
        self.assertEqual(self.image.blob[self.image.offset(0x24F941A)], 0x75)
        self.assertNotEqual(self.mutant(0x24F941A, 0, 0x74, case), "")

    def test_wrong_copy_offset_is_seen(self):
        case = self.case([t.order_row()], "b")
        self.assertEqual(self.image.blob[self.image.offset(0x43293B5) + 3], 0x08)
        self.assertNotEqual(self.mutant(0x43293B5, 3, 0x88, case), "")


class Turn(Base):
    def test_turned_price_side_and_notional(self):
        answer = self.turn(sibling={"value": 100000000, "token": 1}, image=t.turn_image(px=60000000, size=25, side=1), pair=False)
        out = answer["out"]["bytes"]
        self.assertEqual([t.word(out, at) for at in (0x1F0, 0x1F8, 0x200, 0x208, 0x210)], [40000000, 1, 25, 1000000000, 0])
        self.assertEqual(out[0x224], 0)

    def test_legs_swap(self):
        answer = self.turn(pair=False, image=t.turn_image(tags=(0, 1), bytes_=(5, 6)))
        out = answer["out"]["bytes"]
        self.assertEqual((t.word(out, 0), out[8], t.word(out, t.LEG_SIZE), out[t.LEG_SIZE + 8]), (1, 6, 0, 5))

    def test_codes(self):
        self.assertEqual(self.turn(image=t.turn_image(px=0))["out"], {"tag": 3, "byte": 9})
        self.assertEqual(self.turn(sibling={"value": 0xFF, "token": 1})["out"], {"tag": 3, "byte": 8})
        self.assertEqual(self.turn(sibling={"value": 0x100, "token": 1})["out"], {"tag": 3, "byte": 9})
        self.assertEqual(self.turn(sibling={"error": 4})["out"], {"tag": 3, "byte": 4})

    def test_class_below_two_is_no_turn(self):
        self.assertEqual(self.turn(**{"class": 1})["out"], {"tag": 2})

    def test_notional_limit(self):
        self.assertEqual(self.turn(sibling={"value": 0x100 + 0x7FFFFFFFFFFFFFFF, "token": 1}, image=t.turn_image(size=1))["out"], {"tag": 3, "byte": 0x11})
        self.assertEqual(t.word(self.turn(sibling={"value": 0x100 + 0x7FFFFFFFFFFFFFFE, "token": 1}, image=t.turn_image(size=1))["out"]["bytes"], 0x208), 0x7FFFFFFFFFFFFFFE)

    def test_leg_stop_code(self):
        self.assertEqual(self.turn(legs=(2, 7, 1, 3))["out"], {"tag": 3, "byte": 7})
        self.assertEqual(self.turn(legs=(1, 7, 2, 9))["out"], {"tag": 3, "byte": 9})

    def test_spot_past_the_list(self):
        self.assertEqual(self.turn(image=t.turn_image(spot=5))["stop"], ("bounds", 5, 5, t.LOC_META))


class Totals(Base):
    def test_average_is_a_floor(self):
        self.assertEqual(self.total([(5, 7, 100)])["answer"], (14, 7, 100, 5))

    def test_two_fills(self):
        self.assertEqual(self.total([(5, 4, 100), (5, 6, 100)])["answer"], (20, 10, 200, 5))

    def test_keys_must_match(self):
        self.assertIsNone(self.total([(5, 4, 100), (6, 6, 100)])["answer"])

    def test_first_above_second_is_none(self):
        self.assertIsNone(self.total([(5, 8, 7)])["answer"])
        self.assertIsNone(self.total([(5, 0, 7)])["answer"])

    def test_empty_is_none(self):
        self.assertIsNone(self.total([])["answer"])

    def test_saturation_records(self):
        run = self.total([(5, t.MASK[8], t.MASK[8]), (5, 1, 1)], "a")
        self.assertEqual(run["events"], [("recorded", t.LOC_SUM_FIRST), ("recorded", t.LOC_SUM_SECOND)])
        self.assertEqual(run["answer"], (1, t.MASK[8], t.MASK[8], 5))

    def test_copies_agree(self):
        for fills in ([(5, 4, 100)], [(5, 4, 100), (5, 6, 100)], [(5, 4, 100), (6, 6, 100)]):
            self.assertEqual(self.total(fills, "a")["answer"], self.total(fills, "b")["answer"])


class Packet(Base):
    def setUp(self):
        self.doc = json.loads((FOLDER / "evidence.json").read_text())

    def test_no_mismatch(self):
        self.assertEqual(self.doc["mismatches"], 0)
        self.assertEqual(self.doc["cases"]["total"], len(t.all_cases()))

    def test_no_unexplained_mutant(self):
        lines = (FOLDER / "mutations.tsv").read_text().splitlines()[1:]
        rows = [line.split("\t") for line in lines]
        self.assertEqual({key: sum(1 for row in rows if row[3] == key) for key in ("killed", "survived", "unreached")}, self.doc["mutations"])
        self.assertFalse([row for row in rows if row[3] != "killed" and not row[5]])

    def test_static_files_match_the_tool(self):
        files = t.render(t.analyse(self.image, full=False))
        self.assertEqual(files["call_sites.tsv"], (FOLDER / "call_sites.tsv").read_text())
        self.assertEqual(files["row_actions.tsv"], (FOLDER / "row_actions.tsv").read_text())

    def test_manifest(self):
        lines = (FOLDER / "MANIFEST.sha256").read_text().splitlines()
        self.assertTrue(lines)
        for line in lines:
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_no_external_program(self):
        text = (ROOT / "tools" / "queued_row_rewrite.py").read_text()
        for word_ in ("subprocess", "os.system", "popen"):
            self.assertNotIn(word_, text)


if __name__ == "__main__":
    unittest.main()
