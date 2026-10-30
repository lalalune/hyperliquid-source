import hashlib
import json
import pathlib
import struct
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import twap_fill_result as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-006-twap-slice-result-94"
PERP_ROW, SPOT_ROW = tool.HANDLERS[0], tool.HANDLERS[2]
CALLER = tool.CALLERS[0]
TAG_THREE = tool.NICHE_BIT | 3
KEEP = (1, 2, 8, 10, 11, 12, 13, 14, 15, 16, 17)


def load(self):
    self.image = tool.load_image()
    self.harness = tool.Harness(self.image)


def case_named(cases, label):
    return next(case for case in cases if case.label == label)


class Identity(unittest.TestCase):
    setUpClass = classmethod(load)

    def test_wrong_digest_is_refused(self):
        with self.assertRaisesRegex(tool.EvidenceError, "SHA-256 mismatch"):
            tool.load_image(expected="0" * 64)

    def test_every_function_starts_an_fde(self):
        for start in [row["start"] for row in tool.HANDLERS + tool.CALLERS] + [tool.DISPLAY]:
            self.assertEqual(self.image.exact_fde(start)[0], start)

    def test_inner_address_is_not_a_start(self):
        with self.assertRaisesRegex(tool.EvidenceError, "not an FDE start"):
            self.image.exact_fde(PERP_ROW["start"] + 1)

    def test_address_in_a_gap_is_refused(self):
        with self.assertRaisesRegex(tool.EvidenceError, "outside every FDE"):
            self.image.fde(0x42EDCED)

    def test_bss_has_no_file_bytes(self):
        with self.assertRaisesRegex(tool.EvidenceError, "outside file-backed"):
            self.image.offset(0x5788300)

    def test_function_sizes(self):
        sizes = {row["family"]: set() for row in tool.HANDLERS}
        for row in tool.HANDLERS:
            sizes[row["family"]].add(self.image.exact_fde(row["start"])[1] - row["start"])
        self.assertEqual(sizes, {tool.PERP: {2541}, tool.SPOT: {2207}})
        self.assertEqual({self.image.exact_fde(row["start"])[1] - row["start"] for row in tool.CALLERS}, {1598})

    def test_chain_of_calls(self):
        pairs = tool.check_pairing(self.image)
        self.assertEqual(len(pairs), 10)
        self.assertTrue(all(len(row["sites"]) == 1 for row in pairs))

    def test_broken_chain_is_refused(self):
        saved = PERP_ROW["advance"]
        PERP_ROW["advance"] = tool.HANDLERS[1]["advance"]
        try:
            with self.assertRaisesRegex(tool.EvidenceError, "does not reach"):
                tool.check_pairing(self.image)
        finally:
            PERP_ROW["advance"] = saved

    def test_perp_copies_differ_in_market_fields_and_the_advance(self):
        rows = tool.copy_differences(self.image, tool.HANDLERS[0]["start"], tool.HANDLERS[1]["start"])
        self.assertEqual([row["offset"] for row in rows], [0x3D4, 0x3E1, 0x851])
        self.assertTrue(rows[2]["left"].startswith("call"))

    def test_spot_copies_differ_only_in_the_advance(self):
        rows = tool.copy_differences(self.image, tool.HANDLERS[2]["start"], tool.HANDLERS[3]["start"])
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["left"].endswith("%#x" % tool.HANDLERS[2]["advance"]))

    def test_caller_differences_are_fields_and_calls(self):
        rows = tool.copy_differences(self.image, tool.CALLERS[0]["start"], tool.CALLERS[1]["start"])
        self.assertEqual(len(rows), 21)
        self.assertTrue(all(row["left"].startswith(("call", "cmp", "mov", "lea")) for row in rows))

    def test_copies_of_other_size_are_refused(self):
        with self.assertRaisesRegex(tool.EvidenceError, "differ in size"):
            tool.copy_differences(self.image, tool.HANDLERS[0]["start"], tool.HANDLERS[2]["start"])

    def test_pins_are_unique(self):
        self.assertEqual(len(tool.handler_pins(self.image)), 4 * 5)

    def test_missing_pattern_is_refused(self):
        with self.assertRaisesRegex(tool.EvidenceError, "not unique"):
            tool.find_once(self.image, PERP_ROW["start"], b"\xb9\xf9\x02\xfc\x01")

    def test_repeated_pattern_is_refused(self):
        with self.assertRaisesRegex(tool.EvidenceError, "not unique"):
            tool.find_once(self.image, PERP_ROW["start"], b"\x48\x8b")

    def test_status_words_load_once(self):
        self.assertEqual(len(tool.word_sites(self.image, [row["advance"] for row in tool.HANDLERS], tool.FINISH_WORD)), 4)
        self.assertEqual(len(tool.word_sites(self.image, tool.HALT_ROWS, tool.HALT_WORD)), 2)

    def test_word_in_the_wrong_function_is_refused(self):
        with self.assertRaisesRegex(tool.EvidenceError, "not unique"):
            tool.word_sites(self.image, tool.HALT_ROWS, tool.FINISH_WORD)


class Texts(unittest.TestCase):
    setUpClass = classmethod(load)

    def test_table_has_24_arms(self):
        self.assertEqual(len(tool.display_table(self.image)), 24)

    def test_damaged_table_stops_early(self):
        damaged = tool.Image.__new__(tool.Image)
        damaged.__dict__.update(self.image.__dict__)
        blob = bytearray(self.image.blob)
        struct.pack_into("<i", blob, self.image.offset(tool.DISPLAY_TABLE) + 12, 0)
        damaged.blob = bytes(blob)
        self.assertEqual(len(tool.display_table(damaged)), 3)

    def test_mask_gives_the_keep_set(self):
        self.assertEqual([tag for tag in range(tool.TAG_COUNT) if not tool.terminal(tag)], list(KEEP))

    def test_every_tag_runs_through_the_real_display(self):
        for word, label in tool.display_cases():
            self.assertEqual(tool.compare_display(self.harness, None, (word, label)), "", label)

    def test_wrong_text_is_noticed(self):
        saved = tool.LITERALS[3]
        tool.LITERALS[3] = b"Insufficient margin."
        try:
            self.assertIn("tag 3", tool.compare_display(self.harness, None, (TAG_THREE, "tag 3")))
        finally:
            tool.LITERALS[3] = saved

    def test_template_reader(self):
        self.assertEqual(tool.decode_template(self.image.blob, self.image.offset(0x1FC3FA)), "Order must have minimum value of ${}.")

    def test_template_reader_refuses_an_unknown_byte(self):
        with self.assertRaisesRegex(tool.EvidenceError, "unknown template byte"):
            tool.decode_template(b"\x80", 0)

    def test_arguments_of_the_floats(self):
        self.assertEqual(struct.unpack_from("<d", self.image.blob, self.image.offset(tool.F64_TEN))[0], 10.0)
        self.assertEqual(struct.unpack_from("<d", self.image.blob, self.image.offset(tool.F64_HUNDREDTH))[0], 0.01)

    def test_tag_of_a_plain_word_is_two(self):
        self.assertEqual(tool.tag_of(0), 2)
        self.assertEqual(tool.tag_of(tool.NICHE_BIT - 1), 2)
        self.assertEqual(tool.tag_of(tool.NICHE_BIT), 0)
        self.assertEqual(tool.tag_of(tool.NICHE_BIT | 23), 23)


class Handlers(unittest.TestCase):
    setUpClass = classmethod(load)

    def run_case(self, row, **options):
        return self.harness.run_result(row, tool.ResultCase("direct", **options))

    def advanced(self, outcome):
        return [event for event in outcome["events"] if event[0] == "advance"]

    def test_all_cases_on_all_copies(self):
        cases = tool.result_cases()
        self.assertGreater(len(cases), 100)
        for row in tool.HANDLERS:
            for case in cases:
                self.assertEqual(tool.compare_result(self.harness, row, case), "", case.label)

    def test_every_copy_steps_most_of_its_rows(self):
        self.harness.machine.seen.clear()
        for case in tool.result_cases():
            tool.compare_result(self.harness, SPOT_ROW, case)
        rows = tool.decode_range(self.image, *self.image.exact_fde(SPOT_ROW["start"]))
        self.assertGreater(sum(1 for row in rows if row.va in self.harness.machine.seen), 430)

    def test_fills_reach_the_record(self):
        for row in (PERP_ROW, SPOT_ROW):
            outcome = self.run_case(row, fills=[tool.Fill(9, 100, 200), tool.Fill(9, 30, 70)], executed=500, second=9000)
            self.assertEqual(struct.unpack_from("<QQ", outcome["body"], tool.EXECUTED), (630, 9270))
            self.assertEqual(len(self.advanced(outcome)), 1)
            self.assertEqual(outcome["count"], 1)

    def test_first_above_second_adds_nothing_and_still_advances(self):
        for row in (PERP_ROW, SPOT_ROW):
            outcome = self.run_case(row, fills=[tool.Fill(9, 101, 100)], executed=1, second=2)
            self.assertEqual(struct.unpack_from("<QQ", outcome["body"], tool.EXECUTED), (1, 2))
            self.assertEqual(len(self.advanced(outcome)), 1)

    def test_first_equal_to_second_adds(self):
        outcome = self.run_case(PERP_ROW, fills=[tool.Fill(9, 100, 100)], executed=1, second=2)
        self.assertEqual(struct.unpack_from("<QQ", outcome["body"], tool.EXECUTED), (101, 102))

    def test_differing_key_adds_nothing(self):
        for row in (PERP_ROW, SPOT_ROW):
            outcome = self.run_case(row, fills=[tool.Fill(9, 100, 200), tool.Fill(8, 30, 70)], executed=1, second=2)
            self.assertEqual(struct.unpack_from("<QQ", outcome["body"], tool.EXECUTED), (1, 2))

    def test_saturation_records_and_keeps_the_top(self):
        outcome = self.run_case(SPOT_ROW, fills=[tool.Fill(9, 10, 20)], executed=tool.MASK[8] - 5)
        self.assertEqual(struct.unpack_from("<Q", outcome["body"], tool.EXECUTED)[0], tool.MASK[8])
        self.assertIn(("recorder", 0, tool.LOCATION_ADD_FIRST), outcome["events"])

    def test_keep_tags_only_advance(self):
        for row in (PERP_ROW, SPOT_ROW):
            for tag in KEEP:
                outcome = self.run_case(row, status=tool.STATUS_REJECTED, word=tool.NICHE_BIT | tag, executed=7, second=8)
                self.assertEqual([event[0] for event in outcome["events"]], ["advance"], tag)
                self.assertEqual(outcome["count"], 1)

    def test_end_tag_writes_the_text_row(self):
        for row in (PERP_ROW, SPOT_ROW):
            outcome = self.run_case(row, status=tool.STATUS_REJECTED, word=TAG_THREE, oid=5, user=1)
            self.assertEqual(outcome["count"], 2)
            head, text, tail = outcome["row"]
            self.assertEqual(text, b"Insufficient margin to place order.")
            self.assertEqual(struct.unpack_from("<Q", head)[0], 4)
            self.assertEqual(tail, struct.pack("<Q", 5) + tool.TIME_BYTES + tool.user_id(1))
            self.assertEqual(self.advanced(outcome), [])

    def test_unknown_status_writes_its_text(self):
        outcome = self.run_case(PERP_ROW, status=0xC5)
        self.assertEqual(outcome["row"][1], b"status 197")

    def test_neighbour_keeps_the_user(self):
        outcome = self.run_case(PERP_ROW, status=7, orders=(2,))
        self.assertNotIn("remove user", [event[0] for event in outcome["events"]])

    def test_last_order_removes_the_user(self):
        outcome = self.run_case(SPOT_ROW, status=7)
        self.assertIn("remove user", [event[0] for event in outcome["events"]])

    def test_perp_has_a_market_bound_and_spot_has_none(self):
        outcome = self.run_case(PERP_ROW, status=7, asset=30000, markets=3)
        self.assertEqual(outcome["stop"], ("unwrap", tool.LOCATION_MARKET, tool.UNWRAP_TEXT, tool.UNWRAP_SIZE, tool.ERROR_WORD))
        self.assertNotIn("stop", self.run_case(SPOT_ROW, status=7, asset=30000, markets=3))

    def test_failed_write_is_a_panic(self):
        outcome = self.run_case(PERP_ROW, status=tool.STATUS_REJECTED, word=TAG_THREE, write_fails=True)
        self.assertEqual(outcome["stop"][1], tool.LOCATION_STRING)

    def test_missing_order_does_nothing(self):
        outcome = self.run_case(PERP_ROW, status=7, order_missing=True, orders=(2,))
        self.assertEqual(outcome["events"], [])

    def test_mask_mutation_is_noticed(self):
        at = tool.find_once(self.image, PERP_ROW["start"], b"\xb9\xf9\x02\xfc\x00")
        changed = tool.Harness(self.image, {at + 1: 0xF1})
        case = case_named(tool.result_cases(), "rejected tag 3")
        self.assertIn("rejected tag 3", tool.compare_result(changed, PERP_ROW, case))

    def test_status_mutation_is_noticed(self):
        at = tool.find_once(self.image, SPOT_ROW["start"], b"\x3d\x86\x01\x00\x00")
        changed = tool.Harness(self.image, {at + 1: 0x87})
        case = case_named(tool.result_cases(), "one fill")
        self.assertIn("one fill", tool.compare_result(changed, SPOT_ROW, case))

    def test_wrong_rule_is_noticed(self):
        saved = tool.TERMINAL_MASK
        tool.TERMINAL_MASK = saved ^ 8
        try:
            case = case_named(tool.result_cases(), "rejected tag 3")
            self.assertIn("rejected tag 3", tool.compare_result(self.harness, PERP_ROW, case))
        finally:
            tool.TERMINAL_MASK = saved


class Callers(unittest.TestCase):
    setUpClass = classmethod(load)

    def run_case(self, row=CALLER, **options):
        return self.harness.run_caller(row, tool.CallerCase("direct", **options))

    def collected_flag(self, **options):
        return next(event for event in self.run_case(**options)["events"] if event[0] == "collect")[5]

    def test_all_cases_on_both_copies(self):
        for row in tool.CALLERS:
            for case in tool.caller_cases():
                self.assertEqual(tool.compare_caller(self.harness, row, case), "", case.label)

    def test_flag_by_time_and_height(self):
        self.assertEqual(self.collected_flag(), 0)
        self.assertEqual(self.collected_flag(now=(4, 9, 9)), 1)
        self.assertEqual(self.collected_flag(now=(6, 0, 0)), 0)
        self.assertEqual(self.collected_flag(height=9), 1)
        self.assertEqual(self.collected_flag(now=(6, 0, 0), height=9), 1)
        self.assertEqual(self.collected_flag(now=(0xFFFFFFFF, 6, 7), limit=(1, 6, 7)), 1)

    def test_gate_skips_the_spot_side(self):
        outcome = self.run_case(gate=1, spot=((20003, 7, 1),))
        kinds = [event[0] for event in outcome["events"]]
        self.assertNotIn("spot drain", kinds)
        self.assertEqual(outcome["spot"], (0, 8, 0))

    def test_rows_flush_after_each_result(self):
        kinds = [event[0] for event in self.run_case(perp=((3, 7, 1), (20003, 8, 2)))["events"]]
        self.assertEqual(kinds.count("flush perp"), 2)
        self.assertLess(kinds.index("handler"), kinds.index("flush perp"))

    def test_dex_index_picks_the_tracker(self):
        outcome = self.run_case(perp=((29999, 7, 1),))
        event = next(event for event in outcome["events"] if event[0] == "handler")
        self.assertEqual(event[2], tool.DEXES + 2 * 0x138 + 0x18)

    def test_dex_bound_panics(self):
        self.assertEqual(self.run_case(perp=((30000, 7, 1),))["stop"][1], tool.LOCATION_DEX)

    def test_gate_mutation_is_noticed(self):
        at = CALLER["start"] + 0x334
        self.assertEqual(self.image.blob[self.image.offset(at)], 0x74)
        changed = tool.Harness(self.image, {at: 0x75})
        case = case_named(tool.caller_cases(), "empty block")
        self.assertIn("empty block", tool.compare_caller(changed, CALLER, case))


class Serializer(unittest.TestCase):
    setUpClass = classmethod(load)

    def status_of(self, word, text=b""):
        shown = self.harness.run_serial(tool.SerialCase("direct", word=word, text=text))
        return shown["text"].split(b',"status":')[1][:-1]

    def test_all_cases(self):
        for case in tool.serial_cases():
            self.assertEqual(tool.compare_serial(self.harness, None, case), "", case.label)

    def test_field_wrapper_cases(self):
        for case in tool.field_cases():
            self.assertEqual(tool.compare_field(self.harness, None, case), "", case.label)

    def test_status_arms(self):
        self.assertEqual(len(tool.serial_table(self.image)), 4)
        self.assertEqual(self.status_of(tool.NICHE_BIT), b'"activated"')
        self.assertEqual(self.status_of(tool.HALT_WORD), b'"terminated"')
        self.assertEqual(self.status_of(tool.FINISH_WORD), b'"finished"')
        self.assertEqual(self.status_of(6, b"Halted"), b'{"error":"Halted"}')

    def test_keys_come_from_the_bytes(self):
        shown = self.harness.run_serial(tool.SerialCase("direct", word=tool.FINISH_WORD))
        self.assertEqual(shown["text"], b'{"time":"T","twap_id":77,"state":{},"status":"finished"}')
        self.assertEqual(shown["events"][:3], [("time", tool.HISTORY + 0x78), ("twap_id", tool.HISTORY + 0x70), ("state", tool.HISTORY)])

    def test_handler_row_through_the_real_serializer(self):
        for row in tool.HANDLERS:
            case = tool.ResultCase("direct", status=tool.STATUS_REJECTED, word=TAG_THREE)
            _, shown = self.harness.run_chain(row, case)
            self.assertTrue(shown["text"].endswith(b'"status":{"error":"Insufficient margin to place order."}}'), shown["text"])

    def test_flush_copies_the_row_body(self):
        found = tool.flush_body(self.image)
        self.assertEqual((found["arm"], found["copied"]), ("0x432a2a7", "0x98"))

    def test_damaged_flush_table_is_refused(self):
        damaged = tool.Image.__new__(tool.Image)
        damaged.__dict__.update(self.image.__dict__)
        blob = bytearray(self.image.blob)
        struct.pack_into("<i", blob, self.image.offset(tool.FLUSH_TABLE) + 8, 0)
        damaged.blob = bytes(blob)
        with self.assertRaisesRegex(tool.EvidenceError, "flush table entry"):
            tool.flush_body(damaged)

    def test_stream_name_is_in_the_file(self):
        start = self.image.offset(tool.STREAM_NAME)
        self.assertEqual(bytes(self.image.blob[start:start + len(tool.STREAM_TEXT)]), tool.STREAM_TEXT)

    def test_row_body_is_the_sum_of_its_fields(self):
        self.assertEqual(tool.ROW_BODY, 0x58 + 0x18 + 8 + 12 + 20)

    def test_bad_reserve_is_noticed(self):
        at = tool.SERIAL_STATUS + 0x3B
        self.assertEqual(self.image.blob[self.image.offset(at) + 1], 0x84)
        changed = tool.Harness(self.image, {at + 1: 0x85})
        case = next(case for case in tool.serial_cases() if case.label == "activated")
        self.assertIn("activated", tool.compare_serial(changed, None, case))


class Evidence(unittest.TestCase):
    def setUp(self):
        self.maxDiff = 2000

    def load_analysis():
        Evidence.image = tool.load_image()
        Evidence.evidence = tool.analyse(Evidence.image)
        Evidence.files = tool.render(Evidence.evidence)

    setUpClass = staticmethod(load_analysis)

    def test_generated_files_match_the_folder(self):
        for name, text in self.files.items():
            self.assertEqual((FOLDER / name).read_text(encoding="ascii"), text, name)

    def test_manifest_covers_the_folder(self):
        rows = dict(line.split("  ")[::-1] for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines())
        names = sorted(path.name for path in FOLDER.iterdir() if path.name != "MANIFEST.sha256")
        self.assertEqual(sorted(rows), names)
        for name in names:
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), rows[name], name)

    def test_no_mismatch(self):
        self.assertEqual(self.evidence["mismatches"], 0)
        self.assertEqual(self.evidence["first_mismatch"], "")

    def test_every_row_that_lived_has_a_reason(self):
        for row in self.evidence["_results"]:
            if row["result"] != "killed":
                self.assertTrue(tool.reason_for(row), hex(row["va"]))

    def test_mutants_mostly_die(self):
        tally = self.evidence["mutations"]
        self.assertGreater(tally["killed"], 20 * (tally["survived"] + tally["unreached"]))

    def test_evidence_has_no_absolute_path(self):
        document = json.dumps(self.evidence["locations"])
        self.assertNotIn("/home", document)
        self.assertNotIn("/rustc", document)

    def test_tool_runs_no_external_program(self):
        source = (ROOT / "tools" / "twap_fill_result.py").read_text()
        self.assertNotIn("subprocess", source)
        self.assertNotIn("os.system", source)


if __name__ == "__main__":
    unittest.main()
