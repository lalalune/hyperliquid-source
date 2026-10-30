import hashlib
import json
import math
import pathlib
import struct
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import twap_slice as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-006-twap-slice-94"


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
        for row in tool.COPIES:
            for key in ("drain", "collect", "slice", "advance"):
                self.assertEqual(self.image.exact_fde(row[key])[0], row[key])

    def test_inner_address_is_not_a_start(self):
        with self.assertRaisesRegex(tool.EvidenceError, "not an FDE start"):
            self.image.exact_fde(tool.COPIES[0]["slice"] + 1)

    def test_address_in_a_gap_is_refused(self):
        with self.assertRaisesRegex(tool.EvidenceError, "outside every FDE"):
            self.image.fde(0x42F18BD)

    def test_bss_has_no_file_bytes(self):
        with self.assertRaisesRegex(tool.EvidenceError, "outside file-backed"):
            self.image.offset(0x5788300)

    def test_function_sizes(self):
        sizes = {key: {self.image.exact_fde(row[key])[1] - row[key] for row in tool.COPIES if row["family"] == tool.PERP} for key in ("slice", "advance", "drain")}
        self.assertEqual(sizes, {"slice": {2909}, "advance": {2574}, "drain": {957}})
        spot = {key: {self.image.exact_fde(row[key])[1] - row[key] for row in tool.COPIES if row["family"] == tool.SPOT} for key in ("slice", "advance", "drain")}
        self.assertEqual(spot, {"slice": {2625}, "advance": {2223}, "drain": {957}})

    def test_chain_of_calls(self):
        pairs = tool.check_pairing(self.image)
        self.assertEqual(len(pairs), 12)
        self.assertTrue(all(row["sites"] for row in pairs))

    def test_broken_chain_is_refused(self):
        saved = tool.COPIES[0]["advance"]
        tool.COPIES[0]["advance"] = tool.COPIES[1]["advance"]
        try:
            with self.assertRaisesRegex(tool.EvidenceError, "does not reach"):
                tool.check_pairing(self.image)
        finally:
            tool.COPIES[0]["advance"] = saved

    def test_copy_differences_are_fields_and_calls_only(self):
        rows = []
        for key in ("slice", "advance"):
            rows += tool.copy_differences(self.image, tool.COPIES[0][key], tool.COPIES[1][key])
            rows += tool.copy_differences(self.image, tool.COPIES[2][key], tool.COPIES[3][key])
        self.assertEqual(len(rows), 6)
        self.assertEqual(sum(1 for row in rows if row["left"].startswith("call")), 2)

    def test_copies_of_different_size_are_refused(self):
        with self.assertRaisesRegex(tool.EvidenceError, "differ in size"):
            tool.copy_differences(self.image, tool.COPIES[0]["slice"], tool.COPIES[2]["slice"])

    def test_drains_differ_only_in_the_collector(self):
        for index in (1, 2, 3):
            rows = tool.copy_differences(self.image, tool.COPIES[0]["drain"], tool.COPIES[index]["drain"])
            self.assertEqual(len(rows), 1)
            self.assertTrue(rows[0]["left"].startswith("call"))

    def test_byte_pins_hold(self):
        self.assertEqual(len(tool.byte_pins(self.image)), len(tool.BYTE_PINS))

    def test_tampered_pin_is_refused(self):
        va = tool.BYTE_PINS[0][0]
        blob = bytearray(self.image.blob)
        blob[self.image.offset(va)] ^= 1
        broken = tool.Image.__new__(tool.Image)
        broken.__dict__.update(self.image.__dict__)
        broken.blob = bytes(blob)
        with self.assertRaisesRegex(tool.EvidenceError, "pin changed"):
            tool.byte_pins(broken)

    def test_float_constants(self):
        values = tool.float_constants(self.image)
        self.assertEqual(values, {"buckets_divisor_60": 60.0, "buy_factor": 1.03, "jitter_divisor": 100.0, "jitter_offset": -0.2, "sell_factor": 0.97, "step_30": 30.0})

    def test_locations_are_cut_below_the_crate_root(self):
        relative = self.harness.relative
        path, line, _ = self.image.location(tool.LOCATION_SZ, relative)
        self.assertEqual((path, line), ("l1/src/qtys/impl_sz.rs", 9))
        self.assertEqual(self.image.location(tool.LOCATION_BOOKS, relative)[:2], ("l1/src/books.rs", 14))

    def test_every_slot_is_a_function_start(self):
        relative = self.harness.relative
        for slot in (tool.SLOT_ROUND, tool.SLOT_FMA, tool.SLOT_FLOOR, tool.SLOT_CEIL, tool.SLOT_SPOT_MID):
            self.assertEqual(self.image.exact_fde(relative[slot])[0], relative[slot])
        self.assertEqual((relative[tool.SLOT_ROUND], relative[tool.SLOT_FLOOR], relative[tool.SLOT_CEIL], relative[tool.SLOT_FMA]), (tool.ROUND, tool.FLOOR, tool.CEIL, tool.FMA))


class Specification(unittest.TestCase):
    def test_five_figures(self):
        self.assertEqual(tool.five_figures(99999), 99999)
        self.assertEqual(tool.five_figures(100019), 100010)
        self.assertEqual(tool.five_figures(123456789), 123450000)
        self.assertEqual(tool.five_figures(10 ** 19 + 12345), 10 ** 19)

    def test_step_count(self):
        self.assertEqual(tool.duration_steps(0.0), 1)
        self.assertEqual(tool.duration_steps(59.9), 1)
        self.assertEqual(tool.duration_steps(60.0), 3)
        self.assertEqual(tool.duration_steps(3600.0), 121)
        self.assertEqual(tool.duration_steps(math.inf), 1)
        self.assertEqual(tool.duration_steps(1e300), tool.MASK[8])
        self.assertIsNone(tool.duration_steps(-1.0))
        self.assertIsNone(tool.duration_steps(math.nan))

    def test_saturating_cast(self):
        self.assertEqual(tool.saturate(math.nan), 0)
        self.assertEqual(tool.saturate(math.inf), 0)
        self.assertEqual(tool.saturate(-1.0), 0)
        self.assertEqual(tool.saturate(1.9), 1)
        self.assertEqual(tool.saturate(18446744073709551616.0), tool.MASK[8])

    def test_unix_millis(self):
        self.assertEqual(tool.unix_millis((tool.pack_date(1970, 1), 0, 0)), 0)
        self.assertEqual(tool.unix_millis((tool.pack_date(1970, 2), 1, 2000000)), 86401002)
        self.assertEqual(tool.unix_millis((tool.pack_date(2000, 1), 0, 0)), 946684800000)
        self.assertLess(tool.unix_millis((tool.pack_date(0, 1), 0, 0)), 0)

    def test_fused_keeps_the_exact_sum(self):
        self.assertEqual(tool.fused(1.0 + 2.0 ** -30, 1.0 + 2.0 ** -30, -(1.0 + 2.0 ** -29)), 2.0 ** -60)
        self.assertEqual(tool.fused(2.0, 3.0, 4.0), 10.0)

    def test_tree_shape_counts_keys(self):
        self.assertEqual(tool.tree_height(11, 11), 0)
        self.assertEqual(tool.tree_height(12, 11), 1)
        keys = list(range(14))
        separators, children = tool.chunks(keys, 2, 2)
        self.assertEqual(sorted(separators + [key for child in children for key in child]), keys)


class Evaluation(unittest.TestCase):
    setUpClass = classmethod(load)

    def test_helpers_are_round_floor_and_ceil(self):
        machine = self.harness.machine
        self.harness.reset()
        for value in (0.5, 1.5, 2.5, -0.5, -1.5, 0.49999999999999994, 1e300, 4503599627370497.0, 2.0, 0.0, -0.25, 1e-300, -1e-300):
            for start, expected in ((tool.ROUND, tool.round_half_away(value)), (tool.FLOOR, float(math.floor(value))), (tool.CEIL, float(math.ceil(value)))):
                machine.xmm[0] = tool.to_bits(value)
                machine.run(start, {})
                self.assertEqual(tool.to_float(machine.xmm[0] & tool.MASK[8]), expected, (hex(start), value))

    def test_slices(self):
        for copy, row in enumerate(tool.COPIES):
            for case in tool.slice_cases(row["family"]):
                self.assertEqual(tool.compare_slice(self.harness, copy, case), "")

    def test_advances(self):
        for copy in range(4):
            for case in tool.advance_cases():
                self.assertEqual(tool.compare_advance(self.harness, copy, case), "")

    def test_drains(self):
        for copy in range(4):
            for case in tool.drain_cases():
                self.assertEqual(tool.compare_drain(self.harness, copy, case), "")

    def test_heap(self):
        for entries in tool.heap_cases():
            self.assertEqual(tool.compare_heap(self.harness, 0, entries), "")

    def test_every_outcome_occurs(self):
        for family, copy in ((tool.PERP, 0), (tool.SPOT, 2)):
            kinds = set()
            for case in tool.slice_cases(family):
                spec = tool.spec_slice(copy, case)
                kinds.add("stop" if "stop" in spec else spec["tag"])
            self.assertEqual(kinds, {"stop", 1, 2})

    def test_jitter_ignores_whole_seconds_and_days(self):
        first = tool.SliceCase("a", randomize=1, now=(tool.pack_date(2025, 100), 3600, 37000000), total=121 * 10 ** 10, executed=10 ** 11, counter=11, top=(1 << 30, 1 << 30))
        second = tool.SliceCase("b", randomize=1, now=(tool.pack_date(2031, 7), 11, 37999999), total=121 * 10 ** 10, executed=10 ** 11, counter=11, top=(1 << 30, 1 << 30))
        third = tool.SliceCase("c", randomize=1, now=(tool.pack_date(2025, 100), 3600, 38000000), total=121 * 10 ** 10, executed=10 ** 11, counter=11, top=(1 << 30, 1 << 30))
        records = [self.harness.run_slice(0, case)["bytes"] for case in (first, second, third)]
        self.assertEqual(records[0], records[1])
        self.assertNotEqual(records[0], records[2])

    def test_negative_millis_count_as_zero(self):
        case = tool.SliceCase("a", randomize=1, now=(tool.pack_date(1960, 1), 3, 7000000), total=121 * 10 ** 10, executed=10 ** 11, counter=11, top=(1 << 30, 1 << 30))
        expected = tool.spec_slice(0, case)["fields"][8]
        self.assertEqual(self.harness.run_slice(0, case)["bytes"][8:16], expected)

    def test_last_step_is_capped_but_unrounded(self):
        case = tool.SliceCase("a", total=1234567891, executed=1, counter=121, duration=3600.0, top=(1 << 40, 1 << 40))
        size = struct.unpack("<Q", self.harness.run_slice(0, case)["bytes"][8:16])[0]
        # Still under the cap of three even shares, and not floored to 5 figures (that would be 30609000).
        self.assertEqual(size, 30609121)

    def test_thresholds_differ_by_family(self):
        self.assertEqual(tool.THRESHOLDS[tool.PERP], {"whole": 30000000, "floor": 12000000})
        self.assertEqual(tool.THRESHOLDS[tool.SPOT], {"whole": 3000000000, "floor": 1200000000})

    def test_stale_head_goes_even_when_not_due(self):
        base = tool.pack_date(2025, 100)
        case = tool.DrainCase("a", entries=[tool.Entry(9, 1, (base, 9000, 0))], users={1: (1,)})
        self.assertEqual(self.harness.run_drain(0, case)["left"], 0)
        kept = tool.DrainCase("b", entries=[tool.Entry(1, 1, (base, 9000, 0))], users={1: (1,)})
        self.assertEqual(self.harness.run_drain(0, kept)["left"], 1)

    def test_heap_key_order(self):
        base = tool.pack_date(2025, 100)
        rows = [tool.Entry(1, 1, (base, 5, 2)), tool.Entry(1, 1, (base, 5, 1)), tool.Entry(1, 1, (base, 4, 9)), tool.Entry(1, 1, (base - 16, 9, 9))]
        popped, left = self.harness.run_heap(rows)
        self.assertEqual(popped, [rows[3].bytes(), rows[2].bytes(), rows[1].bytes(), rows[0].bytes(), None])
        self.assertEqual(left, 0)


class Controls(unittest.TestCase):
    setUpClass = classmethod(load)

    def flips(self, va, at, label, copy=0, kind="immediate", family=None, cases=None, check=None):
        machine = self.harness.machine
        machine.patches = tool.mutate_patch(self.image, va, at, kind)
        machine.cache.pop(va, None)
        machine.step_limit = tool.MUTANT_STEP_LIMIT
        try:
            found = (check or tool.compare_slice)(self.harness, copy, case_named(cases if cases is not None else tool.slice_cases(family), label))
        finally:
            machine.patches = {}
            machine.cache.pop(va, None)
            machine.step_limit = tool.STEP_LIMIT
        self.assertNotEqual(found, "")

    def test_perp_threshold_byte(self):
        self.flips(0x4339C2B, 2, "exact threshold 0", family=tool.PERP)

    def test_spot_threshold_byte(self):
        self.flips(0x4337273, 1, "exact threshold 1", copy=2, family=tool.SPOT)

    def test_floor_dividend(self):
        self.flips(0x4339C45, 1, "floor at a divisor of the next integer", family=tool.PERP)

    def test_catch_up_multiple(self):
        self.flips(0x4339CD8, 1, "catch-up cap", family=tool.PERP)

    def test_jitter_switch(self):
        self.flips(0x4339A14, 1, "jitter at 41 ms", family=tool.PERP, kind="branch")

    def test_side_branch(self):
        rows = tool.decode_range(self.image, *self.image.exact_fde(0x4339480))
        row = next(item for item in rows if item.va == 0x43398B1)
        self.flips(row.va, row.size - 2, "plain mid book", family=tool.PERP, kind="branch")

    def test_finish_compare(self):
        rows = tool.decode_range(self.image, *self.image.exact_fde(0x42EEF80))
        row = next(item for item in rows if item.va == 0x42EF3BA)
        self.flips(row.va, row.size - 5, "requeue before the end", kind="branch", cases=tool.advance_cases(), check=tool.compare_advance)

    def test_step_seconds(self):
        self.flips(0x42EF1FE, 1, "requeue before the end", kind="immediate", cases=tool.advance_cases(), check=tool.compare_advance)

    def test_nanos_field_of_the_drain(self):
        self.flips(0x42F1752, 0, "one a nano later", kind="branch", cases=tool.drain_cases(), check=tool.compare_drain)

    def test_wrong_market_field(self):
        case = tool.SliceCase("a", markets=1)
        self.assertEqual(tool.spec_slice(0, case)["stop"][0], "unwrap")
        self.assertEqual(tool.compare_slice(self.harness, 0, case), "")

    def test_spec_change_is_noticed(self):
        original = tool.CATCH_UP
        tool.CATCH_UP = 2
        try:
            self.assertNotEqual(tool.compare_slice(self.harness, 0, case_named(tool.slice_cases(tool.PERP), "catch-up cap")), "")
        finally:
            tool.CATCH_UP = original

    def test_record_byte_change_is_noticed(self):
        case = tool.SliceCase("a")
        expected = tool.spec_slice(0, case)
        expected["fields"][0x10] = b"\x04"
        actual = self.harness.run_slice(0, case)
        record = bytearray([tool.STACK_MARK]) * tool.SLICE_SIZE
        for offset, value in expected["fields"].items():
            record[offset:offset + len(value)] = value
        self.assertNotEqual(bytes(record), actual["bytes"])


class Packet(unittest.TestCase):
    def test_manifest_matches(self):
        lines = (FOLDER / "MANIFEST.sha256").read_text().splitlines()
        names = {path.name for path in FOLDER.iterdir() if path.name != "MANIFEST.sha256"}
        self.assertEqual({line.split("  ")[1] for line in lines}, names)
        for line in lines:
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_every_row_not_killed_has_a_reason(self):
        rows = [line.split("\t") for line in (FOLDER / "mutations.tsv").read_text().splitlines()[1:]]
        self.assertGreater(len(rows), 900)
        for row in rows:
            if row[3] != "killed":
                self.assertTrue(row[5], row)

    def test_no_row_is_marked_equivalent_while_killed(self):
        rows = [line.split("\t") for line in (FOLDER / "mutations.tsv").read_text().splitlines()[1:]]
        survived = {int(row[1], 16) for row in rows if row[3] == "survived"}
        self.assertEqual(set(tool.EQUIVALENT), survived)

    def test_evidence_has_no_mismatch(self):
        evidence = json.loads((FOLDER / "evidence.json").read_text())
        self.assertEqual(evidence["mismatches"], 0)
        self.assertEqual(evidence["target"]["sha256"], tool.SHA256)
        self.assertEqual(evidence["drain_copy_differences"], 3)

    def test_outputs_stay_portable(self):
        for path in FOLDER.iterdir():
            text = path.read_text(encoding="utf-8")
            for word in ("/home", "/tmp", "/srv", "/mnt", ".cargo"):
                self.assertNotIn(word, text, path.name)

    def test_quick_render_is_repeatable(self):
        image = tool.load_image()
        first = tool.render(tool.analyse(image, full=False))
        second = tool.render(tool.analyse(image, full=False))
        self.assertEqual(first, second)
        self.assertEqual(sorted(first), ["call_sites.tsv", "copy_differences.tsv", "evidence.json", "mutations.tsv"])


if __name__ == "__main__":
    unittest.main()
