import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import spot_second_path as t  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-006-spot-second-path-94"


def shared(cls):
    cls.image = t.load_image()
    cls.harness = t.Harness(cls.image)


class Base(unittest.TestCase):
    setUpClass = classmethod(shared)

    def run_world(self, which="a", **change):
        case = t.Case("test", "second", which, t.world(**change))
        self.assertEqual(t.compare_run(self.harness, case), "")
        return self.harness.run(case)

    def names(self, which="a", **change):
        return [event[0] for event in self.run_world(which, **change)["events"]]

    def mutant(self, va, offset, value, world):
        """One patched byte: the run must stop agreeing with the specification."""
        machine = self.harness.machine
        machine.patches = {va + offset: value}
        machine.cache.pop(va, None)
        try:
            return t.compare_run(self.harness, t.Case("mutant", "second", "a", world))
        finally:
            machine.patches = {}
            machine.cache.pop(va, None)


class Identity(Base):
    def test_wrong_digest_is_refused(self):
        with self.assertRaisesRegex(t.EvidenceError, "SHA-256 mismatch"):
            t.load_image(expected="0" * 64)

    def test_function_ends_come_from_fdes(self):
        self.assertEqual(self.image.exact_fde(t.SECOND_A), (0x4D2F4A0, 0x4D2FF52))
        self.assertEqual(self.image.exact_fde(t.SECOND_B), (0x4D2E9E0, 0x4D2F492))
        self.assertEqual(self.image.exact_fde(t.SECOND_C), (0x2726CE0, 0x2727BB1))
        self.assertEqual(self.image.exact_fde(t.POST_A), (0x46F26F0, 0x46F2954))
        self.assertEqual(self.image.exact_fde(t.POST_C), (0x2739B00, 0x2739D64))

    def test_a_middle_address_is_not_a_function_start(self):
        with self.assertRaisesRegex(t.EvidenceError, "not an FDE start"):
            self.image.exact_fde(t.SECOND_A + 1)

    def test_address_past_every_section_is_refused(self):
        with self.assertRaisesRegex(t.EvidenceError, "outside file-backed"):
            self.image.offset(0x7FFFFFFFFFFF)

    def test_bss_has_no_file_bytes(self):
        bss = self.image.named[".bss"]
        with self.assertRaisesRegex(t.EvidenceError, "outside file-backed"):
            self.image.offset(bss["address"] + 8)


class Flow(Base):
    def test_full_order_keeps_this_event_order(self):
        self.assertEqual(self.names(), ["report", "health", "reserve", "apply", "run", "settle", "settle", "report", "health", "drop map"])

    def test_all_copies_end_the_same(self):
        for which in "abc":
            found = self.run_world(which)
            self.assertEqual(found["out"]["word"], 0x186)
            self.assertEqual(found["out"]["rest"], t.run_bytes(t.world()))

    def test_quote_settles_before_base(self):
        events = [event for event in self.run_world()["events"] if event[0] == "settle"]
        self.assertEqual([event[2] for event in events], [t.QUOTE, t.BASE])

    def test_first_report_stop_runs_nothing(self):
        found = self.run_world(before=(1, 0x37))
        self.assertEqual([event[0] for event in found["events"]], ["report", "free"])
        self.assertEqual((found["out"]["word"], found["out"]["byte"]), (t.WORD_FAILED, 0x37))

    def test_tag_two_keeps_the_vector(self):
        self.assertNotIn("free", self.names(before=(1, 0x37), tag=2))

    def test_vector_size_is_0x48_per_row(self):
        events = self.run_world(before=(1, 0x37), capacity=5)["events"]
        self.assertEqual(events[-1], ("free", t.VECTOR, 5 * 0x48, 0))

    def test_no_last_skips_the_reserve(self):
        self.assertNotIn("reserve", self.names(last=0))

    def test_reserve_tag_two_skips_the_apply(self):
        names = self.names(reserve=(2, 0x33, 1, 1))
        self.assertIn("run", names)
        self.assertNotIn("apply", names)

    def test_short_reserve_stops_with_code_c(self):
        found = self.run_world(reserve=(0, 0x5C, 899, 0))
        self.assertEqual(found["out"]["byte"], t.BYTE_SHORT)
        self.assertNotIn("run", [event[0] for event in found["events"]])

    def test_reserve_flag_stops(self):
        self.assertEqual(self.run_world(reserve=(0, 0x5C, 900, 1))["out"]["byte"], t.BYTE_SHORT)

    def test_reserve_good_byte_goes_on(self):
        self.assertIn("run", self.names(reserve=(3, 0x11, 900, 0)))

    def test_failed_reserve_still_checks_after(self):
        found = self.run_world(reserve=(3, 0x33, 900, 0), health=(0, 1000, 1100), post=(0, 999, 1100))
        names = [event[0] for event in found["events"]]
        self.assertIn("insert", names)
        self.assertEqual(found["out"]["byte"], 0x33)

    def test_second_report_stop_drops_the_result(self):
        found = self.run_world(after=(1, 0x39))
        self.assertEqual((found["out"]["word"], found["out"]["byte"]), (t.WORD_FAILED, 0x39))
        self.assertIn("drop result", [event[0] for event in found["events"]])

    def test_post_stop_replaces_the_result(self):
        found = self.run_world(post=(1, 0x22))
        self.assertEqual((found["out"]["word"], found["out"]["byte"]), (t.WORD_FAILED, 0x22))
        self.assertIn("drop result", [event[0] for event in found["events"]])

    def test_post_stop_with_failed_run_has_no_drop(self):
        self.assertNotIn("drop result", self.names(run_word=0x187, post=(1, 0x22)))

    def test_carried_word_becomes_failed(self):
        found = self.run_world(run_word=0x188)
        self.assertEqual((found["out"]["word"], found["out"]["byte"]), (t.WORD_FAILED, t.run_bytes(t.world(run_word=0x188))[2]))

    def test_row_word_zero_stops_with_the_row_byte(self):
        found = self.run_world(row_word=0)
        self.assertEqual((found["out"]["word"], found["out"]["byte"]), (t.WORD_FAILED, 0x2E))

    def test_negative_word_panics(self):
        self.assertEqual(self.run_world(health=(0, t.TOP, 5))["stop"][:2], ("unwrap", t.LOC_UNWRAP))
        self.assertEqual(self.run_world(post=(0, 5, t.TOP))["stop"][:2], ("unwrap", t.LOC_UNWRAP))

    def test_map_with_no_root_panics(self):
        self.assertEqual(self.run_world("a", row_map=(4, 0, 2))["stop"], ("none", t.LOC_NONE_A))
        self.assertEqual(self.run_world("c", row_map=(4, 0, 2))["stop"], ("none", t.LOC_NONE_C))

    def test_missing_user_reads_the_default_row(self):
        found = self.run_world(tree=None)
        self.assertEqual(found["out"]["word"], 0x186)
        self.assertEqual(found["events"][1][1], bytes(8) + t.DEFAULT_DATE.to_bytes(4, "little") + bytes(12))

    def test_row_added_by_the_order_is_read_after(self):
        found = self.run_world(tree=None, tree_after=([t.USER], []))
        reports = [event for event in found["events"] if event[0] == "report"]
        self.assertEqual(reports[0][1], t.DEFAULT_ROW)
        self.assertEqual(reports[1][1], t.ROOT_NODE)


class Shortfall(Base):
    def test_larger_shortfall_inserts(self):
        self.assertIn("insert", self.names(health=(0, 1000, 1100), post=(0, 999, 1100)))

    def test_same_shortfall_does_not(self):
        self.assertNotIn("insert", self.names(health=(0, 1000, 1100), post=(0, 1000, 1100)))

    def test_smaller_shortfall_does_not(self):
        self.assertNotIn("insert", self.names(health=(0, 1000, 1100), post=(0, 1001, 1100)))

    def test_zero_margin_does_not(self):
        self.assertNotIn("insert", self.names(post=(0, 1000, 1000)))

    def test_new_shortfall_of_one_inserts(self):
        self.assertIn("insert", self.names(post=(0, 999, 1000)))

    def test_exempt_address_never_inserts(self):
        self.assertNotIn("insert", self.names(user=t.EXEMPT_USER, tree=([t.EXEMPT_USER], []), health=(0, 1000, 1100), post=(0, 999, 1100)))

    def test_insert_does_not_change_the_result(self):
        found = self.run_world(health=(0, 1000, 1100), post=(0, 999, 1100))
        self.assertEqual(found["out"]["rest"], t.run_bytes(t.world()))

    def test_first_and_third_copy_use_one_offset(self):
        for which, offset in (("a", 0x8B8), ("b", 0x1338), ("c", 0x8B8)):
            found = self.run_world(which, health=(0, 1000, 1100), post=(0, 999, 1100))
            event = [row for row in found["events"] if row[0] == "insert"][0]
            self.assertEqual(event[1], t.STATE + offset)

    def test_exempt_constants_are_0xbb(self):
        self.assertEqual(t.exempt_address(self.image, t.EXEMPT_PARTS), b"\xbb" * 20)
        self.assertEqual(t.exempt_address(self.image, t.SWEEP_EXEMPT_PARTS), b"\xbb" * 20)


class Ratio(Base):
    def test_lower_after_ratio_calls_the_lookup(self):
        self.assertIn("balance lookup", self.names(after=(0, 1000, 21, 499, 23, 27)))

    def test_equal_ratio_does_not(self):
        self.assertNotIn("balance lookup", self.names(after=(0, 1000, 21, 500, 23, 27)))

    def test_zero_denominators_do_not(self):
        self.assertNotIn("balance lookup", self.names(before=(0, 0, 11, 500, 13, 17), after=(0, 1000, 21, 1, 23, 27)))
        self.assertNotIn("balance lookup", self.names(after=(0, 0, 21, 1, 23, 27)))

    def test_lookup_result_is_not_read(self):
        with_call = self.run_world(after=(0, 1000, 21, 499, 23, 27))
        without = self.run_world(after=(0, 1000, 21, 500, 23, 27))
        self.assertEqual(with_call["out"], without["out"])

    def test_ratio_is_unsigned_and_in_doubles(self):
        self.assertIn("balance lookup", self.names(before=(0, 1, 11, t.TOP + 4096, 13, 17), after=(0, 1, 21, t.TOP, 23, 27)))


class Controls(Base):
    def test_flipped_shortfall_branch_is_seen(self):
        world = t.world(health=(0, 1000, 1100), post=(0, 999, 1100))
        self.assertIn("differs", self.mutant(0x46F2860, 0, 0x74, world))

    def test_flipped_ratio_branch_is_seen(self):
        world = t.world(after=(0, 1000, 21, 499, 23, 27))
        self.assertIn("differs", self.mutant(0x4D2FBF5, 0, 0x77, world))

    def test_changed_mode_immediate_is_seen(self):
        self.assertIn("differs", self.mutant(0x46F0A51, 2, 0x02, t.world()))

    def test_changed_good_byte_is_seen(self):
        self.assertTrue(self.mutant(0x46F285B, 2, 0x12, t.world()))

    def test_case_rows_are_all_reached(self):
        self.assertGreater(len(t.all_cases()), 300)

    def test_a_wrong_host_byte_is_refused(self):
        saved = t.HOST_BYTES
        t.HOST_BYTES = ((0x2765701, "00" * 7, "wrong"),)
        try:
            with self.assertRaisesRegex(t.EvidenceError, "host bytes"):
                t.read_host_bytes(self.image)
        finally:
            t.HOST_BYTES = saved

    def test_twins_refuse_a_wrong_pair(self):
        with self.assertRaises(t.EvidenceError):
            t.twin_rows(self.image, t.SECOND_A, t.SECOND_C)


class Packet(unittest.TestCase):
    def test_manifest_lists_every_file(self):
        names = sorted(path.name for path in FOLDER.iterdir() if path.name != "MANIFEST.sha256")
        rows = (FOLDER / "MANIFEST.sha256").read_text().splitlines()
        self.assertEqual(sorted(row.split("  ")[1] for row in rows), names)
        for row in rows:
            digest, name = row.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_evidence_counts(self):
        doc = json.loads((FOLDER / "evidence.json").read_text())
        self.assertEqual(doc["mismatches"], 0)
        self.assertEqual(doc["target"]["sha256"], t.SHA256)
        self.assertEqual(doc["cases"]["total"], len(t.all_cases()))
        rows = (FOLDER / "mutations.tsv").read_text().splitlines()[1:]
        self.assertEqual(sum(doc["mutations"].values()), len(rows))
        for line in rows:
            fields = line.split("\t")
            if fields[3] != "killed":
                self.assertTrue(fields[5], line)

    def test_tool_needs_the_out_flag(self):
        done = subprocess.run([sys.executable, "-B", str(ROOT / "tools" / "spot_second_path.py")], capture_output=True, text=True)
        self.assertNotEqual(done.returncode, 0)


if __name__ == "__main__":
    unittest.main()
