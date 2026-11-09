import hashlib
import pathlib
import struct
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import twap_finish_115 as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-006-twap-finish-115"


def names(events):
    return [event[0] for event in events]


class FinishStep115(unittest.TestCase):
    def prepare(cls):
        cls.image = tool.load_image()
        cls.harness = tool.FinishHarness(cls.image)

    setUpClass = classmethod(prepare)

    def run_cases(self, count, variant="", copies=range(4)):
        wrong = 0
        for index in copies:
            for case in tool.cases_for(index, count):
                ok, _, _ = tool.check(self.harness, index, case, variant)
                wrong += not ok
        return wrong

    def one(self, index, **options):
        case = tool.FinCase("unit", **options)
        case.family = tool.FINISH[index]["family"]
        ok, expected, actual = tool.check(self.harness, index, case)
        self.assertTrue(ok)
        return expected, actual

    def test_bytes_match_specification(self):
        self.assertEqual(self.run_cases(250), 0)

    def test_every_outcome_is_reached(self):
        seen = set()
        for index in range(4):
            for case in tool.cases_for(index, 250):
                _, expected, _ = tool.check(self.harness, index, case)
                seen.add((tool.FINISH[index]["family"], tool.outcome_of(expected)))
        for family in (tool.PERP, tool.SPOT):
            for outcome in ("pushed", "pushed after removing user", "error", "error, reason freed"):
                self.assertIn((family, outcome), seen)
        self.assertIn((tool.PERP, "stop: expect"), seen)

    def test_wrong_digest_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(tool.BINARY, "0" * 64)

    def test_address_outside_every_fde_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            self.image.fde(0x10)
        with self.assertRaises(tool.EvidenceError):
            self.image.exact_fde(tool.FINISH[0]["finish"] + 1)

    def test_every_wrong_specification_is_caught(self):
        for variant in tool.VARIANTS:
            with self.subTest(variant=variant):
                self.assertGreater(self.run_cases(120, variant), 0)

    def test_flipped_conditions_are_caught(self):
        probe = list(tool.cases_for(0, 300))
        caught = 0
        for name in ("finish", "take"):
            sites = [insn for insn in tool.function_rows(self.image, tool.FINISH[0][name])[2] if insn.op == "jcc"]
            for insn in sites[:24:3]:
                patch = tool.jcc_patch(self.image, insn)
                caught += tool.detects(self.image, 0, {patch[0]: patch[1]}, probe)
        self.assertGreaterEqual(caught, 6)

    def test_pins_match_and_corruption_is_refused(self):
        for va, expected, what in tool.BYTE_PINS:
            at = self.image.offset(va)
            self.assertEqual(bytes(self.image.blob[at:at + len(expected)]), expected, what)
        for row in tool.pin_controls(self.image):
            self.assertTrue(row[2] and row[3])

    def test_copy_differences_are_the_known_ones(self):
        rows = tool.copy_differences(self.image)
        finish_pair = [row for row in rows if row[0] == "finish" and (row[1], row[2]) == (0, 1)]
        self.assertEqual(len(finish_pair), 2)
        self.assertEqual([row for row in rows if row[0] == "finish" and (row[1], row[2]) == (2, 3)], [])
        take = [row for row in rows if row[0] == "take"]
        self.assertTrue(take and all(row[6] == "call target" for row in take))

    def test_render_is_deterministic_and_counted(self):
        first = tool.render(self.image, 12, 2, 4)
        second = tool.render(self.image, 12, 2, 4)
        self.assertEqual(first, second)
        measure = tool.json.loads(first["measure.json"])
        self.assertEqual(measure["cases"], 4 * (len(list(tool.named_cases())) + 12))
        self.assertEqual(measure["negative_controls"], measure["negative_detected"])
        self.assertGreaterEqual(measure["negative_controls"], 20)

    def test_committed_manifest(self):
        manifest = FOLDER / "MANIFEST.sha256"
        if not manifest.exists():
            return
        for line in manifest.read_text().splitlines():
            digest, name = line.split("  ", 1)
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)


class GoldenScenarios(unittest.TestCase):
    def prepare(cls):
        cls.image = tool.load_image()
        cls.harness = tool.FinishHarness(cls.image)

    setUpClass = classmethod(prepare)

    def run_one(self, index, **options):
        case = tool.FinCase("golden", **options)
        case.family = tool.FINISH[index]["family"]
        ok, expected, actual = tool.check(self.harness, index, case)
        self.assertTrue(ok)
        return actual

    def test_plain_finish_sequence(self):
        for index in range(4):
            actual = self.run_one(index)
            expected = ["precheck", "find user", "remove order"]
            expected += ["drop temp"] if index < 2 else []
            expected += ["build", "copy", "copy"]
            self.assertEqual(names(actual["events"]), expected)
            event = actual["event"]
            self.assertEqual(struct.unpack_from("<Q", event, 0)[0], 4)
            self.assertEqual(struct.unpack_from("<Q", event, 0x98)[0], 77)
            self.assertEqual(event[0xAC:0xC0], tool.user_id(3))
            self.assertEqual(struct.unpack_from("<III", event, 0xA0), (0x12345678, 3600, 123456789))

    def test_emptied_ring_removes_the_user_and_frees_the_ring(self):
        for index in range(4):
            actual = self.run_one(index, after_len=0, user_free=3)
            self.assertIn("remove user", names(actual["events"]))
            self.assertIn(("free", tool.FREED, 3 * 0x70, 0), actual["events"])
            self.assertEqual(actual["ring_len"], 0)

    def test_missing_order_is_an_error_and_frees_a_positive_reason_capacity(self):
        for index in range(4):
            actual = self.run_one(index, removal="none", reason_cap=24)
            self.assertEqual(actual["events"][-2:], [("drop error", tool.ERROR_CODE), ("free", 0x50000, 24, 0)])
            self.assertNotIn("event", actual)
            actual = self.run_one(index, removal="none", reason_cap=tool.TREE | 2)
            self.assertEqual(actual["events"][-1], ("drop error", tool.ERROR_CODE))

    def test_market_index_must_be_below_the_count(self):
        actual = self.run_one(0, asset=4 * tool.DIVISOR, count=4)
        self.assertEqual(actual["stop"], "expect")
        actual = self.run_one(0, asset=3 * tool.DIVISOR + 9999, count=4)
        self.assertIn(("build", "5182b60", tool.FinCase("x", asset=3 * tool.DIVISOR + 9999).body(), 3), actual["events"])

    def test_tree_arm_walks_the_nodes_and_finds_the_user(self):
        for index in range(4):
            actual = self.run_one(index, user_state="tree", tree=(1, 4, 3), tree_pos=5, user=9)
            compares = [event for event in actual["events"] if event[0] == "compare"]
            self.assertTrue(compares)
            removes = [event for event in actual["events"] if event[0] == "remove order"]
            self.assertEqual(len(removes), 1)
            self.assertEqual(removes[0][1][0], "tree")
            actual = self.run_one(index, user_state="tree", tree=(1, 4, 3), user_in_tree=False, user=11)
            self.assertNotIn("remove order", names(actual["events"]))
            self.assertEqual(actual["events"][-1][0], "drop error")

    def test_vector_grows_only_when_full(self):
        for index in range(4):
            self.assertNotIn("grow", names(self.run_one(index, vec=(4, 3))["events"]))
            actual = self.run_one(index, vec=(4, 4))
            self.assertIn(("grow", 4), actual["events"])
            self.assertEqual(actual["vec"], (8, 5))

    def test_precheck_rejection_takes_the_other_builder(self):
        actual = self.run_one(0, pre="alt")
        builds = [event for event in actual["events"] if event[0] == "build"]
        self.assertEqual(builds[0][1], "5181da0")
        actual = self.run_one(2, pre="alt")
        builds = [event for event in actual["events"] if event[0] == "build"]
        self.assertEqual(builds[0][1], "51821b0")


class EngineUnits(unittest.TestCase):
    def test_ring_position(self):
        self.assertEqual(tool.phys((5, 2, 3, 0)), 2)
        self.assertEqual(tool.phys((5, 4, 3, 2)), 1)

    def test_builder_output_depends_on_every_argument(self):
        record = bytes(range(tool.BODY))
        base = tool.builder_output("5182b60", record, 3)
        self.assertEqual(len(base), 0x78)
        self.assertNotEqual(base, tool.builder_output("5181da0", record, 3))
        self.assertNotEqual(base, tool.builder_output("5182b60", record, 4))
        self.assertNotEqual(base, tool.builder_output("5182b60", record[:-1] + b"\x00", 3))

    def test_magic_multiplier_is_division_by_ten_thousand(self):
        for value in (0, 9999, 10000, 123456789, tool.MASK[8], tool.MASK[8] - 9999):
            self.assertEqual(((value * 0x346DC5D63886594B) >> 64) >> 11, value // 10000)


if __name__ == "__main__":
    unittest.main()
