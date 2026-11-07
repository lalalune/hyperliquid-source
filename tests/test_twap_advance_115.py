import hashlib
import pathlib
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import twap_advance_115 as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-006-twap-advance-115"
DATE = tool.pack_date(2025, 100)
NOW = (DATE, 3600, 123456789)

# (name, case fields, order fields, outcome, counter after, due after (secs, nanos) or None)
GOLDEN = (
    ("next moment equals now", {}, dict(due=(DATE, 3570, 123456789), counter=7), "reschedule", 8, (3600, 123456789)),
    ("next moment one nano behind", {}, dict(due=(DATE, 3570, 123456788), counter=7), "reschedule", 8, (3630, 123456788)),
    ("next moment one nano ahead", {}, dict(due=(DATE, 3570, 123456790), counter=7), "reschedule", 8, (3600, 123456790)),
    ("behind by 59.5 s needs two more steps", {}, dict(due=(DATE, 3510, 500000000), counter=7), "reschedule", 8, (3600, 500000000)),
    ("exactly one step behind", {}, dict(due=(DATE, 3510, 123456789), counter=7), "reschedule", 8, (3600, 123456789)),
    ("executed reaches total", {}, dict(executed=1000000, due=(DATE, 3570, 123456789)), "finish", 8, (3600, 123456789)),
    ("counter becomes the last step", {}, dict(counter=119, duration=3600.0), "reschedule", 120, None),
    ("counter reaches the step count", {}, dict(counter=120, duration=3600.0), "reschedule", 121, None),
    ("counter passes the step count", {}, dict(counter=121, duration=3600.0), "finish", 122, None),
    ("counter saturates and finishes", {}, dict(counter=tool.MASK[8], duration=3600.0), "finish", tool.MASK[8], None),
    ("infinite duration is zero buckets", {}, dict(counter=0, duration=float("inf")), "reschedule", 1, None),
    ("infinite duration finishes on the second step", {}, dict(counter=1, duration=float("inf")), "finish", 2, None),
    ("negative duration is zero buckets", {}, dict(counter=1, duration=-1.0), "finish", 2, None),
    ("NaN duration is zero buckets", {}, dict(counter=1, duration=float("nan")), "finish", 2, None),
)


class AdvanceStep115(unittest.TestCase):
    def prepare(cls):
        cls.image = tool.load_image()
        cls.harness = tool.AdvanceHarness(cls.image)

    setUpClass = classmethod(prepare)

    def run_cases(self, count, variant="", copies=range(4)):
        wrong = 0
        for index in copies:
            for case in tool.cases_for(index, count):
                ok, _, _ = tool.check(self.harness, index, case, variant)
                wrong += not ok
        return wrong

    def test_bytes_match_specification(self):
        self.assertEqual(self.run_cases(250), 0)

    def test_every_outcome_is_reached(self):
        seen = set()
        for index in range(4):
            for case in tool.cases_for(index, 250):
                _, expected, _ = tool.check(self.harness, index, case)
                seen.add((tool.ADVANCE[index]["family"], tool.outcome_of(expected)))
        for family in (tool.PERP, tool.SPOT):
            for outcome in ("finish", "reschedule", "none", "user inserted", "stop"):
                self.assertIn((family, outcome), seen)

    def test_wrong_digest_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(tool.BINARY, "0" * 64)

    def test_address_outside_every_fde_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            self.image.fde(0x10)
        with self.assertRaises(tool.EvidenceError):
            self.image.exact_fde(tool.ADVANCE[0]["advance"] + 1)

    def test_every_wrong_specification_is_caught(self):
        for variant in tool.VARIANTS:
            with self.subTest(variant=variant):
                self.assertGreater(self.run_cases(120, variant), 0)

    def test_flipped_conditions_are_caught(self):
        sites = [insn for insn in tool.function_rows(self.image, tool.ADVANCE[0]["advance"])[2] if insn.op == "jcc"]
        probe = list(tool.cases_for(0, 300))
        caught = 0
        for insn in sites[:40:4]:
            patch = tool.jcc_patch(self.image, insn)
            caught += tool.detects(self.image, 0, {patch[0]: patch[1]}, probe)
        self.assertGreaterEqual(caught, 5)

    def test_pins_match_and_corruption_is_refused(self):
        for va, expected, what in tool.BYTE_PINS:
            at = self.image.offset(va)
            self.assertEqual(bytes(self.image.blob[at:at + len(expected)]), expected, what)
        for row in tool.pin_controls(self.image):
            self.assertTrue(row[2] and row[3])

    def test_perp_and_spot_copies_differ_only_in_callees(self):
        rows = tool.copy_differences(self.image)
        self.assertEqual([row for row in rows if row[5] != "call target"], [])
        self.assertEqual(len(rows), 5)

    def test_render_is_deterministic_and_counted(self):
        first = tool.render(self.image, 12, 2, 4)
        second = tool.render(self.image, 12, 2, 4)
        self.assertEqual(first, second)
        measure = tool.json.loads(first["measure.json"])
        self.assertEqual(measure["cases"], 4 * (len(list(tool.named_cases())) + 12))
        self.assertGreaterEqual(measure["negative_controls"], 20)
        self.assertEqual(measure["negative_controls"], measure["negative_detected"])

    def test_committed_manifest(self):
        manifest = FOLDER / "MANIFEST.sha256"
        if not manifest.exists():
            self.skipTest("packet folder not present in this checkout")
        for line in manifest.read_text().splitlines():
            digest, name = line.split("  ", 1)
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)


class GoldenScenarios(unittest.TestCase):
    def prepare(cls):
        cls.image = tool.load_image()
        cls.harness = tool.AdvanceHarness(cls.image)

    setUpClass = classmethod(prepare)

    def test_hand_checked_scenarios(self):
        for index in range(4):
            for name, case_fields, order_fields, outcome, counter, due in GOLDEN:
                with self.subTest(copy=index, name=name):
                    fields = dict(order_fields)
                    case = tool.AdvCase(name, now=NOW, **fields, **case_fields)
                    case.family = tool.ADVANCE[index]["family"]
                    ok, expected, actual = tool.check(self.harness, index, case)
                    self.assertTrue(ok)
                    self.assertEqual(tool.outcome_of(expected), outcome)
                    self.assertEqual(actual["state"]["counter"], counter)
                    if due is not None:
                        self.assertEqual(struct.unpack("<III", actual["state"]["due"])[1:], due)

    def test_missing_user_is_added_empty(self):
        case = tool.AdvCase("missing", lookup="user_missing", users=(5, 4, 3, 1))
        case.family = tool.PERP
        ok, expected, actual = tool.check(self.harness, 0, case)
        self.assertTrue(ok)
        self.assertEqual([event[0] for event in actual["events"]], ["find user", "insert user", "find order"])
        self.assertEqual(len(actual["users"]), 4)
        self.assertEqual(actual["users"][1][0], tool.user_id(1))
        self.assertEqual(actual["users"][1][1], struct.pack("<QQQQ", 0, 8, 0, 0))

    def test_sixty_four_users_hand_the_ring_to_the_promotion(self):
        for index, promote in ((0, 0x515A060), (2, 0x51581B0)):
            for length, stops in ((0x3F, False), (0x40, True)):
                case = tool.AdvCase("big", lookup="user_missing", users=(0x50, 3, length, 7))
                case.family = tool.ADVANCE[index]["family"]
                ok, expected, actual = tool.check(self.harness, index, case)
                self.assertTrue(ok)
                self.assertEqual("stop" in actual, stops)
                if stops:
                    self.assertEqual(actual["stop"], ("boundary", promote))

    def test_order_past_the_ring_length_changes_nothing(self):
        case = tool.AdvCase("beyond", lookup="beyond", orders=(5, 2, 1, 1))
        case.family = tool.PERP
        ok, expected, actual = tool.check(self.harness, 0, case)
        self.assertTrue(ok)
        self.assertEqual([event[0] for event in actual["events"]], ["find user", "find order"])
        self.assertNotIn("state", actual)

    def test_failed_date_add_uses_the_stored_moment(self):
        case = tool.AdvCase("date failure", date_none=True)
        case.family = tool.PERP
        ok, expected, actual = tool.check(self.harness, 0, case)
        self.assertTrue(ok)
        self.assertEqual(struct.unpack("<III", actual["state"]["due"]), self.harness.default)


class EngineUnits(unittest.TestCase):
    def test_time_add_carries_whole_days(self):
        self.assertEqual(tool.mc_time_add(86399, 5, 30, 0), (29, 5, 86400))
        self.assertEqual(tool.mc_time_add(10, 999999999, 0, 2), (11, 1, 0))
        self.assertEqual(tool.mc_time_add(5, 0, -10, 0), (86395, 0, (-86400) & tool.MASK[8]))

    def test_time_sub_normalises_nanos(self):
        self.assertEqual(tool.mc_time_sub((DATE, 10, 5), (DATE, 9, 10)), (0, 999999995))
        self.assertEqual(tool.mc_time_sub((DATE, 9, 10), (DATE, 10, 5)), (-1, 5))

    def test_truncating_division(self):
        self.assertEqual(tool.sdiv_trunc(-86399, 86400), 0)
        self.assertEqual(tool.sdiv_trunc(-86400, 86400), -1)
        self.assertEqual(tool.sdiv_trunc(86401, 86400), 1)

    def test_date_add_is_ordinal_arithmetic(self):
        self.assertEqual(tool.mc_date_add(DATE, 1), DATE + 16)
        self.assertEqual(tool.mc_date_add(DATE, -1), DATE - 16)

    def test_duration_steps(self):
        self.assertEqual(tool.duration_steps(3600.0), 121)
        self.assertEqual(tool.duration_steps(0.0), 1)
        self.assertEqual(tool.duration_steps(float("nan")), 1)
        self.assertEqual(tool.duration_steps(1e300), tool.MASK[8])

    def test_ring_position(self):
        self.assertEqual(tool.phys((5, 2, 1, 0)), 2)
        self.assertEqual(tool.phys((5, 4, 3, 2)), 1)

    def test_carry_range_constants(self):
        for carry in (0, 86400, (-86400) & tool.MASK[8], (1 << 31) * 86400 - 1):
            self.assertFalse((carry + tool.CARRY_ADD_1) & tool.MASK[8] < tool.CARRY_LIMIT_1)
        self.assertTrue((((1 << 31) * 86400) + tool.CARRY_ADD_1) & tool.MASK[8] < tool.CARRY_LIMIT_1 or
                        (((1 << 31) * 86400) + tool.CARRY_ADD_2) & tool.MASK[8] < tool.CARRY_LIMIT_2)


if __name__ == "__main__":
    unittest.main()
