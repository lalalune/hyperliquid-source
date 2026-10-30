import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import priority_admission as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-004-priority-admission-94"
SHARED = {}


def setUpModule():
    image = tool.load_image()
    SHARED["image"] = image
    SHARED["harness"] = tool.Harness(image)
    SHARED["named"] = tool.named_cases()
    SHARED["result"] = tool.analyse(image, full=False)
    SHARED["files"] = tool.render(SHARED["result"])


def named(text):
    return next(case for name, case in SHARED["named"] if name == text)


def flipped(offset, index=0):
    image = SHARED["image"]
    va = tool.GATE + offset + index
    return {va: image.blob[image.offset(va)] ^ 1}


def run(case, patches=None, statics=None):
    return tool.Harness(SHARED["image"], patches, statics).run_case(case)


class ClosedForm(unittest.TestCase):
    def test_interpolation_by_hand(self):
        case = tool.Case(5000000, (tool.GOOD,), a=0.25, b=2.0, d=0.1)
        self.assertEqual(tool.to_float(tool.spec(case)[1]), 0.25 + (1.0 - 0.05 / 0.1) * 1.75)

    def test_priority_zero_is_the_far_end(self):
        self.assertEqual(tool.to_float(tool.spec(tool.Case(0, (tool.GOOD,), a=0.25, b=2.0, d=0.1))[1]), 2.0)

    def test_id_classes(self):
        self.assertTrue(tool.admitted_asset(9999))
        self.assertFalse(tool.admitted_asset(10000))
        self.assertFalse(tool.admitted_asset(109999))
        self.assertTrue(tool.admitted_asset(110000))
        self.assertTrue(tool.admitted_asset(99999999))
        self.assertFalse(tool.admitted_asset(100000000))

    def test_weight_range(self):
        self.assertTrue(tool.in_unit_range(0.0))
        self.assertTrue(tool.in_unit_range(-0.0))
        self.assertTrue(tool.in_unit_range(1.0))
        self.assertFalse(tool.in_unit_range(1.0000000000000002))
        self.assertFalse(tool.in_unit_range(-5e-324))
        self.assertFalse(tool.in_unit_range(float("nan")))
        self.assertFalse(tool.in_unit_range(float("inf")))

    def test_divide_by_zero_follows_ieee(self):
        self.assertEqual(tool.ieee_divide(-1.0, 0.0), float("-inf"))
        self.assertEqual(tool.ieee_divide(-1.0, -0.0), float("inf"))
        self.assertNotEqual(tool.ieee_divide(0.0, 0.0), tool.ieee_divide(0.0, 0.0))


class RealBytes(unittest.TestCase):
    def test_named_cases(self):
        self.assertIsNone(tool.run_all(SHARED["harness"], SHARED["named"]))

    def test_outcome_kinds(self):
        counts = SHARED["result"]["counts"]
        for key in ("ok plain", "ok priority", "tag 0xb2", "tag 0xb3", "tag 0xb5", "assert 0x566ae28", "assert 0x566ae58"):
            self.assertGreater(counts[key], 0, key)

    def test_first_bad_element_decides(self):
        self.assertEqual(SHARED["harness"].run_case(named("priority, first bad element decides: tif then asset")), ("tag", tool.TAG_IOC))
        self.assertEqual(SHARED["harness"].run_case(named("priority, first bad element decides: asset then tif")), ("tag", tool.TAG_ASSET))

    def test_weight_is_tested_before_the_duration_asserts(self):
        self.assertEqual(SHARED["harness"].run_case(named("bad weight beats a above b")), ("tag", tool.TAG_PRIORITY))

    def test_tif_three_ends_the_plain_walk(self):
        got = SHARED["harness"].run_case(named("plain, tif 3 ends the walk"))
        self.assertEqual(got[4][2], 1)

    def test_call_sites_and_forms(self):
        result = SHARED["result"]
        self.assertEqual(sorted(result["sites"]), sorted(tool.CALL_SITES))
        forms = [row[2] for row in result["callers"]]
        self.assertEqual(sum(1 for form in forms if form == "constant 0"), 3)
        self.assertEqual(sum(1 for form in forms if form.startswith("word 3 selects")), 7)

    def test_handler_guards(self):
        self.assertEqual([row[0] for row in SHARED["result"]["guards"]], list(tool.ORDER_HANDLERS))

    def test_tag_texts(self):
        texts = {row[0]: row[3] for row in SHARED["result"]["tags"]}
        self.assertEqual(texts[0xB3], "Priority order must be IOC")
        self.assertEqual(texts[0xB5], "Invalid asset for priority order")

    def test_uncovered_directions_are_listed(self):
        self.assertEqual(set(SHARED["result"]["missing"]), set(tool.UNCOVERED))


class WholeDomain(unittest.TestCase):
    def test_weight_table_covers_every_pattern(self):
        rows = SHARED["result"]["weights"]
        self.assertEqual(sum(hi - lo + 1 for lo, hi, _ in rows), 1 << 64)
        self.assertEqual([row[0] for row in rows if row[2]], [0, 1 << 63])

    def test_id_table_covers_every_word(self):
        rows = SHARED["result"]["assets"]
        self.assertEqual(sum(hi - lo + 1 for lo, hi, _, _ in rows), 1 << 32)
        self.assertEqual([row[2] for row in rows], [1, 0, 1, 0])
        self.assertEqual([row[3] for row in rows], ["second", "first", "second", "first"])

    def test_edges_follow_d(self):
        rows = {row[0]: row[1] for row in SHARED["result"]["edges"]}
        self.assertEqual(rows[1.0], 100000000)
        self.assertEqual(rows[0.25], 25000000)
        self.assertEqual(rows[0.001], 100000)
        self.assertEqual(rows[100.0], tool.MASK[4])


class NegativeControls(unittest.TestCase):
    def test_hash_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_other_file_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "fake"
            path.write_bytes(b"\x7fELF")
            with self.assertRaises(tool.EvidenceError):
                tool.load_image(path=path)

    def test_address_outside_a_function(self):
        with self.assertRaises(tool.EvidenceError):
            SHARED["image"].exact_fde(tool.GATE + 1)

    def test_nobits_has_no_file_bytes(self):
        bss = SHARED["image"].named[".bss"]
        with self.assertRaises(tool.EvidenceError):
            SHARED["image"].offset(bss["address"] + 8)

    def test_id_compare_flip(self):
        case = named("priority, id 9999")
        self.assertNotEqual(run(case, flipped(0x231, 0)), tool.spec(case))

    def test_tif_compare_flip(self):
        case = named("priority, one perp IOC order")
        self.assertNotEqual(run(case, flipped(0x24C, 3)), tool.spec(case))

    def test_divisor_sign(self):
        case = named("half span")
        self.assertNotEqual(run(case, None, {tool.SCALE_AT: tool.to_bits(1e8)}), tool.spec(case))

    def test_weight_table_sees_a_flipped_bound(self):
        harness = tool.Harness(SHARED["image"], flipped(0x50C, 1))
        with self.assertRaises(tool.EvidenceError):
            tool.weight_table(harness)

    def test_iterator_word_control(self):
        harness = tool.Harness(SHARED["image"], flipped(0x28A, 5))
        with self.assertRaises(tool.Halt):
            harness.run_case(named("priority, tif 0"))

    def test_tag_text_refuses_another_arm_shape(self):
        with self.assertRaises(tool.EvidenceError):
            tool.tag_text(SHARED["image"], tool.TAG_OK)


class Packet(unittest.TestCase):
    def test_evidence_matches_the_tool(self):
        summary = json.loads((FOLDER / "evidence.json").read_text())
        mutations = summary.pop("mutations")
        self.assertEqual(summary, json.loads(SHARED["files"]["evidence.json"]))
        for name, text in SHARED["files"].items():
            if name != "evidence.json":
                self.assertEqual((FOLDER / name).read_text(encoding="ascii"), text, name)
        self.assertEqual(mutations["killed"] + mutations["survived"], mutations["total"])

    def test_survivors_are_the_explained_ones(self):
        rows = [line.split("\t") for line in (FOLDER / "mutations.tsv").read_text().splitlines()[1:]]
        survivors = {int(row[0], 16) - tool.GATE for row in rows if row[2] == "survived"}
        self.assertEqual(survivors, set(tool.EXPECTED_SURVIVORS))

    def test_tool_calls_no_external_program(self):
        source = (ROOT / "tools" / "priority_admission.py").read_text()
        self.assertNotIn("subp" + "rocess", source)
        self.assertNotIn("os.sy" + "stem", source)


if __name__ == "__main__":
    unittest.main()
