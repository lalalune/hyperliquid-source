import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import priority_native_cost as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-004-priority-native-cost-94"
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


def outcome(patches=None, statics=None, case=None, entry=tool.COPIES[0]):
    harness = tool.Harness(SHARED["image"], patches, statics)
    return harness.run_case(entry, case)


def flipped(va, index=0):
    image = SHARED["image"]
    return {va + index: image.blob[image.offset(va + index)] ^ 1}


class ClosedForm(unittest.TestCase):
    def test_worked_division_by_hand(self):
        case = tool.Case(native=1, pairs=(0,), tokens=((8, 8), (2, 8)), tree={1: 3050000}, a=100000000, b=500)
        self.assertEqual(tool.spec(case), ("ok", 16393442623))
        self.assertEqual(SHARED["harness"].run_case(tool.COPIES[0], case), ("ok", 16393442623))

    def test_factor_scales_after_the_ceiling(self):
        case = tool.Case(native=1, pairs=(0,), tokens=((8, 8), (2, 8)), tree={1: 3050000}, a=100000000, b=500, factor=50000)
        self.assertEqual(tool.spec(case), ("ok", int(16393442623.0 * (50000.0 / 1e8))))

    def test_decimal_shift_without_a_price(self):
        case = tool.Case(native=1, pairs=(2,), tokens=((8, 8), (2, 8), (0, 6)), a=100000000, b=500)
        self.assertEqual(tool.spec(case), ("ok", 5000000000000))

    def test_cast_edges(self):
        self.assertEqual(tool.spec_cast(float("nan")), 0)
        self.assertEqual(tool.spec_cast(float("inf")), 0)
        self.assertEqual(tool.spec_cast(-1.0), 0)
        self.assertEqual(tool.spec_cast(2.0 ** 64), tool.MASK[8])
        self.assertEqual(tool.spec_cast(1e300), tool.MASK[8])
        self.assertEqual(tool.spec_cast(1.5), 1)

    def test_power_helpers(self):
        case = tool.Case(tokens=((0, 19), (0, 3)))
        self.assertEqual(tool.one_price(case, 1), 10 ** 19)
        self.assertEqual(tool.one_price(tool.Case(tokens=((0, 20), (0, 3))), 1), ("panic", tool.LOCATION_POWER))
        self.assertEqual(tool.one_price(tool.Case(tokens=((0, 1), (2, 3))), 1), ("panic", tool.LOCATION_SUB))
        self.assertEqual(tool.one_price(case, 2), ("panic", tool.LOCATION_TABLE))
        self.assertEqual(tool.unit_ratio(case, 1), 1000)
        self.assertEqual(tool.unit_ratio(tool.Case(tokens=((0, 0), (4, 3))), 1), ("panic", tool.LOCATION_UNIT))

    def test_random_vectors_are_fixed(self):
        first = tool.random_cases(20)
        second = tool.random_cases(20)
        self.assertEqual([(c.a, c.b, c.factor) for _, c in first], [(c.a, c.b, c.factor) for _, c in second])


class RealBytes(unittest.TestCase):
    def test_every_named_case_on_every_copy(self):
        for entry in tool.COPIES:
            self.assertIsNone(tool.run_all(SHARED["harness"], entry, SHARED["named"]))

    def test_all_outcome_kinds_seen(self):
        table = SHARED["result"]["tables"][tool.COPIES[0]]
        for key in ("ok", "tag 0xfb", "tag 0x13f", "tag 0xb2", "bounds 0x56bb188", "panic 0x56f21f0", "panic 0x56f2240", "panic 0x56f2258", "panic 0x56f2270"):
            self.assertGreater(table[key], 0, key)

    def test_copies_have_the_same_shape(self):
        result = SHARED["result"]
        self.assertEqual(set(result["instructions"].values()), {256})
        self.assertEqual(len(result["differences"]), 8)
        self.assertEqual({row[1] for row in result["differences"]}, {0x4C, 0x133, 0x144, 0x40C})

    def test_order_native_flag_before_everything(self):
        self.assertEqual(SHARED["harness"].run_case(tool.COPIES[0], named("flag beats a bad native id")), ("tag", tool.TAG_NO_NATIVE))

    def test_product_before_the_pair_bound(self):
        self.assertEqual(SHARED["harness"].run_case(tool.COPIES[0], named("product beats a bad pair")), ("tag", tool.TAG_PRODUCT))

    def test_each_call_site_is_single(self):
        for entry, sites in SHARED["result"]["sites"].items():
            self.assertEqual(len(sites), 1, hex(entry))
        self.assertEqual(SHARED["result"]["relocated"], [])

    def test_uncovered_directions_are_the_listed_two(self):
        self.assertEqual({key for key, _ in SHARED["result"]["unreached"]}, set(tool.UNREACHED))

    def test_tag_texts(self):
        texts = {row[0]: row[3] for row in SHARED["result"]["tags"]}
        self.assertEqual(texts[0xB2], "Invalid priority")
        self.assertEqual(texts[0xB3], "Priority order must be IOC")
        self.assertEqual(texts[0xFB], "Native token does not exist")
        self.assertEqual(texts[0x13F], "Invalid input number")


class WholeDomain(unittest.TestCase):
    def test_factor_edge_every_copy(self):
        for entry, row in SHARED["result"]["factor"].items():
            self.assertEqual(row[:2], (101000000, 101000001), hex(entry))

    def test_factor_edge_moves_with_the_limit(self):
        harness = tool.Harness(SHARED["image"], None, {tool.LIMIT_AT: tool.to_bits(1.02)})
        self.assertEqual(tool.factor_edge(harness, tool.COPIES[0])[0], 102000000)

    def test_tail_pieces(self):
        rows = SHARED["result"]["tails"][tool.COPIES[0]]
        self.assertEqual(len(rows), 9)
        self.assertEqual(rows[0][:2], (0, 0x43EFFFFFFFFFFFFF))
        self.assertEqual(sum(hi - lo + 1 for lo, hi, _, _, _ in rows), 1 << 64)

    def test_helper_domains_cover_every_pair(self):
        domains = SHARED["result"]["domains"]
        self.assertEqual(sum(v for k, v in domains.items() if k.startswith("one price")), 65536)
        self.assertEqual(sum(v for k, v in domains.items() if k.startswith("unit ratio")), 65536)


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
            SHARED["image"].exact_fde(tool.COPIES[0] + 1)
        with self.assertRaises(tool.EvidenceError):
            SHARED["image"].fde(0x10)

    def test_nobits_has_no_file_bytes(self):
        bss = SHARED["image"].named[".bss"]
        with self.assertRaises(tool.EvidenceError):
            SHARED["image"].offset(bss["address"] + 8)

    def test_gate_cmov_flip(self):
        case = named("gate keeps the product")
        self.assertNotEqual(outcome(flipped(tool.COPIES[0] + 0x29B, 2), None, case), tool.spec(case))

    def test_ceiling_flip(self):
        case = named("ceiling adds one")
        self.assertNotEqual(outcome(flipped(tool.COPIES[0] + 0x2FE, 1), None, case), tool.spec(case))

    def test_scale_constant(self):
        case = named("factor 1.0")
        self.assertNotEqual(outcome(None, {tool.SCALE_AT: tool.to_bits(1e7)}, case), tool.spec(case))

    def test_wrong_divide_target_stops(self):
        with self.assertRaises(tool.Halt):
            outcome(None, {tool.SLOT_DIVIDE: 0x565F7F0}, named("ceiling adds one"))

    def test_tail_mutation_breaks_the_refinement(self):
        harness = tool.Harness(SHARED["image"], flipped(tool.COPIES[0] + 0x3B7, 2))
        with self.assertRaises(tool.EvidenceError):
            tool.refine_tail(harness, tool.COPIES[0])

    def test_tag_text_refuses_another_arm_shape(self):
        with self.assertRaises(tool.EvidenceError):
            tool.tag_text(SHARED["image"], tool.TAG_OK)


class Packet(unittest.TestCase):
    def test_evidence_matches_the_tool(self):
        summary = json.loads((FOLDER / "evidence.json").read_text())
        mutations = summary.pop("mutations")
        fresh = json.loads(SHARED["files"]["evidence.json"])
        self.assertEqual(summary, fresh)
        for name, text in SHARED["files"].items():
            if name != "evidence.json":
                self.assertEqual((FOLDER / name).read_text(encoding="ascii"), text, name)
        self.assertEqual(mutations["killed"] + mutations["survived"], mutations["total"])

    def test_survivors_are_the_explained_ones(self):
        rows = [line.split("\t") for line in (FOLDER / "mutations.tsv").read_text().splitlines()[1:]]
        survivors = {int(row[0], 16) - tool.COPIES[0] for row in rows if row[2] == "survived"}
        self.assertEqual(survivors, set(tool.EXPECTED_SURVIVORS))
        self.assertTrue(all(row[3] for row in rows))

    def test_tool_calls_no_external_program(self):
        source = (ROOT / "tools" / "priority_native_cost.py").read_text()
        self.assertNotIn("subp" + "rocess", source)
        self.assertNotIn("os.sy" + "stem", source)


if __name__ == "__main__":
    unittest.main()
