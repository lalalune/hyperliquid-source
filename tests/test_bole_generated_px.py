import math
import pathlib
import tempfile
import unittest

from tools import bole_generated_px as tool

ROOT = pathlib.Path(__file__).resolve().parents[1]
FOLDER = ROOT / "research" / "work-items" / "RE-004-bole-generated-px-94"
FIRST, SECOND = tool.ROW_BUILDERS
STATE = {}


def setUpModule():
    STATE["image"] = tool.load_image()
    STATE["result"] = tool.analyse(STATE["image"], full=False)
    STATE["files"] = tool.render(STATE["result"])


def harness(patches=None, statics=None):
    return tool.Harness(STATE["image"], patches, statics)


def flipped(at):
    image = STATE["image"]
    return {at: image.blob[image.offset(at)] ^ 1}


class Identity(unittest.TestCase):
    def test_wrong_hash_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_flipped_byte_is_refused(self):
        blob = bytearray(tool.BINARY.read_bytes())
        blob[-1] ^= 1
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "flipped"
            path.write_bytes(blob)
            with self.assertRaises(tool.EvidenceError):
                tool.load_image(path)

    def test_fde_extents(self):
        image = STATE["image"]
        for entry in tool.ROW_BUILDERS:
            self.assertEqual(image.exact_fde(entry), (entry, entry + 902))
        for entry, _ in tool.WRAPPERS:
            self.assertEqual(image.exact_fde(entry), (entry, entry + 843))

    def test_address_inside_a_function_is_not_a_start(self):
        with self.assertRaises(tool.EvidenceError):
            STATE["image"].exact_fde(FIRST + 1)

    def test_address_outside_every_fde(self):
        with self.assertRaises(tool.EvidenceError):
            STATE["image"].fde(0x10)

    def test_nobits_section_has_no_file_bytes(self):
        bss = STATE["image"].named[".bss"]
        with self.assertRaises(tool.EvidenceError):
            STATE["image"].offset(bss["address"] + 8)

    def test_slot_targets(self):
        result = STATE["result"]
        self.assertEqual(result["row_helper_slot"], tool.HELPER_ROW)
        self.assertEqual(result["round_slot_target"], tool.ROUND)

    def test_copies_differ_only_in_one_location(self):
        result = STATE["result"]
        self.assertEqual(result["instructions"], 177)
        self.assertEqual(len(result["differences"]), 1)
        self.assertEqual(result["differences"][0][0], 0x2D5)

    def test_call_sites(self):
        result = STATE["result"]
        self.assertEqual(result["row_sites"][FIRST], [0x251A2FD, 0x251A45A])
        self.assertEqual(result["row_sites"][SECOND], [0x47F723D, 0x47F739A, 0x47F85BD, 0x47F871A])

    def test_locations(self):
        locations = STATE["result"]["locations"]
        self.assertEqual(locations[tool.LOCATION_TABLE], ("l1/src/spot_meta.rs", 113, 33))
        self.assertEqual(locations[tool.LOCATION_SLOTS], ("l1/src/spot_meta.rs", 565, 25))
        for at in tool.LOCATION_ROW.values():
            self.assertEqual(locations[at], ("l1/src/exchange/impl_bole.rs", 377, 35))


class Price(unittest.TestCase):
    def run_price(self, m, reference, entry=FIRST, patches=None):
        case = tool.Case(m=m, tree={5: reference})
        return harness(patches).run_case(entry, case)[2][2]

    def test_additions_change_the_price(self):
        for entry in tool.ROW_BUILDERS:
            self.assertEqual(self.run_price(0.1, 15, entry), 1)
        self.assertEqual(tool.reference_price(0.1, 15), 2)

    def test_tiny_multiplier_is_erased(self):
        self.assertEqual(self.run_price(1e-17, 10 ** 18), 1)
        self.assertEqual(tool.reference_price(1e-17, 10 ** 18), 10)

    def test_unit_range_keeps_m(self):
        stream = tool.lcg(5)
        for _ in range(2000):
            word = next(stream)
            m = 0.5 + (word >> 12) / 2.0 ** 52 * 1.5
            self.assertEqual(tool.spec_multiplier(m), m)

    def test_floor_of_one(self):
        for m, reference in ((0.0, 7), (-3.0, 7), (math.nan, 7), (math.inf, 7), (1.0, 0), (math.inf, 0)):
            self.assertEqual(self.run_price(m, reference), 1)

    def test_saturation(self):
        self.assertEqual(self.run_price(1e19, 3), tool.U64_MAX)
        self.assertEqual(self.run_price(2.0, 1 << 63), tool.U64_MAX)

    def test_half_rounds_away(self):
        self.assertEqual(self.run_price(1.5, 3), 5)
        self.assertEqual(self.run_price(0.5, 3), 2)

    def test_nop_of_both_additions_is_seen(self):
        patch = {}
        for offset in (tool.OFFSET_MINUS_ONE, tool.OFFSET_PLUS_ONE):
            patch.update({FIRST + offset + i: 0x90 for i in range(8)})
        self.assertEqual(self.run_price(0.1, 15, patches=patch), 2)

    def test_multiplier_rows_are_pinned(self):
        image = STATE["image"]
        blob = bytearray(image.blob)
        at = image.offset(FIRST + tool.OFFSET_PLUS_ONE)
        blob[at:at + 8] = b"\x90" * 8
        other = object.__new__(tool.Image)
        other.__dict__.update(image.__dict__)
        other.blob = bytes(blob)
        with self.assertRaises(tool.EvidenceError):
            tool.pin_price_rows(other, FIRST)

    def test_round_helper_exact(self):
        testing = harness()
        for value in tool.round_cases():
            self.assertTrue(tool.compare_round(testing, value))

    def test_round_spec_edges(self):
        self.assertEqual(tool.spec_round(0.49999999999999994), 0.0)
        self.assertEqual(tool.spec_round(-2.5), -3.0)
        self.assertEqual(math.copysign(1.0, tool.spec_round(-0.25)), -1.0)

    def test_constant_is_read_from_the_image(self):
        patched = harness(None, {tool.MINUS_ONE_AT: tool.to_bits(-2.0)})
        case = tool.Case(m=1.5, tree={5: 1000})
        self.assertNotEqual(patched.run_case(FIRST, case)[2][2], 1500)


class Tail(unittest.TestCase):
    def test_every_seed_is_covered_without_gaps(self):
        for rows in STATE["result"]["tails"].values():
            ordered = sorted(rows)
            self.assertEqual(ordered[0][0], 0)
            self.assertEqual(ordered[-1][1], tool.MASK[8])
            for left, right in zip(ordered, ordered[1:]):
                self.assertEqual(left[1] + 1, right[0])

    def test_closed_form(self):
        self.assertEqual(tool.spec_tail(0.5), 1)
        self.assertEqual(tool.spec_tail(2.0 ** 64), tool.U64_MAX)
        self.assertEqual(tool.spec_tail(math.inf), 1)
        self.assertEqual(tool.spec_tail(-math.inf), 1)
        self.assertEqual(tool.spec_tail(math.nan), 1)
        self.assertEqual(tool.spec_tail(float(1 << 63)), 1 << 63)

    def test_refinement_fails_on_a_changed_tail(self):
        # cmova r13,r8 at +0x2b1 becomes cmovbe: values below 2^64 saturate.
        with self.assertRaises(tool.EvidenceError):
            tool.refine_tail(harness(flipped(FIRST + 0x2B3)), FIRST)

    def test_refinement_fails_without_the_floor(self):
        # adc $0,r8 at +0x2b9 adds 1 instead of 0.
        with self.assertRaises(tool.EvidenceError):
            tool.refine_tail(harness(flipped(FIRST + 0x2BC)), FIRST)


class Outcomes(unittest.TestCase):
    def test_case_counts(self):
        for counts in STATE["result"]["tables"].values():
            self.assertEqual(counts["panic"], 3)
            self.assertEqual(counts["bounds"], 2)
            self.assertEqual(counts["none"], 9)

    def test_table_bound_panics_with_no_counter_change(self):
        got = harness().run_case(FIRST, tool.Case(key=9, tables=9, counter=7))
        self.assertEqual(got, ("panic", 7, tool.LOCATION_TABLE))

    def test_row_failure_keeps_the_counter_bump(self):
        got = harness().run_case(SECOND, tool.Case(status=2, counter=7))
        self.assertEqual(got[:2], ("none", 8))

    def test_template_bytes(self):
        got = harness().run_case(FIRST, tool.Case(counter=7))
        self.assertEqual(got[3], tool.spec_template(7))
        self.assertEqual(got[3].count(b"\xbb" * 20), 1)

    def test_reference_word_lands_in_the_row(self):
        got = harness().run_case(FIRST, tool.Case(tree={5: 0x1122334455667788}))
        self.assertEqual(int.from_bytes(got[4][0x210:0x218], "little"), 0x1122334455667788)

    def test_changed_bound_is_seen(self):
        # jae of the table bound at +0x2b becomes jb.
        got = tool.run_all(harness(flipped(FIRST + 0x2C)), FIRST, tool.outcome_cases())
        self.assertIsNotNone(got)


class Wrappers(unittest.TestCase):
    def test_order_and_capacity(self):
        rows = {(row[0], row[2]): row for row in STATE["result"]["wrappers"]}
        for entry, _ in tool.WRAPPERS:
            self.assertEqual(rows[(entry, "five kept, grow")][4:], (5, 8))
            self.assertEqual(rows[(entry, "all dropped")][4:], (0, 0))

    def test_changed_filter_is_seen(self):
        image = STATE["image"]
        entry, inner = tool.WRAPPERS[0]
        testing = tool.Harness(image, flipped(0x251A30D))
        got = testing.run_wrapper((entry, inner), [1, 2, 3], {2})
        self.assertNotEqual(got["rows"], tool.spec_wrapper([1, 2, 3], {2})["rows"])


class Evidence(unittest.TestCase):
    def test_stored_files_match(self):
        for name, text in STATE["files"].items():
            if name != "evidence.json":
                self.assertEqual((FOLDER / name).read_text(encoding="ascii"), text, name)

    def test_summary_matches_apart_from_the_mutation_block(self):
        stored = tool.json.loads((FOLDER / "evidence.json").read_text(encoding="ascii"))
        stored.pop("mutations")
        self.assertEqual(stored, tool.json.loads(STATE["files"]["evidence.json"]))

    def test_mutation_table(self):
        lines = (FOLDER / "mutations.tsv").read_text(encoding="ascii").splitlines()[1:]
        rows = [line.split("\t") for line in lines]
        stored = tool.json.loads((FOLDER / "evidence.json").read_text(encoding="ascii"))["mutations"]
        self.assertEqual(stored["total"], len(rows))
        self.assertEqual(stored["killed"], sum(1 for row in rows if row[2] == "killed"))
        survivors = {row[0] for row in rows if row[2] == "survived"}
        self.assertEqual(survivors, {"%#x" % va for va in tool.EXPECTED_SURVIVORS})

    def test_no_external_tool(self):
        source = pathlib.Path(tool.__file__).read_text(encoding="utf-8")
        self.assertNotIn("subprocess", source)
        self.assertNotIn("objdump", source.replace("No\nobjdump", ""))


if __name__ == "__main__":
    unittest.main()
