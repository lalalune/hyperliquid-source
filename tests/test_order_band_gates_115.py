"""Tests for tools/order_band_gates_115.py: real node #115 bytes with corruption controls."""

import copy
import hashlib
import importlib.util
import json
import math
import pathlib
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FOLDER = ROOT / "research" / "work-items" / "RE-004-order-band-gates-115"
spec_ = importlib.util.spec_from_file_location("order_band_gates_115", ROOT / "tools" / "order_band_gates_115.py")
tool = importlib.util.module_from_spec(spec_)
sys.modules["order_band_gates_115"] = tool
spec_.loader.exec_module(tool)

IMAGE = None
HARNESS = None
RESULT = None


def setUpModule():
    global IMAGE, HARNESS, RESULT
    IMAGE = tool.load_image()
    HARNESS = tool.Harness(IMAGE)
    RESULT = tool.analyse(IMAGE, full=False, vectors=300, grid_step=6)


def edited(image, edits):
    """A copy of the image with file bytes replaced at virtual addresses."""
    clone = copy.copy(image)
    data = bytearray(image.blob)
    for va, value in edits.items():
        data[image.offset(va)] = value
    clone.blob = bytes(data)
    return clone


def byte_at(va):
    return IMAGE.blob[IMAGE.offset(va)]


class Identity(unittest.TestCase):
    def test_digest_is_the_target(self):
        self.assertEqual(hashlib.sha256(IMAGE.blob).hexdigest(), tool.SHA256)
        self.assertEqual(tool.SHA256, "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")

    def test_wrong_digest_fails(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_changed_last_byte_fails(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "copy"
            path.write_bytes(IMAGE.blob[:-1] + bytes([IMAGE.blob[-1] ^ 1]))
            with self.assertRaises(tool.EvidenceError):
                tool.load_image(path)

    def test_nobits_never_resolves(self):
        section = IMAGE.named[".bss"]
        self.assertEqual(section["type"], 8)
        with self.assertRaises(tool.EvidenceError):
            IMAGE.offset(section["address"] + 1)

    def test_address_outside_every_section_fails(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.offset(0x7FFFFFFFFF)

    def test_gate_starts_are_fde_starts(self):
        for start in (tool.SPOT_GATE, tool.PERP_GATE):
            IMAGE.exact_fde(start)
            with self.assertRaises(tool.EvidenceError):
                IMAGE.exact_fde(start + 1)

    def test_fde_sizes(self):
        sizes = {name: (end - start, count) for name, start, end, _, count in [(r[0], r[1], r[2], r[3], r[4]) for r in RESULT["targets"]]}
        self.assertEqual(sizes["perp gate"][0], 227)
        self.assertEqual(sizes["spot gate"][0], 705)


class Decision(unittest.TestCase):
    def test_five_paths_for_both_gates(self):
        rows = RESULT["paths"]
        self.assertEqual(len(rows), 10)
        spot = [row for row in rows if row[0] == "spot"]
        perp = [row for row in rows if row[0] == "perp"]
        self.assertEqual([row[3:] for row in spot], [row[3:] for row in perp])

    def test_a_flipped_branch_changes_the_paths(self):
        # the first jbe after ucomisd in the perp gate: 0x4488389
        patched = {0x4488389: 0x77}
        with self.assertRaises(tool.EvidenceError):
            tool.prove_paths(IMAGE, patched)

    def test_corrupt_conversion_constant_refuses(self):
        for va in (0x451210, 0x450170):
            clone = edited(IMAGE, {va + 7: byte_at(va + 7) ^ 1})
            with self.assertRaises(tool.EvidenceError):
                tool.check_conversion(clone, None, tool.CONVERT_START["perp"])
            with self.assertRaises(tool.EvidenceError):
                tool.check_conversion(clone, None, tool.CONVERT_START["spot"])

    def test_wrong_conversion_shape_refuses(self):
        with self.assertRaises(tool.EvidenceError):
            tool.check_conversion(IMAGE, {tool.CONVERT_START["perp"] + 0x10: 0x90}, tool.CONVERT_START["perp"])

    def test_walk_refuses_an_unmodelled_instruction(self):
        walker = tool.Walker(IMAGE, {0x4488367: 0x90})
        walker.out, walker.start = tool.RBX, {0: "A", 2: "B"}
        with self.assertRaises(tool.EvidenceError):
            walker.paths(0x4488367, tool.JOIN["perp"])


class Specification(unittest.TestCase):
    def test_band_edges_of_the_text_example(self):
        # b = 100, p = 0.5: 50 refused, 51 admitted, 200 admitted, 201 refused
        self.assertFalse(tool.band_admits(50, 100, 0.5))
        self.assertTrue(tool.band_admits(51, 100, 0.5))
        self.assertTrue(tool.band_admits(200, 100, 0.5))
        self.assertFalse(tool.band_admits(201, 100, 0.5))

    def test_named_cases_match(self):
        for name, case in tool.named_cases():
            self.assertEqual(HARNESS.run_case(case), tool.spec(case), name)

    def test_outcome_words(self):
        got = HARNESS.run_case(tool.Case(a=5, first="single_hit", second="single_hit"))
        self.assertEqual(got[:3], ("tag", tool.TAG_OK, None))
        got = HARNESS.run_case(tool.Case(a=tool.CAP + 1, first="single_hit", second="single_hit"))
        self.assertEqual(got[:3], ("tag", tool.TAG_LARGE, None))
        got = HARNESS.run_case(tool.Case(tree="leaf_hit"))
        self.assertEqual(got[:3], ("tag", tool.TAG_INVALID, None))
        got = HARNESS.run_case(tool.Case(a=301, b=100, p=0.5))
        self.assertEqual(got[:2], ("tag", tool.TAG_BAND))
        self.assertEqual(tool.to_float(got[2]), 50.0)

    def test_cap_is_one_hundred_million_less_one_thousand(self):
        self.assertEqual(tool.CAP, 10 ** 8 - 1000)
        data = bytes(IMAGE.blob[IMAGE.offset(0x3C0FAAA):IMAGE.offset(0x3C0FAAA) + 7])
        self.assertEqual(data, bytes.fromhex("4981f818ddf505"))

    def test_chain_cases_match(self):
        for case in tool.chain_cases()[::5]:
            self.assertEqual(HARNESS.run_case(case), tool.spec(case), vars(case))

    def test_grid_matches(self):
        for case in tool.grid_cases(tool.GRID_U64[::8], tool.GRID_P[::3]):
            self.assertEqual(HARNESS.run_case(case), tool.spec(case), vars(case))

    def test_random_cases_match(self):
        for case in tool.random_cases(150, seed=7):
            self.assertEqual(HARNESS.run_case(case), tool.spec(case), vars(case))

    def test_band_edges_hold_on_real_bytes(self):
        for b, p in ((100, 0.5), (10 ** 8, 0.8), (2 ** 53 + 2, 0.95)):
            first, last = tool.band_edges(b, p)
            for kind in ("spot", "perp"):
                for a, want in ((first - 1, tool.TAG_BAND), (first, tool.TAG_OK), (last, tool.TAG_OK), (last + 1, tool.TAG_BAND)):
                    if 0 <= a <= tool.MASK[8]:
                        self.assertEqual(HARNESS.run_case(tool.Case(kind=kind, a=a, b=b, p=p))[1], want)


class WrongImplementations(unittest.TestCase):
    """Wrong specifications must be caught by the real bytes."""

    def mismatches(self, wrong, cases):
        return sum(1 for case in cases if HARNESS.run_case(case) != wrong(case))

    def cases(self):
        return [case for _, case in tool.named_cases()] + [case for _, case in tool.cap_sets()] + tool.chain_cases()[::9] + tool.grid_cases(tool.GRID_U64[::6], tool.GRID_P[::3])

    def with_patch(self, **names):
        saved = {name: getattr(tool, name) for name in names}
        for name, value in names.items():
            setattr(tool, name, value)
        try:
            return self.mismatches(tool.spec, self.cases())
        finally:
            for name, value in saved.items():
                setattr(tool, name, value)

    def test_cap_off_by_one(self):
        self.assertGreater(self.with_patch(CAP=tool.CAP + 1), 0)
        self.assertGreater(self.with_patch(CAP=tool.CAP - 1), 0)

    def test_scale_not_one_hundred(self):
        self.assertGreater(self.with_patch(SCALE=10.0), 0)

    def test_closed_lower_edge(self):
        original = tool.band_admits

        def closed(a, b, p):
            return abs(tool.band_ratio(a, b)) <= p or original(a, b, p)

        saved = tool.band_admits
        tool.band_admits = closed
        try:
            self.assertGreater(self.mismatches(tool.spec, self.cases()), 0)
        finally:
            tool.band_admits = saved

    def test_exclusive_upper_edge(self):
        def exclusive(a, b, p):
            ratio = tool.band_ratio(a, b)
            if abs(ratio) < p:
                return True
            return p < 1.0 and ratio > 0.0 and 1.0 / (1.0 - p) - 1.0 > ratio

        saved = tool.band_admits
        tool.band_admits = exclusive
        try:
            self.assertGreater(self.mismatches(tool.spec, self.cases()), 0)
        finally:
            tool.band_admits = saved

    def test_side_dependent_band(self):
        def sided(a, b, p):
            return abs(tool.band_ratio(a, b)) < p

        saved = tool.band_admits
        tool.band_admits = sided
        try:
            self.assertGreater(self.mismatches(tool.spec, self.cases()), 0)
        finally:
            tool.band_admits = saved

    def test_tag_swap(self):
        self.assertGreater(self.with_patch(TAG_INVALID=tool.TAG_LARGE), 0)

    def test_ignoring_the_tree_set(self):
        def wrong(case):
            clean = copy.copy(case)
            clean.tree = "none"
            return tool.spec(clean)

        self.assertGreater(self.mismatches(wrong, self.cases()), 0)

    def test_ignoring_the_second_map(self):
        def wrong(case):
            clean = copy.copy(case)
            if clean.kind == "spot" and clean.first != "none":
                clean.second = "single_hit"
            return tool.spec(clean)

        self.assertGreater(self.mismatches(wrong, self.cases()), 0)

    def test_perp_exempt_on_any_bits(self):
        def wrong(case):
            clean = copy.copy(case)
            if clean.kind == "perp" and clean.exempt:
                clean.exempt = 0xFF
            return tool.spec(clean)

        self.assertGreater(self.mismatches(wrong, self.cases()), 0)
        case = tool.Case(kind="perp", exempt=0x100, a=10 ** 9, b=1, p=0.2)
        self.assertEqual(HARNESS.run_case(case)[1], tool.TAG_BAND)


class Mutants(unittest.TestCase):
    """Edited bytes of the gates must make the real-bytes comparison fail."""

    def killed(self, patch):
        harness = tool.Harness(IMAGE, patch)
        harness.machine.step_limit = tool.MUTANT_STEP_LIMIT
        sets = tool.named_cases() + [("chain", case) for case in tool.chain_cases()[::11]] + [("grid", case) for case in tool.grid_cases(tool.GRID_U64[::6], tool.GRID_P[::3])]
        return tool.first_failure(harness, sets) is not None

    def test_cap_immediate(self):
        self.assertTrue(self.killed({0x3C0FAAD: byte_at(0x3C0FAAD) ^ 1}))

    def test_branch_conditions(self):
        for va in (0x3C0FA05, 0x3C0FA1D, 0x3C0FA27, 0x3C0FA41, 0x4488389, 0x44883CD):
            row = tool.decode(HARNESS.machine.read_code, va)
            self.assertEqual(row.op, "jcc")
            at = row.size - 5 if row.size >= 6 else 0
            self.assertTrue(self.killed({va + at: byte_at(va + at) ^ 1}), hex(va))

    def test_tag_immediates(self):
        for va in (0x3C0FA4B, 0x44883D7):
            self.assertTrue(self.killed({va + 3: byte_at(va + 3) ^ 1}), hex(va))

    def test_tree_displacement(self):
        # flip the key displacement of the first B-tree compare
        self.assertTrue(self.killed({0x3C0F8A8: byte_at(0x3C0F8A8) ^ 8}))

    def test_unedited_bytes_pass(self):
        self.assertFalse(self.killed({}))


class Details(unittest.TestCase):
    def test_result_word(self):
        self.assertEqual(tool.result_word(("tag", 0x1A2, None, ())), "0x1a2")
        self.assertEqual(tool.result_word(("tag", 0x63, 0x4049000000000000, ())), "0x63 0x4049000000000000")
        self.assertEqual(tool.result_word(("panic", 0x6493B30, (3, 3), ())), "panic 0x6493b30 3 3")

    def test_recorder_digest_depends_on_every_field(self):
        case = tool.Case()
        got = HARNESS.run_case(case)
        first = tool.Recorder()
        first(case, got)
        second = tool.Recorder()
        second(tool.Case(a=101), got)
        self.assertNotEqual(first.digest.hexdigest(), second.digest.hexdigest())
        third = tool.Recorder()
        third(case, ("tag", 0x100, None, ()))
        self.assertNotEqual(first.digest.hexdigest(), third.digest.hexdigest())

    def test_compact_text_stops_at_zero(self):
        self.assertEqual(tool.compact_text(IMAGE, 0x435CCF).count("{}"), 1)

    def test_case_rejects_unknown_fields(self):
        with self.assertRaises(ValueError):
            tool.Case(unknown=1)

    def test_tree_kinds_cover_every_search_exit(self):
        seen = set()
        for tree in tool.TREES:
            got = HARNESS.run_case(tool.Case(tree=tree, first="single_hit", second="single_hit", a=5))
            seen.add((tree, got[1]))
        hits = {tree for tree, tag in seen if tag == tool.TAG_INVALID}
        self.assertEqual(hits, {"root_hit", "leaf_hit", "deep_hit"})

    def test_first_map_kinds_split_band_and_chain(self):
        outcomes = {}
        for first in tool.FIRSTS:
            outcomes[first] = HARNESS.run_case(tool.Case(first=first, second="single_hit", a=5, b=1, p=0.2))[:2]
        self.assertEqual(outcomes["none"][1], tool.TAG_BAND)
        self.assertEqual(outcomes["single_miss"][1], tool.TAG_BAND)
        self.assertEqual(outcomes["multi_miss"][1], tool.TAG_BAND)
        self.assertEqual(outcomes["single_hit"][1], tool.TAG_OK)
        self.assertEqual(outcomes["multi_oob"][0], "panic")

    def test_second_map_kinds_end_in_invalid_or_cap(self):
        for second in tool.SECONDS:
            got = HARNESS.run_case(tool.Case(first="single_hit", second=second, a=5))
            if second in ("single_hit", "multi_hit"):
                self.assertEqual(got[1], tool.TAG_OK)
            elif second == "multi_oob":
                self.assertEqual(got[0], "panic")
            else:
                self.assertEqual(got[1], tool.TAG_INVALID)

    def test_hash_arguments_are_checked(self):
        harness = tool.Harness(IMAGE)
        case = tool.Case(first="multi_hit", second="multi_hit", a=5)
        harness.prepare(case)
        harness.machine.memory.write(tool.CONTEXT + tool.FIRST_HASHER, 8, 1)
        with self.assertRaises(tool.Halt):
            harness.machine.run(tool.SPOT_GATE, {tool.RDI: tool.OUT, tool.RSI: tool.CONTEXT, tool.RDX: 1, tool.R8: 5, tool.R9: 100, tool.RCX: 0})

    def test_wrong_exemption_argument_is_refused(self):
        harness = tool.Harness(IMAGE)
        harness.case = tool.Case(kind="perp", exempt=1)
        harness.machine.regs[tool.RDI] = 5
        with self.assertRaises(tool.Halt):
            harness.on_exempt(harness.machine)


class Census(unittest.TestCase):
    def test_tag_writes(self):
        self.assertIn("0x3c0fa4b", RESULT["tags"]["0x63"])
        self.assertIn("0x44883d7", RESULT["tags"]["0x63"])

    def test_display_texts(self):
        texts = {row[0]: row[3] for row in RESULT["display"]}
        self.assertEqual(texts[0x63], "Order price cannot be more than {}% away from the reference price")
        self.assertEqual(texts[0x100], "Price too large")
        self.assertEqual(texts[0x195], "Invalid spot")

    def test_callers_are_listed(self):
        gates = {row[0] for row in RESULT["calls"]}
        self.assertEqual(gates, {"spot", "perp"})

    def test_panic_records(self):
        rows = {row[0]: row for row in RESULT["panics"]}
        self.assertEqual(rows["meta bound"][2:], (19, 590, 25))
        self.assertEqual(rows["map index"][2:], (57, 762, 26))


class Evidence(unittest.TestCase):
    def test_folder_matches_regeneration(self):
        self.assertTrue(FOLDER.exists(), "evidence folder is missing")
        files = tool.render(tool.analyse(IMAGE, full=False, vectors=3000))
        for name in ("targets.tsv", "paths.tsv", "callers.tsv", "status-texts.tsv", "panic-records.tsv", "band-edges.tsv", "outcomes.tsv", "chain-runs.tsv", "edge-runs.tsv", "grid-runs.tsv"):
            self.assertEqual((FOLDER / name).read_text(), files[name], name)

    def test_measure_file_is_consistent(self):
        measure = json.loads((FOLDER / "measure.json").read_text())
        self.assertGreaterEqual(measure["cases"], 10000)
        self.assertEqual(measure["negative_controls"], measure["negative_detected"])
        evidence = json.loads((FOLDER / "evidence.json").read_text())
        self.assertEqual(evidence["sha256"], tool.SHA256)
        self.assertEqual(len(evidence["run_digest"]), 64)


if __name__ == "__main__":
    unittest.main()
