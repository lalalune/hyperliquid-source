import hashlib
import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import re014_book_impact_walk_115 as walk  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-014-book-impact-walk-115"
IMAGE = walk.load_image()


def example(rows, arena, target, kind="deque", flag=0, count=None):
    case = {"label": "hand", "kind": kind, "rows": rows, "arena": arena,
            "count": len(arena) if count is None else count, "flag": flag, "target": target}
    if kind == "deque":
        case["cap"], case["head"] = len(rows) + 2, 1
    else:
        rng = walk.Rng(5)
        case["tree"] = walk.build_tree(len(rows), rng) if rows else (None, 0, [], [])
    return case


NEG = (-100) & walk.M64
TWO_LEVELS = [(NEG, 1, 0), (101, 1, 1)]
TWO_ARENA = [(1, 0, 99, 3), (1, 0, 99, 2)]


class SpecTests(unittest.TestCase):
    def test_worked_example(self):
        # 300 + a partial 101 -> notional 401 over fill 4 -> floor 100
        case = example(TWO_LEVELS, TWO_ARENA, 500)
        self.assertEqual(walk.spec_walk(case), {"ret": 100, "events": []})
        self.assertEqual(walk.spec_walk(dict(case, target=300)), {"ret": 100, "events": []})

    def test_exact_boundary_and_exhaustion(self):
        case = example(TWO_LEVELS, TWO_ARENA, 502)
        self.assertEqual(walk.spec_walk(case)["ret"], 100)  # 502 over fill 5, exact boundary
        self.assertEqual(walk.spec_walk(example(TWO_LEVELS, TWO_ARENA, 503))["ret"], 0)

    def test_flag_logs_only_on_bad_level(self):
        case = example([(5, 2, 0)], [(1, 0, 9, 4)], 10, flag=3)
        self.assertEqual(walk.spec_walk(case)["events"], [("slow", walk.FLAG_WORD, 1)])
        self.assertEqual(walk.spec_walk(dict(case, flag=0))["events"], [])


class ByteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.harness = walk.Harness(IMAGE)

    def test_worked_example_runs_real_bytes(self):
        for kind in ("deque", "btree"):
            case = example(TWO_LEVELS, TWO_ARENA, 500, kind)
            self.assertEqual(self.harness.run_walk(case), {"ret": 100, "events": []})

    def test_walk_cases_match(self):
        for index in range(0, 2400, 6):
            kind = "btree" if index % 2 else "deque"
            self.assertIsNone(walk.compare_walk(self.harness, walk.walk_case(index, kind)), index)

    def test_next_cases_match(self):
        for index in range(120):
            self.assertIsNone(walk.compare_next(self.harness, walk.next_case(index)), index)

    def test_scale_cases_match(self):
        for index in range(400):
            self.assertIsNone(walk.compare_scale(self.harness, walk.scale_case(index)), index)

    def test_function_bounds_are_fde_exact(self):
        self.assertEqual(IMAGE.exact_fde(walk.WALK), (0x46A6370, 0x46A685C))
        self.assertEqual(IMAGE.exact_fde(walk.SCALE), (0x46A6860, 0x46A69CF))
        self.assertEqual(IMAGE.exact_fde(walk.NEXT), (0x37C5DD0, 0x37C5FF4))

    def test_location_table(self):
        rows = walk.location_rows(IMAGE, self.harness)
        self.assertEqual(len(rows), 5)
        for name, slot, path, line, column in rows:
            self.assertFalse(path.startswith("/"), name)
            self.assertGreater(line, 0)


class NegativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.harness = walk.Harness(IMAGE)

    def test_wrong_reconstructions_are_caught(self):
        cases = [walk.walk_case(index, "btree" if index % 2 else "deque") for index in range(1500)]
        for variant in ("ge-to-gt", "ceil-div", "sat-wrap", "no-abs", "final-gt", "reverse-order", "count-le"):
            caught = any(walk.compare_walk(self.harness, case, (variant,)) for case in cases)
            self.assertTrue(caught, variant)

    def test_scale_and_next_variants_are_caught(self):
        scales = [walk.scale_case(index) for index in range(200)]
        self.assertTrue(any(walk.compare_scale(self.harness, case, ("mul-99",)) for case in scales))
        nexts = [walk.next_case(index) for index in range(60)]
        self.assertTrue(any(walk.compare_next(self.harness, case, ("next-stops-early",)) for case in nexts))

    def test_byte_damage_is_caught(self):
        machine = self.harness.machine
        cases = [walk.walk_case(index, "deque") for index in range(120)]
        rows = walk.decode_function(IMAGE, walk.WALK)
        target = next(row for row in rows if row.va == 0x46A6414 or row.op == "jcc" and row.va > 0x46A65C0)
        machine.patches = walk.eng.mutate_patch(IMAGE, target.va, target.size - (2 if target.size == 2 else 5))
        machine.cache.clear()
        machine.step_limit = 6000
        try:
            damaged = any(walk.compare_walk(self.harness, case) for case in cases)
        finally:
            machine.patches = {}
            machine.cache.clear()
            machine.step_limit = walk.eng.STEP_LIMIT
        self.assertTrue(damaged)

    def test_wrong_digest_and_addresses_are_refused(self):
        with self.assertRaises(walk.EvidenceError):
            walk.load_image(walk.BINARY, "0" * 64)
        with self.assertRaises(walk.EvidenceError):
            IMAGE.exact_fde(walk.WALK + 4)
        with self.assertRaises(walk.EvidenceError):
            IMAGE.offset(0x10)

    def test_damaged_case_changes_result(self):
        case = example(TWO_LEVELS, TWO_ARENA, 500)
        damaged = dict(case, rows=[(NEG ^ 0x10, 1, 0), (101, 1, 1)])
        self.assertNotEqual(self.harness.run_walk(damaged), walk.spec_walk(case))


class EvidenceTests(unittest.TestCase):
    def test_manifest_and_measure(self):
        manifest = FOLDER / "MANIFEST.sha256"
        if not manifest.exists():
            self.fail("evidence folder missing")
        for line in manifest.read_text().splitlines():
            digest, name = line.split("  ", 1)
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)
        measure = json.loads((FOLDER / "measure.json").read_text())
        self.assertEqual(measure["negative_controls"], measure["negative_detected"])
        self.assertGreaterEqual(measure["cases"], 10000)


if __name__ == "__main__":
    unittest.main()
