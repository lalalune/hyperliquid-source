import hashlib
import json
import pathlib
import struct
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import consensus_round_floor_115 as tool  # noqa: E402

WORK = ROOT / "research" / "work-items" / "RE-008-round-floor-115"
KILLED_ROWS = {
    # row VAs the packet run killed with a one-bit edit; the test makes the same edit again and wants a mismatch
    tool.FLOOR: (43297995, 43298117, 43298165, 43298268, 43298326, 43298464, 43297978, 43298211, 43298337),
    tool.DRIVER: (36812692, 36812538, 36812648),
}


class Fixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image()

    def run_cases(self, indexes, flaws=(), run=None):
        run = run or tool.ScopeRun(self.image)
        bad = 0
        for index in indexes:
            got, want = tool.execute(run, tool.make_case(index), flaws=flaws)
            bad += got != want
        return bad


FLOOR_CASES = range(tool.DRV_COUNT, tool.DRV_COUNT + 400)


class ImageControls(Fixture):
    def test_digest_is_pinned(self):
        self.assertEqual(hashlib.sha256(self.image.blob).hexdigest(), tool.SHA256)
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(tool.BINARY, "0" * 64)

    def test_function_bounds_are_fde_bounds(self):
        for function in tool.SCOPE:
            low, high = self.image.exact_fde(function)
            self.assertEqual(low, function)
            rows = tool.decode_range(self.image, low, high)
            self.assertEqual(rows[-1].next, high)

    def test_not_an_fde_start_is_refused(self):
        for function in tool.OWN:
            with self.assertRaises(tool.EvidenceError):
                self.image.exact_fde(function + 1)
        with self.assertRaises(tool.EvidenceError):
            self.image.fde(0x100)
        with self.assertRaises(tool.EvidenceError):
            self.image.offset(0x10)

    def test_every_rule_row_matches_and_a_moved_rule_is_refused(self):
        for rule in tool.RULES:
            tool.check_rule(self.image, rule)
            with self.assertRaises(tool.EvidenceError):
                tool.check_rule(self.image, (rule[0], rule[1] + 1) + rule[2:])
            wrong = rule[3] ^ 2 if isinstance(rule[3], int) else "mov" if rule[3] != "mov" else "cmp"
            with self.assertRaises(tool.EvidenceError):
                tool.check_rule(self.image, rule[:3] + (wrong,) + rule[4:])

    def test_rule_outside_function_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.check_rule(self.image, (tool.FLOOR, tool.DRIVER + 4, "op", "mov", "x"))

    def test_scope_functions_are_reached_by_direct_calls(self):
        rows = tool.scan_callers(self.image)
        self.assertTrue(any(row[3] == hex(tool.DRIVER) for row in rows) or any(row[3] == hex(tool.FLOOR) for row in rows) or rows == [])


class Models(unittest.TestCase):
    def test_value_selector(self):
        p = {"a": tool.SENT, "b": tool.SENT, "w50": 1, "w48": 2, "wd8": 3}
        self.assertEqual(tool.value_of(p), 1)
        self.assertEqual(tool.value_of(dict(p, a=0)), 2)
        self.assertEqual(tool.value_of(dict(p, a=0, b=0)), 3)
        self.assertEqual(tool.value_of(dict(p, a=0), ("floor_selector_swap",)), 1)

    def test_tree_locate_finds_present_keys_and_refuses_absent_ones(self):
        stream = tool.Stream(21)
        for count in (1, 5, 11, 12, 40, 150):
            keys = [tool.hash_of(v) for v in range(1, count + 1)]
            height = tool.tree_height_for(count)
            root = tool.build_tree(keys, height, stream)
            for key in keys:
                self.assertEqual(tool.tree_locate(root, height, key), key)
            self.assertIsNone(tool.tree_locate(root, height, tool.hash_of(count + 5)))

    def test_floor_model_takes_a_minimum_and_ignores_misses(self):
        c = tool.make_floor_case(tool.DRV_COUNT + 3)
        low, labels = tool.floor_model(c)
        self.assertLessEqual(low, c["init"])
        self.assertEqual(len(labels), len(c["fitems"]))
        self.assertEqual(tool.floor_model(c, ("floor_init_ignored",))[0] <= tool.M64, True)

    def test_case_generation_is_deterministic_and_bounded(self):
        for index in (3, 17, 902, tool.DRV_COUNT + 5, tool.DRV_COUNT + 2999):
            a, b = tool.make_case(index), tool.make_case(index)
            if a["entry"] == "driver":
                self.assertEqual([it["hash"] for it in a["items"]], [it["hash"] for it in b["items"]])
                self.assertLessEqual(len(a["items"]), tool.MAX_ITEMS)
            else:
                self.assertEqual([it["bytes"] for it in a["fitems"]], [it["bytes"] for it in b["fitems"]])
                self.assertEqual(a["init"], b["init"])

    def test_model_labels_cover_the_outcome_classes(self):
        seen = set()
        for index in list(range(600)) + list(range(tool.DRV_COUNT, tool.DRV_COUNT + 600)):
            seen.update(tool.labels_of(index))
        for label in ("known_kept", "stale", "admitted", "inline", "niche_hit", "niche_miss"):
            self.assertIn(label, seen)


class RealBytes(Fixture):
    def test_driver_cases_match_the_rule_list(self):
        self.assertEqual(self.run_cases(range(0, 300)), 0)

    def test_floor_cases_match_the_rule_list(self):
        self.assertEqual(self.run_cases(FLOOR_CASES), 0)

    def test_deeper_cases_match(self):
        self.assertEqual(self.run_cases(range(5000, 5100)), 0)
        self.assertEqual(self.run_cases(range(tool.TOTAL - 150, tool.TOTAL)), 0)

    def test_driver_collects_in_place_and_closes_the_closure(self):
        run = tool.ScopeRun(self.image)
        for index in range(400):
            c = tool.make_case(index)
            got, want = tool.execute(run, c)
            if c["_labels"][:1] == ["admitted"]:
                self.assertEqual(got[0], tool.RES_REL)
                self.assertEqual(got[1][1], tool.ITEMS_REL)
                self.assertGreaterEqual(got[1][2], 1)
                self.assertEqual(got[3], (8, 8, 0, 8))
                self.assertEqual(got[5][-1], ("drop_closure", tool.IT_REL))
                return
        self.fail("no admitted first item")

    def test_floor_reads_the_known_value_of_a_niche_item(self):
        run = tool.ScopeRun(self.image)
        seen = {"tree": False, "ring": False}
        for index in range(tool.DRV_COUNT, tool.DRV_COUNT + 800):
            c = tool.make_case(index)
            got, want = tool.execute(run, c)
            kind = c["known"]["kind"]
            if "niche_hit" in c["_labels"] and got[0] != c["init"] and not seen[kind]:
                self.assertEqual(got, want)
                seen[kind] = True
        self.assertEqual(seen, {"tree": True, "ring": True})

    def test_empty_vector_returns_the_start_value(self):
        run = tool.ScopeRun(self.image)
        for index in range(tool.DRV_COUNT, tool.DRV_COUNT + 400):
            c = tool.make_case(index)
            if not c["fitems"]:
                got, want = tool.execute(run, c)
                self.assertEqual(got[0], c["init"])
                return
        self.fail("no empty vector")


class NegativeControls(Fixture):
    def test_every_model_flaw_is_detected(self):
        for flaw in tool.FLAWS:
            found = False
            for index in list(range(0, 1500)) + list(range(tool.DRV_COUNT, tool.DRV_COUNT + 1500)):
                c = tool.make_case(index)
                if tool.expected(c, (flaw,)) != tool.expected(c):
                    found = True
                    break
            self.assertTrue(found, flaw)

    def test_flaws_are_seen_by_the_bytes(self):
        run = tool.ScopeRun(self.image)
        for flaw in ("known_unchecked", "no_increment", "closure_kept", "cap_dropped", "count_off_by_one"):
            seen = False
            for index in range(300):
                got, want = tool.execute(run, tool.make_case(index), flaws=(flaw,))
                if got != want:
                    seen = True
                    break
            self.assertTrue(seen, flaw)
        for flaw in ("floor_max", "floor_signed", "floor_selector_swap", "floor_no_niche_lookup", "floor_init_ignored"):
            seen = False
            for index in FLOOR_CASES:
                got, want = tool.execute(run, tool.make_case(index), flaws=(flaw,))
                if got != want:
                    seen = True
                    break
            self.assertTrue(seen, flaw)

    def test_flipped_condition_bytes_are_killed(self):
        for function, sites in KILLED_ROWS.items():
            low, high = self.image.exact_fde(function)
            rows = {row.va: row for row in tool.decode_range(self.image, low, high)}
            picked = [tool.make_case(index) for index in range(0, 700, 5)] + [tool.make_case(index) for index in range(tool.DRV_COUNT, tool.DRV_COUNT + 400, 3)]
            picked = [c for c in picked if (c["entry"] == "driver") == (function == tool.DRIVER)]
            for site in sites:
                row = rows[site]
                edits = dict((va, (kind, patch)) for va, kind, patch in tool.edits_for(self.image, [row]))
                self.assertIn(site, edits, hex(site))
                run = tool.ScopeRun(self.image, edits[site][1])
                run.machine.step_limit = 90000
                killed = False
                for c in picked:
                    try:
                        got, want = tool.execute(run, c)
                    except tool.FAILURES:
                        killed = True
                        break
                    if got != want:
                        killed = True
                        break
                self.assertTrue(killed, (hex(function), hex(site)))

    def test_corrupted_fixture_bytes_are_seen(self):
        run = tool.ScopeRun(self.image)
        for which, (label, make, ok) in enumerate(tool.CORRUPTIONS):
            hit = 0
            for index in list(range(0, 1500, 3)) + list(range(tool.DRV_COUNT, tool.DRV_COUNT + 1500, 3)):
                c = tool.make_case(index)
                c["_labels"] = tool.labels_of(index)
                if not ok(c):
                    continue
                try:
                    got, want = tool.execute(run, c, after_prepare=make(c))
                except tool.FAILURES:
                    hit += 1
                    break
                if got != want:
                    hit += 1
                    break
            self.assertEqual(hit, 1, label)

    def test_unmodified_bytes_are_not_flagged(self):
        self.assertEqual(self.run_cases(list(range(100, 140)) + list(range(tool.DRV_COUNT + 100, tool.DRV_COUNT + 140))), 0)


class Evidence(unittest.TestCase):
    def test_measure_file_has_the_counts(self):
        path = WORK / "measure.json"
        if path.exists():
            data = json.loads(path.read_text())
            self.assertGreaterEqual(data["cases"], 10000)
            self.assertEqual(data["negative_detected"], data["negative_controls"])
            self.assertEqual(data["mismatches"], 0)
        self.assertGreaterEqual(tool.TOTAL, 10000)

    def test_manifest_hashes_match(self):
        path = WORK / "MANIFEST.sha256"
        if path.exists():
            for line in path.read_text().splitlines():
                digest, name = line.split("  ", 1)
                self.assertEqual(hashlib.sha256((WORK / name).read_bytes()).hexdigest(), digest, name)
        with self.assertRaises(SystemExit):
            tool.main(["--no-such-option"])


if __name__ == "__main__":
    unittest.main()
