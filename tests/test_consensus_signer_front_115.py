import hashlib
import json
import pathlib
import struct
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import consensus_signer_front_115 as tool  # noqa: E402

WORK = ROOT / "research" / "work-items" / "RE-008-signed-message-admission-115"
KILLED_ROWS = {
    # row VAs the packet run killed with a one-bit edit; the test makes the same edit again and wants a mismatch
    tool.FRONT: (0x57E89CF, 0x57E89A6, 0x57E8A23, 0x57E8A73, 0x57E8A8B),
    tool.SIGNER: (0x57E8BE6, 0x57E8BF3, 0x57E8C43, 0x57E8C73),
    tool.RING: (0x57F54F6, 0x57F5504, 0x57F5514, 0x57F553A, 0x57F5545),
    tool.WRAP_BLOCK: (0x27868CE, 0x27868FE, 0x2786913, 0x2786915),
    tool.WRAP_TV: (0x2786A53, 0x2786B14, 0x2786B73, 0x2786B79),
}


class Fixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image()

    def run_cases(self, entry, count, flaws=(), run=None):
        run = run or tool.Run(self.image)
        bad = 0
        for index in range(count):
            got, want = tool.execute(run, tool.make_case(entry, index), flaws=flaws)
            bad += got != want
        return bad


class ImageControls(Fixture):
    def test_digest_is_pinned(self):
        self.assertEqual(hashlib.sha256(self.image.blob).hexdigest(), tool.SHA256)
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(tool.BINARY, "0" * 64)

    def test_function_bounds_are_fde_bounds(self):
        for function, (_, _, _) in tool.SCOPE.items():
            low, high = self.image.exact_fde(function)
            self.assertEqual(low, function)
            rows = tool.decode_range(self.image, low, high)
            self.assertEqual(rows[-1].next, high)

    def test_not_an_fde_start_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            self.image.exact_fde(tool.FRONT + 1)
        with self.assertRaises(tool.EvidenceError):
            self.image.fde(0x100)
        with self.assertRaises(tool.EvidenceError):
            self.image.offset(0x10)

    def test_every_rule_row_matches_and_a_moved_rule_is_refused(self):
        for rule in tool.RULES:
            tool.check_rule(self.image, rule)
            with self.assertRaises(tool.EvidenceError):
                tool.check_rule(self.image, (rule[0], rule[1] + 1) + rule[2:])
            wrong = rule[3] ^ 2 if isinstance(rule[3], int) else "mov"
            with self.assertRaises(tool.EvidenceError):
                tool.check_rule(self.image, rule[:3] + (wrong,) + rule[4:])

    def test_rule_outside_function_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.check_rule(self.image, (tool.FRONT, tool.SIGNER + 4, "op", "mov", "x"))

    def test_slot_targets_come_from_relocations(self):
        relative = self.image.relative()
        self.assertEqual(relative[tool.SLOT_STAKES], 0x595E5C0)
        self.assertEqual(relative[tool.SLOT_SIGNER], tool.SIGNER)
        self.assertEqual(relative[tool.SLOT_VERIFY], 0x59D6B80)


class Models(unittest.TestCase):
    def test_tree_walk_matches_membership_on_sorted_trees(self):
        stream = tool.Stream(5)
        for count in (1, 5, 11, 12, 30, 143, 144, 400):
            keys = tool.universe(count, stream)
            root = tool.build_tree(keys, tool.tree_height_for(count), stream)
            for key in keys[::7] + [tool.addr_of(1), bytes([255]) * 20]:
                self.assertEqual(tool.tree_contains(root, tool.tree_height_for(count), key), key in keys)

    def test_ring_search_matches_membership_on_sorted_rows(self):
        stream = tool.Stream(9)
        for cap, head, length in tool.RING_SHAPES:
            keys = tool.universe(length, stream)
            rows = [key + bytes(12) for key in keys]
            for key in keys + [tool.addr_of(1), bytes([255]) * 20]:
                found, index = tool.ring_search(rows, head, cap, key)
                self.assertEqual(found, key in keys)
                if found:
                    self.assertEqual(rows[index][:20], key)

    def test_ring_search_flaw_changes_an_unsorted_answer(self):
        rows = [tool.addr_of(v) + bytes(12) for v in (5, 1, 9, 3, 7, 2, 8)]
        seen = set()
        for key in rows:
            seen.add(tool.ring_search(rows, 0, 8, key[:20]) != tool.ring_search(rows, 0, 8, key[:20], ("ring_ge_moves",)))
        self.assertIn(True, seen)

    def test_digest_contract_depends_on_variant_and_content(self):
        self.assertNotEqual(tool.digest_of(0, b"a"), tool.digest_of(2, b"a"))
        self.assertNotEqual(tool.digest_of(2, b"a"), tool.digest_of(2, b"b"))

    def test_round_selection_rule(self):
        base = {"rounds": (1, 2, 3)}
        self.assertEqual(tool.block_round(dict(base, a=tool.SENT, b=0)), 1)
        self.assertEqual(tool.block_round(dict(base, a=7, b=tool.SENT)), 2)
        self.assertEqual(tool.block_round(dict(base, a=7, b=9)), 3)

    def test_case_generation_is_deterministic(self):
        for entry in tool.COUNTS:
            a, b = tool.make_case(entry, 17), tool.make_case(entry, 17)
            self.assertEqual(a["addr"], b["addr"])
            self.assertEqual(a["plan"], b["plan"])


class RealBytes(Fixture):
    def test_every_entry_matches_the_rule_list(self):
        run = tool.Run(self.image)
        for entry in tool.COUNTS:
            self.assertEqual(self.run_cases(entry, 160, run=run), 0, entry)

    def test_deeper_cases_match(self):
        run = tool.Run(self.image)
        for entry in tool.COUNTS:
            for index in range(1000, 1060):
                got, want = tool.execute(run, tool.make_case(entry, index))
                self.assertEqual(got, want, (entry, index))

    def test_classes_are_all_reached(self):
        run = tool.Run(self.image)
        seen = set()
        for entry in ("front", "wrap_block", "wrap_tv", "signer", "ring"):
            for index in range(600):
                c = tool.make_case(entry, index)
                got, _ = tool.execute(run, c)
                seen.add((entry, tool.classify(c, got)))
        for expected in (("front", "admitted"), ("front", "stakes_error"), ("front", "signer_not_in_set"), ("front", "recover_error"),
                         ("wrap_block", "verify_error"), ("wrap_tv", "pair_mismatch"), ("wrap_tv", "round_order"), ("wrap_tv", "admitted"),
                         ("signer", "match"), ("ring", "found_wrapped"), ("ring", "absent_straight")):
            self.assertIn(expected, seen)

    def test_success_moves_the_block_and_skips_the_drops(self):
        run = tool.Run(self.image)
        for index in range(400):
            c = tool.make_case("wrap_block", index)
            got, want = tool.execute(run, c)
            if tool.classify(c, got) == "admitted":
                self.assertEqual(got[1][:tool.BLOCK_SIZE], c["block"]["bytes"])
                self.assertNotIn("drop_cert", [e[0] for e in got[2]])
                self.assertNotIn("free", [e[0] for e in got[2]])
                return
        self.fail("no admitted block case")

    def test_alloc_failure_stops_at_the_handler(self):
        run = tool.Run(self.image)
        for index in range(1200):
            c = tool.make_case("wrap_tv", index)
            if c.get("fail_at") and c["plan"]["stakes"][0] == tool.OK_TAG:
                got, want = tool.execute(run, c)
                self.assertEqual(got[0], "panic")
                self.assertEqual(got[2][-1], ("alloc_error", 8, 0x38))
                return
        self.fail("no allocation failure case")


class NegativeControls(Fixture):
    def test_every_model_flaw_is_detected_by_the_bytes(self):
        run = tool.Run(self.image)
        for flaw, entries in tool.FLAWS:
            found = False
            for entry in entries:
                for index in range(700):
                    got, want = tool.execute(run, tool.make_case(entry, index), flaws=(flaw,))
                    if got != want:
                        found = True
                        break
                if found:
                    break
            self.assertTrue(found, flaw)

    def test_flipped_condition_bytes_are_killed(self):
        for function, sites in KILLED_ROWS.items():
            low, high = self.image.exact_fde(function)
            rows = {row.va: row for row in tool.decode_range(self.image, low, high)}
            picked = [tool.make_case(entry, index) for entry in tool.USES[function] for index in range(0, 400, 9)]
            for site in sites:
                row = rows[site]
                edits = dict((va, (kind, patch)) for va, kind, patch in tool.edits_for(self.image, [row]))
                self.assertIn(site, edits, hex(site))
                run = tool.Run(self.image, edits[site][1])
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
        run = tool.Run(self.image)
        detected = 0
        for which, (entry, label, make, allowed) in enumerate(tool.CORRUPTIONS):
            hit = 0
            for index in range(300):
                c = tool.make_case(entry, index)
                clean, _ = tool.execute(run, c)
                if tool.classify(c, clean) not in allowed:
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
            detected += hit
        self.assertEqual(detected, len(tool.CORRUPTIONS))

    def test_unmodified_bytes_are_not_flagged(self):
        run = tool.Run(self.image)
        for entry in tool.COUNTS:
            self.assertEqual(self.run_cases(entry, 40, run=run), 0)

    def test_ring_with_a_wrong_head_word_is_flagged(self):
        run = tool.Run(self.image)
        flagged = 0
        for index in range(120):
            c = tool.make_case("ring", index)
            ring = dict(c["set"])
            if len(ring["rows"]) < 3:
                continue
            c2 = dict(c, set=dict(ring, head=(ring["head"] + 1) % ring["cap"]))
            got, _ = tool.execute(run, c)
            got2, want2 = tool.execute(run, c2, after_prepare=lambda r, h=ring["head"]: r.memory.write(tool.SETOBJ_AT + 0x10, 8, h))
            flagged += got2 != want2
        self.assertGreater(flagged, 0)


class Evidence(unittest.TestCase):
    def test_measure_file_has_the_counts(self):
        path = WORK / "measure.json"
        if path.exists():
            data = json.loads(path.read_text())
            self.assertGreaterEqual(data["cases"], 10000)
            self.assertEqual(data["negative_detected"], data["negative_controls"])
            self.assertEqual(data["mismatches"], 0)
        self.assertEqual(sum(tool.COUNTS.values()), 14400)

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
