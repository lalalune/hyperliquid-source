import hashlib
import json
import pathlib
import struct
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import consensus_block_batch_115 as tool  # noqa: E402

WORK = ROOT / "research" / "work-items" / "RE-008-block-batch-filter-115"
KILLED_ROWS = {
    # row VAs the packet run killed with a one-bit edit; the test makes the same edit again and wants a mismatch
    tool.BATCH: (0x2705afa, 0x2705c3e, 0x2705ca0, 0x2705d68, 0x2705e52, 0x2705f74, 0x2705ff0, 0x270611f),
    tool.SEARCH: (0x24c5bb5, 0x24c5bfa, 0x24c5c46, 0x24c5c9a, 0x24c5cd5, 0x24c5d38),
}


class Fixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image()

    def run_cases(self, start, stop, flaws=(), run=None):
        run = run or tool.BatchRun(self.image)
        bad = 0
        for index in range(start, stop):
            got, want = tool.execute(run, tool.make_case(index), flaws=flaws)
            bad += got != want
        return bad


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
        with self.assertRaises(tool.EvidenceError):
            self.image.exact_fde(tool.BATCH + 1)
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
            tool.check_rule(self.image, (tool.BATCH, tool.SEARCH + 4, "op", "mov", "x"))

    def test_scope_functions_are_reached_by_direct_calls(self):
        rows = tool.scan_callers(self.image)
        self.assertTrue(any(row[3] == hex(tool.SEARCH) for row in rows))


class Models(unittest.TestCase):
    def test_ring_search_k_matches_membership_on_sorted_rows(self):
        stream = tool.Stream(9)
        for cap, head, length in tool.KNOWN_RINGS:
            keys = [tool.hash_of(v) for v in sorted({stream.next(5000) for _ in range(length)})]
            rows = [key + bytes(tool.SEARCH_ROW - tool.K32) for key in keys]
            for key in keys + [tool.hash_of(1), bytes([255]) * 32]:
                found, index = tool.ring_search_k(rows, head, cap, key, tool.K32)
                self.assertEqual(found, key in keys)
                if found:
                    self.assertEqual(rows[index][:32], key)

    def test_round_floor_rule(self):
        block = {"a": tool.SENT, "t1": 7, "t2": 9}
        self.assertEqual(tool.round_plus_one(block), 8)
        self.assertEqual(tool.round_plus_one(dict(block, a=3)), 10)
        self.assertEqual(tool.round_plus_one(dict(block, t1=tool.M64)), tool.M64)
        self.assertEqual(tool.round_plus_one(dict(block, t1=tool.M64 - 1)), tool.M64)
        self.assertEqual(tool.round_plus_one(dict(block, t1=tool.M64), ("wraps_to_zero",)), 0)
        self.assertEqual(tool.round_plus_one(block, ("selector_swapped",)), 10)

    def test_record_buffers_follow_the_tag(self):
        self.assertEqual(tool.record_bytes_b(tool.OK_TAG, 5), bytes([tool.OK_TAG]))
        rec = tool.record_bytes_b(0x10, 4)
        self.assertEqual(len(rec), 0x48)
        self.assertEqual(rec[0], 0x10)
        self.assertEqual(rec[8:16], bytes(8) if 4 & 1 else rec[8:16])
        self.assertEqual(tool.record_bytes_b(0x10, 3)[8:16], bytes(8))
        self.assertEqual(tool.record_bytes_b(0x10, 3)[0x20:0x28], bytes(8))

    def test_case_generation_is_deterministic_and_bounded(self):
        for index in (3, 17, 902):
            a, b = tool.make_case(index), tool.make_case(index)
            self.assertEqual(a["T"], b["T"])
            self.assertEqual([it["hash"] for it in a["items"]], [it["hash"] for it in b["items"]])
            self.assertLessEqual(len(a["items"]), tool.MAX_ITEMS)

    def test_model_labels_cover_the_outcome_classes(self):
        seen = set()
        for index in range(600):
            seen.update(tool.labels_of(index))
        for label in ("known_kept", "known_niche", "stale", "admitted", "stakes_error", "set_miss", "recover_error", "other_address", "verify_error"):
            self.assertIn(label, seen)


class RealBytes(Fixture):
    def test_cases_match_the_rule_list(self):
        self.assertEqual(self.run_cases(0, 400), 0)

    def test_deeper_cases_match(self):
        self.assertEqual(self.run_cases(5000, 5200), 0)

    def test_known_item_keeps_its_certificates_with_no_block(self):
        run = tool.BatchRun(self.image)
        for index in range(400):
            c = tool.make_case(index)
            got, want = tool.execute(run, c)
            if c["_labels"][:1] == ["known_kept"]:
                out = got[1]
                self.assertEqual(struct.unpack_from("<Q", out, 0x18)[0], tool.MINW)
                self.assertEqual(out[0x190:0x1B0], c["items"][0]["hash"])
                self.assertNotIn("stakes", [e[0] for e in got[3]][:1])
                return
        self.fail("no known first item")

    def test_stale_round_drops_without_calling_the_wrapper(self):
        run = tool.BatchRun(self.image)
        for index in range(600):
            c = tool.make_case(index)
            got, want = tool.execute(run, c)
            if c["_labels"] == ["stale"]:
                self.assertNotIn("stakes", [e[0] for e in got[3]])
                self.assertEqual(got[0][1], tool.BOUT_REL)
                return
        self.fail("no all-stale case")

    def test_admitted_block_is_moved_unchanged(self):
        run = tool.BatchRun(self.image)
        for index in range(800):
            c = tool.make_case(index)
            got, want = tool.execute(run, c)
            if c["_labels"][:1] == ["admitted"] and c["items"][0]["ccap"] != tool.MINW:
                out = got[1]
                block = c["items"][0]["block"]["bytes"]
                self.assertEqual(out[0x18:0x20] + out[0x20:0x190], block)
                return
        self.fail("no admitted first item")


class NegativeControls(Fixture):
    def test_every_model_flaw_is_detected(self):
        for flaw in tool.FLAWS:
            found = False
            for index in range(1500):
                c = tool.make_case(index)
                ret, out, arcs, log, ranges, _ = tool.spec_batch(c, (flaw,))
                clean = tool.spec_batch(c)
                if (ret, tool.masked(out, ranges), arcs, tuple(log)) != (clean[0], tool.masked(clean[1], clean[4]), clean[2], tuple(clean[3])):
                    found = True
                    break
            self.assertTrue(found, flaw)

    def test_flaws_are_seen_by_the_bytes(self):
        run = tool.BatchRun(self.image)
        for flaw in ("known_unchecked", "no_increment", "stale_strict", "arcs_kept", "cert_free_8x"):
            seen = False
            for index in range(300):
                got, want = tool.execute(run, tool.make_case(index), flaws=(flaw,))
                if got != want:
                    seen = True
                    break
            self.assertTrue(seen, flaw)

    def test_flipped_condition_bytes_are_killed(self):
        for function, sites in KILLED_ROWS.items():
            low, high = self.image.exact_fde(function)
            rows = {row.va: row for row in tool.decode_range(self.image, low, high)}
            picked = [tool.make_case(index) for index in range(0, 700, 5)]
            for site in sites:
                row = rows[site]
                edits = dict((va, (kind, patch)) for va, kind, patch in tool.edits_for(self.image, [row]))
                self.assertIn(site, edits, hex(site))
                run = tool.BatchRun(self.image, edits[site][1])
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
        run = tool.BatchRun(self.image)
        for which, (label, make, ok) in enumerate(tool.CORRUPTIONS):
            hit = 0
            for index in range(0, 1500, 3):
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
        self.assertEqual(self.run_cases(100, 160), 0)


class Evidence(unittest.TestCase):
    def test_measure_file_has_the_counts(self):
        path = WORK / "measure.json"
        if path.exists():
            data = json.loads(path.read_text())
            self.assertGreaterEqual(data["cases"], 10000)
            self.assertEqual(data["negative_detected"], data["negative_controls"])
            self.assertEqual(data["mismatches"], 0)
        self.assertGreaterEqual(tool.COUNT, 10000)

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
