"""Tests for tools/commit_walk_path.py: rule list, byte pins and negative controls on corrupted copies."""

import json
import pathlib
import re
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import commit_walk_path as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-008-commit-walk-94"
Block, Tx, Case, chain = tool.Block, tool.Tx, tool.Case, tool.chain
DATE = tool.DATE


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image()
        cls.harness = tool.Harness(cls.image)

    def run_case(self, case):
        label, want = tool.spec_run(case)
        got = self.harness.run(case)
        self.assertEqual(tool.same(got, want), [], case.name)
        return label, got

    def corrupted(self, va, delta=1):
        blob = bytearray(self.image.blob)
        blob[self.image.offset(va)] ^= delta
        return tool.Image(bytes(blob))


class CommitRule(Base):
    def test_empty_map_does_nothing(self):
        label, got = self.run_case(Case("empty"))
        self.assertEqual(label, "no blocks")
        self.assertEqual(got["changed"], [])

    def test_two_chain_commits_the_block_two_under_the_tip_qc(self):
        label, got = self.run_case(Case("c", blocks=chain(100, 4)))
        self.assertEqual(label, "committed")
        self.assertEqual(got["watermark"], 101)
        row = got["out"][0][1]
        self.assertEqual((row["key"], row["round"]), (0x7010, 101))
        self.assertEqual(row["proof"]["child"], 0x7020)
        self.assertEqual(row["proof"]["qc_hash"], 0x7020)

    def test_gap_under_the_child_blocks_commit_and_prune(self):
        old = Tx(0x51, (DATE, 100, 0))
        blocks = [Block(0x6000, 100, 0x5000), Block(0x7000, 101, 0x6000), Block(0x7010, 103, 0x7000), Block(0x7020, 104, 0x7010)]
        label, got = self.run_case(Case("c", blocks=blocks, txs=[old]))
        self.assertEqual(label, "rounds not consecutive")
        self.assertEqual(got["tx_keys"], [0x51])
        self.assertEqual(got["watermark"], 100)

    def test_gap_above_the_child_does_not_block(self):
        blocks = [Block(0x7000, 100, 0x6000), Block(0x7010, 101, 0x7000), Block(0x7020, 102, 0x7010), Block(0x7030, 900, 0x7020)]
        self.assertEqual(self.run_case(Case("c", blocks=blocks))[0], "committed")

    def test_qc_round_is_not_read_by_the_rule(self):
        one = chain(100, 4)
        for row in one:
            row.qc_round = 12345
        self.assertEqual(self.run_case(Case("c", blocks=one))[0], "committed")

    def test_tie_uses_last_key(self):
        blocks = chain(100, 4) + [Block(0x7100, 103, 0x6100)]
        label, got = self.run_case(Case("c", blocks=blocks))
        self.assertTrue(label.startswith("tip parent missing"))
        self.assertEqual(got["watermark"], 100)

    def test_watermark_equal_only_prunes(self):
        label, got = self.run_case(Case("c", blocks=chain(100, 4), watermark=101))
        self.assertEqual(label, "nothing to commit, pruned")
        self.assertEqual(got["block_keys"], [0x7010, 0x7020, 0x7030])

    def test_start_under_watermark_touches_nothing(self):
        label, got = self.run_case(Case("c", blocks=chain(100, 4), watermark=102, txs=[Tx(0x51, (DATE, 100, 0))]))
        self.assertEqual(label, "walk passed the watermark")
        self.assertEqual(got["changed"], [])


class Walk(Base):
    def test_missing_tx_commits_nothing(self):
        blocks = chain(100, 5, hashes=[(), (0x51,), (0x52,), (), ()])
        label, got = self.run_case(Case("c", blocks=blocks, txs=[Tx(0x52)]))
        self.assertTrue(label.startswith("tx missing"))
        self.assertEqual(got["watermark"], 100)
        self.assertEqual(got["tx_keys"], [0x52])
        self.assertEqual(got["throttle"], {(100, 0x7010): (self.case_now(), 0, [1])})

    def case_now(self):
        return Case("n").now

    def test_missing_ancestor_uses_reason_two(self):
        label, got = self.run_case(Case("c", blocks=chain(103, 3, first=0x7020)))
        self.assertTrue(label.startswith("ancestor missing"))
        self.assertEqual(got["throttle"][(100, 0x7010)][2], [2])
        self.assertIn(("lazy",), got["trace"])

    def test_gap_in_the_walk_drops_the_proof(self):
        blocks = [Block(0x7000, 100, 0x6000), Block(0x7010, 101, 0x7000), Block(0x7020, 104, 0x7010), Block(0x7030, 105, 0x7020), Block(0x7040, 106, 0x7030)]
        _, got = self.run_case(Case("c", blocks=blocks))
        rows = [item[1] for item in got["out"]]
        self.assertEqual([row["round"] for row in rows], [101, 104])
        self.assertIsNone(rows[0]["proof"])
        self.assertIsNotNone(rows[1]["proof"])

    def test_records_are_oldest_first_and_log_is_newest_first(self):
        _, got = self.run_case(Case("c", blocks=chain(100, 6)))
        self.assertEqual([item[1]["round"] for item in got["out"]], [101, 102, 103])
        log = next(item for item in got["trace"] if item[0] == "committed")
        self.assertEqual(log[1], [0x7030, 0x7020, 0x7010])

    def test_walk_over_the_watermark_drops_all(self):
        blocks = [Block(0x7000, 99, 0x6000), Block(0x7010, 103, 0x7000), Block(0x7020, 104, 0x7010), Block(0x7030, 105, 0x7020)]
        label, got = self.run_case(Case("c", blocks=blocks))
        self.assertEqual(label, "walk passed the watermark")
        self.assertEqual(got["out"], [])


class Prune(Base):
    def test_tx_edge_of_20_seconds(self):
        now = (DATE, 40000, 500000000)
        keep, late = Tx(0x52, (DATE, 39980, 500000000)), Tx(0x51, (DATE, 39980, 499999999))
        _, got = self.run_case(Case("c", blocks=chain(100, 4), watermark=101, now=now, txs=[keep, late]))
        self.assertEqual(got["tx_keys"], [0x52])

    def test_midnight_goes_through_the_date(self):
        _, got = self.run_case(Case("c", blocks=chain(100, 4), watermark=101, now=(DATE + 16, 1, 0), txs=[Tx(0x51, (DATE, 86395, 0))]))
        self.assertEqual(got["tx_keys"], [0x51])

    def test_fork_at_committed_round_stays(self):
        _, got = self.run_case(Case("c", blocks=chain(100, 4) + [Block(0x7200, 101, 0x6000), Block(0x7210, 100, 0x6000)]))
        self.assertIn(0x7200, got["block_keys"])
        self.assertNotIn(0x7210, got["block_keys"])


class Throttle(Base):
    def blocks(self):
        return [Block(0x7000, 101, 0x6000)]

    def test_new_row_never_asks(self):
        label, got = self.run_case(Case("c", blocks=self.blocks()))
        self.assertTrue(label.endswith("no request"))
        self.assertEqual(got["out"], [])

    def test_exact_second_asks_once(self):
        row = {(100, 0x6000): ((DATE, 39999, 500000000), False, ())}
        label, got = self.run_case(Case("c", blocks=self.blocks(), throttle=row))
        self.assertTrue(label.endswith(", request"))
        self.assertEqual(got["out"], [("ask", 1, 100, 0x6000)])
        self.assertEqual(got["throttle"][(100, 0x6000)][1], 1)

    def test_sent_row_stays_silent(self):
        row = {(100, 0x6000): ((DATE, 100, 0), True, (0,))}
        self.assertEqual(self.run_case(Case("c", blocks=self.blocks(), throttle=row))[1]["out"], [])

    def test_new_committed_round_is_a_new_key(self):
        row = {(100, 0x6000): ((DATE, 100, 0), True, (0,))}
        _, got = self.run_case(Case("c", blocks=self.blocks(), watermark=120, throttle=row))
        self.assertIn((120, 0x6000), got["throttle"])


class Seen(Base):
    def test_limit_evicts_in_insert_order(self):
        blocks = chain(100, 4, hashes=[(), (0x51, 0x52), (), ()])
        _, got = self.run_case(Case("c", blocks=blocks, txs=[Tx(0x51), Tx(0x52)], seen={0x40: 1, 0x41: 1}, limit=3))
        self.assertEqual(got["deque"], [0x41, 0x51, 0x52])

    def test_constructor_limit_bytes(self):
        at = self.image.offset(0x44A8C82)
        self.assertEqual(struct.unpack_from("<I", self.image.blob, at + 8)[0], 100000)


class Controls(Base):
    def test_all_named_cases(self):
        rows = tool.check_all(self.harness, tool.named_cases())
        self.assertEqual(len(rows), len(tool.named_cases()))

    def test_vectors_reach_every_outcome_group(self):
        labels = {label for _, label, _ in tool.check_all(self.harness, tool.named_cases() + tool.vector_cases(120))}
        for _, _, _, _, label in tool.GATES:
            if label:
                self.assertTrue(any(name.startswith(label) for name in labels), label)

    def test_rule_list_is_sensitive(self):
        case = Case("c", blocks=chain(100, 4))
        _, want = tool.spec_run(case)
        want["watermark"] = 100
        self.assertEqual(tool.same(self.harness.run(case), want), ["watermark"])

    def test_edited_consecutive_check_is_caught(self):
        harness = tool.Harness(self.image, {0x44ABE9F + 1: self.image.blob[self.image.offset(0x44ABE9F + 1)] ^ 1})
        case = Case("c", blocks=chain(100, 4))
        self.assertIsNotNone(tool.first_failure(harness, [case]))

    def test_edited_twenty_seconds_halts(self):
        harness = tool.Harness(self.image, {0x489B6F7: 0x15})
        case = Case("c", blocks=chain(100, 4), watermark=101, txs=[Tx(0x51)])
        self.assertIsNotNone(tool.first_failure(harness, [case]))

    def test_digest_refuses_a_foreign_block(self):
        harness = tool.Harness(self.image)
        harness.set_state(Case("c", blocks=chain(100, 4)))
        harness.block_at.clear()
        with self.assertRaises(tool.Halt):
            harness.machine.run(tool.COMMIT, {tool.RDI: tool.STATE})

    def test_pin_negative(self):
        tool.check_pins(self.image)
        with self.assertRaises(tool.EvidenceError):
            tool.check_pins(self.corrupted(0x44ABE8F))

    def test_constant_negative(self):
        tool.check_constants(self.image)
        with self.assertRaises(tool.EvidenceError):
            tool.check_constants(self.corrupted(0x20A737))

    def test_string_negative(self):
        tool.check_strings(self.image)
        with self.assertRaises(tool.EvidenceError):
            tool.check_strings(self.corrupted(0x6F4DC5))

    def test_line_word_negative(self):
        rows = tool.check_locations(self.image)
        self.assertTrue(any(row[3] == 411 for row in rows))
        with self.assertRaises(tool.EvidenceError):
            tool.check_locations(self.corrupted(0x44ACB39))

    def test_call_sites_negative(self):
        self.assertEqual(tool.scan_triggers(self.image), [0x44AE320, 0x44B1802])
        with self.assertRaises(tool.EvidenceError):
            tool.scan_triggers(self.corrupted(0x44AE321))

    def test_wrong_digest_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "copy"
            path.write_bytes(b"not the binary")
            with self.assertRaises(tool.EvidenceError):
                tool.load_image(path)

    def test_address_outside_every_fde(self):
        with self.assertRaises(tool.EvidenceError):
            self.image.exact_fde(tool.COMMIT + 1)


class Evidence(unittest.TestCase):
    def test_manifest_matches(self):
        import hashlib
        rows = (FOLDER / "MANIFEST.sha256").read_text().split("\n")
        names = []
        for row in rows:
            if row:
                digest, name = row.split("  ")
                names.append(name)
                self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)
        self.assertEqual(sorted(names), sorted(path.name for path in FOLDER.iterdir() if path.name != "MANIFEST.sha256"))

    def test_generated_tables_rebuild_without_mutants(self):
        image = tool.load_image()
        files = tool.render(tool.analyse(image, mutate=False), image)
        for name, text in files.items():
            if name != "evidence.json":
                self.assertEqual((FOLDER / name).read_text(), text, name)
        summary = json.loads((FOLDER / "evidence.json").read_text())
        self.assertEqual(summary["sha256"], tool.SHA256)
        self.assertEqual(summary["mutations"]["total"], summary["mutations"]["killed"] + summary["mutations"]["survived"])

    def test_no_absolute_paths_in_evidence(self):
        for path in FOLDER.iterdir():
            self.assertIsNone(re.search("/(tmp|home|srv|mnt)/", path.read_text()), path.name)


if __name__ == "__main__":
    unittest.main()
