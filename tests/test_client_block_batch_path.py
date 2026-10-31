"""Tests for tools/client_block_batch_path.py: rule list, byte pins and negative controls on corrupted copies."""

import hashlib
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import client_block_batch_path as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-008-client-block-batch-94"
Case, Step, chain, steps_of, ok_block, proof_for = tool.Case, tool.Step, tool.chain, tool.steps_of, tool.ok_block, tool.proof_for
IMAGE = tool.load_image()


class Base(unittest.TestCase):
    image = IMAGE
    harness = tool.Harness(IMAGE)

    def run_case(self, case):
        label, want = tool.spec_run(case)
        got = self.harness.run(case)
        self.assertEqual(tool.same(got, want), [], case.name)
        return label, got

    def corrupted(self, va, delta=1):
        blob = bytearray(self.image.blob)
        blob[self.image.offset(va)] ^= delta
        return tool.Image(bytes(blob))

    def proof_case(self, **edit):
        block = ok_block()
        block.child = proof_for(block, **edit)
        return Case("c", steps_of([block]))


class Gate(Base):
    def test_old_block_is_dropped_with_success(self):
        label, got = self.run_case(Case("c", steps_of([ok_block(qc_round=999)]), bootstrapped=True))
        self.assertEqual(label, "old block")
        self.assertEqual(got["last_recv"], 1000)
        self.assertIn(("log", tool.LOG_OLD_BLOCK), got["trace"])

    def test_equal_round_sets_bootstrapped(self):
        _, got = self.run_case(Case("c", steps_of(chain(1, proof=False))))
        self.assertEqual(got["bootstrapped"], 1)
        self.assertEqual(got["pending"], [0xB1])

    def test_gap_depends_on_bootstrapped(self):
        block = ok_block(qc_round=1005)
        self.assertEqual(self.run_case(Case("c", steps_of([block]), bootstrapped=True))[0], "gap after start")
        label, got = self.run_case(Case("c", steps_of([block])))
        self.assertEqual(label, "bootstrap")
        self.assertEqual(got["results"], [("bootstrap", 1001, 1005)])
        self.assertEqual(got["bootstrapped"], 0)

    def test_old_rule_reads_the_qc_round_not_the_block_round(self):
        block = ok_block(round=5000, qc_round=999)
        self.assertEqual(self.run_case(Case("c", steps_of([block]), bootstrapped=True))[0], "old block")


class Join(Base):
    tx = {tool.HASH_A: tool.TX_A, tool.HASH_B: tool.TX_B}

    def test_rows_from_the_local_map(self):
        block = ok_block()
        block.child = proof_for(block)
        label, got = self.run_case(Case("c", [Step(block)], tx_map=dict(self.tx)))
        self.assertEqual(label, "flushed")
        self.assertEqual(got["tx_strong"], {key: 2 for key in sorted(self.tx)})

    def test_first_missing_hash_is_named_and_rows_are_returned(self):
        block = ok_block(hashes=[tool.HASH_A, 0x4321, 0x5555])
        _, got = self.run_case(Case("c", [Step(block)], tx_map=dict(self.tx)))
        self.assertEqual(got["results"], [("err", 0x1C, 0x4321)])
        self.assertEqual(set(got["tx_strong"].values()), {1})

    def test_map_bytes_still_face_the_tx_hash_rule(self):
        block = ok_block(hashes=[tool.HASH_A])
        block.child = proof_for(block)
        self.assertEqual(self.run_case(Case("c", [Step(block)], tx_map={tool.HASH_A: b"other"}))[0], "check 0x17")

    def test_two_level_map(self):
        rows = {tool.tx_digest(b"%d" % index): b"%d" % index for index in range(25)}
        keys = sorted(rows)
        block = ok_block(hashes=[keys[5], keys[24], keys[6]])
        block.child = proof_for(block)
        self.assertEqual(self.run_case(Case("c", [Step(block)], tx_map=rows))[0], "flushed")


class Buffer(Base):
    def test_limit_is_over_one_hundred(self):
        self.assertEqual(self.run_case(Case("c", steps_of(chain(100, proof=False)), direct=True))[0], "buffered")
        label, got = self.run_case(Case("c", steps_of(chain(101, proof=False)), direct=True))
        self.assertEqual(label, "text too many")
        self.assertEqual(got["results"][-1], ("text", tool.TOO_MANY, 0x1B))
        self.assertEqual(len(got["pending"]), 101)

    def test_proof_row_is_read_past_the_limit(self):
        label, got = self.run_case(Case("c", steps_of(chain(101)), direct=True))
        self.assertEqual(label, "flushed")
        self.assertEqual(got["confirmed"], 1101)

    def test_failed_verify_keeps_pending_and_moved_round(self):
        blocks = chain(2)
        blocks[0].bad = True
        label, got = self.run_case(Case("c", steps_of(blocks)))
        self.assertEqual(label, "check 0x1")
        self.assertEqual(got["pending"], [0xB1, 0xB2])
        self.assertEqual((got["last_recv"], got["confirmed"]), (1002, 1000))
        self.assertIn(("log", tool.LOG_VERIFY_FAILED), got["trace"])

    def test_flush_order_and_state(self):
        label, got = self.run_case(Case("c", steps_of(chain(3)), waker=True))
        self.assertEqual(label, "flushed")
        self.assertEqual([row[1] for row in got["trace"] if row[0] == "send"], [0xB1, 0xB2, 0xB3])
        self.assertEqual(got["trace"].count(("wake",)), 1)
        self.assertEqual((got["pending"], got["confirmed"], got["sender"], got["channel"]), ([], 1003, 3, 6))

    def test_closed_channel_after_one_send(self):
        label, got = self.run_case(Case("c", steps_of(chain(3)), closed_after=1))
        self.assertEqual(label, "check 0x35")
        self.assertEqual(got["confirmed"], 1003)
        self.assertEqual(got["strong"], {0xB1: 1, 0xB2: 1, 0xB3: 0})
        self.assertIn(("print", tool.PRINT_SEND_FAILED), got["trace"])

    def test_outer_round_tag_is_only_reached_without_the_gate(self):
        label, got = self.run_case(Case("c", steps_of([ok_block(qc_round=999)]), direct=True))
        self.assertEqual(label, "check 0x2c")
        self.assertEqual(got["results"], [("err", 0x2C, 999)])
        self.assertEqual(got["strong"], {0xB1: 0})

    def test_slow_lock_paths(self):
        _, got = self.run_case(Case("c", steps_of(chain(1)), lock_held=True, lock_parked=True))
        self.assertIn(("lock slow",), got["trace"])
        self.assertIn(("unlock slow",), got["trace"])
        self.assertEqual(got["lock"], 0)


class Batch(Base):
    def test_gaps_pass_the_batch(self):
        self.assertEqual(self.run_case(Case("c", steps_of(chain(3, gap=9))))[0], "flushed")

    def test_empty(self):
        self.assertEqual(self.run_case(Case("c", [], empty_batch=True))[0], "check 0x14")

    def test_round_and_hash_rows_report_both_values(self):
        _, got = self.run_case(Case("c", steps_of(chain(1)), confirmed=999))
        self.assertEqual(got["results"], [("err", 0x15, 1000, 999)])
        first, second = ok_block(key=0xB1), ok_block(key=0xB2, round=1002, qc_round=1001, qc_hash=0xB0)
        second.child = proof_for(second)
        _, got = self.run_case(Case("c", steps_of([first, second])))
        self.assertEqual(got["results"][-1], ("err", 0x16, 0xB0, 0xB1))

    def test_first_block_hash_is_free(self):
        for value in (0, 0x77, (1 << 256) - 1):
            block = ok_block(qc_hash=value)
            block.child = proof_for(block)
            self.assertEqual(self.run_case(Case("c", steps_of([block])))[0], "flushed")

    def test_tx_rows(self):
        self.assertEqual(self.run_case(Case("c", [Step(chain(1)[0], [(tool.HASH_A, b"z"), (tool.HASH_B, tool.TX_B)])]))[0], "check 0x17")
        self.assertEqual(self.run_case(Case("c", [Step(chain(1)[0], [(tool.HASH_B, tool.TX_B), (tool.HASH_A, tool.TX_A)])]))[0], "check 0x18")
        self.assertEqual(self.run_case(Case("c", [Step(chain(1)[0], tool.GOOD_ROWS[:1])]))[0], "check 0x18")

    def test_time_words(self):
        for value in ((9, 2, 3), (1, 9, 3), (1, 2, 9)):
            self.assertEqual(self.run_case(Case("c", [Step(chain(1)[0], list(tool.GOOD_ROWS), value)]))[0], "check 0x19")

    def test_proof_rows_in_order(self):
        self.assertEqual(self.run_case(self.proof_case(bad=True, proof_bad=True))[1]["results"][-1][1:3], (1, tool.error_words(0x10B1)[1]))
        self.assertEqual(self.run_case(self.proof_case(proof_bad=True, qc_hash=0x99))[1]["trace"][-2:], [("qc", 0x10B1), ("log", tool.LOG_VERIFY_FAILED)])
        self.assertEqual(self.run_case(self.proof_case(qc_hash=0x99, proof_hash=0x98))[0], "check 0x1d")
        self.assertEqual(self.run_case(self.proof_case(proof_hash=0x98, round=1009))[0], "check 0x1e")
        self.assertEqual(self.run_case(self.proof_case(round=1003))[0], "check 0x1f")
        self.assertEqual(self.run_case(self.proof_case(round=1001))[0], "check 0x1f")

    def test_saturated_round(self):
        block = ok_block(round=tool.MAX_ROUND)
        block.child = proof_for(block, round=tool.MAX_ROUND)
        self.assertEqual(self.run_case(Case("c", steps_of([block])))[0], "flushed")
        block.child = proof_for(block, round=0)
        self.assertEqual(self.run_case(Case("c", steps_of([block])))[0], "check 0x1f")

    def test_proof_rounds_are_not_read(self):
        one, two = self.proof_case(proof_round=1, qc_round=2), self.proof_case(proof_round=900, qc_round=1000)
        self.assertEqual(self.run_case(one)[0], self.run_case(two)[0])

    def test_rules_past_the_flush_rule(self):
        early = chain(2)
        early[0].child = proof_for(early[0])
        self.assertEqual(self.run_case(Case("c", steps_of(early), batch=True))[0], "check 0x1a")
        self.assertEqual(self.run_case(Case("c", steps_of(chain(2, proof=False)), batch=True))[0], "check 0x1b")
        self.assertEqual(self.run_case(Case("c", steps_of(chain(2)), batch=True))[0], "verified")


class Bytes(Base):
    def test_callers(self):
        self.assertEqual(tool.scan_callers(self.image), list(tool.BUFFER_SLOT_SITES))

    def test_caller_scan_finds_a_new_site(self):
        saved = tool.BUFFER_SLOT_SITES
        tool.BUFFER_SLOT_SITES = saved[1:]
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.scan_callers(self.image)
        finally:
            tool.BUFFER_SLOT_SITES = saved

    def test_pins_hold_and_corrupted_copy_fails(self):
        self.assertEqual(tool.check_pins(self.image), len(tool.PINS))
        with self.assertRaises(tool.EvidenceError):
            tool.check_pins(self.corrupted(tool.PINS[3][1]))

    def test_strings_and_slots(self):
        self.assertEqual(tool.check_strings(self.image), tool.STRINGS)
        with self.assertRaises(tool.EvidenceError):
            tool.check_strings(self.corrupted(tool.STRINGS[0][0]))
        self.assertEqual(len(tool.check_slots(self.image)), len(tool.SLOTS))

    def test_slot_with_wrong_target_fails(self):
        saved = tool.SLOTS
        tool.SLOTS = ((saved[0][0], saved[0][1] + 1, "x"),)
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.check_slots(self.image)
        finally:
            tool.SLOTS = saved

    def test_gate_site_inside_a_row_fails(self):
        saved = tool.GATES
        row = saved[0]
        tool.GATES = ((row[0], row[1], row[2] + 1, row[3], row[4], row[5]),)
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.check_gate_sites(self.image)
        finally:
            tool.GATES = saved

    def test_out_of_range_address(self):
        with self.assertRaises(tool.EvidenceError):
            self.image.offset(0x7FFFFFFF0000)
        with self.assertRaises(tool.EvidenceError):
            self.image.exact_fde(tool.BUFFER + 1)

    def test_wrong_digest_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "copy"
            path.write_bytes(b"not the binary")
            with self.assertRaises(tool.EvidenceError):
                tool.load_image(path)

    def test_a_flipped_condition_is_seen(self):
        at = 0x4547CB8
        self.assertEqual(self.image.blob[self.image.offset(at)], 0x75)
        harness = tool.Harness(self.image, {at: 0x74})
        case = self.proof_case()
        self.assertNotEqual(tool.same(harness.run(case), tool.spec_run(case)[1]), [])

    def test_a_changed_limit_is_seen(self):
        at = 0x43600A2
        self.assertEqual(self.image.blob[self.image.offset(at)], 0x64)
        harness = tool.Harness(self.image, {at: 0x65})
        case = Case("c", steps_of(chain(101, proof=False)), direct=True)
        self.assertNotEqual(tool.same(harness.run(case), tool.spec_run(case)[1]), [])

    def test_rule_list_differs_when_a_rule_is_wrong(self):
        case = self.proof_case()
        got = self.harness.run(case)
        want = tool.spec_run(case)[1]
        want["confirmed"] = 1000
        self.assertEqual(tool.same(got, want), ["confirmed"])


class Packet(Base):
    def test_evidence_matches_a_fresh_run(self):
        result = tool.analyse(self.image, mutate=False)
        files = tool.render(result, self.image)
        for name in ("gates.tsv", "functions.tsv", "pins.tsv", "outcomes.tsv", "cases.tsv", "layouts.tsv", "error-tags.tsv", "callers.tsv"):
            self.assertEqual((FOLDER / name).read_text(encoding="ascii"), files[name], name)

    def test_manifest(self):
        rows = (FOLDER / "MANIFEST.sha256").read_text(encoding="ascii").splitlines()
        self.assertTrue(rows)
        names = set()
        for row in rows:
            digest, name = row.split("  ", 1)
            names.add(name)
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)
        self.assertEqual(names, {path.name for path in FOLDER.iterdir() if path.name != "MANIFEST.sha256"})

    def test_summary_counts(self):
        summary = json.loads((FOLDER / "evidence.json").read_text(encoding="ascii"))
        self.assertEqual(summary["sha256"], tool.SHA256)
        self.assertEqual(summary["pins"], len(tool.PINS))
        self.assertEqual(summary["mutations"]["killed"] + summary["mutations"]["survived"], summary["mutations"]["total"])
        self.assertGreaterEqual(summary["cases"], 450)


if __name__ == "__main__":
    unittest.main()
