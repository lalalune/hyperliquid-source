"""Tests for tools/block_admission_path.py: rule list, byte pins and negative controls on corrupted copies."""

import hashlib
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import block_admission_path as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-008-block-admission-94"
Case, Sig, Tc, Vote = tool.Case, tool.Sig, tool.Tc, tool.Vote
ok_block, votes_for, tc_for, stored, many = tool.ok_block, tool.votes_for, tool.tc_for, tool.stored, tool.many
GOOD_TXS = [0x21, 0x22]


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


class Admission(Base):
    def test_plain_block_registers_and_goes_to_the_channel(self):
        label, got = self.run_case(Case("c", ok_block(), txs=GOOD_TXS))
        self.assertEqual(label, "registered")
        self.assertEqual(got["blocks"], [0xB10C])
        self.assertIn(("send", 0, 1000, 0xB10C), got["trace"])
        self.assertEqual(got["changed"], [0x1B8, 0x1C8])

    def test_equal_to_committed_round_passes_one_under_does_not(self):
        self.assertEqual(self.run_case(Case("c", ok_block(), committed=1000, txs=GOOD_TXS))[0], "registered")
        label, got = self.run_case(Case("c", ok_block(), committed=1001))
        self.assertEqual(label, "below committed")
        self.assertEqual(got["result"], ("err", 3, 1000, 1001))
        self.assertEqual(got["changed"], [])

    def test_duplicate_and_same_round_order(self):
        rows = [stored(0xB10C, 1000), stored(0xB10D, 1000)]
        self.assertEqual(self.run_case(Case("c", ok_block(), stored=rows))[0], "duplicate hash")
        label, got = self.run_case(Case("c", ok_block(key=0xFFFF), stored=rows))
        self.assertEqual(label, "same round")
        self.assertEqual(got["result"][1], 0x0E)
        self.assertEqual(got["blocks"], [0xB10C, 0xB10D])

    def test_ancestor_and_seen_lookups_change_nothing(self):
        plain = self.run_case(Case("c", ok_block(hashes=[0x21]), stored=[stored(0x77, 999, 0x76)], txs=[0x21]))
        both = self.run_case(Case("c", ok_block(hashes=[0x21]), stored=[stored(0x77, 999, 0x76, [0x21])], seen=[0x21], txs=[0x21]))
        self.assertEqual(plain[0], both[0])
        self.assertEqual(plain[1]["result"], both[1]["result"])
        self.assertEqual(plain[1]["trace"], both[1]["trace"])

    def test_unknown_hash_gets_a_placeholder_with_event_time(self):
        case = Case("c", ok_block(hashes=[0x31, 0x31, 0x21]), txs=[0x21])
        _, got = self.run_case(case)
        self.assertEqual(got["txs"][0x31], (case.now, tool.PLACEHOLDER_TAG))
        self.assertEqual(got["txs"][0x21][1], 0x55)
        self.assertIn(("unknown", [0x31, 0x31]), got["trace"])

    def test_forward_flag_and_closed_channel(self):
        _, got = self.run_case(Case("c", ok_block(), txs=GOOD_TXS, forward_off=True))
        self.assertFalse([row for row in got["trace"] if row[0] in ("send", "closed")])
        self.assertEqual(got["sender"], 5)
        _, got = self.run_case(Case("c", ok_block(), txs=GOOD_TXS, closed=True))
        self.assertIn(("closed", 0, 1000, 0xB10C), got["trace"])
        self.assertEqual(got["blocks"], [0xB10C])
        _, got = self.run_case(Case("c", ok_block(), txs=GOOD_TXS, waker=True))
        self.assertEqual(got["wakes"], 1)

    def test_failed_block_keeps_its_request_row(self):
        _, got = self.run_case(Case("c", ok_block(proposer=2), rows=[0xB10C]))
        self.assertEqual(got["rows"], [0xB10C])
        _, got = self.run_case(Case("c", ok_block(), rows=[0xB10C], txs=GOOD_TXS))
        self.assertEqual(got["rows"], [])


class Signed(Base):
    def test_proposer_rule_error_and_mismatch(self):
        label, got = self.run_case(Case("c", ok_block(proposer=2)))
        self.assertEqual(label, "check 0xc")
        self.assertIn(("log", "proposer"), got["trace"])
        self.assertEqual(self.run_case(Case("c", ok_block(), leader_error=tool.NONE_TAG + 0x10))[0], "check 0x10")

    def test_signature_is_read_last(self):
        self.assertEqual(self.run_case(Case("c", ok_block(sig=Sig(broken=True), qc=votes_for(round=1500))))[0], "check 0x4")
        self.assertEqual(self.run_case(Case("c", ok_block(sig=Sig(broken=True))))[0], "check 0x1")
        self.assertEqual(self.run_case(Case("c", ok_block(sig=Sig(good=False))))[0], "check 0x1")

    def test_block_hash_is_not_checked_here(self):
        self.assertEqual(self.run_case(Case("c", ok_block(key=0x1), txs=GOOD_TXS))[0], "registered")
        self.assertEqual(self.run_case(Case("c", ok_block(key=0x2), txs=GOOD_TXS))[0], "registered")

    def test_high_round_warns_and_goes_on(self):
        label, got = self.run_case(Case("c", ok_block(), valid_until=999, txs=GOOD_TXS))
        self.assertEqual(label, "registered")
        self.assertIn(("log", "high round"), got["trace"])


class Quorum(Base):
    def run_quorum(self, stakes, signers):
        return self.run_case(Case("c", ok_block(qc=votes_for(signers=signers)), stakes={0: stakes}, txs=GOOD_TXS))[0]

    def test_two_thirds_exact_fails_one_more_passes(self):
        self.assertEqual(self.run_quorum({1: 10, 2: 10, 3: 10}, (1, 2)), "check 0x9")
        self.assertEqual(self.run_quorum({1: 11, 2: 10, 3: 10}, (1, 2)), "registered")

    def test_weight_is_stake_not_count(self):
        self.assertEqual(self.run_quorum({1: 300, 2: 50, 3: 50}, (1,)), "registered")
        self.assertEqual(self.run_quorum({1: 300, 2: 50, 3: 50}, (2, 3)), "check 0x9")

    def test_repeated_signer_counts_once(self):
        self.assertEqual(self.run_quorum(many(3), (1, 2, 1, 2, 1)), "check 0x9")

    def test_values_past_64_bits_compare_right(self):
        self.assertEqual(self.run_quorum({1: 1 << 62, 2: 1 << 62, 3: 1 << 62, 4: 5}, (1, 2, 3, 4)), "registered")

    def test_stake_sum_overflow_panics(self):
        self.assertEqual(self.run_quorum({1: 1 << 63, 2: 1 << 63}, (1, 2)), "panic stake overflow")

    def test_carry_of_the_doubled_total_counts(self):
        case = Case("c", ok_block(qc=votes_for(signers=(1, 2, 3))), stakes={0: {1: 1 << 62, 2: 1 << 62, 3: 1 << 62, 4: 5}}, txs=GOOD_TXS)
        self.assertEqual(self.run_case(case)[0], "registered")
        edited = tool.Harness(self.image, {0x4AD9611: 0x3E})
        self.assertNotEqual(tool.same(edited.run(case), tool.spec_run(case)[1]), [])

    def test_two_level_trees(self):
        self.assertEqual(self.run_quorum(many(13), tuple(range(1, 10))), "registered")
        self.assertEqual(self.run_quorum(many(13), tuple(range(1, 9))), "check 0x9")


class QcPair(Base):
    def label(self, block, **extra):
        return self.run_case(Case("c", block, txs=GOOD_TXS, **extra))[0]

    def test_genesis_needs_zero_hash_and_no_votes(self):
        self.assertEqual(self.label(ok_block(qc=votes_for(round=100, hash_value=0, signers=()))), "registered")
        self.assertEqual(self.label(ok_block(qc=votes_for(round=100, hash_value=5 << 200, signers=()))), "check 0x8")
        self.assertEqual(self.label(ok_block(qc=votes_for(round=100, hash_value=0))), "check 0x8")

    def test_under_start_and_over_start(self):
        self.assertEqual(self.label(ok_block(qc=votes_for(round=99))), "check 0x7")
        self.assertEqual(self.label(ok_block(qc=votes_for(round=101))), "registered")

    def test_older_pair_and_newer_pair(self):
        self.assertEqual(self.run_case(Case("c", ok_block(qc=votes_for(version=1))))[1]["result"], ("err", 0, 1, 100, 2, 100))
        self.assertEqual(self.label(ok_block(qc=votes_for(version=3))), "panic newer hardfork")
        self.assertEqual(self.label(ok_block(qc=votes_for(version=3, signers=(1,)))), "check 0x0")

    def test_same_version_other_start_is_rejected_even_when_higher_is_signed(self):
        self.assertEqual(self.label(ok_block(qc=votes_for(start=500))), "check 0x0")


class StakeSet(Base):
    def label(self, round, **extra):
        block = ok_block(round=round, qc=votes_for(round=round - 1))
        return self.run_case(Case("c", block, committed=0, txs=GOOD_TXS, **extra))[0]

    def test_recent_span_uses_the_base_key(self):
        self.assertEqual(self.label(1999, stakes={0: many(4), 1500: {8: 1}}), "registered")

    def test_lag_of_200_rounds(self):
        new = {0: {8: 1}, 2799: many(4)}
        self.assertEqual(self.label(3000, stakes=new), "registered")
        self.assertEqual(self.label(3000, stakes={0: many(4), 2801: {8: 1}}), "registered")

    def test_no_set(self):
        self.assertEqual(self.label(1000, stakes={}), "check 0x28")


class Timeout(Base):
    good = votes_for(round=991)
    tie_bad = votes_for(round=991, signers=(1,))
    low_bad = votes_for(round=900, signers=(1,))

    def label(self, tc, **extra):
        return self.run_case(Case("c", ok_block(qc=votes_for(round=990), tc=tc), txs=GOOD_TXS, **extra))[0]

    def test_good_tc(self):
        self.assertEqual(self.label(tc_for()), "registered")

    def test_previous_round_only(self):
        self.assertEqual(self.label(tc_for(round=998)), "check 0x5")

    def test_only_highest_qc_is_read(self):
        votes = [Vote(self.good, 999, 1), Vote(self.low_bad, 999, 2), Vote(self.good, 999, 3)]
        self.assertEqual(self.label(Tc(999, votes)), "registered")

    def test_tie_takes_the_later_vote(self):
        self.assertEqual(self.label(Tc(999, [Vote(self.tie_bad, 999, 1), Vote(self.good, 999, 2), Vote(self.good, 999, 3)])), "registered")
        self.assertEqual(self.label(Tc(999, [Vote(self.good, 999, 1), Vote(self.good, 999, 2), Vote(self.tie_bad, 999, 3)])), "check 0x9")

    def test_empty_and_mixed_rounds(self):
        self.assertEqual(self.label(Tc(999, [])), "check 0xb")
        self.assertEqual(self.label(Tc(999, [Vote(self.good, 999, 1), Vote(self.good, 1000, 2)])), "check 0xf")

    def test_every_vote_signature_is_read(self):
        self.assertEqual(self.label(Tc(999, [Vote(self.good, 999, 1), Vote(self.good, 999, 2, Sig(good=False)), Vote(self.good, 999, 3)])), "check 0x1")

    def test_repeated_voter_counts_once(self):
        self.assertEqual(self.label(tc_for(signers=(1, 2, 1, 2)), stakes={0: many(3)}), "check 0xa")


class Bytes(Base):
    def test_call_sites(self):
        self.assertEqual(tool.scan_triggers(self.image), [row[0] for row in tool.TRIGGERS])

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
            self.image.exact_fde(tool.REGISTER + 1)

    def test_wrong_digest_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "copy"
            path.write_bytes(b"not the binary")
            with self.assertRaises(tool.EvidenceError):
                tool.load_image(path)

    def test_a_flipped_condition_is_seen(self):
        edit = {0x44B8474: 0x82}
        blob = self.image.blob
        self.assertEqual(blob[self.image.offset(0x44B8474) + 1], 0x83)
        harness = tool.Harness(self.image, {0x44B8475: 0x82})
        case = Case("c", ok_block(), committed=1001)
        self.assertNotEqual(tool.same(harness.run(case), tool.spec_run(case)[1]), [])
        self.assertTrue(edit)

    def test_rule_list_differs_when_a_rule_is_wrong(self):
        case = Case("c", ok_block(), txs=GOOD_TXS)
        got = self.harness.run(case)
        want = tool.spec_run(case)[1]
        want["blocks"] = []
        self.assertEqual(tool.same(got, want), ["blocks"])


class Packet(Base):
    def test_evidence_matches_a_fresh_run(self):
        result = tool.analyse(self.image, mutate=False)
        files = tool.render(result, self.image)
        for name in ("gates.tsv", "qc-tc-gates.tsv", "functions.tsv", "pins.tsv", "outcomes.tsv", "cases.tsv", "layouts.tsv", "error-tags.tsv"):
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
        self.assertGreaterEqual(summary["cases"], 400)


if __name__ == "__main__":
    unittest.main()
