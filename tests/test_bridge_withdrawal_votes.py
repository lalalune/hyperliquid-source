"""Checks for tools/bridge_withdrawal_votes.py, with negative controls on bytes, hash and rules."""

import hashlib
import json
import pathlib
import struct
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import bridge_withdrawal_votes as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "bridge-withdrawal-votes-94"


class Shared:
    image = None

    @classmethod
    def get(cls):
        if cls.image is None:
            cls.image = tool.load_image()
        return cls.image


def run(*scenarios, patches=None):
    harness = tool.Harness(Shared.get(), patches)
    return [harness.run(scenario) for scenario in scenarios], harness


def named(name):
    return next(row for row in tool.named_scenarios() if row.name == name)


class Binding(unittest.TestCase):
    def test_wrong_digest_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_address_outside_every_fde_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            Shared.get().fde(0x10)

    def test_inner_address_is_not_an_fde_start(self):
        with self.assertRaises(tool.EvidenceError):
            Shared.get().exact_fde(tool.SIGN_ARM + 1)

    def test_every_path_function_decodes_to_its_fde_end(self):
        for target in tool.TARGETS:
            start, stop = Shared.get().exact_fde(target)
            rows = tool.decode_range(Shared.get(), start, stop)
            self.assertEqual(rows[-1].next, stop)


class Rules(unittest.TestCase):
    def test_named_scenarios_match_the_rule_list(self):
        harness = tool.Harness(Shared.get())
        done = tool.check_all(harness, tool.named_scenarios())
        self.assertEqual(len(done), len(tool.named_scenarios()))

    def test_vectors_match_the_rule_list(self):
        tool.check_all(tool.Harness(Shared.get()), tool.vector_scenarios(25))

    def test_limit_is_i64_max_over_ten(self):
        rows = tool.limit_rows(Shared.get())
        self.assertEqual(len(rows), 3)
        self.assertEqual({row[4] for row in rows}, {0x0CCCCCCCCCCCCCCC})
        self.assertTrue(all(row[5] for row in rows))

    def test_limit_edges(self):
        (below, at, reference), _ = run(named("sign_at_limit_minus_one"), named("sign_at_limit"), named("sign_reference_limit"))
        self.assertEqual(below[0][0], (tool.TAG_OK,))
        self.assertEqual(at[0][0], (tool.TAG_LIMIT, tool.USD_LIMIT))
        self.assertEqual(reference[0][0][0], tool.TAG_LIMIT)

    def test_exact_two_thirds_does_not_finish(self):
        (trace,), _ = run(named("exact_two_thirds_is_short"))
        rows = trace[1][2][0]
        self.assertEqual(rows[tool.row_key(tool.NONCE, tool.USER)]["done"], 0)
        rows = trace[2][2][0]
        self.assertEqual(rows[tool.row_key(tool.NONCE, tool.USER)]["done"], 1)

    def test_repeat_signature_overwrites_and_passes(self):
        (trace,), _ = run(named("repeat_vote_overwrites"))
        self.assertEqual(trace[1][0], (tool.TAG_OK,))
        votes = trace[1][2][0][tool.row_key(tool.NONCE, tool.USER)]["inner"][(tool.USD, tool.DEST)]
        self.assertEqual(votes[tool.V1[0]], tool.blob(0x52, 0x48))

    def test_tag_0x90_is_a_missing_row(self):
        (trace, other), _ = run(named("sign_no_row"), named("finalize_other_destination"))
        self.assertEqual(trace[0][0], (tool.TAG_NO_ROW,))
        self.assertEqual(other[0][0], (tool.TAG_NO_ROW,))

    def test_finish_needs_no_signature_quorum_and_clears_both_rows(self):
        (trace,), _ = run(named("finalize_three_of_four"))
        rows, finals, times = trace[2][2]
        self.assertEqual((rows, finals), ({}, {}))
        self.assertEqual(list(times), [tool.row_key(tool.NONCE, tool.USER)])
        self.assertEqual(trace[2][1][0][0], "finished")

    def test_event_balance_is_the_dex_word_not_the_bridge_balance(self):
        (trace,), _ = run(named("finalize_limit_minus_one"))
        event = trace[2][1][0]
        self.assertEqual(event[3], tool.to_bits(float((1 << 63) + 12345) / 1000000.0))

    def test_row_count_note_changes_nothing(self):
        (trace,), _ = run(named("no_trim_101_rows"))
        self.assertEqual(len(trace[0][2][0]), 101)
        self.assertEqual([event for event in trace[0][1] if event[0] in ("alloc", "free")], [("alloc", 800), ("free", 800)])
        (trace,), _ = run(named("no_trim_100_rows"))
        self.assertEqual([event for event in trace[0][1] if event[0] in ("alloc", "free")], [])

    def test_note_rows_have_no_store_between_collect_and_free(self):
        self.assertEqual(len(tool.note_rows(Shared.get())), 2)

    def test_status_texts_and_fields(self):
        texts = {row[0]: row[2] for row in tool.status_rows(Shared.get())}
        self.assertEqual(len(texts), len(tool.STATUS_TAGS))
        fields = {row[2]: row[3] for row in tool.field_rows(Shared.get())}
        self.assertEqual(fields["withdrawal_signatures"], "0x40")
        self.assertEqual(fields["withdrawal_finalized_votes"], "0x70")
        self.assertEqual(fields["finished_withdrawal_to_time"], "0x118")

    def test_second_stack_argument_is_never_read(self):
        self.assertEqual(tool.stack_argument_reads(Shared.get()), 0)


class Negative(unittest.TestCase):
    def failing(self, patches, names):
        scenarios = [named(name) for name in names]
        wants = [tool.spec_run(row) for row in scenarios]
        return tool.first_failure(tool.Harness(Shared.get(), patches), scenarios, wants)

    def test_unedited_bytes_pass(self):
        self.assertIsNone(self.failing(None, ("sign_at_limit", "exact_two_thirds_is_short", "no_trim_101_rows")))

    def test_edited_limit_is_caught(self):
        for target in (tool.SIGN_ARM, tool.WRAP):
            at = int(next(row for row in tool.limit_rows(Shared.get()) if row[0] == "%#x" % target)[1], 16) + 2
            self.assertIsNotNone(self.failing({at: 0xCB}, ("sign_at_limit_minus_one", "finalize_limit_minus_one")))

    def test_edited_threshold_is_caught(self):
        self.assertIsNotNone(self.failing({0x3367388: 2}, ("exact_two_thirds_is_short",)))
        self.assertIsNotNone(self.failing({0x336739D + 1: 0x93}, ("exact_two_thirds_is_short",)))

    def test_edited_status_is_caught(self):
        self.assertIsNotNone(self.failing({0x374EFDF + 3: 0x91}, ("sign_no_row",)))
        self.assertIsNotNone(self.failing({0x374EE8A + 3: 0x1E}, ("sign_signer_mismatch",)))

    def test_rule_list_with_a_wrong_limit_fails(self):
        scenario = named("sign_at_limit")
        saved = tool.USD_LIMIT
        tool.USD_LIMIT = 0xCCCCCCCCCCCCCCCD
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.check_all(tool.Harness(Shared.get()), [scenario])
        finally:
            tool.USD_LIMIT = saved

    def test_rule_list_with_a_wrong_threshold_fails(self):
        saved = tool.spec_weight
        tool.spec_weight = lambda stakes, voters: 3 * sum(stakes[v] for v in voters if v in stakes) >= 2 * sum(stakes.values()) if voters else False
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.check_all(tool.Harness(Shared.get()), [named("exact_two_thirds_is_short")])
        finally:
            tool.spec_weight = saved

    def test_corrupted_field_offset_is_refused(self):
        image = Shared.get()
        blob = bytearray(image.blob)
        blob[image.offset(0x22156D4) + 3] ^= 0x10
        broken = tool.Image(bytes(blob))
        with self.assertRaises(tool.EvidenceError):
            tool.field_rows(broken)


class Packet(unittest.TestCase):
    def test_manifest_covers_the_folder(self):
        lines = (FOLDER / "MANIFEST.sha256").read_text(encoding="ascii").split("\n")
        listed = {}
        for line in lines:
            if line:
                digest, name = line.split("  ")
                listed[name] = digest
        names = sorted(path.name for path in FOLDER.iterdir() if path.name != "MANIFEST.sha256")
        self.assertEqual(sorted(listed), names)
        for name, digest in listed.items():
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_stored_files_match_a_short_regeneration(self):
        files = tool.render(tool.analyse(Shared.get(), mutate=False))
        for name, text in files.items():
            if name != "evidence.json":
                self.assertEqual((FOLDER / name).read_text(encoding="ascii"), text, name)

    def test_evidence_summary(self):
        data = json.loads((FOLDER / "evidence.json").read_text(encoding="ascii"))
        self.assertEqual(data["sha256"], tool.SHA256)
        self.assertEqual(data["functions"], len(tool.TARGETS))
        self.assertGreater(data["mutations"]["killed"], 0)
        self.assertEqual(data["mutations"]["total"], data["mutations"]["killed"] + data["mutations"]["survived"])

    def test_mutation_rows_are_explained(self):
        rows = (FOLDER / "mutations.tsv").read_text(encoding="ascii").strip().split("\n")[1:]
        self.assertFalse([row for row in rows if row.endswith("UNEXPLAINED")])


if __name__ == "__main__":
    unittest.main()
