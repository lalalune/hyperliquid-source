"""Tests for tools/margin_table_ids.py: real bytes against the specification, with negative controls."""

import importlib.util
import json
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("margin_table_ids", ROOT / "tools" / "margin_table_ids.py")
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)
PACKET = ROOT / "research" / "work-items" / "RE-007-margin-table-ids-94"
IMAGE = tool.load_image()
EVIDENCE, _ = tool.analyse(IMAGE, full=False)


def patched(va, xor):
    harness = tool.Harness(IMAGE)
    harness.machine.patches = {va: IMAGE.blob[IMAGE.offset(va)] ^ xor}
    return harness


def base_case():
    return tool.rewrite_case("control", 51, users={1: {1: tool.position(lev=33)}})


class Identity(unittest.TestCase):
    def test_wrong_digest_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_changed_bytes_are_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "copy"
            path.write_bytes(b"not the target")
            with self.assertRaises(tool.EvidenceError):
                tool.load_image(path=path)

    def test_address_outside_every_fde(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.exact_fde(tool.REWRITE + 1)


class Behaviour(unittest.TestCase):
    def test_all_cases_match(self):
        self.assertEqual(EVIDENCE["mismatches"], 0, EVIDENCE["first_mismatch"])
        self.assertEqual(EVIDENCE["cases"]["total"], len(tool.all_cases()))

    def state_after(self, new, old):
        harness = tool.Harness(IMAGE)
        case = tool.rewrite_case("w", new, rows=(old, old, old), users={1: {1: tool.position(lev=33, table=old)}})
        harness.run_rewrite(case)
        spot = harness.spots[0, 1, 1]
        memory = harness.machine.memory
        return memory.read(spot + 4, 4), memory.read(spot + 0x38, 4)

    def test_lower_table_keeps_the_position_table(self):
        self.assertEqual(self.state_after(51, 50), (20, 50))

    def test_higher_table_moves_the_position_table(self):
        self.assertEqual(self.state_after(50, 51), (33, 50))

    def test_crossing_table_keeps_the_position_table(self):
        self.assertEqual(self.state_after(53, 50), (30, 50))

    def test_equal_tiers_keep_the_position_table(self):
        self.assertEqual(self.state_after(55, 50), (33, 50))

    def test_row_is_written_before_a_missing_table_panics(self):
        harness = tool.Harness(IMAGE)
        with self.assertRaises(tool.Panicked) as caught:
            harness.run_rewrite(tool.rewrite_case("m", 99))
        self.assertEqual(caught.exception.args[0], tool.LOC_TABLE)
        rows = harness.machine.memory.read(tool.CH_BASE + 8, 8)
        self.assertEqual(harness.machine.memory.read(rows + 0x30 + 0x18, 4), 99)

    def test_asset_outside_the_dex_panics(self):
        harness = tool.Harness(IMAGE)
        with self.assertRaises(tool.Panicked) as caught:
            harness.run_rewrite(tool.rewrite_case("a", 51, asset=10001))
        self.assertEqual(caught.exception.args[0], tool.LOC_ASSET)

    def test_gate_validates_before_it_applies(self):
        harness = tool.Harness(IMAGE)
        case = dict(kind="gate", label="v", start=tool.GATES[0], entries=(("AAA", 51), ("BBB", 99)), coins=tool.coins(), dexes=tool.dex_pair())
        harness.run_gate(case)
        self.assertEqual(harness.machine.memory.read(tool.OUT, 2), tool.NO_TABLE)
        self.assertEqual(harness.calls, [])

    def test_missing_id_payload_is_the_previous_id(self):
        rows = EVIDENCE["missing_table_payload"]
        self.assertEqual(rows[1]["word_at_out_plus_4"], "0x33")
        self.assertEqual(rows[2]["word_at_out_plus_4"], "0x33")


class Controls(unittest.TestCase):
    def test_flipped_leverage_compare_is_seen(self):
        self.assertIsNotNone(tool.compare_run(patched(0x3704DBD + 1, 1), base_case()))

    def test_flipped_table_result_compare_is_seen(self):
        harness = patched(0x3704EE5, 1)
        case = tool.rewrite_case("c", 50, rows=(51, 51, 51), users={1: {1: tool.position(table=51)}})
        self.assertIsNotNone(tool.compare_run(harness, case))

    def test_changed_builtin_limit_is_seen(self):
        self.assertIsNotNone(tool.compare_run(patched(0x37046F3, 1), tool.rewrite_case("b", 52, users={1: {1: tool.position()}})))

    def test_changed_coin_limit_is_seen(self):
        harness = patched(0x273C247, 1)
        case = dict(kind="gate", label="l", start=tool.GATES[0], entries=(("A" * 101, 5),), coins={"A" * 101: (0, 0)}, dexes=tool.dex_pair())
        self.assertIsNotNone(tool.compare_run(harness, case))

    def test_wrong_specification_is_seen(self):
        original = tool.relation
        tool.relation = lambda new, old: 0
        try:
            failed = tool.compare_run(tool.Harness(IMAGE), tool.rewrite_case("s", 50, rows=(51, 51, 51), users={1: {1: tool.position(table=51)}}))
        finally:
            tool.relation = original
        self.assertIsNotNone(failed)


class Packet(unittest.TestCase):
    def test_static_evidence_matches_the_stored_file(self):
        stored = json.loads((PACKET / "evidence.json").read_text(encoding="utf-8"))
        stored.pop("mutations")
        self.assertEqual(json.loads(json.dumps(EVIDENCE, sort_keys=True)), stored)

    def test_mutation_table_totals(self):
        stored = json.loads((PACKET / "evidence.json").read_text(encoding="utf-8"))["mutations"]
        rows = (PACKET / "mutations.tsv").read_text(encoding="utf-8").splitlines()[1:]
        self.assertEqual(len(rows), sum(stored.values()))
        for row in rows:
            fields = row.split("\t")
            self.assertTrue(fields[3] == "killed" or fields[5], row)


if __name__ == "__main__":
    unittest.main()
