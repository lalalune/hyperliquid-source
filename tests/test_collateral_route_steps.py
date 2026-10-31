"""Tests for tools/collateral_route_steps.py: the static pins, the specification on real bytes, and negative controls."""

import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("collateral_route_steps", ROOT / "tools" / "collateral_route_steps.py")
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)
FOLDER = ROOT / "research" / "work-items" / "RE-006-collateral-route-steps-94"


def load_shared(cls):
    cls.image = tool.load_image()
    cls.harness = tool.Harness(cls.image)
    cls.cases = tool.all_cases()


class Base(unittest.TestCase):
    setUpClass = classmethod(load_shared)

    def world(self, **options):
        return tool.world(**options)

    def run_case(self, kind, **options):
        case = tool.Case("test", kind, tool.world(**options))
        got = self.harness.run(case)
        expected = tool.spec_run(case)
        self.assertEqual(got, expected)
        return got

    def transfers(self, result):
        return [row[1:] for row in result["log"] if row[0] == "transfer"]

    def poke(self, va, value):
        """Run with one byte of .text changed."""
        machine = self.harness.machine
        machine.patches = {va: value}
        machine.cache.clear()

    def tearDown(self):
        self.harness.machine.patches = {}
        self.harness.machine.cache.clear()


class Input(unittest.TestCase):
    def test_wrong_digest_is_refused(self):
        with self.assertRaisesRegex(tool.EvidenceError, "SHA-256"):
            tool.load_image(expected="0" * 64)

    def test_other_file_is_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "blob"
            path.write_bytes(b"not an elf")
            with self.assertRaises(tool.EvidenceError):
                tool.load_image(path=path)


class Static(Base):
    def test_templates(self):
        rows = tool.text_rows(self.image)
        self.assertEqual([row["text"] for row in rows], ["move_token to_spot: ", "move_token from_spot: "])

    def test_mismatch_text(self):
        for row in tool.mismatch_sites(self.image):
            self.assertEqual(row["text"], "token mismatch")
            self.assertEqual(len(row["sites"]), 2)

    def test_function_bounds(self):
        for name, pair in tool.FAMILIES:
            for start in pair:
                self.assertEqual(self.image.exact_fde(start)[0], start)

    def test_inside_a_function_is_not_a_start(self):
        with self.assertRaisesRegex(tool.EvidenceError, "not an FDE start"):
            self.image.exact_fde(tool.MOVE[0] + 1)

    def test_outside_every_mapping_is_refused(self):
        with self.assertRaisesRegex(tool.EvidenceError, "address outside"):
            self.image.offset(0x7FFFFFFFFFFF)

    def test_copies_differ_only_by_the_shift(self):
        for row in tool.copy_rows(self.image):
            if row["family"] == "collateral move":
                self.assertFalse(row["same_shape"])
                continue
            self.assertTrue(row["same_shape"], row["family"])
            self.assertEqual(row["other_differences"], 0, row["family"])
        settle = [row for row in tool.copy_rows(self.image) if row["family"] == "settle pass"][0]
        self.assertEqual(settle["shifted_fields"], 18)

    def test_amount_table(self):
        self.assertEqual([row["arm"] for row in tool.table_rows(self.image)], ["0x4c23262", "0x4c23129", "0x4c231c4", "0x4c2325d"])

    def test_share_constant_is_three(self):
        self.assertEqual(tool.float_words(self.image)["0x20aab8"], "0x4008000000000000")

    def test_routers(self):
        rows = tool.router_rows(self.image)
        self.assertEqual(len(rows), 4)
        self.assertEqual(rows[1]["pull"], "0x4ca9401")
        self.assertEqual(rows[1]["sweep"], "0x4ca94e8")

    def test_router_refuses_a_wrong_function(self):
        saved = tool.ROUTERS
        tool.ROUTERS = (tool.MOVE[0],)
        try:
            with self.assertRaisesRegex(tool.EvidenceError, "mode tests"):
                tool.router_rows(self.image)
        finally:
            tool.ROUTERS = saved

    def test_call_rows(self):
        rows = tool.call_rows(self.image)
        pulls = [row for row in rows if row["name"] == "pull" and row["copy"] == 1]
        self.assertEqual(len(pulls), 17)
        self.assertIn("0x4311140", {row["host"] for row in pulls})
        self.assertEqual(len([row for row in rows if row["name"] == "gather"]), 2)


class Move(Base):
    def test_every_case_agrees(self):
        for case in self.cases:
            self.assertIsNone(tool.compare_run(self.harness, case))

    def test_spot_divides_by_100(self):
        got = self.run_case("move", spot={tool.T1: (1299, 100)}, args=tool.move_args(target=0))
        self.assertEqual(got["result"], {"status": tool.OK, "value": 11})
        self.assertEqual(self.transfers(got), [[0, 0, 11]])

    def test_limit_of_a_limited_row(self):
        got = self.run_case("move", rows=[tool.dex_row(0, tag=1, cap=500, used=470)], args=tool.move_args(target=0))
        self.assertEqual(got["result"]["value"], 30)

    def test_tag_3_has_no_limit(self):
        got = self.run_case("move", rows=[tool.dex_row(0, tag=3, cap=500, used=470)], args=tool.move_args(target=0))
        self.assertEqual(got["result"]["value"], 99000000)

    def test_exempt_user_moves_nothing_but_counts(self):
        got = self.run_case("move", exempt=True, args=tool.move_args(target=0))
        self.assertEqual(got["log"], [])
        self.assertEqual(got["counts"], [6, 8])

    def test_equal_ends_do_nothing(self):
        got = self.run_case("move", args=tool.move_args(source=1, target=1, token=tool.T2))
        self.assertEqual((got["log"], got["counts"]), ([], [6, 8]))

    def test_wrong_source_token_is_dropped(self):
        got = self.run_case("move", args=tool.move_args(source=1))
        self.assertEqual(got["result"], {"status": tool.OK, "value": 0})
        self.assertEqual(got["log"], [["drop", tool.TEXT_STATUS, "token mismatch"]])

    def test_wrong_target_token_after_a_debit_has_no_undo(self):
        got = self.run_case("move", available={"0:4": 700}, args=tool.move_args(source=0, target=1))
        self.assertEqual(got["result"], {"status": tool.TEXT_STATUS, "value": "token mismatch"})
        self.assertEqual(self.transfers(got), [[0, 1, 700]])

    def test_failed_credit_is_undone_then_worded(self):
        got = self.run_case("move", rows=[tool.dex_row(0), tool.dex_row(1)], available={"0:4": 700}, fail={1: 0x73}, args=tool.move_args(source=0, target=1))
        self.assertEqual(self.transfers(got), [[0, 1, 700], [1, 0, 700], [0, 0, 700]])
        self.assertEqual(got["result"]["value"], "move_token from_spot: 0x73")

    def test_bad_target_panics(self):
        self.assertEqual(self.run_case("move", args=tool.move_args(target=2))["panic"], "dex")

    def test_negative_cap_panics(self):
        self.assertEqual(self.run_case("move", rows=[tool.dex_row(0, tag=1, cap=tool.MIN63)], args=tool.move_args(target=0))["panic"], "cap")

    def test_second_copy_reads_the_low_fields(self):
        got = self.run_case("move", copy=1, spot={tool.T1: (300, 0)}, args=tool.move_args(target=0))
        self.assertEqual(self.transfers(got), [[0, 0, 3]])

    def test_first_copy_refuses_the_shifted_layout(self):
        case = tool.Case("test", "move", tool.world(copy=1, args=tool.move_args(target=0)))
        machine = self.harness.machine
        saved = tool.MOVE
        tool.MOVE = (tool.MOVE[0], tool.MOVE[0])
        try:
            self.assertIsNotNone(tool.compare_run(self.harness, case))
        finally:
            tool.MOVE = saved


class Steps(Base):
    def test_account_mode_1_passes_wei(self):
        got = self.run_case("account", spot={tool.T1: (1299, 100)}, args={"token": tool.T1, "mode": 1, "opt": None, "byte": 0})
        self.assertEqual(got["log"][0], ["helper", tool.T1, 1, 1199, None, 3])

    def test_account_word_3_keeps_its_byte(self):
        got = self.run_case("account", helper={0: (3, 0x2D, 0)}, args={"token": tool.T1, "mode": 0, "opt": None, "byte": 0})
        self.assertEqual(got["result"], {"status": tool.ACCOUNT_ERROR, "value": 0x2D})

    def test_account_finish_error_is_byte_10(self):
        got = self.run_case("account", helper={0: (0, 1, 2)}, finish={0: 0x12}, args={"token": tool.T1, "mode": 0, "opt": None, "byte": 0})
        self.assertEqual(got["result"], {"status": tool.ACCOUNT_ERROR, "value": 0xA})

    def test_reserve_word_2_runs_3_then_0(self):
        got = self.run_case("reserve", reserve=(tool.T1,), args={"token": tool.T1, "target": 0, "word": [2, 0, 0], "byte": 0})
        self.assertEqual([row[2] for row in got["log"] if row[0] == "helper"], [3, 0])

    def test_reserve_failed_key_step_stops_the_move(self):
        got = self.run_case("reserve", reserve=(tool.T1, tool.T2), helper={3: (3, 9, 0)}, args={"token": tool.T1, "target": 0, "word": [1, tool.T2, 5], "byte": 0})
        self.assertEqual(self.transfers(got), [])
        self.assertEqual(got["counts"], [5, 7])

    def test_sweep_runs_2_then_1(self):
        got = self.run_case("sweep", reserve=(tool.T1,), args={"token": tool.T1, "source": None})
        self.assertEqual([row[2] for row in got["log"] if row[0] == "helper"], [2, 1])

    def test_sweep_of_a_token_outside_the_map(self):
        got = self.run_case("sweep", reserve=(tool.T2,), args={"token": tool.T1, "source": None})
        self.assertEqual([row for row in got["log"] if row[0] == "helper"], [])

    def test_gather_moves_every_row_to_spot(self):
        got = self.run_case("gather", available={"0:4": 5, "1:4": 6})
        self.assertEqual(self.transfers(got), [[0, 1, 5], [1, 1, 6]])

    def test_pull_without_flag_never_calls_the_helper(self):
        got = self.run_case("pull", reserve=(tool.T1,), args={"token": tool.T1, "target": 0, "word": [2, 0, 0], "flag": 0})
        self.assertEqual([row for row in got["log"] if row[0] == "helper"], [])

    def test_pull_with_flag_settles_every_key(self):
        got = self.run_case("pull", reserve=(tool.T1, tool.T2), args={"token": tool.T1, "target": 0, "word": [2, 0, 0], "flag": 1})
        self.assertEqual([row[1:3] for row in got["log"] if row[0] == "helper"][:4], [[tool.T1, 2], [tool.T1, 1], [tool.T2, 2], [tool.T2, 1]])

    def test_only_the_low_byte_of_the_flag_counts(self):
        got = self.run_case("pull", reserve=(tool.T1,), args={"token": tool.T1, "target": 0, "word": [2, 0, 0], "flag": 0x100})
        self.assertEqual([row for row in got["log"] if row[0] == "helper"], [])


class Settle(Base):
    def share(self, every, wei):
        return self.run_case("settle", rows=[tool.dex_row(0), tool.dex_row(1)], reserve=(tool.T1,) if every else (), spot={tool.T1: (wei, 0)}, ready={"0:2": 1, "1:2": 1}, available={"0:4": -tool.MAX63, "1:4": -tool.MAX63},
                             args={"flag": 1, "every": every, "token": tool.T1})

    def test_share_splits_equally(self):
        self.assertEqual(self.transfers(self.share(False, 10 ** 8))[-2:], [[0, 0, 500000], [1, 0, 500000]])

    def test_share_keeps_one_part_for_the_map(self):
        self.assertEqual([row[2] for row in self.transfers(self.share(True, 10 ** 8)) if row[1] == 0][-2:], [428571, 428571])

    def test_samples_match(self):
        self.assertEqual(tool.sample_lines()[1], "every=1 free=1000000: dex 0 +428571 dex 1 +428571")

    def test_short_move_lists_the_token(self):
        got = self.run_case("settle", spot={tool.T1: (10000, 0)}, available={"0:4": -500}, args={"flag": 0, "every": False, "token": tool.T1})
        self.assertEqual(got["result"], {"fails": [tool.T1]})

    def test_covered_need_returns_none(self):
        got = self.run_case("settle", available={"0:4": -500}, args={"flag": 0, "every": False, "token": tool.T1})
        self.assertEqual(got["result"], {"fails": None})

    def test_flag_changes_the_read_mode(self):
        got = self.run_case("settle", args={"flag": 1, "every": False, "token": tool.T1})
        self.assertEqual([row[2] for row in got["log"] if row[0] == "available"], [2])
        got = self.run_case("settle", args={"flag": 0, "every": False, "token": tool.T1})
        self.assertEqual([row[2:] for row in got["log"] if row[0] == "available"], [[4, 0]] * 2)

    def test_most_negative_panics(self):
        got = self.run_case("settle", available={"0:4": -(1 << 63)}, args={"flag": 0, "every": False, "token": tool.T1})
        self.assertEqual(got["panic"], "negate")

    def test_index_past_count_panics(self):
        got = self.run_case("settle", rows=[tool.dex_row(2), tool.dex_row(1, tool.T2)], args={"flag": 0, "every": False, "token": tool.T1})
        self.assertEqual(got["panic"], "dex")


class Controls(Base):
    def test_a_flipped_branch_is_seen(self):
        case = tool.Case("test", "move", tool.world(rows=[tool.dex_row(0, tag=1, cap=500, used=470)], args=tool.move_args(target=0)))
        self.assertIsNone(tool.compare_run(self.harness, case))
        va = 0x46EA2A8
        self.assertEqual(self.image.blob[self.image.offset(va)], 0x0F)
        self.poke(va + 1, self.image.blob[self.image.offset(va + 1)] ^ 1)
        self.assertIsNotNone(tool.compare_run(self.harness, case))

    def test_a_changed_divisor_is_seen(self):
        case = tool.Case("test", "move", tool.world(spot={tool.T1: (1299, 100)}, args=tool.move_args(target=0)))
        va = 0x46EA4D1 + 3
        self.assertEqual(self.image.blob[self.image.offset(va)], 2)
        self.poke(va, 3)
        self.assertIsNotNone(tool.compare_run(self.harness, case))

    def test_a_spec_change_is_seen(self):
        case = tool.Case("test", "account", tool.world(helper={0: (3, 0x2D, 0)}, args={"token": tool.T1, "mode": 0, "opt": None, "byte": 0}))
        expected = tool.spec_run(case)
        expected["result"]["value"] ^= 1
        self.assertNotEqual(self.harness.run(case), expected)

    def test_a_leak_is_refused(self):
        case = tool.Case("test", "move", tool.world(args=tool.move_args()))
        original = self.harness.on_free
        table = self.harness.machine.slots
        hook = self.harness.relative[tool.SLOT_FREE]
        table[hook] = lambda m: None
        try:
            settle = tool.Case("test", "settle", tool.world(args={"flag": 0, "every": False, "token": tool.T1}))
            with self.assertRaisesRegex(tool.Halt, "leak"):
                self.harness.run(settle)
        finally:
            table[hook] = original

    def test_a_tree_with_a_mutated_length_is_seen(self):
        case = tool.Case("test", "sweep", tool.world(reserve=(tool.T1, tool.T2, tool.T3, tool.T4, 0x9000), args={"token": 0x9000, "source": None}))
        self.assertIsNone(tool.compare_run(self.harness, case))
        va = 0x46EF571 + 3
        self.assertEqual(self.image.blob[self.image.offset(va)], 0xF2)
        self.poke(va, 0xF3)
        self.assertIsNotNone(tool.compare_run(self.harness, case))


class Packet(unittest.TestCase):
    def test_manifest(self):
        for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_manifest_covers_the_folder(self):
        listed = {line.split("  ")[1] for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines()}
        self.assertEqual(listed, {path.name for path in FOLDER.iterdir() if path.name != "MANIFEST.sha256"})

    def test_regeneration_is_byte_identical(self):
        image = tool.load_image()
        files = tool.render(tool.analyse(image))
        for name, text in files.items():
            self.assertEqual((FOLDER / name).read_text(encoding="ascii"), text, name)

    def test_every_open_row_has_a_reason(self):
        lines = (FOLDER / "mutations.tsv").read_text(encoding="ascii").splitlines()[1:]
        rows = [line.split("\t") for line in lines]
        self.assertTrue(rows)
        self.assertEqual([row for row in rows if row[3] != "killed" and not row[5]], [])
        self.assertNotIn("pending", {row[5] for row in rows})

    def test_evidence_counts(self):
        doc = json.loads((FOLDER / "evidence.json").read_text())
        self.assertEqual(doc["mismatches"], 0)
        self.assertEqual(doc["target"]["sha256"], tool.SHA256)
        self.assertEqual(doc["route_call_summary"]["pull copy 1"], 17)
        self.assertEqual(len(doc["routers"]), 4)


if __name__ == "__main__":
    unittest.main()
