import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import spot_half_supply_gate as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-004-spot-half-supply-gate-94"
IMAGE = None
DAMAGED = None
FULL = None


def setUpModule():
    global IMAGE, DAMAGED, FULL
    IMAGE = tool.load_image()
    FULL = tool.analyse(IMAGE)
    blob = bytearray(IMAGE.blob)
    compare = FULL["tails"][0][2] - 3
    blob[IMAGE.offset(compare + 1)] ^= 1
    blob[IMAGE.offset(tool.FINAL_BLOCK + 5)] ^= 1
    blob[IMAGE.offset(tool.COPIES[2]["supply"] + 3)] ^= 1
    blob[IMAGE.offset(tool.META_VALUE_LEA + 3)] ^= 8
    blob[IMAGE.offset(FULL["fields"][1][2])] ^= 1
    DAMAGED = tool.Image(blob)


def verdict(case, copy=0):
    return tool.Harness(IMAGE, tool.COPIES[copy]).run_case(case)


def patched(at, value, copy=0):
    harness = tool.Harness(IMAGE, tool.COPIES[copy], {at: value})
    harness.machine.step_limit = tool.MUTANT_STEP_LIMIT
    return tool.run_all(harness, tool.named_cases())


class Parsing(unittest.TestCase):
    def test_short_file_fails_the_hash(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "short"
            path.write_bytes(b"\x7fELF")
            with self.assertRaises(tool.EvidenceError):
                tool.load_image(path)

    def test_wrong_expected_hash_fails(self):
        wrong = ("0" if tool.SHA256[0] != "0" else "1") + tool.SHA256[1:]
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected=wrong)

    def test_address_outside_every_section_fails(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.offset(0xFFFFFFFFFF)

    def test_nobits_section_has_no_file_bytes(self):
        bss = IMAGE.named[".bss"]
        with self.assertRaises(tool.EvidenceError):
            IMAGE.offset(bss["address"] + 8)

    def test_mid_function_is_not_an_fde_start(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.exact_fde(tool.COPIES[0]["gate"] + 1)

    def test_tool_starts_no_process(self):
        source = (ROOT / "tools" / "spot_half_supply_gate.py").read_text()
        for word in ("subprocess", "os.system", "objdump -d"):
            self.assertNotIn(word, source)


class Vector(unittest.TestCase):
    def machine(self):
        return tool.Machine(IMAGE)

    def test_pmovmskb_takes_the_top_bit_of_each_byte(self):
        machine = self.machine()
        machine.xmm[2] = int.from_bytes(bytes([0x80, 0x7F, 0xFF] + [0] * 12 + [0x81]), "little")
        row = tool.Insn(0, 4, "pmovmskb", ("r", tool.RAX), ("x", 2), 4)
        machine.regs[tool.RAX] = tool.MASK[8]
        machine.step(row)
        self.assertEqual(machine.regs[tool.RAX], 0x8005)

    def test_tzcnt_of_zero_gives_the_width_and_carry(self):
        machine = self.machine()
        machine.regs[tool.RCX] = 0
        machine.step(tool.Insn(0, 4, "tzcnt", ("r", tool.RAX), ("r", tool.RCX), 4))
        self.assertEqual(machine.regs[tool.RAX], 32)
        self.assertTrue(machine.cf)

    def test_tag_broadcast_fills_all_sixteen_bytes(self):
        machine = self.machine()
        machine.xmm[0] = 0x5A
        for op, target in (("punpcklbw", None), ("pshuflw", 0), ("pshufd", 0x44)):
            machine.step(tool.Insn(0, 4, op, ("x", 0), ("x", 0), 16, target=target))
        self.assertEqual(machine.xmm[0], int.from_bytes(b"\x5a" * 16, "little"))


class Specification(unittest.TestCase):
    def test_zero_size_comes_first(self):
        self.assertEqual(tool.spec(tool.Case(0, index=9, halt="flagged"))[1], tool.TAG_ZERO)

    def test_half_is_inclusive_and_floored(self):
        self.assertEqual(tool.spec(tool.Case(500, 1001))[1], tool.TAG_OK)
        self.assertEqual(tool.spec(tool.Case(501, 1001))[1], tool.TAG_HALF)

    def test_wrapped_product_is_not_compared(self):
        case = tool.Case(1 << 63, tool.MASK[8], 0, 1)
        self.assertEqual(case.sz * 10 & tool.MASK[8], 0)
        self.assertEqual(tool.spec(case)[1], tool.TAG_HALF)


class RealBytes(unittest.TestCase):
    def test_every_copy_matches_the_specification(self):
        for copy in tool.COPIES:
            self.assertIsNone(tool.run_all(tool.Harness(IMAGE, copy), tool.named_cases()))

    def test_size_edge_in_every_copy(self):
        for copy in range(3):
            self.assertEqual(verdict(tool.Case(500, 1000), copy)[1], tool.TAG_OK)
            self.assertEqual(verdict(tool.Case(501, 1000), copy)[1], tool.TAG_HALF)

    def test_supply_zero_and_one_refuse_every_size(self):
        self.assertEqual(verdict(tool.Case(1, 0))[1], tool.TAG_HALF)
        self.assertEqual(verdict(tool.Case(1, 1))[1], tool.TAG_HALF)

    def test_wrapped_product_is_refused_with_a_huge_supply(self):
        self.assertEqual(verdict(tool.Case(1 << 63, tool.MASK[8], 0, 1))[1], tool.TAG_HALF)

    def test_outcome_error_carries_payload_seven(self):
        self.assertEqual(verdict(tool.Case(1, outcome=2, flag=1))[:3], ("tag", tool.TAG_OUTCOME, 7))
        self.assertEqual(verdict(tool.Case(1, outcome=2, flag=0))[1], tool.TAG_OK)

    def test_missing_halt_entry_counts_as_halted(self):
        self.assertEqual(verdict(tool.Case(1, halt="absent"))[1], tool.TAG_HALTED)
        self.assertEqual(verdict(tool.Case(1, halt="no_root"))[1], tool.TAG_HALTED)

    def test_missing_supply_entry_is_invalid_size(self):
        self.assertEqual(verdict(tool.Case(1, supply=None))[1], tool.TAG_SIZE)

    def test_panics_carry_their_location(self):
        self.assertEqual(verdict(tool.Case(1, index=3))[:2], ("panic", tool.BOUNDS_META))
        self.assertEqual(verdict(tool.Case(1, token=16, token_count=16))[:2], ("panic", tool.BOUNDS_TOKEN))
        self.assertEqual(verdict(tool.Case(1, sz_decimals=0, wei_decimals=20))[:2], ("panic", tool.SCALE_PANIC))

    def test_empty_map_never_calls_the_hash(self):
        self.assertEqual(verdict(tool.Case(1, fallback="empty", record="same"))[3], ("outcome",))

    def test_wrong_vault_offset_is_seen(self):
        wrong = dict(tool.COPIES[1], vault=0x8D0)
        self.assertIsNotNone(tool.run_all(tool.Harness(IMAGE, wrong), tool.named_cases()))

    def test_call_target_of_the_third_copy_is_not_modelled_by_the_first_lookup(self):
        wrong = dict(tool.COPIES[2], supply=tool.COPIES[0]["supply"])
        self.assertIn("stopped", tool.run_all(tool.Harness(IMAGE, wrong), tool.named_cases()))

    def test_flipped_ja_is_seen(self):
        at = FULL["tails"][0][2]
        self.assertEqual(IMAGE.blob[IMAGE.offset(at)], 0x77)
        self.assertIsNotNone(patched(at, 0x76))

    def test_shift_turned_left_is_seen(self):
        at = FULL["tails"][0][2] - 3 - 1
        self.assertEqual(IMAGE.blob[IMAGE.offset(at)], 0xEB)
        self.assertIsNotNone(patched(at, 0xE3))

    def test_every_mutant_but_the_equal_dword_is_killed(self):
        rows = FULL["mutations"]
        self.assertGreater(len(rows), 120)
        self.assertEqual([row[:2] for row in rows if row[2] != "killed"], [(0x445F3CD, "immediate")])

    def test_every_branch_ran_both_ways(self):
        self.assertTrue(all(row[2] and row[3] for row in FULL["branches"]))


class WholeDomain(unittest.TestCase):
    def test_ladder_has_one_row_per_k(self):
        rows = FULL["ladder"]
        self.assertEqual([row[0] for row in rows], list(range(20)))
        self.assertEqual(rows[19][1], 10 ** 19)
        self.assertEqual(rows[19][3], 1)
        self.assertEqual(rows[0][4], "")

    def test_size_used_before_the_final_mul_fails(self):
        row = tool.Insn(0x100, 3, "test", ("r", tool.RDX), ("r", tool.RDX))
        with self.assertRaises(tool.EvidenceError):
            tool.taint_walk([row])

    def test_path_without_the_final_mul_fails(self):
        with self.assertRaises(tool.EvidenceError):
            tool.taint_walk([])

    def test_damaged_final_block_fails(self):
        with self.assertRaises(tool.EvidenceError):
            tool.amount_row_rules(DAMAGED)

    def test_damaged_comparison_fails(self):
        with self.assertRaises(tool.EvidenceError):
            tool.tail_facts(DAMAGED, tool.COPIES[0])

    def test_tails_hold_in_every_copy(self):
        self.assertEqual(len(FULL["tails"]), 3)
        self.assertEqual(FULL["threshold_runs"] % 3, 0)


class Static(unittest.TestCase):
    def test_copies_differ_only_in_the_listed_rows(self):
        self.assertEqual([len(row[3]) for row in FULL["differences"]], [2, 1])

    def test_damaged_copy_fails_the_compare(self):
        with self.assertRaises(tool.EvidenceError):
            tool.copy_differences(DAMAGED)

    def test_lookup_copies_are_equal(self):
        self.assertEqual(FULL["lookups"][0][2], FULL["lookups"][1][2])

    def test_damaged_lookup_fails(self):
        with self.assertRaises(tool.EvidenceError):
            tool.lookup_copies(DAMAGED)

    def test_tag_texts(self):
        texts = {row[0]: row[3] for row in FULL["tags"]}
        self.assertEqual(texts[tool.TAG_HALF], "Order size cannot be larger than half of total supply.")
        self.assertEqual(texts[tool.TAG_FALLBACK], "Cannot trade fallback token")
        self.assertEqual(texts[tool.TAG_REDUCE], "Reduce-only is invalid for spot trading.")

    def test_outcome_text(self):
        self.assertEqual(FULL["outcome_prefix"], "Outcome error: ")
        self.assertEqual(FULL["outcome_text"][2], "Internal")

    def test_tag_census_has_three_writes_and_one_call_operand(self):
        kinds = [row[2] for row in FULL["census"]]
        self.assertEqual(kinds.count("gate write"), 3)
        self.assertEqual(len(kinds), 4)
        self.assertGreater(len(tool.tag_writes(IMAGE, tool.TAG_OK)), 100)

    def test_six_call_sites(self):
        self.assertEqual(len(FULL["callers"]), 6)
        self.assertEqual({row[3] for row in FULL["callers"]}, {"0x80"})

    def test_field_rows_bind_the_key_to_the_offset(self):
        rows = FULL["fields"]
        self.assertEqual(rows[0][3:], ("meta", tool.META_VALUE_LEA, tool.TOKENS))
        self.assertEqual({row[5] for row in rows[1:]}, {tool.SUPPLY_ROOT})
        self.assertEqual(len(rows), 7)

    def test_damaged_key_fails(self):
        with self.assertRaises(tool.EvidenceError):
            tool.field_rows(DAMAGED)

    def test_panic_paths_are_short_names(self):
        for _, path, _, _ in FULL["locations"]:
            self.assertTrue(path.startswith("l1/"))

    def test_no_pointer_to_a_gate(self):
        self.assertEqual(FULL["gate_slots"], [])


class Files(unittest.TestCase):
    def test_folder_matches_a_fresh_run(self):
        files = tool.render(FULL)
        for name, text in files.items():
            self.assertEqual((FOLDER / name).read_text(encoding="ascii"), text, name)
        kept = {path.name for path in FOLDER.iterdir()} - {"README.md", "MANIFEST.sha256"}
        self.assertEqual(kept, set(files))

    def test_summary_is_json_and_sorted(self):
        summary = json.loads(tool.render(FULL)["evidence.json"])
        self.assertEqual(summary["sha256"], tool.SHA256)
        self.assertEqual(summary["outcome_payload_7"]["text"], "Internal")


if __name__ == "__main__":
    unittest.main()
