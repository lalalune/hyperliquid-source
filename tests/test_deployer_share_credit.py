"""Tests for tools/deployer_share_credit.py: real node #94 bytes with corruption controls."""

import copy
import hashlib
import importlib.util
import pathlib
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FOLDER = ROOT / "research" / "work-items" / "RE-004-deployer-share-credit-94"
spec_ = importlib.util.spec_from_file_location("deployer_share_credit", ROOT / "tools" / "deployer_share_credit.py")
tool = importlib.util.module_from_spec(spec_)
sys.modules["deployer_share_credit"] = tool
spec_.loader.exec_module(tool)

IMAGE = None
HARNESS = None
RESULT = None


def setUpModule():
    global IMAGE, HARNESS, RESULT
    IMAGE = tool.load_image()
    HARNESS = tool.Harness(IMAGE)
    RESULT = tool.analyse(IMAGE)


def edited(edits):
    """A copy of the image with file bytes replaced at virtual addresses."""
    clone = copy.copy(IMAGE)
    data = bytearray(IMAGE.blob)
    for va, value in edits.items():
        data[IMAGE.offset(va)] = value
    clone.blob = bytes(data)
    return clone


def byte_at(va):
    return IMAGE.blob[IMAGE.offset(va)]


def credit(harness, case):
    outcome = harness.run(case)
    return struct.unpack_from("<Q", outcome[1], 0x20)[0]


class Identity(unittest.TestCase):
    def test_digest_is_the_target(self):
        self.assertEqual(hashlib.sha256(IMAGE.blob).hexdigest(), tool.SHA256)

    def test_wrong_digest_fails(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_nobits_section_does_not_resolve(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.offset(IMAGE.named[".bss"]["address"])

    def test_fde_is_exact(self):
        self.assertEqual(IMAGE.exact_fde(tool.TARGET), (0x3C01BF0, 0x3C01DC6))
        with self.assertRaises(tool.EvidenceError):
            IMAGE.exact_fde(tool.TARGET + 1)

    def test_address_past_the_text_fails(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.offset(1 << 40)


class Files(unittest.TestCase):
    def test_tool_output_matches_the_folder(self):
        files = tool.render(RESULT)
        for name, text in files.items():
            self.assertEqual((FOLDER / name).read_text(encoding="ascii"), text, name)
        on_disk = {p.name for p in FOLDER.iterdir()} - {"README.md", "MANIFEST.sha256"}
        self.assertEqual(on_disk, set(files))

    def test_manifest(self):
        rows = (FOLDER / "MANIFEST.sha256").read_text().splitlines()
        names = {p.name for p in FOLDER.iterdir()} - {"MANIFEST.sha256"}
        self.assertEqual({row.split("  ")[1] for row in rows}, names)
        for row in rows:
            digest, name = row.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_output_writes(self):
        with tempfile.TemporaryDirectory() as folder:
            target = pathlib.Path(folder) / "out"
            original = tool.analyse
            tool.analyse = lambda image: RESULT
            try:
                self.assertEqual(tool.main(["--out", str(target)]), 0)
            finally:
                tool.analyse = original
            self.assertTrue((target / "evidence.json").is_file())


class Anchors(unittest.TestCase):
    def fields(self, rows):
        return {offset: key for _, offset, _, key in rows}

    def test_token_fields(self):
        fields = self.fields(RESULT["token_fields"])
        self.assertEqual(fields[0xA8], "deployer_trading_fee_share")
        self.assertEqual(fields[0xD2], "deployer")

    def test_spot_meta_fields(self):
        fields = self.fields(RESULT["meta_fields"])
        self.assertEqual(fields[0x250], "quote_token_to_status")
        self.assertEqual(fields[0x220], "quote_token_to_aligned_quote_token_info")
        self.assertEqual(fields[0x178], "token_infos")

    def test_changed_key_byte_changes_the_row(self):
        address = next(c for _, offset, c, _ in RESULT["meta_fields"] if offset == 0x250)
        clone = edited({address: byte_at(address) ^ 1})
        fields = self.fields(tool.serde_fields(clone, tool.SPOT_META_SERIALIZER))
        self.assertNotEqual(fields[0x250], "quote_token_to_status")

    def test_one_call_site_through_the_slot(self):
        self.assertEqual(RESULT["callers"], [0x271AFAA])
        self.assertEqual(RESULT["direct"], [])

    def test_slot_holds_the_function(self):
        self.assertEqual(IMAGE.relative()[tool.SLOT_TARGET], tool.TARGET)

    def test_a_slot_with_no_calls_is_empty(self):
        self.assertEqual(tool.calls_through(IMAGE, 0x10), [])

    def test_panic_location(self):
        self.assertEqual(RESULT["location"], ("l1/src/spot_meta.rs", 113, 33))

    def test_constants_are_pinned(self):
        self.assertEqual(len(RESULT["constants"]), len(tool.CONSTANTS))

    def test_changed_constant_fails(self):
        for va in (tool.ONE_E5, tool.ONE_POINT_ZERO_ONE, 0x20A218):
            with self.assertRaises(tool.EvidenceError):
                tool.constant_rows(edited({va: byte_at(va) ^ 1}))

    def test_pair_census(self):
        self.assertEqual(len(RESULT["sites"]), 8)
        self.assertEqual(sum(0x3C01BF0 <= va < 0x3C01DC6 for va in RESULT["sites"]), 2)

    def test_every_real_row_ran(self):
        self.assertEqual(RESULT["unreached"], [])


class Decisions(unittest.TestCase):
    def test_named_cases_match(self):
        self.assertEqual(RESULT["outcomes"], [tool.spec_run(case) for case in RESULT["named"]])

    def test_vector_count(self):
        self.assertEqual(RESULT["vector_count"], 2500)

    def test_token_in_map_gets_nothing(self):
        for share in (0, 1, 30000, 100000, 200000, tool.MAX_U64):
            for amount in (0, 1, 1 << 40, tool.MAX_U64):
                self.assertEqual(credit(HARNESS, tool.Case(keys=(5,), shape="leaf", share=share, amount=amount)), 0)

    def test_token_outside_map_earns(self):
        self.assertEqual(credit(HARNESS, tool.Case(keys=())), 300000000)
        self.assertEqual(credit(HARNESS, tool.Case(keys=(4, 6), shape="leaf")), 300000000)

    def test_value_byte_is_not_read(self):
        self.assertEqual(HARNESS.run(tool.Case(keys=(5,), shape="leaf")), HARNESS.run(tool.Case(keys=(1, 5), shape="leaf")))

    def test_aligned_membership_alone_changes_nothing(self):
        self.assertEqual(credit(HARNESS, tool.Case(keys=(), shape="none")), 300000000)

    def test_reference_rule_differs_in_two_of_four_states(self):
        self.assertEqual([row[4] for row in RESULT["reference"]], [False, True, True, False])

    def test_only_bit_zero_of_deployer_byte(self):
        self.assertEqual(tool.describe(HARNESS.run(tool.Case(flag=0xFE)))[0], "none")
        self.assertEqual(tool.describe(HARNESS.run(tool.Case(flag=0xFF)))[0], "some")

    def test_panic(self):
        self.assertEqual(HARNESS.run(tool.Case(token=40)), ("panic", tool.PANIC_LOCATION))

    def test_gate_pieces(self):
        self.assertEqual(RESULT["gates"], [(0, 101000, "admitted"), (101001, tool.MAX_U64, "refused")])

    def test_tail_pieces_cover_every_pattern(self):
        rows = RESULT["tails"]
        self.assertEqual(rows[0][0], 0)
        self.assertEqual(rows[-1][1], tool.MAX_U64)
        for left, right in zip(rows, rows[1:]):
            self.assertEqual(left[1] + 1, right[0])

    def test_credit_can_pass_the_amount(self):
        rows = {(share, amount): row for share, amount, *row in RESULT["edges"]}
        self.assertEqual(rows[(101000, 1000000)][0], 1010000)
        self.assertEqual(rows[(100000, 2 ** 64 - 1024)][0], tool.MAX_U64)
        self.assertEqual(rows[(100000, 2 ** 64 - 1025)][0], 2 ** 64 - 2048)

    def test_spec_is_not_integer_arithmetic(self):
        self.assertGreater(sum(row[2] for row in RESULT["rounding"] if row[1] != "same"), 0)

    def test_spec_saturate_edges(self):
        self.assertEqual(tool.spec_saturate(float("nan")), 0)
        self.assertEqual(tool.spec_saturate(float("inf")), 0)
        self.assertEqual(tool.spec_saturate(1e300), tool.MAX_U64)
        self.assertEqual(tool.spec_saturate(-1e300), 0)
        self.assertEqual(tool.spec_saturate(1.9), 1)


class Corruption(unittest.TestCase):
    def fails(self, patch, cases=None):
        harness = tool.Harness(IMAGE, patch)
        harness.machine.step_limit = tool.MUTANT_STEP_LIMIT
        return tool.first_failure(harness, cases or tool.mutant_cases()) is not None

    def test_inverted_found_branch(self):
        self.assertTrue(self.fails({0x3C01C77: byte_at(0x3C01C77) ^ 1}))

    def test_status_field_read_as_aligned_field(self):
        at = 0x3C01C23 + 3
        self.assertEqual(byte_at(at), 0x50)
        self.assertTrue(self.fails({at: 0x20}))

    def test_stale_slot_counted_as_key(self):
        at = 0x3C01C3A + 4
        self.assertEqual(byte_at(at), 0x62)
        self.assertTrue(self.fails({at: 0x60}))

    def test_factor_branch_inverted(self):
        self.assertTrue(self.fails({0x3C01D8E + 1: byte_at(0x3C01D8E + 1) ^ 1}))

    def test_denominator_is_used(self):
        self.assertTrue(self.fails({0x3C01D7A + 2: 0x59}))

    def test_stride_changed(self):
        at = 0x3C01C07 + 3
        self.assertEqual(byte_at(at), 0xE8)
        self.assertTrue(self.fails({at: 0xE0}))

    def test_changed_limit_constant_moves_the_gate(self):
        clone = edited({tool.ONE_POINT_ZERO_ONE + 5: byte_at(tool.ONE_POINT_ZERO_ONE + 5) ^ 8})
        self.assertIsNotNone(tool.first_failure(tool.Harness(clone), tool.mutant_cases()))

    def test_mutation_summary(self):
        rows = RESULT.get("mutations")
        self.assertTrue(rows)
        survived = [row for row in rows if row[2] == "survived"]
        self.assertEqual(len(survived), len(tool.EXPECTED_SURVIVORS))
        self.assertFalse([row for row in rows if row[3] == "UNEXPLAINED"])

    def test_unexplained_survivor_fails_the_tool(self):
        original = tool.run_mutants
        tool.run_mutants = lambda image, rows, seen: [(1, "x", "survived", "UNEXPLAINED")]
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.analyse(IMAGE)
        finally:
            tool.run_mutants = original


if __name__ == "__main__":
    unittest.main()
