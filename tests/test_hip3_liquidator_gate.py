import json
import pathlib
import random
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import hip3_liquidator_gate as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-004-hip3-liquidator-amount-gate-94"
IMAGE = None
DAMAGED = None
FULL = None


def setUpModule():
    global IMAGE, DAMAGED, FULL
    IMAGE = tool.load_image()
    blob = bytearray(IMAGE.blob)
    at = IMAGE.offset(tool.COPIES[0]["gate"] + 0x4F)
    blob[at + 2] ^= 1
    DAMAGED = tool.Image(blob)
    FULL = tool.analyse(IMAGE)


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
        source = (ROOT / "tools" / "hip3_liquidator_gate.py").read_text()
        for word in ("subprocess", "os.system", "objdump -d"):
            self.assertNotIn(word, source)


class RotateProof(unittest.TestCase):
    def test_proof_constants_hold(self):
        proof = tool.multiple_proof()
        self.assertEqual(proof["multiples_in_u64"], 18446744074)

    def test_rotate_test_matches_remainder(self):
        source = random.Random(94)
        for _ in range(20000):
            value = source.getrandbits(64)
            self.assertEqual(tool.rotated(value) < tool.BOUND, value % tool.STEP == 0)
            multiple = source.getrandbits(34) * tool.STEP & tool.MASK[8]
            self.assertLess(tool.rotated(multiple - multiple % tool.STEP), tool.BOUND)

    def test_wrong_multiplier_fails(self):
        saved = tool.INVERSE
        tool.INVERSE = saved ^ 2
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.multiple_proof()
        finally:
            tool.INVERSE = saved

    def test_wrong_bound_fails(self):
        saved = tool.BOUND
        tool.BOUND = saved + 1
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.multiple_proof()
        finally:
            tool.BOUND = saved

    def test_classes_cover_u64(self):
        rows = tool.amount_classes()
        self.assertEqual(sum(row[3] for row in rows), 1 << 64)
        self.assertEqual(rows[2][3], 922337203)
        self.assertEqual(rows[2][2], 922337203000000000)

    def test_first_escape_is_below_the_step(self):
        self.assertLess(tool.FIRST_ESCAPE, tool.STEP)
        self.assertEqual(tool.rotated(tool.FIRST_ESCAPE), tool.BOUND)


class RealBytes(unittest.TestCase):
    def test_every_copy_matches_the_specification(self):
        for copy in tool.COPIES:
            harness = tool.Harness(IMAGE, copy)
            self.assertIsNone(tool.run_all(harness, tool.named_cases()))

    def test_order_of_checks(self):
        harness = tool.Harness(IMAGE, tool.COPIES[1])
        self.assertEqual(harness.run_case(tool.Case(0, 1, 101, 101))[1], tool.TAG_BAD_LENGTH)
        self.assertEqual(harness.run_case(tool.Case(tool.CAP, 1, 3, 3, False))[1], tool.TAG_BAD_NUMBER)
        self.assertEqual(harness.run_case(tool.Case(0, 0, 3, 3, False))[1], tool.TAG_WITHDRAW_ZERO)
        self.assertEqual(harness.run_case(tool.Case(1, 1, 3, 3, False, 0))[1], tool.TAG_MULTIPLE)

    def test_cap_reports_its_value(self):
        harness = tool.Harness(IMAGE, tool.COPIES[2])
        self.assertEqual(harness.run_case(tool.Case(tool.CAP + 7))[2], tool.CAP + 7)

    def test_success_keeps_the_name(self):
        harness = tool.Harness(IMAGE, tool.COPIES[0])
        self.assertEqual(harness.run_case(tool.Case(tool.TOP_MULTIPLE)), ("runner", tool.TAG_OK, None, 0))
        self.assertEqual(harness.freed, [])

    def test_wrong_registry_offset_is_seen(self):
        wrong = dict(tool.COPIES[1], registry=0x5B8)
        harness = tool.Harness(IMAGE, wrong)
        self.assertIn("stopped", tool.run_all(harness, tool.named_cases()))

    def test_flipped_bound_byte_is_seen(self):
        copy = tool.COPIES[0]
        at = copy["gate"] + 0x75 + 2
        data = IMAGE.blob[IMAGE.offset(at)]
        harness = tool.Harness(IMAGE, copy, {at: data ^ 1})
        self.assertIsNotNone(tool.run_all(harness, tool.named_cases()))

    def test_flipped_cap_jump_is_seen(self):
        copy = tool.COPIES[0]
        at = copy["gate"] + 0x5C
        data = IMAGE.blob[IMAGE.offset(at)]
        harness = tool.Harness(IMAGE, copy, {at: data ^ 1})
        self.assertIsNotNone(tool.run_all(harness, tool.named_cases()))

    def test_swapped_zero_tag_is_seen(self):
        copy = tool.COPIES[2]
        at = copy["gate"] + 0xBC
        self.assertEqual(IMAGE.blob[IMAGE.offset(at)], 0x84)
        harness = tool.Harness(IMAGE, copy, {at: 0x85})
        self.assertIsNotNone(tool.run_all(harness, tool.named_cases()))

    def test_every_mutant_is_killed(self):
        rows = FULL["mutations"]
        self.assertGreater(len(rows), 60)
        self.assertEqual([row for row in rows if row[3] != "killed"], [])

    def test_only_the_landing_pad_is_unreached(self):
        self.assertEqual(len(FULL["missing"]), 6)
        self.assertTrue(all(":" in row for row in FULL["missing"]))


class Wrappers(unittest.TestCase):
    def test_success_and_error_bytes(self):
        for copy in tool.COPIES:
            harness = tool.Harness(IMAGE, copy)
            self.assertEqual(harness.run_wrapper(tool.Case(), None), tool.WRAPPER_OK)
            self.assertEqual(harness.run_wrapper(tool.Case(), bytes(range(tool.RESULT_SIZE))), tool.WRAPPER_ERROR)

    def test_wrong_kind_byte_is_seen(self):
        copy = tool.COPIES[0]
        at = copy["wrapper"] + 0x93
        self.assertEqual(IMAGE.blob[IMAGE.offset(at)], tool.WRAPPER_OK)
        harness = tool.Harness(IMAGE, copy, {at: tool.WRAPPER_ERROR})
        with self.assertRaises(tool.Halt):
            harness.run_wrapper(tool.Case(), None)


class Static(unittest.TestCase):
    def test_ntl_has_only_the_pinned_readers(self):
        for copy in tool.COPIES:
            found, _ = tool.amount_uses(IMAGE, copy["gate"])
            self.assertEqual(sorted(found), sorted(tool.AMOUNT_READS))

    def test_gate_reads_no_state_memory(self):
        for copy in tool.COPIES:
            self.assertEqual(tool.state_reads(IMAGE, copy["gate"]), [])

    def test_state_scan_sees_a_read(self):
        row = tool.Insn(0x100, 4, "mov", ("r", tool.RAX), ("m", tool.R15, None, 1, 8, False))
        saved = tool.decode_range
        tool.decode_range = lambda image, low, high: [row]
        try:
            self.assertEqual(tool.state_reads(IMAGE, tool.COPIES[0]["gate"]), [0x100])
        finally:
            tool.decode_range = saved

    def test_constants_in_all_copies(self):
        for copy in tool.COPIES:
            self.assertEqual(tool.constants_of(IMAGE, copy["gate"]), ([tool.CAP, tool.INVERSE, tool.BOUND], 9, 101))

    def test_damaged_constant_fails(self):
        with self.assertRaises(tool.EvidenceError):
            tool.constants_of(DAMAGED, tool.COPIES[0]["gate"])

    def test_copies_differ_only_in_the_listed_rows(self):
        rows = tool.copy_differences(IMAGE)
        self.assertEqual([len(row[3]) for row in rows], [2, 1])

    def test_damaged_copy_fails_the_compare(self):
        with self.assertRaises(tool.EvidenceError):
            tool.copy_differences(DAMAGED)

    def test_tag_texts(self):
        texts = {row[0]: row[3] for row in FULL["tags"]}
        self.assertEqual(texts[0x185], "Must deposit or withdraw multiple of 1000 quote tokens")
        self.assertEqual(texts[0x2F], "Deposit amount cannot be zero.")
        self.assertEqual(texts[0x30], "Withdrawal amount cannot be zero.")

    def test_tag_writes_are_the_three_gates(self):
        self.assertEqual(len(FULL["tag_sites"]), 3)
        self.assertGreater(len(tool.tag_writes(IMAGE, tool.TAG_OK)), 100)

    def test_field_lists_name_three_fields(self):
        self.assertTrue(FULL["fields"])
        for _, names in FULL["fields"]:
            self.assertEqual(names, ["dex", "ntl", "isDeposit"])

    def test_no_pointer_to_a_gate(self):
        self.assertEqual(FULL["indirect"], [])


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
        self.assertEqual(summary["admitted_values"], 922337203)


if __name__ == "__main__":
    unittest.main()
