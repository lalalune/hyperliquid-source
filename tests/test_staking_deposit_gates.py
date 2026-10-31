"""Tests for tools/staking_deposit_gates.py: real node #94 bytes with corruption controls."""

import copy
import hashlib
import importlib.util
import json
import pathlib
import struct
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FOLDER = ROOT / "research" / "work-items" / "RE-004-staking-deposit-gates-94"
spec_ = importlib.util.spec_from_file_location("staking_deposit_gates", ROOT / "tools" / "staking_deposit_gates.py")
tool = importlib.util.module_from_spec(spec_)
sys.modules["staking_deposit_gates"] = tool
spec_.loader.exec_module(tool)

IMAGE = None
HARNESS = None
RESULT = None


def setUpModule():
    global IMAGE, HARNESS, RESULT
    IMAGE = tool.load_image()
    HARNESS = tool.Harness(IMAGE)
    RESULT = tool.analyse(IMAGE)


def run(kind=tool.COPIES[0], **fields):
    case = tool.Case("t", kind, **fields)
    got = HARNESS.run(case)
    assert got == tool.spec_run(case, HARNESS.before, HARNESS.table), case.__dict__
    return got


def status(got):
    return struct.unpack_from("<H", got[2], tool.OUT - tool.HEAP_BASE)[0]


def names(got):
    return [event[0] for event in got[1]]


def corrupted(va, value):
    bad = copy.copy(IMAGE)
    data = bytearray(IMAGE.blob)
    data[IMAGE.offset(va)] = value
    bad.blob = bytes(data)
    bad.relative_map = None
    return bad


class Identity(unittest.TestCase):
    def test_digest_is_the_target(self):
        self.assertEqual(hashlib.sha256(IMAGE.blob).hexdigest(), tool.SHA256)

    def test_wrong_digest_fails(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_nobits_section_does_not_resolve(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.offset(IMAGE.named[".bss"]["address"])

    def test_fdes_are_exact(self):
        self.assertEqual(IMAGE.exact_fde(tool.COPIES[0]), (0x2734840, 0x2734CA9))
        self.assertEqual(IMAGE.exact_fde(tool.COPIES[1]), (0x4D40EB0, 0x4D41319))
        self.assertEqual(IMAGE.exact_fde(tool.COPIES[2]), (0x4D44E60, 0x4D452F2))
        for target in tool.TARGETS:
            with self.assertRaises(tool.EvidenceError):
                IMAGE.exact_fde(target + 1)

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

    def test_manifest_matches(self):
        rows = (FOLDER / "MANIFEST.sha256").read_text().splitlines()
        names_ = sorted(p.name for p in FOLDER.iterdir() if p.name != "MANIFEST.sha256")
        self.assertEqual([row.split("  ")[1] for row in rows], names_)
        for row in rows:
            digest, name = row.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_no_external_program(self):
        text = (ROOT / "tools" / "staking_deposit_gates.py").read_text()
        self.assertNotIn("subprocess", text)

    def test_evidence_counts(self):
        data = json.loads((FOLDER / "evidence.json").read_text())
        self.assertEqual(data["named_cases"], 3 * len(tool.NAMED))
        self.assertEqual(data["functions"]["core_a"]["instructions"], 244)
        self.assertEqual(data["functions"]["core_c"]["instructions"], 260)


class Gates(unittest.TestCase):
    def test_every_copy_passes_plain(self):
        for kind in tool.COPIES:
            self.assertEqual(status(run(kind)), tool.TAG_OK)

    def test_cap(self):
        got = run(x=tool.CAP)
        self.assertEqual(status(got), tool.TAG_NUMBER)
        self.assertEqual(struct.unpack_from("<Q", got[2], tool.OUT - tool.HEAP_BASE + 8)[0], tool.CAP)
        self.assertEqual(status(run(x=tool.CAP - 1, balances={7: (tool.MASK[8], 0, 0)})), tool.TAG_OK)

    def test_order_of_first_three(self):
        self.assertEqual(status(run(x=tool.CAP, native_some=0)), tool.TAG_NUMBER)
        self.assertEqual(status(run(x=0, native_some=0)), tool.TAG_NO_NATIVE)
        self.assertEqual(status(run(x=0)), tool.TAG_ZERO)

    def test_native_byte_any_nonzero(self):
        self.assertEqual(status(run(native_some=0x80)), tool.TAG_OK)

    def test_room_edge(self):
        self.assertEqual(status(run(x=4000)), tool.TAG_OK)
        self.assertEqual(status(run(x=4001)), tool.TAG_FUNDS)

    def test_hold_sum_wraps_to_refusal(self):
        self.assertEqual(status(run(balances={7: (tool.MASK[8], tool.MASK[8] - 2, 0)}, x=3)), tool.TAG_FUNDS)
        self.assertEqual(status(run(balances={7: (tool.MASK[8], tool.MASK[8] - 2, 0)}, x=2)), tool.TAG_OK)

    def test_absent_row_refuses(self):
        self.assertEqual(status(run(shape="none")), tool.TAG_FUNDS)
        self.assertEqual(status(run(balances={9: (5000, 0, 0)})), tool.TAG_FUNDS)

    def test_tree_descent(self):
        self.assertEqual(status(run(shape="deep", balances=tool.LADDER, native=3, x=9)), tool.TAG_OK)
        self.assertEqual(status(run(shape="deep", balances=tool.LADDER, native=4)), tool.TAG_FUNDS)

    def test_stake_runs_before_debit(self):
        got = run(debit_ok=False)
        self.assertEqual(status(got), tool.TAG_FUNDS)
        self.assertEqual(names(got)[-2:], ["stake", "debit"])

    def test_stake_failure_copies_record(self):
        got = run(stake_tag=0xBE)
        at = tool.OUT - tool.HEAP_BASE
        self.assertEqual(got[2][at:at + tool.OUT_SIZE], tool.failure_body(0xBE))
        self.assertNotIn("debit", names(got))

    def test_event_amount_is_float_over_power(self):
        got = run(x=4000, wei=2)
        row = [event for event in got[1] if event[0] == "event"][0]
        self.assertEqual(struct.unpack("<d", row[5])[0], 40.0)

    def test_mode_one_only_calls_ledger(self):
        self.assertIn("ledger", names(run(mode=1)))
        self.assertNotIn("ledger", names(run(mode=2)))
        self.assertNotIn("ledger", names(run(mode=0x101)))

    def test_third_copy_tail(self):
        got = run(tool.COPIES[2])
        self.assertEqual(names(got)[-2:], ["event_dex", "after_dex"])
        self.assertNotIn("event", names(got))

    def test_token_bound_panics_after_add(self):
        got = run(tokens=7)
        self.assertEqual(got[:2], ("panic", "index"))
        self.assertEqual(got[2][-1][0], "name")

    def test_depth_saturates(self):
        got = run(depth=tool.MASK[8])
        self.assertEqual(struct.unpack_from("<Q", got[2], tool.STATE + tool.S_DEPTH - tool.HEAP_BASE)[0], tool.MASK[8] - 1)

    def test_outcomes_for_all_copies(self):
        for kind in tool.COPIES:
            self.assertEqual(len(RESULT["outcomes"][kind]), len(tool.NAMED))


class Static(unittest.TestCase):
    def test_constants(self):
        self.assertEqual({row[2] for row in RESULT["constants"]}, {"0xccccccccccccccc"})

    def test_cap_scan_fails_on_edit(self):
        bad = corrupted(0x273486F, IMAGE.blob[IMAGE.offset(0x273486F)] ^ 1)
        with self.assertRaises(ValueError):
            tool.constant_rows(bad)

    def test_status_text(self):
        rows = {row[0]: row[2] for row in RESULT["statuses"]}
        self.assertEqual(rows["0x2c"], "Insufficient funds available to deposit.")
        self.assertEqual(rows["0x2f"], "Deposit amount cannot be zero.")

    def test_slot_control(self):
        bad = copy.copy(IMAGE)
        bad.relative = lambda: {}
        with self.assertRaises(tool.EvidenceError):
            tool.slot_rows(bad)

    def test_pieces_walk_equal_rows(self):
        self.assertEqual(len(RESULT["pieces"]), 12)
        self.assertTrue(all(row[6] for row in RESULT["pieces"]))
        statuses = [row[3] for row in RESULT["pieces"][::3]]
        self.assertEqual(statuses, ["0x2f", "0x186", "0x2c", "0x13f"])


class Mutations(unittest.TestCase):
    def test_counts(self):
        rows = RESULT["mutations"]
        self.assertGreater(len(rows), 200)
        self.assertFalse([row for row in rows if row[3] == "UNEXPLAINED"])

    def test_survivors_are_listed(self):
        survivors = {(row[0], row[1]) for row in RESULT["mutations"] if row[2] == "survived"}
        self.assertEqual(survivors, set(tool.EXPECTED_SURVIVORS))

    def test_cap_edit_is_caught(self):
        harness = tool.Harness(IMAGE, {0x273486F: IMAGE.blob[IMAGE.offset(0x273486F)] ^ 1})
        self.assertIsNotNone(tool.first_failure(harness, tool.named_cases(tool.COPIES[0])))

    def test_room_edit_is_caught(self):
        harness = tool.Harness(IMAGE, {0x27349B3: IMAGE.blob[IMAGE.offset(0x27349B3)] ^ 1})
        self.assertIsNotNone(tool.first_failure(harness, tool.named_cases(tool.COPIES[0])))

    def test_unedited_image_passes(self):
        self.assertIsNone(tool.first_failure(tool.Harness(IMAGE), tool.named_cases(tool.COPIES[2])))


if __name__ == "__main__":
    unittest.main()
