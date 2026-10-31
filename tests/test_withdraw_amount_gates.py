"""Tests for tools/withdraw_amount_gates.py: real node #94 bytes with corruption controls."""

import copy
import hashlib
import importlib.util
import json
import pathlib
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FOLDER = ROOT / "research" / "work-items" / "RE-004-withdraw-amount-gates-94"
spec_ = importlib.util.spec_from_file_location("withdraw_amount_gates", ROOT / "tools" / "withdraw_amount_gates.py")
tool = importlib.util.module_from_spec(spec_)
sys.modules["withdraw_amount_gates"] = tool
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
    assert got == tool.spec_run(case, HARNESS.before), case.__dict__
    return got


def status(got):
    return struct.unpack_from("<H", got[2], tool.OUT - tool.HEAP_BASE)[0]


def events(got):
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
        self.assertEqual(IMAGE.exact_fde(tool.COPIES[0]), (0x2734200, 0x273483E))
        self.assertEqual(IMAGE.exact_fde(tool.COPIES[1]), (0x4D49260, 0x4D4989E))
        self.assertEqual(IMAGE.exact_fde(tool.COPIES[2]), (0x4D498A0, 0x4D49EDE))
        self.assertEqual(IMAGE.exact_fde(tool.RECORD), (0x374FCE0, 0x374FE60))
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
        names = sorted(p.name for p in FOLDER.iterdir() if p.name != "MANIFEST.sha256")
        self.assertEqual([row.split("  ")[1] for row in rows], names)
        for row in rows:
            digest, name = row.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_render_is_stable(self):
        self.assertEqual(tool.render(RESULT), tool.render(RESULT))

    def test_no_external_program(self):
        text = (ROOT / "tools" / "withdraw_amount_gates.py").read_text()
        self.assertNotIn("subprocess", text)
        self.assertNotIn("objdump", text.replace("No objdump or readelf output", ""))

    def test_evidence_counts(self):
        data = json.loads((FOLDER / "evidence.json").read_text())
        self.assertEqual(data["sha256"], tool.SHA256)
        self.assertEqual(data["named_cases"], 3 * len(tool.NAMED))
        for name in ("core_a", "core_b", "core_c"):
            self.assertEqual(data["functions"][name]["instructions"], 339)
            self.assertEqual(data["functions"][name]["unreached_rows"], [])


class Gates(unittest.TestCase):
    def test_every_copy_agrees_with_the_rules(self):
        for kind in tool.COPIES:
            self.assertEqual(len(RESULT["outcomes"][kind]), len(tool.NAMED))
            self.assertEqual(status(run(kind)), tool.TAG_OK)

    def test_lengths(self):
        self.assertEqual(status(run(dest_len=100)), tool.TAG_OK)
        self.assertEqual(status(run(dest_len=101)), tool.TAG_LEN)
        self.assertEqual(status(run(usd_len=101)), tool.TAG_LEN)
        got = run(usd_len=101)
        self.assertEqual(struct.unpack_from("<Q", got[2], tool.OUT - tool.HEAP_BASE + 8)[0], tool.ACTION + 0x18)

    def test_window_byte(self):
        got = run(height=5000, gate_height=6000)
        self.assertEqual(status(got), tool.TAG_DISABLED)
        self.assertEqual(got[2][tool.OUT - tool.HEAP_BASE + 2], 1)
        self.assertEqual(run(height=4999, gate_height=6000)[2][tool.OUT - tool.HEAP_BASE + 2], 0)

    def test_window_sum_saturates(self):
        got = run(height=tool.MASK[8] - 1, gate_height=tool.MASK[8], base_word=tool.MASK[8] - 4998)
        self.assertEqual(got[2][tool.OUT - tool.HEAP_BASE + 2], 0)
        got = run(height=tool.MASK[8], gate_height=tool.MASK[8], now=(20000, 100, 4), base_word=tool.MASK[8] - 4999)
        self.assertEqual(got[2][tool.OUT - tool.HEAP_BASE + 2], 1)

    def test_time_order_is_signed_then_unsigned(self):
        self.assertEqual(status(run(now=(0xFFFFFFF0, 200, 200))), tool.TAG_DISABLED)
        self.assertEqual(status(run(now=(20000, 0x80000000, 0), gate=(20000, 1, 0))), tool.TAG_OK)

    def test_flag_needs_exact_one_and_zero_byte(self):
        self.assertEqual(status(run(flag=1, oaw=0)), tool.TAG_BRIDGE)
        self.assertEqual(status(run(flag=2, oaw=0)), tool.TAG_OK)
        self.assertEqual(status(run(flag=1, oaw=2)), tool.TAG_OK)

    def test_nonce_scale_overflow(self):
        self.assertEqual(status(run(nonce=tool.MASK[8] // 1000)), tool.TAG_OK)
        got = run(nonce=tool.MASK[8] // 1000 + 1)
        self.assertEqual(status(got), tool.TAG_NONCE)
        self.assertEqual(got[2][tool.NONCE_TEXT - tool.HEAP_BASE:tool.NONCE_TEXT - tool.HEAP_BASE + 11], b"nonce error")

    def test_absent_key_counts_as_zero(self):
        self.assertEqual(status(run(nonce=0, table="miss")), tool.TAG_NONCE_USED)
        self.assertEqual(status(run(nonce=0, table="skip", items=0)), tool.TAG_NONCE_USED)
        self.assertEqual(status(run(nonce=1, table="skip", items=0)), tool.TAG_OK)

    def test_stored_nonce_is_strict(self):
        self.assertEqual(status(run(table="hit", nonce=5, stored=4999)), tool.TAG_OK)
        self.assertEqual(status(run(table="hit", nonce=5, stored=5000)), tool.TAG_NONCE_USED)
        self.assertEqual(status(run(table="hit_second", nonce=5, stored=5000)), tool.TAG_NONCE_USED)

    def test_probe_positions(self):
        for table in ("hit_first", "hit_next", "hit_second", "hit_last_group"):
            self.assertEqual(status(run(table=table, nonce=5, stored=5000)), tool.TAG_NONCE_USED, table)

    def test_amount_ladder(self):
        self.assertEqual(status(run(x=0)), tool.TAG_ZERO)
        self.assertEqual(status(run(x=500, bal=499)), tool.TAG_BRIDGE)
        self.assertEqual(status(run(x=tool.CAP)), tool.TAG_OK)
        self.assertEqual(status(run(x=tool.CAP + 1)), tool.TAG_LIMIT)
        self.assertEqual(events(run(x=tool.MARK_LEVEL - 1)).count("mark"), 0)
        self.assertEqual(events(run(x=tool.MARK_LEVEL)).count("mark"), 1)
        self.assertEqual(events(run(x=tool.CAP + 1)).count("mark"), 1)

    def test_level_changes_no_state(self):
        below = run(x=tool.MARK_LEVEL - 1)
        at = run(x=tool.MARK_LEVEL)
        self.assertEqual(below[2], at[2])

    def test_balance_gate_comes_before_cap(self):
        self.assertEqual(status(run(x=tool.CAP + 1, bal=tool.CAP)), tool.TAG_BRIDGE)

    def test_cap_comes_before_destination(self):
        got = run(x=tool.CAP + 1, dest_tag=7)
        self.assertEqual(status(got), tool.TAG_LIMIT)
        self.assertNotIn("dest", events(got))

    def test_bad_destination_keeps_only_0xb6(self):
        self.assertEqual(status(run(dest_tag=7)), tool.TAG_ADDRESS)
        self.assertEqual(status(run(dest_tag=0x286)), tool.TAG_ADDRESS)

    def test_record_takes_the_debit_result_and_volume_the_parsed_amount(self):
        got = run(x=5000000, net=4000000)
        table = dict((event[0], event[1:]) for event in got[1])
        self.assertEqual(table["insert"], (5000, 4000000))
        self.assertEqual(table["volume"], ((-5000000) & tool.MASK[8],))
        at = tool.STATE + tool.S_BRIDGE + tool.BRIDGE_BAL - tool.HEAP_BASE
        self.assertEqual(struct.unpack_from("<Q", got[2], at)[0], (1 << 60) - 4000000)

    def test_failed_debit_leaves_no_record(self):
        got = run(debit_tag=0x5C)
        self.assertEqual(status(got), 0x5C)
        self.assertNotIn("insert", events(got))

    def test_row_gets_scaled_nonce_and_clears_flag(self):
        got = run(nonce=7)
        at = tool.ROW_AT - tool.HEAP_BASE
        self.assertEqual(struct.unpack_from("<Q", got[2], at)[0], 7000)
        self.assertEqual(got[2][at + tool.ROW_PENDING], 0)

    def test_third_copy_uses_shifted_state(self):
        got = run(tool.COPIES[2])
        at = tool.STATE + 0xA80 + tool.S_BRIDGE + tool.BRIDGE_BAL - tool.HEAP_BASE
        self.assertEqual(struct.unpack_from("<Q", got[2], at)[0], (1 << 60) - 4000000)

    def test_panics(self):
        self.assertEqual(run(dex_len=0)[:2], ("panic", "dex"))
        self.assertEqual(run(x=500, bal=500, net=501)[:2], ("panic", "balance"))
        self.assertEqual(run(insert_tag=0x9A)[:2], ("panic", "unwrap"))

    def test_depth_word_saturates(self):
        for depth, last in ((0, 0), (tool.MASK[8], tool.MASK[8] - 1), (tool.MASK[8] - 1, tool.MASK[8] - 1)):
            got = run(depth=depth)
            self.assertEqual(struct.unpack_from("<Q", got[2], tool.STATE + tool.S_DEPTH - tool.HEAP_BASE)[0], last)


class Static(unittest.TestCase):
    def test_constants_in_each_copy(self):
        self.assertEqual(len(RESULT["constants"]), 3)
        for row in RESULT["constants"]:
            self.assertEqual(row[2], 10 ** 13)
            self.assertEqual(row[5], 3 * 10 ** 12)

    def test_constant_scan_fails_on_edited_cap(self):
        bad = corrupted(0x2734628, IMAGE.blob[IMAGE.offset(0x2734628)] ^ 1)
        with self.assertRaises(ValueError):
            tool.constant_rows(bad)

    def test_status_text(self):
        rows = {row[0]: row[2] for row in RESULT["statuses"]}
        self.assertEqual(rows["0x28"], "Withdrawal amount over single withdrawal limit.")
        self.assertEqual(rows["0x27"], "Error withdrawing from bridge")
        self.assertEqual(rows["0x75"], "Withdrawals disabled {}")
        self.assertEqual(rows["0xc6"], "Invalid nonce: {}")

    def test_status_arm_control(self):
        at = tool.STATUS_TABLE + 4 * tool.TAG_LIMIT
        bad = corrupted(at + 1, IMAGE.blob[IMAGE.offset(at + 1)] ^ 0x40)
        with self.assertRaises((tool.EvidenceError, ValueError, IndexError)):
            tool.status_rows(bad)

    def test_field_keys(self):
        keys = {row[3] for row in RESULT["fields"]}
        self.assertLessEqual({"bal", "oaw", "last_pruned_deposit_block_number"}, keys)

    def test_field_scan_fails_on_edit(self):
        bad = corrupted(0x22157A7, 0x31)
        with self.assertRaises(tool.EvidenceError):
            tool.field_rows(bad)

    def test_slots(self):
        self.assertEqual(len(RESULT["slots"]), 8)

    def test_slot_control(self):
        bad = copy.copy(IMAGE)
        bad.relative = lambda: {}
        with self.assertRaises(tool.EvidenceError):
            tool.slot_rows(bad)

    def test_copy_differences_are_only_the_third_copy_layout(self):
        self.assertEqual({row[0] for row in RESULT["copies"]}, {"%#x" % tool.COPIES[2]})
        for row in RESULT["copies"]:
            self.assertEqual(len(row[3]), len(row[4]))

    def test_pieces(self):
        self.assertEqual(len(RESULT["pieces"]), 7 * 3)
        by = {(row[0], row[2], row[1]): row[4] for row in RESULT["pieces"]}
        self.assertEqual(by[("amount", tool.CAP + 1, "%#x" % tool.COPIES[0])], "0x28")
        self.assertEqual(by[("amount", tool.MARK_LEVEL, "%#x" % tool.COPIES[2])], "0x186")


class Mutations(unittest.TestCase):
    def test_counts(self):
        rows = RESULT["mutations"]
        self.assertGreater(len(rows), 300)
        self.assertFalse([row for row in rows if row[3] == "UNEXPLAINED"])

    def test_survivors_are_listed(self):
        survivors = {(row[0], row[1]) for row in RESULT["mutations"] if row[2] == "survived"}
        self.assertEqual(survivors, set(tool.EXPECTED_SURVIVORS))

    def test_cap_edit_is_caught(self):
        patch = {0x2734628: IMAGE.blob[IMAGE.offset(0x2734628)] ^ 1}
        harness = tool.Harness(IMAGE, patch)
        self.assertIsNotNone(tool.first_failure(harness, tool.named_cases(tool.COPIES[0])))

    def test_unedited_image_passes(self):
        self.assertIsNone(tool.first_failure(tool.Harness(IMAGE), tool.named_cases(tool.COPIES[1])))

    def test_flipped_length_guard_is_caught(self):
        harness = tool.Harness(IMAGE, {0x273422F: IMAGE.blob[IMAGE.offset(0x273422F)] ^ 1})
        self.assertIsNotNone(tool.first_failure(harness, tool.named_cases(tool.COPIES[0])))

    def test_spec_is_not_constant(self):
        base = run()
        other = tool.Case("t", tool.COPIES[0], x=1000)
        got = HARNESS.run(other)
        self.assertNotEqual(got, base)
        self.assertNotEqual(tool.spec_run(tool.Case("t", tool.COPIES[0], nonce=9), HARNESS.before), got)


class Cli(unittest.TestCase):
    def test_small_run_writes_files(self):
        with tempfile.TemporaryDirectory() as folder:
            files = tool.render(tool.analyse(IMAGE, mutate=False, vectors=30))
            path = pathlib.Path(folder) / "e.json"
            path.write_text(files["evidence.json"])
            self.assertIn("named_cases", json.loads(path.read_text()))


if __name__ == "__main__":
    unittest.main()
