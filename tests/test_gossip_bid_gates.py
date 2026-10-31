"""Tests for tools/gossip_bid_gates.py: real node #94 bytes with corruption controls."""

import copy
import hashlib
import importlib.util
import json
import pathlib
import struct
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FOLDER = ROOT / "research" / "work-items" / "RE-004-gossip-bid-gates-94"
spec_ = importlib.util.spec_from_file_location("gossip_bid_gates", ROOT / "tools" / "gossip_bid_gates.py")
tool = importlib.util.module_from_spec(spec_)
sys.modules["gossip_bid_gates"] = tool
spec_.loader.exec_module(tool)

IMAGE = None
HARNESS = None
RESULT = None
TOP = 0xFFFFFFFFFFFFFFFF


def setUpModule():
    global IMAGE, HARNESS, RESULT
    IMAGE = tool.load_image()
    HARNESS = tool.Harness(IMAGE)
    RESULT = tool.analyse(IMAGE)


def run(**fields):
    case = tool.Case("t", **fields)
    got = HARNESS.run(case)
    assert got == tool.spec_run(case, HARNESS.before), case.__dict__
    return got


def status(got):
    return struct.unpack_from("<H", got[2], tool.OUT - tool.HEAP_BASE)[0]


def names(got):
    return [event[0] for event in got[1]]


def bytes_at(got, addr, size):
    return got[2][addr - tool.HEAP_BASE:addr - tool.HEAP_BASE + size]


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
        self.assertEqual(IMAGE.exact_fde(tool.HANDLER), (0x2727BC0, 0x2727F2A))
        self.assertEqual(IMAGE.exact_fde(tool.CHARGE), (0x2206560, 0x22065F5))
        self.assertEqual(IMAGE.exact_fde(tool.PARSER), (0x1573AF0, 0x1573EC2))

    def test_mid_function_address_is_no_start(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.exact_fde(tool.HANDLER + 1)

    def test_tool_runs_no_other_program(self):
        text = (ROOT / "tools" / "gossip_bid_gates.py").read_text()
        self.assertNotIn("import subprocess", text)


class Order(unittest.TestCase):
    def test_success_runs_every_step(self):
        got = run()
        self.assertEqual(status(got), tool.TAG_OK)
        self.assertEqual(names(got), ["info", "drop_disabled", "drop_slot", "price", "user", "charge"])

    def test_info_only_for_first_word_one(self):
        self.assertNotIn("info", names(run(word=0)))
        self.assertNotIn("info", names(run(word=2)))
        self.assertIn("info", names(run(word=1 << 32 | 1)))

    def test_info_block_is_zero_when_skipped(self):
        got = run(word=0)
        self.assertEqual(next(event for event in got[1] if event[0] == "charge")[4], bytes(32))

    def test_disabled_only_at_the_none_word(self):
        self.assertEqual(status(run(cap=1 << 63)), tool.TAG_DISABLED)
        self.assertEqual(status(run(cap=(1 << 63) + 1)), tool.TAG_OK)
        self.assertEqual(status(run(cap=(1 << 63) - 1)), tool.TAG_OK)

    def test_disabled_comes_before_the_slot(self):
        self.assertEqual(status(run(cap=1 << 63, slot=TOP)), tool.TAG_DISABLED)

    def test_slot_bound_is_the_length(self):
        self.assertEqual(status(run(slot=3)), tool.TAG_OK)
        self.assertEqual(status(run(slot=4)), tool.TAG_SLOT)
        self.assertEqual(status(run(slot=1 << 63)), tool.TAG_SLOT)

    def test_price_error_is_copied_whole(self):
        got = run(price_err=True, flag=1, limit=0)
        self.assertEqual(bytes_at(got, tool.OUT, tool.OUT_SIZE), tool.ERROR_BYTES)
        self.assertNotIn("user", names(got))

    def test_auction_stride_reads_the_slot_token(self):
        got = run(slot=2)
        event = next(event for event in got[1] if event[0] == "charge")
        self.assertEqual(event[5], tool.AUCTIONS + 2 * 0x50)
        self.assertEqual(struct.unpack("<Q", event[3][8:16])[0], 150)


class Amounts(unittest.TestCase):
    def test_limit_needs_bit_zero(self):
        self.assertEqual(status(run(flag=0, limit=10)), tool.TAG_OK)
        self.assertEqual(status(run(flag=1, limit=10)), tool.TAG_MAX)
        self.assertEqual(status(run(flag=2, limit=10)), tool.TAG_OK)
        self.assertEqual(status(run(flag=3, limit=10)), tool.TAG_MAX)

    def test_price_equal_to_limit_passes(self):
        self.assertEqual(status(run(flag=1, limit=1000)), tool.TAG_OK)
        self.assertEqual(status(run(flag=1, limit=999)), tool.TAG_MAX)

    def test_limit_refusal_carries_price_and_token(self):
        got = run(flag=1, limit=999)
        self.assertEqual(struct.unpack("<QQ", bytes_at(got, tool.OUT + 8, 16)), (1000, 150))

    def test_limit_comes_before_the_balance(self):
        got = run(flag=1, limit=1, row=(0, 0))
        self.assertEqual(status(got), tool.TAG_MAX)
        self.assertNotIn("user", names(got))

    def test_hold_counts_against_total(self):
        self.assertEqual(status(run(row=(1100, 100))), tool.TAG_OK)
        self.assertEqual(status(run(row=(1099, 100))), tool.TAG_FUNDS)

    def test_wrapped_sum_refuses(self):
        self.assertEqual(status(run(row=(TOP, TOP), price=1)), tool.TAG_FUNDS)
        self.assertEqual(status(run(row=(50, TOP - 9), price=20)), tool.TAG_FUNDS)

    def test_top_sum_passes(self):
        self.assertEqual(status(run(row=(TOP, 1), price=TOP - 1)), tool.TAG_OK)

    def test_hold_above_total_refuses_a_zero_price(self):
        self.assertEqual(status(run(row=(5, 10), price=0)), tool.TAG_FUNDS)
        self.assertEqual(status(run(row=(5, 5), price=0)), tool.TAG_OK)

    def test_no_row_is_zero_balance(self):
        self.assertEqual(status(run(row=None, price=0)), tool.TAG_OK)
        self.assertEqual(status(run(row=None, price=1)), tool.TAG_FUNDS)
        self.assertEqual(status(run(shape="none", price=0)), tool.TAG_OK)
        self.assertEqual(status(run(shape="none", price=1)), tool.TAG_FUNDS)

    def test_token_compare_is_unsigned(self):
        self.assertEqual(status(run(token=1 << 63, near=(-1, 1))), tool.TAG_OK)
        self.assertEqual(status(run(token=5, near=(1 << 63,))), tool.TAG_OK)

    def test_deep_trees(self):
        self.assertEqual(status(run(shape="deep", near=(1, 2, 3, 4))), tool.TAG_OK)
        self.assertEqual(status(run(shape="deep", row=None, near=(-1, -2, -3))), tool.TAG_FUNDS)
        self.assertEqual(status(run(shape="tall", near=(-5, -4, -3, -2, -1, 1, 2, 3))), tool.TAG_OK)

    def test_price_pieces(self):
        self.assertEqual([row[1:] for row in RESULT["pieces"] if row[0] == "funds"], [(0, 900, "0x186"), (901, TOP - 100, "0x179"), (TOP - 99, TOP, "0x179")])


class Charge(unittest.TestCase):
    def test_charge_gets_price_token_and_zero_byte(self):
        event = next(event for event in run(price=77)[1] if event[0] == "charge")
        self.assertEqual(event[3], struct.pack("<QQ", 77, 150) + b"\0")
        self.assertEqual(event[6], tool.CLOSURE)

    def test_success_stores_five_bytes(self):
        got = run(ip=(0x12, 0x34, 0x56, 0x78), slot=0)
        at = tool.AUCTIONS + tool.A_CW
        self.assertEqual(bytes_at(got, at - 1, 7), b"\x30\x00\x12\x34\x56\x78\x30")

    def test_charge_error_keeps_the_word(self):
        got = run(core_err=True, slot=2)
        at = tool.AUCTIONS + 2 * 0x50 + tool.A_CW
        self.assertEqual(bytes_at(got, at, 5), b"\x32" * 5)
        self.assertEqual(bytes_at(got, tool.OUT, tool.OUT_SIZE), tool.ERROR_BYTES)

    def test_refusal_keeps_the_word(self):
        got = run(row=(0, 0))
        self.assertEqual(bytes_at(got, tool.AUCTIONS + 0x50 + tool.A_CW, 5), b"\x31" * 5)


class Parser(unittest.TestCase):
    def parse(self, text):
        got = HARNESS.parse(text)
        self.assertEqual(got, tool.spec_parse(text), text)
        return got

    def test_plain(self):
        self.assertEqual(self.parse(b"1.2.3.4"), (b"\x01\x02\x03\x04", 7, 0))
        self.assertEqual(self.parse(b"255.255.255.255"), (b"\xFF" * 4, 15, 0))

    def test_rest_is_left_to_the_caller(self):
        self.assertEqual(self.parse(b"1.2.3.4x"), (b"\x01\x02\x03\x04", 7, 1))
        self.assertEqual(self.parse(b"1.2.3.4.5"), (b"\x01\x02\x03\x04", 7, 2))

    def test_refused(self):
        for text in (b"", b"1.2.3", b"1.2.3.", b"256.1.1.1", b"1.2.3.256", b"01.2.3.4", b"1.2.3.04", b"00.1.1.1", b"1..3.4", b" 1.2.3.4", b"1000.1.1.1", b"1.2.3.1000"):
            self.assertIsNone(self.parse(text), text)

    def test_single_zero_passes(self):
        self.assertEqual(self.parse(b"0.0.0.0"), (bytes(4), 7, 0))

    def test_every_position_takes_exactly_256_short_strings(self):
        for position in range(4):
            rows = [row for row in RESULT["octets"] if row[0] == position]
            self.assertEqual([row[3] for row in rows], [10, 90, 156])

    def test_digits_past_the_slice_are_not_read(self):
        self.assertIsNone(self.parse(b"1.2.3"))
        self.assertEqual(self.parse(b"1.2.3.1"), (b"\x01\x02\x03\x01", 7, 0))


class Evidence(unittest.TestCase):
    def test_slot_target(self):
        self.assertEqual(RESULT["slots"][0][:3], ("0x57739b8", "auction price", "0x325ccb0"))

    def test_field_keys(self):
        self.assertEqual([row[1:2] + row[3:] for row in RESULT["names"]], [("0x40", "cw"), ("0x45", "pw")])

    def test_null_row(self):
        self.assertEqual(RESULT["nulls"][0][2:], (2, "0x2970e2b", "null"))

    def test_status_text(self):
        self.assertEqual({row[0]: row[2] for row in RESULT["statuses"]}["0x179"], "Insufficient gas at current auction price.")

    def test_call_counts(self):
        self.assertEqual([row[2] for row in RESULT["calls"]][:2], [1, 1])

    def test_bent_field_key_fails(self):
        with self.assertRaises(tool.EvidenceError):
            tool.name_rows(corrupted(0x3D6E7C, 0x41))

    def test_bent_field_offset_fails(self):
        with self.assertRaises(tool.EvidenceError):
            tool.name_rows(corrupted(tool.SERIALIZER_CW + 3, 0x48))

    def test_bent_null_test_fails(self):
        with self.assertRaises(tool.EvidenceError):
            tool.null_rows(corrupted(tool.NULL_TEST + 3, 1))

    def test_bent_status_table_fails(self):
        with self.assertRaises(tool.EvidenceError):
            tool.status_rows(corrupted(0x3801737 + 18, 0x90))

    def test_edited_slot_bound_is_seen(self):
        harness = tool.Harness(IMAGE, {0x2727C38 + 1: IMAGE.blob[IMAGE.offset(0x2727C38 + 1)] ^ 1})
        self.assertIsNotNone(tool.first_failure(harness, tool.named_cases()))

    def test_edited_wrap_test_is_seen(self):
        harness = tool.Harness(IMAGE, {0x2727E8D + 1: IMAGE.blob[IMAGE.offset(0x2727E8D + 1)] ^ 1})
        self.assertIsNotNone(tool.first_failure(harness, tool.named_cases()))

    def test_edited_store_is_seen(self):
        harness = tool.Harness(IMAGE, {0x22065A1 + 3: 0x48})
        self.assertIsNotNone(tool.first_failure(harness, tool.named_cases()))

    def test_edited_octet_bound_is_seen(self):
        harness = tool.Harness(IMAGE, {0x1573BA9 + 3: 0})
        self.assertIsNotNone(tool.first_parser_failure(harness, tool.edge_texts()))

    def test_unedited_image_passes_with_the_mutant_limit(self):
        harness = tool.Harness(IMAGE)
        harness.machine.step_limit = tool.MUTANT_STEP_LIMIT
        self.assertIsNone(tool.first_failure(harness, tool.named_cases()))
        self.assertIsNone(tool.first_parser_failure(harness, tool.edge_texts()))

    def test_handler_and_wrapper_have_no_survivor(self):
        survivors = [row[0] for row in RESULT["mutations"] if row[2] == "survived"]
        self.assertTrue(all(tool.PARSER <= va < tool.PARSER + 0x3D2 for va in survivors))

    def test_every_survivor_has_a_reason(self):
        rows = RESULT["mutations"]
        survivors = [(row[0], row[1]) for row in rows if row[2] == "survived"]
        self.assertEqual(set(survivors), set(tool.EXPECTED_SURVIVORS))
        self.assertGreater(len(rows), 200)

    def test_packet_files_match_the_tool(self):
        files = tool.render(RESULT)
        for name, text in files.items():
            self.assertEqual((FOLDER / name).read_text(encoding="ascii"), text, name)

    def test_manifest(self):
        lines = (FOLDER / "MANIFEST.sha256").read_text().splitlines()
        listed = {line.split("  ")[1]: line.split("  ")[0] for line in lines}
        self.assertEqual(sorted(listed), sorted(p.name for p in FOLDER.iterdir() if p.name != "MANIFEST.sha256"))
        for name, digest in listed.items():
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_summary_counts(self):
        summary = json.loads((FOLDER / "evidence.json").read_text())
        self.assertEqual(summary["sha256"], tool.SHA256)
        for name in ("bid_handler", "charge_wrapper", "ipv4_parser"):
            self.assertEqual(summary["functions"][name]["unreached_rows"], [])
        self.assertEqual(summary["mutations"]["survived"], len(tool.EXPECTED_SURVIVORS))


if __name__ == "__main__":
    unittest.main()
