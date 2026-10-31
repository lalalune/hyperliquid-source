"""Tests for tools/decimal_px_map.py: real node #94 bytes with corruption controls."""

import copy
import hashlib
import importlib.util
import json
import pathlib
import struct
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FOLDER = ROOT / "research" / "work-items" / "RE-004-decimal-px-map-94"
spec_ = importlib.util.spec_from_file_location("decimal_px_map", ROOT / "tools" / "decimal_px_map.py")
tool = importlib.util.module_from_spec(spec_)
sys.modules["decimal_px_map"] = tool
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


def run(name, rows, **fields):
    case = tool.Case(name, rows, **fields)
    got = HARNESS.run(case)
    assert got == tool.spec_run(case), case.__dict__
    return got


def tag(got):
    return struct.unpack_from("<H", got[2], 0)[0]


def names(got):
    return [event[0] for event in got[1]]


def inserted(got):
    return [event for event in got[1] if event[0] == "insert"]


def text_of(event):
    flags, high, low, mid = struct.unpack("<IIII", event[2])
    return tool.display((flags >> 31, high << 64 | mid << 32 | low, flags >> 16 & 0xFF))


def bent(va, value, size=1):
    bad = copy.copy(IMAGE)
    data = bytearray(IMAGE.blob)
    data[IMAGE.offset(va):IMAGE.offset(va) + size] = value.to_bytes(size, "little")
    bad.blob = bytes(data)
    bad.relative_map = None
    return bad


class Files(unittest.TestCase):
    def test_packet_matches_tool(self):
        files = tool.render(RESULT)
        self.assertEqual(sorted(list(files) + ["MANIFEST.sha256", "README.md"]), sorted(path.name for path in FOLDER.iterdir()))
        for name, text in files.items():
            self.assertEqual((FOLDER / name).read_text(encoding="ascii"), text, name)

    def test_manifest(self):
        rows = (FOLDER / "MANIFEST.sha256").read_text().splitlines()
        self.assertEqual(len(rows), len(list(FOLDER.iterdir())) - 1)
        for row in rows:
            digest, name = row.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_wrong_digest_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)


class Loop(unittest.TestCase):
    def test_empty_list_needs_no_key(self):
        got = run("e", [], dex=1 << 62)
        self.assertEqual(tag(got), tool.TAG_OK)
        self.assertEqual(got[1], ())

    def test_keys(self):
        got = run("k", [(5, 1), (6, 2), (7, 3)], dex=12)
        self.assertEqual([event[1] for event in inserted(got)], [120000, 120001, 120002])
        self.assertEqual(struct.unpack_from("<Q", got[2], 0x18)[0], 3)

    def test_order_in_a_row(self):
        got = run("o", [(5, 1), (6, 7)], dex=1)
        self.assertEqual(names(got), ["price", "drop", "insert", "price", "panic"])
        self.assertEqual(got[1][-1][1:], (tool.SLOT_SLICE, tool.LOC_DECIMALS))

    def test_price_read_before_bound(self):
        got = run("b", [(5, 1), (6, 1)], table_len=1)
        self.assertEqual(names(got), ["price", "drop", "insert", "price", "panic"])
        self.assertEqual(got[1][-1][1:], (tool.SLOT_INDEX, tool.LOC_INDEX))

    def test_sz_edge(self):
        self.assertEqual(tag(run("s6", [(5, 6)])), tool.TAG_OK)
        self.assertEqual(run("s7", [(5, 7)])[0], "panic")

    def test_dex_multiply_edge(self):
        bound = TOP // 10000
        self.assertEqual(tag(run("d", [(5, 1)], dex=bound)), tool.TAG_OK)
        got = run("d2", [(5, 1)], dex=bound + 1)
        self.assertEqual(got[1], (("panic", tool.SLOT_MUL, tool.LOC_PDI),))

    def test_heavy_panics(self):
        outcome = {case.name: got for case, got in zip(RESULT["cases"], RESULT["outcomes"])}
        one = outcome["index_10001_rows"]
        self.assertEqual(one[1][-1], ("panic", tool.SLOT_INDEX, tool.LOC_INDEX))
        self.assertEqual(sum(1 for event in one[1] if event[0] == "insert"), 10000)
        two = outcome["asset_id_wrap"]
        self.assertEqual(two[1][-1], ("panic", tool.SLOT_ADD, tool.LOC_PDI))

    def test_error_drains_the_map(self):
        got = run("f", [(5, 1), (6, 1), (5, 6)], divisors={0: 0.0})
        self.assertEqual(tag(got), tool.TAG_BAD)
        self.assertEqual(got[1][-1][0], "drain")
        self.assertEqual(got[1][-1][3], 2)

    def test_only_landing_pads_unreached(self):
        self.assertTrue(all(va >= 0x3BB7625 for va in RESULT["unreached"]), RESULT["unreached"])
        self.assertEqual(len(RESULT["unreached"]), 12)


class Values(unittest.TestCase):
    def one(self, x, k):
        return text_of(inserted(run("v", [(x, 6 - k)]))[0])

    def test_short_values(self):
        self.assertEqual(self.one(1, 6), "0.000001")
        self.assertEqual(self.one(123456, 3), "123.456")
        self.assertEqual(self.one(1000000, 6), "1")
        self.assertEqual(self.one(0, 3), "0")

    def test_first_inexact(self):
        self.assertEqual(self.one(4096029, 3), "4096.029000000001")
        self.assertEqual(self.one(4096028, 3), "4096.028")
        self.assertEqual(self.one(4096000004, 6), "4096.000004000001")
        self.assertEqual(self.one(419430423, 2), "4194304.230000001")

    def test_top_rounds_past_u64(self):
        self.assertEqual(self.one(TOP, 0), "18446744073709551616")

    def test_integers_above_mantissa_follow_the_f64(self):
        self.assertEqual(self.one((1 << 53) + 1, 0), str(1 << 53))

    def test_range_excludes_error_rows(self):
        bounds = RESULT["bounds"]
        self.assertEqual(float.fromhex(bounds["smallest_nonzero_quotient"]), 1e-06)
        self.assertEqual(float.fromhex(bounds["largest_quotient"]), 2.0 ** 64)


class Exactness(unittest.TestCase):
    def test_four_windows(self):
        self.assertEqual([(row[0], row[1]) for row in RESULT["exact"]["windows"]], [(12, 12), (22, 9), (32, 6), (42, 3)])

    def test_power_two_is_just_below_the_threshold(self):
        row = [row for row in RESULT["exact"]["table"] if row[0] == 2 and row[1] == 15][0]
        self.assertLess(row[4], tool.THRESHOLD)

    def test_inside_only_when_window(self):
        windows = RESULT["exact"]["windows"]
        self.assertTrue(tool.inside(windows, 4096))
        self.assertFalse(tool.inside(windows, 4095))
        self.assertFalse(tool.inside(windows, 4504))

    def test_first_values(self):
        firsts = {row[0]: row[1] for row in RESULT["exact"]["firsts"]}
        self.assertEqual(firsts, {1: None, 2: 419430423, 3: 4096029, 4: 40960254, 5: 409602504, 6: 4096000004})
        for k, x in firsts.items():
            if x is not None:
                self.assertFalse(tool.exact_value(x, k))

    def test_short_prices_stay_exact(self):
        for digits, (tried, bad) in RESULT["exact"]["scans"].items():
            self.assertGreater(tried, 1000)
            self.assertEqual(bad, [], digits)

    def test_rule_sample(self):
        sample = RESULT["exact"]["sample"]
        self.assertEqual(sample["sampled_outside_inexact"], 0)
        self.assertGreater(sample["sampled_outside"], 10000)

    def test_negative_control_on_exact_value(self):
        self.assertTrue(tool.exact_value(4096028, 3))
        self.assertFalse(tool.exact_value(4096029, 3))


class Corruption(unittest.TestCase):
    def test_divisor_word(self):
        with self.assertRaises(tool.EvidenceError):
            tool.divisor_rows(bent(tool.DIVISORS + 8 * 3 + 7, 0x41))

    def test_zero_words(self):
        with self.assertRaises(tool.EvidenceError):
            tool.constant_rows(bent(tool.ZERO_WORDS + 4, 1))

    def test_site_bytes(self):
        with self.assertRaises(tool.EvidenceError):
            tool.site_rows(bent(tool.SITES[0] + 2, IMAGE.blob[IMAGE.offset(tool.SITES[0] + 2)] ^ 1))

    def test_price_call(self):
        with self.assertRaises(tool.EvidenceError):
            tool.site_rows(bent(0x3BB7332, IMAGE.blob[IMAGE.offset(0x3BB7332)] ^ 1))

    def test_out_of_range_address(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.offset(0xFFFFFFFFFF)
        bss = IMAGE.named[".bss"]
        with self.assertRaises(tool.EvidenceError):
            IMAGE.offset(bss["address"] + 8)

    def test_not_an_fde_start(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.exact_fde(tool.TARGET + 1)

    def test_bent_target_row_is_seen(self):
        harness = tool.Harness(IMAGE, {0x3BB7384 + 0: IMAGE.blob[IMAGE.offset(0x3BB7384)]})
        self.assertIsNone(tool.first_failure(harness, tool.structure_cases()[:3]))
        harness = tool.Harness(IMAGE, {0x3BB7382: 0x08})
        self.assertIsNotNone(tool.first_failure(harness, tool.structure_cases()))

    def test_bent_rounding_in_the_callee_is_seen(self):
        self.assertEqual(bytes(IMAGE.blob[IMAGE.offset(0x4EACAF8):IMAGE.offset(0x4EACAF8) + 4]).hex(), "4883fa04")
        harness = tool.Harness(IMAGE, {0x4EACAFB: 5})
        self.assertIsNotNone(tool.first_failure(harness, [tool.Case("w", [(4096029, 3)])]))

    def test_wrong_rule_list_is_seen(self):
        case = tool.Case("w", [(4096029, 3)])
        got = HARNESS.run(case)
        value = list(tool.spec_run(case))
        value[1] = tuple(event if event[0] != "insert" else ("insert", event[1], tool.decimal_bytes((0, 4096029, 3))) for event in value[1])
        self.assertNotEqual(got, tuple(value))


class Mutations(unittest.TestCase):
    def test_counts_and_reasons(self):
        rows = RESULT["mutations"]
        self.assertGreater(len(rows), 60)
        survivors = [row for row in rows if row[2] == "survived"]
        self.assertEqual(len(survivors), len(tool.EXPECTED_SURVIVORS))
        self.assertFalse([row for row in survivors if row[3] == "UNEXPLAINED"])

    def test_evidence_counts(self):
        data = json.loads((FOLDER / "evidence.json").read_text())
        self.assertEqual(data["sha256"], tool.SHA256)
        self.assertEqual(data["mutations"]["total"], len(RESULT["mutations"]))


if __name__ == "__main__":
    unittest.main()
