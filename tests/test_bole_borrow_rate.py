"""Tests for tools/bole_borrow_rate.py. Expected numbers here are literals, not calls to the tool's rule list."""
import copy
import hashlib
import pathlib
import struct
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import bole_borrow_rate as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-004-bole-borrow-rate-curve-94"
E14 = 10 ** 14
TOP = 2 ** 64 - 1


class Shared:
    image = None
    harness = None
    full = None


def shared_get():
    if Shared.image is None:
        Shared.image = tool.load_image()
        Shared.harness = tool.Harness(Shared.image)
    return Shared.image, Shared.harness


def shared_result():
    if Shared.full is None:
        Shared.full = tool.analyse(tool.load_image())
    return Shared.full


def patched(image, va, value):
    other = copy.copy(image)
    blob = bytearray(image.blob)
    blob[image.offset(va)] = value
    other.blob = bytes(blob)
    return other


class Base(unittest.TestCase):
    def setUp(self):
        self.image, self.harness = shared_get()

    def rate(self, **fields):
        return tool.run_value(self.harness, tool.RATE_INT, tool.record(**fields))[1]

    def rate_f64(self, **fields):
        return tool.to_float(tool.run_value(self.harness, tool.RATE, tool.record(**fields))[1])

    def util(self, kind=tool.UTIL_WORD, **fields):
        data = tool.run_value(self.harness, kind, tool.record(**fields))[1]
        if data[0]:
            return "err", data[1]
        word = struct.unpack_from("<Q", data, 8)[0]
        return "ok", word if kind == tool.UTIL_WORD else tool.to_float(word)

    def info(self, rec, **fields):
        case = tool.Case("probe", tool.INFO, rec=rec, **fields)
        return self.harness.run(case)[1]


class Identity(unittest.TestCase):
    def test_wrong_digest_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_changed_byte_refused(self):
        blob = bytearray(tool.BINARY.read_bytes())
        blob[-1] ^= 1
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "copy"
            path.write_bytes(blob)
            with self.assertRaises(tool.EvidenceError):
                tool.load_image(path)

    def test_source_starts_no_program(self):
        text = (ROOT / "tools" / "bole_borrow_rate.py").read_text()
        for word in ("subprocess", "popen", "os.system"):
            self.assertNotIn(word, text)


class Bounds(Base):
    def test_fde_sizes(self):
        sizes = {tool.RATE: 649, tool.RATE_INT: 628, tool.UTIL_WORD: 323, tool.UTIL_F64: 320, tool.INFO: 1271, tool.TOTALS: 421}
        for start, size in sizes.items():
            self.assertEqual(self.image.exact_fde(start), (start, start + size))

    def test_mid_function_is_no_start(self):
        with self.assertRaises(tool.EvidenceError):
            self.image.exact_fde(tool.RATE + 1)

    def test_nobits_has_no_file_bytes(self):
        bss = self.image.named[".bss"]
        with self.assertRaises(tool.EvidenceError):
            self.image.offset(bss["address"] + 8)

    def test_address_outside_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            self.image.fde(0x10)


class Curve(Base):
    CONFIG = dict(mn=0, mx=E14, kr=5 * 10 ** 12, k=8 * 10 ** 13)

    def test_low_arm(self):
        self.assertEqual(self.rate(a=25, b=100, **self.CONFIG), 156)
        self.assertEqual(self.rate_f64(a=25, b=100, **self.CONFIG), 0.015625)

    def test_exact_bend(self):
        self.assertEqual(self.rate(a=80, b=100, **self.CONFIG), 500)

    def test_high_arm(self):
        self.assertEqual(self.rate(a=90, b=100, **self.CONFIG), 5250)
        self.assertEqual(self.rate_f64(a=90, b=100, **self.CONFIG), 0.525)

    def test_full_and_past_full_are_the_top(self):
        self.assertEqual(self.rate(a=100, b=100, **self.CONFIG), 10000)
        self.assertEqual(self.rate(a=150, b=100, **self.CONFIG), 10000)

    def test_floor_at_zero_use(self):
        self.assertEqual(self.rate(a=0, b=100, mn=2 * 10 ** 12, mx=E14, kr=10 ** 13, k=8 * 10 ** 13), 200)

    def test_inverted_low_arm_gives_the_bend_word(self):
        self.assertEqual(self.rate(a=1, b=10, mn=9 * 10 ** 12, kr=10 ** 12, k=5 * 10 ** 13), 100)

    def test_inverted_high_arm_gives_the_top_word(self):
        self.assertEqual(self.rate(a=9, b=10, kr=9 * 10 ** 12, mx=10 ** 12, k=5 * 10 ** 13), 100)

    def test_kink_past_one_never_reaches_the_bend(self):
        self.assertEqual(self.rate(a=9, b=4, mn=0, kr=10 ** 13, mx=E14, k=2 * E14), 500)

    def test_kink_zero_is_all_high_arm(self):
        self.assertEqual(self.rate(a=1, b=2, kr=10 ** 12, mx=3 * 10 ** 12, k=0), 200)

    def test_truncates_twice(self):
        rec = dict(a=1, b=3, mn=0, kr=10 ** 13, k=5 * 10 ** 13)
        # u = 33333333333333, f = 66666666666666, word = 6666666666666 and not 6666666666667.
        self.assertEqual(tool.to_bits(self.rate_f64(**rec)), tool.to_bits(6666666666666 / 1e14))


class Utilization(Base):
    def test_half(self):
        self.assertEqual(self.util(a=50, b=100), ("ok", 5000))
        self.assertEqual(self.util(tool.UTIL_F64, a=50, b=100), ("ok", 0.5))

    def test_borrow_side_rounds_up(self):
        # 3 * (1e14+1) / 1e14 = 3.00000000000003, so 4 over 8.
        self.assertEqual(self.util(a=3, ia=E14 + 1, b=8), ("ok", 5000))

    def test_exact_borrow_does_not_round_up(self):
        self.assertEqual(self.util(a=2, ia=2 * E14, b=8), ("ok", 5000))

    def test_supply_side_rounds_down(self):
        # 8 * (1e14+1) / 1e14 floors to 8.
        self.assertEqual(self.util(a=4, b=8, ib=E14 + 1), ("ok", 5000))

    def test_capped_at_one(self):
        self.assertEqual(self.util(a=300, b=100), ("ok", 10000))

    def test_no_supply_is_zero_not_an_error(self):
        self.assertEqual(self.util(a=3, b=0), ("ok", 0))

    def test_cut_between_184467_and_184468(self):
        self.assertEqual(self.util(a=184467, b=1), ("ok", 10000))
        self.assertEqual(self.util(a=184468, b=1), ("err", 3))

    def test_rate_falls_to_the_floor_at_the_cut(self):
        rec = dict(b=1, mn=10 ** 13, kr=2 * 10 ** 13, mx=5 * 10 ** 13, k=5 * 10 ** 13)
        self.assertEqual(self.rate(a=184467, **rec), 5000)
        self.assertEqual(self.rate(a=184468, **rec), 1000)

    def test_borrow_past_the_word(self):
        self.assertEqual(self.util(a=TOP, ia=TOP, b=1), ("err", 3))

    def test_supply_past_the_word(self):
        self.assertEqual(self.util(a=1, b=1 << 63, ib=2 * E14), ("err", 3))

    def test_supply_top_fits(self):
        self.assertEqual(self.util(a=0, b=TOP, ib=E14), ("ok", 0))


class Reciprocals(unittest.TestCase):
    def test_divides_hold(self):
        rows = tool.reciprocal_rows()
        self.assertEqual([row[0] for row in rows], ["rate_e10", "utilization_e10"])
        for value in (0, 1, 9999999999, 10 ** 10, 10 ** 10 + 1, E14 - 1, E14):
            self.assertEqual(value * tool.MUL_UTIL >> tool.SHIFT_UTIL, value // 10 ** 10)
        for value in (0, 10 ** 10 - 1, 10 ** 10, TOP - 1, TOP):
            self.assertEqual(value * tool.MUL_RATE >> tool.SHIFT_RATE, value // 10 ** 10)

    def test_wrong_multiplier_fails(self):
        with mock.patch.object(tool, "MUL_RATE", tool.MUL_RATE - 1):
            with self.assertRaises(tool.EvidenceError):
                tool.reciprocal_rows()

    def test_guard_claim_fails_when_the_cap_is_wider(self):
        with mock.patch.object(tool, "GUARD", 1 << 100):
            with self.assertRaises(tool.EvidenceError):
                tool.shadow_rows()


class InfoRow(Base):
    def word(self, data, at):
        return struct.unpack_from("<Q", data, at)[0]

    def row(self, rec, **fields):
        fields.setdefault("spots", ((1, 1), (2, 0)))
        fields.setdefault("lists", {1: (0, 1)})
        return self.info(rec, tok=1, **fields)[1]

    def test_supply_rate(self):
        rec = tool.record(a=50, b=100, mn=0, kr=10 ** 13, mx=E14, k=5 * 10 ** 13)
        data = self.row(rec, f=2 * 10 ** 13)
        self.assertEqual(tool.to_float(self.word(data, 0x40)), 0.1)
        self.assertEqual(tool.to_float(self.word(data, 8)), 0.5)
        self.assertEqual(tool.to_float(self.word(data, 0x48)), 0.8 * (0.1 * 0.5))

    def test_totals_floor_and_scale(self):
        rec = tool.record(a=150000000, b=250000000, ia=E14 + 1, ib=E14 + 1)
        data = self.row(rec)
        self.assertEqual(tool.to_float(self.word(data, 0x28)), 2.5)
        self.assertEqual(tool.to_float(self.word(data, 0x38)), 1.5)

    def test_price_shift(self):
        rec = tool.record(a=1, b=2, px=123456789)
        data = self.row(rec)
        self.assertEqual(self.word(data, 0x10), 1)
        # Token 0 wei 8 minus base token sz 3.
        self.assertEqual(tool.to_float(self.word(data, 0x18)), 1234.56789)

    def test_usd_token_price_is_one(self):
        rec = tool.record(a=1, b=2, px=123456789)
        data = self.info(rec, tok=0, spots=(), lists={})[1]
        self.assertEqual(tool.to_float(self.word(data, 0x18)), 1.0)

    def test_cut_is_no_row(self):
        data = self.row(tool.record(a=184468, b=1))
        self.assertEqual(len(data), 8)
        self.assertEqual(self.word(data, 0), 2)

    def test_miss_is_no_row(self):
        got = self.info(tool.record(a=1, b=2), tok=7, spots=(), lists={}, shape="miss")
        self.assertEqual(self.word(got[1], 0), 2)
        self.assertEqual(got[2], [])

    def test_ltv_word(self):
        data = self.row(tool.record(a=1, b=2, ltv=5 * 10 ** 13))
        self.assertEqual(tool.to_float(self.word(data, 0x58)), 0.5)
        data = self.row(tool.record(a=1, b=2))
        self.assertEqual(tool.to_float(self.word(data, 0x58)), 0.0)

    def test_panic_past_the_table(self):
        got = self.info(tool.record(a=1, b=2), tok=9, spots=(), lists={})
        self.assertEqual(got[:2], ("panic", "unwrap"))


class Names(Base):
    def test_rows(self):
        rows = tool.name_rows(self.image)
        self.assertEqual([row[2] for row in rows[:4]], ["min_rate", "max_rate", "kink_rate", "kink_utilization"])
        self.assertIn("borrowYearlyRate", [row[2] for row in rows])

    def test_writer_bytes(self):
        self.assertEqual(len(tool.writer_rows(self.image)), 1)

    def test_writer_bytes_changed(self):
        other = patched(self.image, tool.WRITE_SITE + 7, 0x10)
        with self.assertRaises(tool.EvidenceError):
            tool.writer_rows(other)

    def test_key_changed(self):
        other = patched(self.image, tool.INFO_SERIALIZER + 0x89, 0x00)
        with self.assertRaises((tool.EvidenceError, UnicodeDecodeError)):
            tool.name_rows(other)

    def test_constant_changed(self):
        other = patched(self.image, tool.F_E14 + 7, 0x43)
        with self.assertRaises(tool.EvidenceError):
            tool.constant_rows(other)

    def test_table_changed(self):
        other = patched(self.image, tool.TABLE_TOKEN + 8 * 3 + 6, 0)
        with self.assertRaises(tool.EvidenceError):
            tool.table_rows(other)

    def test_slot_changed(self):
        other = copy.copy(self.image)
        table = dict(self.image.relative())
        table[tool.SLOT_RATE] = tool.RATE + 1
        other.relative_map = table
        with self.assertRaises(tool.EvidenceError):
            tool.site_rows(other)


class Mutants(Base):
    def kind(self, target):
        return [case for case in tool.named_cases() if case.kind == target]

    def test_unedited_passes(self):
        for target in (tool.RATE, tool.UTIL_WORD, tool.INFO):
            self.assertIsNone(tool.first_failure(tool.Harness(self.image), self.kind(target)))

    def flip(self, va, at, cases):
        data = self.image.blob[self.image.offset(va) + at]
        harness = tool.Harness(self.image, {va + at: data ^ 1})
        self.assertIsNotNone(tool.first_failure(harness, cases))

    def test_cap_cmov(self):
        self.flip(0x374163F, 2, self.kind(tool.RATE))

    def test_supply_guard(self):
        self.flip(0x37415A9, 1, self.kind(tool.RATE))

    def test_info_lookup_stride(self):
        self.flip(0x2A32D7A, 3, self.kind(tool.INFO))

    def test_step_limit_control(self):
        harness = tool.Harness(self.image)
        harness.machine.step_limit = 5
        self.assertIsNotNone(tool.first_failure(harness, self.kind(tool.RATE)))

    def test_wrong_model_is_seen(self):
        with mock.patch.object(tool, "E10", 10 ** 9):
            self.assertIsNotNone(tool.first_failure(tool.Harness(self.image), self.kind(tool.RATE_INT)))


class Whole(unittest.TestCase):
    def test_every_row_reached(self):
        result = shared_result()
        for target, rows in result["unreached"].items():
            self.assertEqual(rows, [], hex(target))

    def test_fault_rows_are_shadowed_guards(self):
        rows = {row[0]: row[1] for row in shared_result()["fault_only"]}
        self.assertGreater(rows["rate_f64"], 0)
        self.assertGreater(rows["rate_e10"], 0)

    def test_survivors_are_the_listed_ones(self):
        rows = [row for row in shared_result()["mutations"] if row[2] == "survived"]
        self.assertEqual({(row[0], row[1]) for row in rows}, set(tool.EXPECTED_SURVIVORS))
        self.assertGreater(len(shared_result()["mutations"]), 280)

    def test_files_match_the_packet(self):
        for name, text in tool.render(shared_result()).items():
            self.assertEqual((FOLDER / name).read_text(encoding="ascii"), text, name)

    def test_folder_holds_nothing_else(self):
        generated = set(tool.render(shared_result())) | {"README.md", "MANIFEST.sha256"}
        self.assertEqual({path.name for path in FOLDER.iterdir()}, generated)

    def test_manifest(self):
        lines = (FOLDER / "MANIFEST.sha256").read_text().splitlines()
        names = sorted(path.name for path in FOLDER.iterdir() if path.name != "MANIFEST.sha256")
        self.assertEqual(sorted(line.split("  ")[1] for line in lines), names)
        for line in lines:
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)


if __name__ == "__main__":
    unittest.main()
