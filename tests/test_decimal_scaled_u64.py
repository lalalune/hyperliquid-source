"""Tests for tools/decimal_scaled_u64.py. Each byte control patches one fact in a copy of the target."""
import pathlib
import struct
import sys
import unittest

sys.dont_write_bytecode = True
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import decimal_scaled_u64 as tool  # noqa: E402


def row(negative, mantissa, scale, mode, exponent):
    return ("spot", negative, mantissa, scale, mode, exponent)


SPOT = [
    row(False, 1, 0, 0, 0), row(False, 1, 0, 0, 4), row(False, 1, 0, 0, 18), row(False, 1, 0, 0, 19),
    row(False, 1, 1, 0, 19), row(False, 1, 0, 0, 20), row(False, 1, 0, 0, 32), row(False, 1, 0, 0, 255),
    row(True, 1, 0, 0, 0), row(True, 1, 0, 2, 0), row(True, 4, 1, 2, 0), row(True, 0, 0, 0, 0),
    row(False, 25, 1, 0, 0), row(False, 25, 1, 1, 0), row(False, 25, 1, 2, 0), row(False, 35, 1, 2, 0),
    row(False, 17, 1, 2, 0), row(False, 15, 1, 2, 0), row(False, 14, 1, 2, 0),
    row(False, 10005, 4, 1, 0), row(False, 10015, 4, 1, 0), row(False, 10010, 4, 1, 0), row(False, 10009999, 7, 1, 0),
    row(False, 9995, 4, 1, 0), row(False, 9985, 4, 1, 0), row(True, 10005, 4, 1, 0), row(True, 5, 4, 1, 0),
    row(False, tool.CAP, 0, 0, 0), row(False, tool.CAP + 1, 0, 0, 0), row(False, tool.CAP + 1, 0, 2, 0),
    row(False, tool.MANTISSA_LIMIT - 1, 0, 0, 0), row(False, tool.MANTISSA_LIMIT - 1, 1, 0, 1),
    row(False, tool.MANTISSA_LIMIT - 1, 0, 0, 1), row(False, 1 << 70, 19, 0, 14), row(False, 1 << 70, 19, 2, 14),
]


def load(cls):
    cls.data = tool.TARGET.read_bytes()
    cls.image = tool.Image(cls.data)


class Fixture(unittest.TestCase):
    setUpClass = classmethod(load)

    def patched(self, edits):
        data = bytearray(self.data)
        for va, new in edits:
            off = self.image.file_offset(va)
            data[off:off + len(new)] = new
        return bytes(data)

    def bad_count(self, edits):
        return len(tool.analyse(self.patched(edits), SPOT)["bad"])


class TargetBytes(Fixture):
    def test_hash_is_checked(self):
        tool.check_target(self.data)
        with self.assertRaises(tool.ToolError):
            tool.check_target(self.data[:-1] + bytes([self.data[-1] ^ 1]))

    def test_spot_rows_match(self):
        outcome = tool.analyse(self.data, SPOT)
        self.assertEqual(outcome["bad"], [])
        self.assertEqual(outcome["panics"], 0)

    def test_expected_results(self):
        got = {row[1:]: (kind, value) for row, kind, value, _ in tool.analyse(self.data, SPOT)["results"]}
        self.assertEqual(got[(False, 25, 1, 2, 0)], ("ok", 2))
        self.assertEqual(got[(False, 35, 1, 2, 0)], ("ok", 4))
        self.assertEqual(got[(False, 17, 1, 2, 0)], ("ok", 2))
        self.assertEqual(got[(False, 25, 1, 1, 0)], ("error", None))
        self.assertEqual(got[(False, 10005, 4, 1, 0)], ("ok", 1))
        self.assertEqual(got[(False, 10010, 4, 1, 0)], ("error", None))
        self.assertEqual(got[(True, 4, 1, 2, 0)], ("ok", 0))
        self.assertEqual(got[(False, 1, 1, 0, 19)], ("ok", 10 ** 18))
        self.assertEqual(got[(False, tool.CAP + 1, 0, 0, 0)], ("error", None))

    def test_constants(self):
        values = tool.constants(self.image)
        self.assertEqual(values["tolerance_mantissa"], 1)
        self.assertEqual(values["tolerance_scale"], 3)
        self.assertEqual(int(values["cap"], 16), tool.CAP)

    def test_call_sites(self):
        rows = tool.call_sites(self.image)
        self.assertEqual(len(rows), 35)
        self.assertEqual(sorted({row[2] for row in rows}), [0, 1, 2])
        for row in rows:
            self.assertEqual(self.image.fde_of(int(row[0], 16))[0], int(row[1], 16))


class ByteControls(Fixture):
    def test_tolerance_constant(self):
        self.assertGreater(self.bad_count([(tool.TOLERANCE_VA, struct.pack("<IIII", 0x30000, 0, 2, 0))]), 0)

    def test_cap_immediate(self):
        self.assertGreater(self.bad_count([(tool.CAP_IMMEDIATE_VA, b"\xfd")]), 0)

    def test_mode_compare(self):
        self.assertGreater(self.bad_count([(tool.MODE_COMPARE_VA + 2, b"\x02")]), 0)

    def test_round_table_entry(self):
        entry = struct.unpack_from("<i", self.data, self.image.file_offset(tool.ROUND_TABLE + 12))[0]
        self.assertGreater(self.bad_count([(tool.ROUND_TABLE, struct.pack("<i", entry))]), 0)

    def test_tie_goes_to_even(self):
        self.assertEqual(self.data[self.image.file_offset(tool.TIE_TEST_VA):][:4], b"\x41\xf6\xc0\x01")
        self.assertGreater(self.bad_count([(tool.TIE_TEST_VA + 3, b"\x00")]), 0)

    def test_ladder_step(self):
        self.assertGreater(self.bad_count([(tool.LADDER_STEP_VA + 3, b"\x11")]), 0)

    def test_sign_guard(self):
        self.assertGreater(self.bad_count([(tool.SIGN_GUARD_VA, b"\x90" * 6)]), 0)

    def test_difference_is_a_subtraction(self):
        self.assertGreater(self.bad_count([(tool.SUBTRACT_FLAG_VA + 1, b"\x00")]), 0)

    def test_scale_reduction_divisor(self):
        off = self.image.file_offset(tool.RESCALE_TABLE)
        self.assertEqual(struct.unpack_from("<I", self.data, off + 7 * 4)[0], 10 ** 7)
        self.assertGreater(self.bad_count([(tool.RESCALE_TABLE + 7 * 4, struct.pack("<I", 10 ** 7 + 1))]), 0)

    def test_unmodelled_stop_is_an_error(self):
        data = self.patched([(tool.ENTRY, b"\xcc")])
        with self.assertRaises(tool.ToolError):
            tool.analyse(data, SPOT[:1])


class Tooling(Fixture):
    def test_address_outside_every_fde(self):
        with self.assertRaises(tool.ToolError):
            self.image.fde_of(0x10)

    def test_fetch_outside_text(self):
        with self.assertRaises(tool.ToolError):
            self.image.fetch(0x10)

    def test_unknown_opcode(self):
        with self.assertRaises(tool.ToolError):
            tool.decode(b"\x06\x00\x00\x00", 0, 0x1000)

    def test_branch_on_unknown_flags_stops(self):
        machine = tool.Machine(self.image)
        machine.flags = [None, None, None, None]
        with self.assertRaises(tool.ToolError):
            machine.jump(4, None, 0x1000)

    def test_model_rejects_a_changed_rule(self):
        self.assertEqual(tool.model(False, 25, 1, 2, 0), ("ok", 2, False))
        self.assertEqual(tool.model(False, 35, 1, 2, 0), ("ok", 4, False))
        self.assertEqual(tool.model(False, 10005, 4, 1, 0), ("ok", 1, True))
        self.assertEqual(tool.model(False, 1, 0, 0, 20), ("error", None, False))
        self.assertEqual(tool.model(False, tool.MANTISSA_LIMIT - 1, 0, 0, 1), ("error", None, False))

    def test_vectors_are_deterministic(self):
        self.assertEqual(tool.vectors(), tool.vectors())


if __name__ == "__main__":
    unittest.main()
