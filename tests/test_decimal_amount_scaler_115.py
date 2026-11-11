import json
import random
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import decimal_amount_scaler_115 as tool  # noqa: E402
import decimal_scaled_u64 as cpu  # noqa: E402

EVIDENCE = ROOT / "research/work-items/l1-shared-decimal-amount-scaler-115"


class ScalerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = tool.TARGET.read_bytes()
        cls.image = tool.load_image(cls.data)

    def real(self, *args):
        outcome, touches, _steps, _seen = tool.run_scaler(self.image, *args)
        return outcome, touches

    def test_directed_cases_match_specification(self):
        for args in tool.DIRECTED:
            self.assertEqual(self.real(*args), tool.spec_scaler(*args), args)

    def test_known_values(self):
        # 123.45 scaled by 10^2 is exactly 12345; 1234.5 * 10^2 = 123450
        self.assertEqual(self.real(2 << 16, 0, 12345, 0, 0, 2), (("ok", 12345), 0))
        self.assertEqual(self.real(1 << 16, 0, 12345, 0, 0, 2), (("ok", 123450), 0))
        # a fraction survives mode 0 as a refusal, mode 2 rounds half to even
        self.assertEqual(self.real(1 << 16, 0, 25, 0, 0, 0), (("err",), 0))
        self.assertEqual(self.real(1 << 16, 0, 25, 0, 2, 0), (("ok", 2), 0))
        self.assertEqual(self.real(1 << 16, 0, 35, 0, 2, 0), (("ok", 4), 0))

    def test_tolerance_mode_touches_the_lazy_global(self):
        # 2.0005 is 0.0005 from 2: snapped, with one touch; 2.0015 is outside 0.001: refused
        self.assertEqual(self.real(4 << 16, 0, 20005, 0, 1, 0), (("ok", 2), 1))
        self.assertEqual(self.real(4 << 16, 0, 20015, 0, 1, 0), (("err",), 0))
        self.assertEqual(self.real(4 << 16, 0, 20000, 0, 1, 0), (("ok", 2), 0))
        # exactly 0.001 away is outside the tolerance
        self.assertEqual(self.real(3 << 16, 0, 2001, 0, 1, 0), (("err",), 0))

    def test_bounds_and_refusals(self):
        self.assertEqual(self.real(0, 0, 0xffffffff, 0x7fffffff, 0, 0)[0], ("err",))
        self.assertEqual(self.real(0, 0, 0xfffffffe, 0x7fffffff, 0, 0)[0], ("ok", 0x7ffffffffffffffe))
        self.assertEqual(self.real(0, 0, 1, 0, 0, 20)[0], ("err",))
        self.assertEqual(self.real(0, 0, 1, 0, 0, 18)[0], ("ok", 10 ** 18))
        self.assertEqual(self.real(0, 0, 1, 0, 0, 19)[0], ("err",))  # 10^19 is above the signed bound
        self.assertEqual(self.real(1 << 31, 0, 5, 0, 0, 0)[0], ("err",))
        self.assertEqual(self.real(1 << 31 | 1 << 16, 0, 3, 0, 2, 0)[0], ("ok", 0))

    def test_random_cases_match_specification(self):
        rng = random.Random(5)
        for kind, _ in tool.PLAN:
            for _ in range(6):
                args = tool.make_case(rng, kind)
                tool.check_args(*args)
                self.assertEqual(self.real(*args), tool.spec_scaler(*args), (kind, args))

    def test_helper_models_agree_with_the_bytes(self):
        stats = {k: [0, 0] for k in tool.KINDS}
        bad = {}
        rng = random.Random(9)
        for kind, _ in tool.PLAN:
            for _ in range(5):
                tool.run_scaler(self.image, *tool.make_case(rng, kind), stats=stats, first_bad=bad)
        self.assertEqual(bad, {})
        for kind in tool.KINDS:
            self.assertGreater(stats[kind][0], 0, kind)
            self.assertEqual(stats[kind][1], 0, kind)

    def test_corrupted_model_of_a_helper_is_caught(self):
        original = tool.model_round
        tool.model_round = lambda a: tool.pack(0, 0, tool.parts(a)[2] // 10 ** tool.parts(a)[1])  # floor, not half-even
        try:
            stats = {k: [0, 0] for k in tool.KINDS}
            rng = random.Random(3)
            for _ in range(30):
                tool.run_scaler(self.image, *tool.make_case(rng, "tie"), stats=stats, first_bad={})
            self.assertGreater(stats["round"][1], 0)
        finally:
            tool.model_round = original

    def test_wrong_specifications_are_caught(self):
        bat = tool.battery(self.image)
        for mut in tool.MUTANTS:
            self.assertTrue(any(tool.spec_scaler(*args, mut=(mut,)) != real for args, real in bat), mut)

    def test_corrupted_bytes_are_caught(self):
        bat = tool.battery(self.image)
        for va, at, old, new, what in tool.PATCHES:
            self.assertTrue(tool.byte_detected(tool.patched(self.image, va, at, old, new), bat), what)
        with self.assertRaises(cpu.ToolError):
            tool.patched(self.image, 0x421ebd7, 1, 0x99, 0x89)

    def test_range_and_digest_checks(self):
        for args in ((1 << 32, 0, 0, 0, 0, 0), (0, 0, -1, 0, 0, 0), (0, 0, 0, 0, 256, 0), (29 << 16, 0, 0, 0, 0, 0),
                     (1 << 24, 0, 0, 0, 0, 0)):
            with self.assertRaises(cpu.ToolError):
                tool.check_args(*args)
        with self.assertRaises(cpu.ToolError):
            tool.load_image(bytes([self.data[0] ^ 1]) + self.data[1:4096])

    def test_instruction_streams_close_on_the_function_extents(self):
        extents = tool.program_extents(self.image, self.data)
        self.assertEqual({k: len(v[1]) for k, v in extents.items()},
                         {0x421e9d0: 193, 0x5c457a0: 266, 0x5c442f0: 432, 0x5c448a0: 79, 0x5c46bb0: 238, 0x5c456c0: 78})
        slots = {row[3] for row in tool.call_rows(self.image, extents) if row[2] == "slot"}
        self.assertTrue({0x5c457a0, 0x5c448a0, 0x5c442f0, 0x1560a40} <= slots)

    def test_helper_models_on_known_values(self):
        dec = lambda neg, scale, mag: tool.pack(neg, scale, mag)  # noqa: E731
        # multiply: zero collapses to +0 scale 0; overflow reduces the scale; scale 0 overflow refuses
        self.assertEqual(tool.canon(tool.model_mul(dec(1, 6, 0), dec(0, 0, 100))), (0, 0, 0))
        self.assertEqual(tool.canon(tool.model_mul(dec(1, 2, 7), dec(0, 0, 100))), (1, 2, 700))
        self.assertEqual(tool.canon(tool.model_mul(dec(0, 3, (1 << 96) - 1), dec(0, 0, 10))), (0, 2, (1 << 96) - 1))
        self.assertIsNone(tool.model_mul(dec(0, 0, (1 << 96) - 1), dec(0, 0, 10)))
        with self.assertRaises(cpu.ToolError):
            tool.model_mul(dec(0, 0, 1), dec(0, 1, 10))
        # round: half to even, sign dropped when the result is zero
        self.assertEqual(tool.canon(tool.model_round(dec(0, 1, 25))), (0, 0, 2))
        self.assertEqual(tool.canon(tool.model_round(dec(0, 1, 35))), (0, 0, 4))
        self.assertEqual(tool.canon(tool.model_round(dec(1, 2, 49))), (0, 0, 0))
        self.assertEqual(tool.canon(tool.model_round(dec(1, 1, 15))), (1, 0, 2))
        # fractional part and subtraction
        self.assertEqual(tool.canon(tool.model_fract(dec(0, 3, 12345))), (0, 3, 345))
        self.assertEqual(tool.canon(tool.model_sub(dec(0, 1, 25), dec(0, 0, 2))), (0, 1, 5))
        self.assertEqual(tool.canon(tool.model_sub(dec(0, 1, 15), dec(0, 0, 2))), (1, 1, 5))
        self.assertEqual(tool.canon(tool.model_sub(dec(1, 0, 3), dec(1, 0, 3))), (0, 0, 0))
        self.assertIsNone(tool.model_sub(dec(0, 0, (1 << 96) - 1), dec(1, 0, 1)))
        # comparison is numeric across scales and signs
        self.assertEqual(tool.model_cmp(dec(0, 3, 1), dec(0, 3, 1)), 0)
        self.assertEqual(tool.model_cmp(dec(0, 1, 5), dec(0, 3, 500)), 0)
        self.assertEqual(tool.model_cmp(dec(1, 0, 1), dec(0, 0, 0)), -1)
        self.assertEqual(tool.model_cmp(dec(0, 2, 101), dec(0, 0, 1)), 1)

    def test_every_class_is_deterministic_and_valid(self):
        for kind, _ in tool.PLAN:
            first = [tool.make_case(random.Random(11 + i), kind) for i in range(40)]
            second = [tool.make_case(random.Random(11 + i), kind) for i in range(40)]
            self.assertEqual(first, second)
            for args in first:
                tool.check_args(*args)
                self.assertLess(args[0] >> 16 & 0xff, 29)

    def test_survivor_flips_are_not_counted_as_controls(self):
        tool.SURVIVORS.clear()
        flips = [row for row in tool.branch_rows(self.image, tool.program_extents(self.image, self.data))]
        self.assertGreater(len(flips), 100)
        self.assertEqual({row[0] for row in flips}, set(tool.FUNCTIONS))

    def test_committed_evidence_counts(self):
        measure = json.loads((EVIDENCE / "measure.json").read_text())
        self.assertGreaterEqual(measure["cases"], 10000)
        self.assertGreaterEqual(measure["negative_controls"], 30)
        self.assertEqual(measure["negative_detected"], measure["negative_controls"])
        self.assertEqual(measure["binary_sha256"], tool.SHA)
        self.assertEqual(sum(measure["class_counts"].values()), measure["cases"])
        rows = (EVIDENCE / "helper_taps.tsv").read_text().splitlines()[1:]
        self.assertEqual(len(rows), len(tool.KINDS))
        for row in rows:
            self.assertEqual(row.split("\t")[3], "0")


if __name__ == "__main__":
    unittest.main()
