import hashlib
import itertools
import json
import random
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import decimal_from_f64_115 as tool  # noqa: E402

EVIDENCE = ROOT / "research/work-items/l1-shared-f64-to-decimal-115"
DATA = tool.TARGET.read_bytes()
IMAGE = tool.load_image(DATA)


def caller(bits, tag=6, blob=None, parse_err=False):
    case = dict(tag=tag, blob=blob if blob is not None else bytes(range(28)), ptr=3, len=9, parse_err=parse_err,
                bits=bits)
    return tool.run_caller(IMAGE, case)


def decimal(bits):
    """(scale, negative, mantissa) of the decimal the caller builds for a float, via a non-passthrough tag."""
    tag, payload, _, _, _ = caller(bits, tag=1)
    assert tag == tool.OK_TAG, hex(tag)
    flags, hi, lo_mid = struct.unpack("<IIQ", payload)
    return (flags >> 16) & 0xff, bool(flags >> 31), (hi << 64) | lo_mid


def f64(x):
    return struct.unpack("<Q", struct.pack("<d", x))[0]


class KernelTests(unittest.TestCase):
    def test_binary_digest_is_checked(self):
        self.assertEqual(hashlib.sha256(DATA).hexdigest(), tool.SHA)
        with self.assertRaises(tool.cpu.ToolError):
            tool.load_image(DATA[:4096])

    def test_specification_matches_the_bytes_per_class(self):
        rng = random.Random(9)
        for kind, count in (("tiny", 12), ("f64_small", 20), ("f64_mid", 20), ("f32", 20), ("wide_mantissa", 30),
                            ("round_edge", 30), ("multiply_overflow", 12), ("clamp_edge", 20), ("carry_edge", 20), ("scale_edge", 20)):
            for _ in range(count):
                args = tool.kernel_case(rng, kind)
                real = tool.run_kernel(IMAGE, *args)
                self.assertEqual(tool.kernel_view(real[:4]), tool.spec_kernel(*args), (kind, args))

    def test_known_conversions(self):
        self.assertEqual(decimal(f64(1.0)), (0, False, 1))
        self.assertEqual(decimal(f64(-1.0)), (0, True, 1))
        self.assertEqual(decimal(f64(0.5)), (1, False, 5))
        self.assertEqual(decimal(f64(0.1)), (1, False, 1))
        self.assertEqual(decimal(f64(123456.789)), (3, False, 123456789))
        self.assertEqual(decimal(f64(1e15)), (0, False, 10 ** 15))
        self.assertEqual(decimal(f64(2.0 ** -1074)), (0, False, 0))
        scale, negative, mantissa = decimal(f64(7.9e28))
        self.assertEqual((scale, negative), (0, False))
        self.assertTrue(7_8 * 10 ** 27 < mantissa < 7_9 * 10 ** 27 + 10 ** 27)

    def test_each_flag_changes_some_result(self):
        rng = random.Random(21)
        seen = {"is64": False, "round": False}
        for _ in range(300):
            lo, mid, hi, e2, pos, _, _ = tool.kernel_case(rng, "f64_mid")
            base = tool.spec_kernel(lo, mid, hi, e2, pos, 1, 1)
            seen["is64"] |= base != tool.spec_kernel(lo, mid, hi, e2, pos, 0, 1)
            seen["round"] |= base != tool.spec_kernel(lo, mid, hi, e2, pos, 1, 0)
        self.assertEqual(seen, {"is64": True, "round": True})
        for is64, rounding in ((0, 0), (0, 1), (1, 0), (1, 1)):
            args = (0x89abcdef, 0x123456, 0, -9, 1, is64, rounding)
            self.assertEqual(tool.kernel_view(tool.run_kernel(IMAGE, *args)[:4]), tool.spec_kernel(*args))

    def test_half_rounds_up_and_carries_across_words(self):
        q = (((1 << 40) + 5) << 32) | 0xffffffff
        m = 2 * q + 1
        args = (m & 0xffffffff, (m >> 32) & 0xffffffff, m >> 64, -1, 1, 1, 1)
        flags, hi, lo_mid = tool.kernel_view(tool.run_kernel(IMAGE, *args)[:4])
        self.assertEqual((flags, hi, lo_mid), (0, (q + 1) >> 64, (q + 1) & ((1 << 64) - 1)))

    def test_zero_keeps_only_its_sign(self):
        self.assertEqual(decimal(0), (0, False, 0))
        self.assertEqual(decimal(1 << 63), (0, True, 0))

    def test_values_that_do_not_fit_are_refused(self):
        for value in (1e30, -1e300, 8e28):
            tag, payload, trace, kargs, _ = caller(f64(value), tag=1)
            self.assertEqual(tag, tool.ERR_TAG)
            self.assertIsNone(payload)
            self.assertEqual(trace[-1][0], "parse")
            self.assertIsNotNone(kargs)
        self.assertEqual(tool.run_kernel(IMAGE, 0xffffffff, 0xffffffff, 0x7fffffff, 3, 1, 1, 1)[0], 0)

    def test_non_finite_values_are_refused_before_the_converter(self):
        for bits in (0x7ff0000000000000, 0xfff0000000000000, 0x7ff8000000000000, 0x7ff0000000000001):
            tag, _, _, kargs, _ = caller(bits, tag=1)
            self.assertEqual((tag, kargs), (tool.ERR_TAG, None))

    def test_scale_never_exceeds_28(self):
        rng = random.Random(4)
        for _ in range(60):
            args = tool.kernel_case(rng, rng.choice(("f64_mid", "clamp_edge", "wide_mantissa")))
            res = tool.spec_kernel(*args)
            if res is not None:
                self.assertLessEqual((res[0] >> 16) & 0x7fff, 28)
                self.assertEqual(res[0] & 0x7fff, 0)

    def test_passthrough_tag_copies_sixteen_bytes_and_skips_parsing(self):
        blob = bytes(range(100, 128))
        tag, payload, trace, kargs, _ = caller(f64(3.5), tag=6, blob=blob)
        self.assertEqual((tag, payload, kargs), (tool.OK_TAG, blob[:16], None))
        self.assertEqual([row[0] for row in trace], ["read"])

    def test_free_happens_only_for_other_tags_with_a_pointer(self):
        blob = struct.pack("<IQQI", 0, 0x1234, 0x56, 0) + bytes(8)
        freed = lambda tag, b=blob: [r for r in caller(f64(2.0), tag=tag, blob=b)[2] if r[0] == "free"]  # noqa: E731
        self.assertEqual(freed(0), [("free", 0x56, 0x1234, 0)])
        self.assertEqual(freed(5), [("free", 0x56, 0x1234, 0)])
        for tag in (1, 2, 3, 4):
            self.assertEqual(freed(tag), [])
        null = struct.pack("<IQQI", 0, 0, 0x56, 0) + bytes(8)
        self.assertEqual(freed(0, null), [])

    def test_parse_error_is_an_error_and_still_frees(self):
        blob = struct.pack("<IQQI", 0, 8, 0x40, 0) + bytes(8)
        tag, payload, trace, kargs, _ = caller(f64(1.0), tag=9, blob=blob, parse_err=True)
        self.assertEqual((tag, payload, kargs), (tool.ERR_TAG, None, None))
        self.assertEqual(trace[-1], ("free", 0x40, 8, 0))


class ControlTests(unittest.TestCase):
    def test_wrong_specifications_are_caught(self):
        results = list(itertools.islice(tool.control_results(IMAGE, DATA), len(tool.KERNEL_MUTANTS) + len(tool.CALLER_MUTANTS)))
        self.assertEqual(len(results), 28)
        self.assertEqual([name for name, _, ok in results if not ok], [])

    def test_byte_corruption_changes_results(self):
        for va, at, old, new, _ in (tool.PATCHES[1], tool.PATCHES[14], tool.PATCHES[18]):
            bad = tool.patched(IMAGE, va, at, old, new)
            self.assertNotEqual(bad.data[IMAGE.file_offset(va) + at], IMAGE.data[IMAGE.file_offset(va) + at])
        with self.assertRaises(tool.cpu.ToolError):
            tool.patched(IMAGE, 0x5c43e5e, 3, 0x55, 0x56)
        bad = tool.patched(IMAGE, 0x4309a19, 2, 0x06, 0x05)
        real = tool.run_caller(IMAGE, dict(tag=6, blob=bytes(28), ptr=0, len=0, parse_err=False, bits=f64(1.0)))
        broken = tool.run_caller(bad, dict(tag=6, blob=bytes(28), ptr=0, len=0, parse_err=False, bits=f64(1.0)))
        self.assertNotEqual(real[:4], broken[:4])

    def test_out_of_range_inputs_are_rejected(self):
        for args in ((1 << 32, 0, 0, 0, 1, 1, 1), (0, 0, 0, 1 << 31, 1, 1, 1), (0, 0, 0, 0, 2, 1, 1), (0, 0, 0, 0, 1, 1, -1)):
            with self.assertRaises(tool.cpu.ToolError):
                tool.check_kernel_args(*args)
        tool.check_kernel_args(0xffffffff, 0xffffffff, 0xffffffff, -(1 << 31), 0, 0, 0)

    def test_mutated_specification_differs_on_a_witness(self):
        self.assertNotEqual(tool.spec_kernel(5, 0, 0, 0, 0, 1, 1), tool.spec_kernel(5, 0, 0, 0, 0, 1, 1, mut=("ignore_sign",)))


class EvidenceTests(unittest.TestCase):
    def test_measure_summary_is_consistent(self):
        measure = json.loads((EVIDENCE / "measure.json").read_text())
        self.assertEqual(measure["binary_sha256"], tool.SHA)
        self.assertEqual(measure["cases"], measure["kernel_cases"] + measure["caller_cases"])
        self.assertEqual(measure["negative_controls"], measure["negative_detected"])
        self.assertGreaterEqual(measure["cases"], 10000)
        self.assertGreaterEqual(measure["negative_controls"], 30)

    def test_manifest_matches_files(self):
        for line in (EVIDENCE / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((EVIDENCE / name).read_bytes()).hexdigest(), digest, name)

    def test_unreached_arms_are_the_documented_ones(self):
        rows = [line.split("\t") for line in (EVIDENCE / "coverage.tsv").read_text().splitlines()[1:]]
        by_function = {row[0]: row for row in rows}
        self.assertEqual(set(by_function), {"0x43099f0", "0x5c43c60"})
        self.assertIn("0x5c441e6", by_function["0x5c43c60"][3].split(","))
        self.assertIn("0x4309be1", by_function["0x43099f0"][3].split(","))


if __name__ == "__main__":
    unittest.main()
