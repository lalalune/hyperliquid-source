#!/usr/bin/env python3
"""Tests for tools/foundation_level_report.py (RE-001, node #94).

Model tests exercise the report behaviour end to end: inputs (a level
count and spans) through the model to observable outputs (the appended
text, the length-error arm). Checker tests verify the evidence packet
against the digest-pinned binary when it is present.
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "tools"))
sys.path.insert(0, os.path.join(REPO_ROOT, "research", "work-items",
                                "RE-001-level-report-94"))

import foundation_level_report as tool
from foundation_level_report import (
    AppendLengthError, Span, build_report, level_line)

PACKET_DIR = os.path.join(REPO_ROOT, "research", "work-items",
                          "RE-001-level-report-94")


def find_binary():
    """The digest-verified node #94 binary, or None if absent."""
    candidates = (os.path.join(REPO_ROOT, "artifacts", "node", "94",
                               "hl-node"),
                  os.path.join(REPO_ROOT, "work", "hl-node-94.bin"))
    for path in candidates:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "rb") as f:
                if hashlib.sha256(f.read()).hexdigest() == \
                        tool.TARGET_SHA256:
                    return path
        except OSError:
            continue
    return None


BINARY = find_binary()


class ModelTests(unittest.TestCase):
    def test_header_only_when_count_is_zero(self):
        self.assertEqual(build_report(0, []), tool.HEADER)

    def test_single_level_line_exact(self):
        span = Span([1048576, 2097152])  # 2 files, 3 MiB total
        out = build_report(1, [span])
        self.assertEqual(out, tool.HEADER +
                         "  0        2        3\n")

    def test_empty_span_is_zero_files_zero_mib(self):
        self.assertEqual(level_line(3, Span([])), "  3        0        0\n")

    def test_null_pointer_ends_the_sum_but_not_the_count(self):
        # 3 pointers in the span, but the sum stops at the null one.
        span = Span([1048576, None, 2097152])
        self.assertEqual(span.file_count(), 3)
        self.assertEqual(span.size_bytes(), 1048576)
        self.assertEqual(level_line(1, span), "  1        3        1\n")

    def test_mib_rounding_half_up_to_even(self):
        # 1.5 MiB prints as 2 under %8.0f (round-half-to-even).
        self.assertEqual(level_line(0, Span([1572864])),
                         "  0        1        2\n")

    def test_unsigned_conversion_of_negative_sum(self):
        # A signed -1 sum is 2**64-1 as an unsigned value.
        span = Span([-1])
        self.assertEqual(span.size_mib(),
                         float(0xFFFFFFFFFFFFFFFF) * 2.0 ** -20)

    def test_count_ignores_extra_spans(self):
        out = build_report(1, [Span([1048576]), Span([2097152])])
        self.assertEqual(out, tool.HEADER + "  0        1        1\n")

    def test_multiple_levels_in_order(self):
        spans = [Span([1048576]), Span([]), Span([524288, 524288])]
        out = build_report(3, spans)
        self.assertEqual(out, tool.HEADER +
                         "  0        1        1\n" +
                         "  1        0        0\n" +
                         "  2        2        1\n")

    def test_header_append_throws_when_too_small(self):
        with self.assertRaises(AppendLengthError) as caught:
            build_report(0, [], max_append=len(tool.HEADER) - 1)
        self.assertEqual(str(caught.exception), "basic_string::append")

    def test_line_append_throws_and_exact_fit_passes(self):
        span = Span([1048576])
        line_len = len(level_line(0, span))
        with self.assertRaises(AppendLengthError):
            build_report(1, [span],
                         max_append=len(tool.HEADER) + line_len - 1)
        out = build_report(1, [span],
                           max_append=len(tool.HEADER) + line_len)
        self.assertEqual(out, tool.HEADER + level_line(0, span))


@unittest.skipUnless(BINARY, "digest-verified node #94 binary absent")
class PacketTests(unittest.TestCase):
    def test_packet_verify_passes(self):
        result = subprocess.run(
            [sys.executable, os.path.join(PACKET_DIR, "verify.py"),
             "--binary", BINARY],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ALL CHECKS PASSED", result.stdout)
        self.assertEqual(tool.check_packet(PACKET_DIR, BINARY), [])

    def test_excerpt_regeneration_is_byte_identical(self):
        with tempfile.TemporaryDirectory() as tmp:
            copy = os.path.join(tmp, "packet")
            shutil.copytree(PACKET_DIR, copy)
            result = subprocess.run(
                [sys.executable, os.path.join(copy, "export_excerpts.py"),
                 "--binary", BINARY],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            for name in ("window.objdump.txt", "cleanup.objdump.txt",
                         "trampoline.objdump.txt", "sum.objdump.txt",
                         "plt.objdump.txt"):
                with open(os.path.join(PACKET_DIR, name), "rb") as f:
                    original = f.read()
                with open(os.path.join(copy, name), "rb") as f:
                    regenerated = f.read()
                self.assertEqual(tool.strip_objdump_header(regenerated),
                                 tool.strip_objdump_header(original), name)

    def test_corrupt_records_sha_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            copy = os.path.join(tmp, "packet")
            shutil.copytree(PACKET_DIR, copy)
            path = os.path.join(copy, "records.json")
            with open(path) as f:
                rec = json.load(f)
            rec["function"]["sha256"] = "0" * 64
            with open(path, "w") as f:
                json.dump(rec, f)
            self.assertNotEqual(tool.check_packet(copy, BINARY), [])

    def test_corrupt_manifest_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            copy = os.path.join(tmp, "packet")
            shutil.copytree(PACKET_DIR, copy)
            path = os.path.join(copy, "MANIFEST.sha256")
            with open(path) as f:
                lines = f.readlines()
            lines[0] = "0" * 64 + lines[0][64:]
            with open(path, "w") as f:
                f.writelines(lines)
            self.assertNotEqual(tool.check_packet(copy, BINARY), [])

    def test_corrupt_excerpt_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            copy = os.path.join(tmp, "packet")
            shutil.copytree(PACKET_DIR, copy)
            path = os.path.join(copy, "window.objdump.txt")
            with open(path, "a") as f:
                f.write("corruption\n")
            self.assertNotEqual(tool.check_packet(copy, BINARY), [])


if __name__ == "__main__":
    unittest.main()
