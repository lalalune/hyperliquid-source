"""Tests for the node #94 unconditional create-and-format model."""

import os
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import foundation_unconditional_create_format as subject

REPO = Path(__file__).resolve().parents[1]
PACKET = REPO / "research" / "work-items" / "RE-001-unconditional-create-format-94"


class CreateFormatTests(unittest.TestCase):
    def test_separators_are_exact_inline_literals(self):
        equals, separator = subject.build_separators()
        self.assertEqual(equals, "=")
        self.assertEqual(separator, "; ")
        self.assertEqual([ord(c) for c in equals], [0x3D])
        self.assertEqual([ord(c) for c in separator], [0x3B, 0x20])

    def test_found_path_returns_zero_and_leaves_destination_unchanged(self):
        events = []
        code, dest = subject.unconditional_create_format(
            lambda: subject.LookupOutcome(status_byte=1),
            lambda record, sep, eq: self.fail("formatter must not run"),
            events)
        self.assertEqual(code, 0)
        self.assertIsNone(dest)
        self.assertEqual(events, [])

    def test_found_path_releases_array_then_control_when_present(self):
        events = []
        code, _ = subject.unconditional_create_format(
            lambda: subject.LookupOutcome(
                status_byte=0xFF, status_array=object(),
                control=object()),
            lambda record, sep, eq: self.fail("formatter must not run"),
            events)
        self.assertEqual(code, 0)
        self.assertEqual(events, [subject.RELEASE_ARRAY,
                                  subject.RELEASE_CONTROL])

    def test_found_path_skips_zero_array_and_control(self):
        events = []
        code, _ = subject.unconditional_create_format(
            lambda: subject.LookupOutcome(status_byte=7),
            lambda record, sep, eq: self.fail("formatter must not run"),
            events)
        self.assertEqual(code, 0)
        self.assertEqual(events, [])

    def test_create_path_formats_with_record_and_separators(self):
        seen = {}
        record = object()

        def formatter(rec, sep, eq):
            seen["record"] = rec
            seen["separator"] = sep
            seen["equals"] = eq
            return "formatted"

        events = []
        code, dest = subject.unconditional_create_format(
            lambda: subject.LookupOutcome(status_byte=0, record=record),
            formatter, events)
        self.assertEqual(code, 1)
        self.assertEqual(dest, "formatted")
        self.assertIs(seen["record"], record)
        self.assertEqual(seen["separator"], "; ")
        self.assertEqual(seen["equals"], "=")

    def test_create_path_disposal_order_then_cleanup(self):
        events = []
        code, dest = subject.unconditional_create_format(
            lambda: subject.LookupOutcome(
                status_byte=0, record=object(), control=object()),
            lambda rec, sep, eq: "out", events)
        self.assertEqual(code, 1)
        self.assertEqual(dest, "out")
        self.assertEqual(events, [subject.DISPOSE_TEMP,
                                  subject.DISPOSE_SEPARATOR,
                                  subject.DISPOSE_EQUALS,
                                  subject.RELEASE_CONTROL])

    def test_create_path_with_zero_status_array_releases_only_control(self):
        events = []
        subject.unconditional_create_format(
            lambda: subject.LookupOutcome(
                status_byte=0, record=object(), control=object()),
            lambda rec, sep, eq: "out", events)
        self.assertNotIn(subject.RELEASE_ARRAY, events)

    def test_create_path_with_no_control_releases_nothing_after_disposal(self):
        events = []
        subject.unconditional_create_format(
            lambda: subject.LookupOutcome(status_byte=0, record=object()),
            lambda rec, sep, eq: "out", events)
        self.assertEqual(events, [subject.DISPOSE_TEMP,
                                  subject.DISPOSE_SEPARATOR,
                                  subject.DISPOSE_EQUALS])

    def test_status_byte_zero_is_the_only_create_signal(self):
        for byte in (1, 2, 0x7F, 0xFF):
            events = []
            code, _ = subject.unconditional_create_format(
                lambda byte=byte: subject.LookupOutcome(status_byte=byte),
                lambda rec, sep, eq: self.fail("formatter must not run"),
                events)
            self.assertEqual(code, 0)

    def test_no_view_or_gate_argument_exists(self):
        # The modelled function takes no view: the lookup runs
        # unconditionally, unlike the indexed sibling's parser/index gates.
        import inspect
        params = inspect.signature(
            subject.unconditional_create_format).parameters
        self.assertEqual(list(params), ["lookup_fn", "format_fn", "events"])

    def test_packet_verification_passes(self):
        binary = REPO / "work" / "hl-node-94.bin"
        if not binary.exists():
            self.skipTest("digest-verified work binary not present")
        result = subprocess.run(
            [sys.executable, str(PACKET / "verify.py"),
             "--binary", str(binary)],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ALL CHECKS PASSED", result.stdout)

    def test_packet_excerpts_regenerate_byte_for_byte(self):
        binary = REPO / "work" / "hl-node-94.bin"
        if not binary.exists():
            self.skipTest("digest-verified work binary not present")
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [sys.executable, str(PACKET / "export_excerpts.py"),
                 "--binary", str(binary), "--out", tmp],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            def normalized(blob):
                lines = blob.split(b"\n")
                for i, line in enumerate(lines):
                    if b"file format" in line:
                        lines[i] = b"file format elf64-x86-64"
                return b"\n".join(lines)

            for name in ("window.objdump.txt", "cleanup.objdump.txt",
                         "lookup.objdump.txt", "formatter.objdump.txt",
                         "moveassign.objdump.txt", "control.objdump.txt"):
                fresh = (Path(tmp) / name).read_bytes()
                committed = (PACKET / name).read_bytes()
                self.assertEqual(normalized(fresh), normalized(committed),
                                 name)


if __name__ == "__main__":
    unittest.main()
