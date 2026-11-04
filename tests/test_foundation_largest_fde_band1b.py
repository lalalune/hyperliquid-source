#!/usr/bin/env python3
"""Committed test for packet RE-001-node115-largest-fde-band1b.

Runs the actual saved checker tools/foundation_largest_fde_band1b.py against
artifacts/node/115/hl-node read in place; the pinned target is never executed,
copied or modified. The literal expectations below are the values recorded
from the focused proof, so they pin the checker's claims independently of the
constants the checker compares against itself.
"""
from __future__ import annotations

import copy
import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TOOL = REPO / "tools" / "foundation_largest_fde_band1b.py"
TARGET = REPO / "artifacts" / "node" / "115" / "hl-node"
MODULE_NAME = "foundation_largest_fde_band1b"

FRAMES_LINE = (
    "010aef40 0000006c 0039672c FDE cie=0039672c "
    "pc=0000000001d7f620..0000000001d9243f"
)
HEAD_PREFIX = (
    "55 41 57 41 56 41 55 41 54 53 48 81 ec 00 10 00 00 48 c7 04 24 00 00 00 00 48"
)


def load_tool():
    assert TOOL.is_file(), "missing checker {}".format(TOOL)
    spec = importlib.util.spec_from_file_location(MODULE_NAME, TOOL)
    assert spec is not None and spec.loader is not None, "cannot load {}".format(TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class LargestFdeBand1bTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        assert TARGET.is_file(), "missing pinned target {}".format(TARGET)
        cls.tool = load_tool()
        blob = TARGET.read_bytes()
        try:
            facts, context = cls.tool.analyze(blob)
            cls.tool.check(facts)
            cls.tool.corruption_controls(blob, facts, context)
            cls.facts = facts
        finally:
            del blob

    def test_cli_exits_zero_and_prints_recorded_values(self):
        proc = subprocess.run(
            [sys.executable, "-B", str(TOOL)],
            cwd=str(REPO),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=900,
            check=False,
        )
        output = proc.stdout.decode("utf-8", "replace")
        self.assertEqual(proc.returncode, 0, output[-4000:])
        self.assertIn("largest-fde-band1b checker OK", output)
        self.assertIn(
            "chosen pc=0x1d7f620..0x1d9243f bytes=77343 file_offset=0x1d7e620",
            output,
        )
        self.assertIn(FRAMES_LINE, output)
        self.assertIn("band 0x1b00000..0x2000000 holds 3437 FDEs", output)

    def test_recorded_identity_and_extent(self):
        facts = self.facts
        self.assertEqual(
            facts["target_sha256"],
            "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301",
        )
        self.assertEqual(facts["target_size"], 105896032)
        self.assertEqual(
            facts["text"], {"va": 0x1419300, "offset": 0x1418300, "size": 83719936}
        )
        self.assertEqual(
            facts["eh_frame"], {"va": 0xCA6ED8, "offset": 0xCA6ED8, "size": 7803772}
        )
        self.assertEqual(facts["cie_count"], 3)
        self.assertEqual(facts["fde_count"], 135313)
        chosen = facts["chosen"]
        self.assertEqual(chosen["start"], 0x1D7F620)
        self.assertEqual(chosen["end"], 0x1D9243F)
        self.assertEqual(chosen["bytes"], 77343)
        self.assertEqual(chosen["file_offset"], 0x1D7E620)
        self.assertEqual(
            chosen["sha256"],
            "7183b9de5bf56bb92e9ac042d79d2bae620eaad91c549e5ef9601b575b605bc2",
        )
        self.assertEqual(chosen["fde_record_offset"], 0x408068)
        self.assertEqual(chosen["cie_record_offset"], 0x39672C)
        self.assertEqual(chosen["cie_augmentation"], "zPLR")
        self.assertEqual(chosen["cie_fde_encoding"], 0x1B)

    def test_band_census_and_candidates(self):
        facts = self.facts
        self.assertEqual(facts["band"], [0x1B00000, 0x2000000])
        self.assertEqual(facts["band_fde_count"], 3437)
        candidates = facts["candidates"]
        self.assertEqual(len(candidates), 10)
        expected = (
            (0x1D7F620, 0x1D9243F, 77343,
             "7183b9de5bf56bb92e9ac042d79d2bae620eaad91c549e5ef9601b575b605bc2"),
            (0x1D793E0, 0x1D7F619, 25145,
             "b61907d78b96b2451f187bebbc48e32745b259fd8921bc0d28b1938f819ab1c2"),
            (0x1BEB080, 0x1BF03EB, 21355,
             "85c3db1daf89c42beba525091139f13c9a45a8ad8849c3694406c04d28b43850"),
            (0x1C14A50, 0x1C19BD5, 20869,
             "4ff2702e4e47268f5b971bbe44bff19a9cb559468ee2d555a483c572b105533f"),
            (0x1C1E610, 0x1C23558, 20296,
             "8477bbf45c0e169511f7b2e7636436048823b98b39df4e6b23d24e87133a6ef1"),
            (0x1F5E410, 0x1F62ECC, 19132,
             "1389818585a4c12e0c2a852ff75abacfa690577a7057f0506761f9e4abe61d39"),
            (0x1E7A3E0, 0x1E7EB37, 18263,
             "df6a429f13c852a2906963ac6895c559765f50bc8b51719272bc85dd195f83a0"),
            (0x1E54850, 0x1E58F97, 18247,
             "7e47475d565ecf25c168155992404dcc779ba06b56c787a075e333cd90f7aaad"),
            (0x1F7E100, 0x1F82681, 17793,
             "6a8a64a57bd3c13c758bacecab6bdee9cac9d503780013cd0eed4fb0b588f38e"),
            (0x1ED4320, 0x1ED86ED, 17357,
             "ddd97f4db968be2e4c7fe76d994086f5c61ef0c9646cbef0d924268d7d705d34"),
        )
        observed = [
            (entry["start"], entry["end"], entry["bytes"], entry["sha256"])
            for entry in candidates
        ]
        self.assertEqual(observed, list(expected))
        text_va, text_size = 0x1419300, 83719936
        for start, end, size, digest in expected:
            self.assertEqual(end - start, size)
            self.assertGreaterEqual(start, 0x1B00000)
            self.assertLessEqual(end, 0x2000000)
            self.assertGreaterEqual(start, text_va)
            self.assertLessEqual(end, text_va + text_size)
            self.assertEqual(len(digest), 64)
        starts = [start for start, _, _, _ in expected]
        self.assertEqual(len(starts), len(set(starts)))
        sizes = [size for _, _, size, _ in expected]
        self.assertEqual(sizes, sorted(sizes, reverse=True))
        self.assertEqual(
            (candidates[0]["start"], candidates[0]["end"], candidates[0]["bytes"]),
            (0x1D7F620, 0x1D9243F, 77343),
        )

    def test_frames_row_and_head_bytes(self):
        facts = self.facts
        self.assertEqual(facts["frames_line"], FRAMES_LINE)
        self.assertEqual(self.tool.FRAMES_LINE, FRAMES_LINE)
        head = facts["head_hex"].split()
        self.assertEqual(len(head), 160)
        self.assertEqual(" ".join(head[:26]), HEAD_PREFIX)

    def test_tampered_extent_is_rejected(self):
        tampered = copy.deepcopy(self.facts)
        tampered["chosen"]["end"] += 1
        with self.assertRaises(AssertionError):
            self.tool.check(tampered)

    def test_tampered_digest_is_rejected(self):
        tampered = copy.deepcopy(self.facts)
        tampered["chosen"]["sha256"] = "0" * 64
        with self.assertRaises(AssertionError):
            self.tool.check(tampered)

    def test_missing_target_fails_closed(self):
        original = self.tool.TARGET_REL
        self.tool.TARGET_REL = Path("artifacts") / "node" / "000" / "absent-node"
        try:
            with self.assertRaises(AssertionError):
                self.tool.main()
        finally:
            self.tool.TARGET_REL = original


if __name__ == "__main__":
    unittest.main()
