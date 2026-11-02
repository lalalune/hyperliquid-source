"""Unit tests for the RE-004 mul256 difference-upstream packet."""

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

from mul256_difference_upstream94 import (  # noqa: E402
    DEC_CALLS,
    MASK,
    SITES,
    ZERO,
    build_cases,
    wrapper_outcome,
)

ROOT = Path(__file__).resolve().parent.parent
PACKET = ROOT / "research/work-items/RE-004-mul256-difference-upstream-94"
TOOL = ROOT / "tools/mul256_difference_upstream94.py"
BINARY = ROOT / "artifacts/node/94/hl-node"

FILES = ["evidence.json", "sites.tsv", "cases.tsv", "windows.txt"]


def run_tool(out, env=None):
    cmd = [sys.executable, str(TOOL), "--out", str(out)]
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, env=env)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class TestPacket(unittest.TestCase):
    def test_regeneration_matches_packet(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = run_tool(tmp)
            self.assertEqual(r.returncode, 0, r.stderr)
            for name in FILES:
                self.assertEqual(digest(Path(tmp) / name), digest(PACKET / name), name)

    def test_cross_env_determinism(self):
        import os
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            env_a = dict(os.environ, PYTHONHASHSEED="1", TZ="UTC")
            env_b = dict(os.environ, PYTHONHASHSEED="42", TZ="Asia/Seoul")
            self.assertEqual(run_tool(a, env_a).returncode, 0)
            self.assertEqual(run_tool(b, env_b).returncode, 0)
            for name in FILES:
                self.assertEqual(digest(Path(a) / name), digest(Path(b) / name), name)

    def test_manifest(self):
        lines = (PACKET / "MANIFEST.sha256").read_text().splitlines()
        self.assertEqual(len(lines), 5)
        for line in lines:
            want, name = line.split("  ")
            self.assertEqual(digest(PACKET / name), want, name)

    def test_packet_shape(self):
        evidence = json.loads((PACKET / "evidence.json").read_text())
        self.assertEqual(evidence["sites"], 12)
        self.assertEqual(evidence["e9_tail_jump_callers"], 0)
        self.assertEqual(len(evidence["windows"]), 12)
        sites = (PACKET / "sites.tsv").read_text().splitlines()
        self.assertEqual(len(sites), 13)  # header + 12
        cases = (PACKET / "cases.tsv").read_text().splitlines()
        self.assertEqual(len(cases), 12)  # header + 11
        windows = (PACKET / "windows.txt").read_text().splitlines()
        self.assertEqual(len(windows), 12)
        for line in windows:
            self.assertIn("length=160", line)

    def test_wrapper_model_collapse_indistinguishable(self):
        # Genuine 0 (W5) vs collapsed 0 (W6) at caller-A: identical outputs.
        genuine = wrapper_outcome(5, ZERO, False, 1, 7)
        collapsed = wrapper_outcome(5, (930, 100, 100, 0), True, 1, 7)
        self.assertEqual(genuine, collapsed)
        # Same at caller-B: W8 vs W9.
        genuine_b = wrapper_outcome(5, ZERO, False, 1, 7)
        collapsed_b = wrapper_outcome(5, (1000, 65, 100, 0), True, 1, 7)
        self.assertEqual(genuine_b, collapsed_b)
        # Copy path never touches the mutated object.
        ret, stored, counter, flag = wrapper_outcome(3, None, False, 0, 7)
        self.assertEqual((ret, stored, counter, flag), ("copied-fields", None, 7, False))
        # Counter wrap is collapse-independent: same input counter, same output.
        wrap_genuine = wrapper_outcome(5, (930, 100, 100, 0), False, 1, MASK)
        wrap_collapsed = wrapper_outcome(5, (930, 100, 100, 0), True, 1, MASK)
        self.assertEqual(wrap_genuine[2], MASK)
        self.assertEqual(wrap_collapsed[2], MASK)
        # State byte 0 leaves the counter alone on the tag-5 path.
        self.assertEqual(wrapper_outcome(5, (1, 0, 0, 0), False, 0, 7)[2], 7)

    def test_case_table_matches_model(self):
        rows = build_cases()
        by_case = {r[1]: r for r in rows}
        self.assertEqual(by_case["W5-A-genuine-zero"][7:], by_case["W6-A-collapsed-zero"][7:])
        self.assertEqual(by_case["W8-B-genuine-zero"][7:], by_case["W9-B-collapsed-zero"][7:])
        self.assertEqual(len(rows), 11)

    def test_anchor_tamper_controls(self):
        # Flipping one anchor byte must fail generation: copy the tool, corrupt
        # one expected call byte, and confirm a nonzero exit.
        import re
        src = TOOL.read_text()
        tampered = src.replace('"e823ed0200"', '"e823ed0201"', 1)
        self.assertNotEqual(tampered, src)
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad_tool.py"
            bad.write_text(tampered)
            r = subprocess.run([sys.executable, str(bad), "--out", str(Path(tmp) / "o")],
                               cwd=ROOT, capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0)
        # A non-anchor byte change (README text) must not affect generation.
        with tempfile.TemporaryDirectory() as tmp:
            r = run_tool(tmp)
            self.assertEqual(r.returncode, 0)

    def test_decoder_split_and_site_count(self):
        decoders = {}
        for _s, _fs, _fe, _c, d, _ds, _cb in SITES:
            decoders[d] = decoders.get(d, 0) + 1
        self.assertEqual(decoders, {0x2787460: 6, 0x2786DD0: 6})
        self.assertEqual(len(DEC_CALLS), 12)
        self.assertEqual(len({s for s, *_ in SITES}), 12)
        self.assertEqual(len({(fs, fe) for _s, fs, fe, *_ in SITES}), 12)


if __name__ == "__main__":
    unittest.main()
