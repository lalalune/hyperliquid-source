#!/usr/bin/env python3
"""Unit tests for the foundation sentinel-increment checker.

Run from the repository root:

    python3 -m unittest tests.test_foundation_sentinel_increment -v

Each corruption control mutates exactly one recorded fact and must make
the checker fail; the real evidence must pass.
"""

import copy
import importlib.util
import json
import os
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVIDENCE = os.path.join(
    ROOT, "research", "work-items", "foundation-sentinel-increment-94",
    "evidence.json")
FRAMES = os.path.join(
    ROOT, "research", "work-items", "foundation-sentinel-increment-94",
    "frames.txt")
TOOL = os.path.join(ROOT, "tools", "foundation_sentinel_increment.py")


def load_tool():
    spec = importlib.util.spec_from_file_location(
        "foundation_sentinel_increment", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SentinelIncrementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.chdir(ROOT)
        cls.tool = load_tool()
        with open(EVIDENCE) as fh:
            cls.evidence = json.load(fh)

    def run_mutated(self, mutate, frames_mutate=None):
        ev = copy.deepcopy(self.evidence)
        mutate(ev)
        with tempfile.TemporaryDirectory() as tmp:
            ev_path = os.path.join(tmp, "evidence.json")
            with open(ev_path, "w") as fh:
                json.dump(ev, fh)
            with open(FRAMES) as fh:
                frames_text = fh.read()
            if frames_mutate is not None:
                frames_text = frames_mutate(frames_text)
            with open(os.path.join(tmp, "frames.txt"), "w") as fh:
                fh.write(frames_text)
            with self.assertRaises(ValueError):
                self.tool.run_all(ev_path)

    def test_real_evidence_passes(self):
        self.tool.run_all(EVIDENCE)

    def test_body_hash_control(self):
        self.run_mutated(lambda ev: ev["function"].__setitem__(
            "sha256", "0" * 64))

    def test_body_length_control(self):
        self.run_mutated(lambda ev: ev["function"].__setitem__("bytes", 29))

    def test_window_padding_control(self):
        self.run_mutated(lambda ev: ev["function"].__setitem__(
            "padding_bytes", 3))

    def test_target_digest_control(self):
        self.run_mutated(lambda ev: ev.__setitem__(
            "target_sha256", "0" * 64))

    def test_window_fde_offset_control(self):
        self.run_mutated(lambda ev: ev["function"].__setitem__(
            "fde_section_offset", "0x00104049"))

    def test_window_next_fde_offset_control(self):
        self.run_mutated(lambda ev: ev["function"].__setitem__(
            "next_fde_section_offset", "0x00104061"))

    def test_window_prev_fde_offset_control(self):
        self.run_mutated(lambda ev: ev["function"].__setitem__(
            "prev_fde_section_offset", "0x00104029"))

    def test_window_cie_control(self):
        self.run_mutated(lambda ev: ev["function"].__setitem__(
            "fde_cie", "0x00000001"))

    def test_callee_start_control(self):
        self.run_mutated(lambda ev: ev["callee"].__setitem__(
            "start_va", "0x3597030"))

    def test_callee_sha_control(self):
        self.run_mutated(lambda ev: ev["callee"].__setitem__(
            "sha256", "0" * 64))

    def test_callee_length_control(self):
        self.run_mutated(lambda ev: ev["callee"].__setitem__("bytes", 369))

    def test_callee_padding_control(self):
        self.run_mutated(lambda ev: ev["callee"].__setitem__(
            "padding_bytes", 13))

    def test_callee_sites_control(self):
        def mutate(ev):
            ev["callee"]["direct_e8_call_sites"] = (
                ev["callee"]["direct_e8_call_sites"][:-1])
        self.run_mutated(mutate)

    def test_caller_list_control(self):
        self.run_mutated(lambda ev: ev["incoming"].__setitem__(
            "direct_e8_callers", ["0x1234"]))

    def test_edge_value_control(self):
        def mutate(ev):
            ev["rule"]["edges"][0]["stored"] = "0x2"
        self.run_mutated(mutate)

    def test_sentinel_value_control(self):
        self.run_mutated(lambda ev: ev["rule"].__setitem__(
            "sentinel", "0xfffffffffffffffe"))

    def test_field_control(self):
        self.run_mutated(lambda ev: ev["rule"].__setitem__(
            "field", "qword at [obj+0x28]"))

    def test_frames_text_control(self):
        self.run_mutated(
            lambda ev: None,
            frames_mutate=lambda t: t.replace("00104048", "00104049"))


if __name__ == "__main__":
    unittest.main()
