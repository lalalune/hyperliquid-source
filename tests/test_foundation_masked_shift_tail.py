#!/usr/bin/env python3
"""Unit tests for the foundation masked-shift tail checker.

Run from the repository root:

    python3 -m unittest tests.test_foundation_masked_shift_tail -v

Each corruption control mutates exactly one recorded fact and must make
the checker fail; the real evidence must pass.
"""

import copy
import importlib.util
import json
import os
import shutil
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVIDENCE = os.path.join(
    ROOT, "research", "work-items", "foundation-masked-shift-tail-94",
    "evidence.json")
FRAMES = os.path.join(
    ROOT, "research", "work-items", "foundation-masked-shift-tail-94",
    "frames.txt")
TOOL = os.path.join(ROOT, "tools", "foundation_masked_shift_tail.py")


def load_tool():
    spec = importlib.util.spec_from_file_location(
        "foundation_masked_shift_tail", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class MaskedShiftTailTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.chdir(ROOT)
        cls.tool = load_tool()
        with open(EVIDENCE) as fh:
            cls.evidence = json.load(fh)

    def run_mutated(self, mutate):
        ev = copy.deepcopy(self.evidence)
        mutate(ev)
        with tempfile.TemporaryDirectory() as tmp:
            ev_path = os.path.join(tmp, "evidence.json")
            with open(ev_path, "w") as fh:
                json.dump(ev, fh)
            shutil.copy(FRAMES, os.path.join(tmp, "frames.txt"))
            with self.assertRaises(ValueError):
                self.tool.run_all(ev_path)

    def test_real_evidence_passes(self):
        self.tool.run_all(EVIDENCE)

    def test_body_hash_control(self):
        self.run_mutated(lambda ev: ev["function"].__setitem__(
            "sha256", "0" * 64))

    def test_body_length_control(self):
        self.run_mutated(lambda ev: ev["function"].__setitem__("bytes", 56))

    def test_window_padding_control(self):
        self.run_mutated(lambda ev: ev["function"].__setitem__(
            "padding_bytes", 6))

    def test_target_digest_control(self):
        self.run_mutated(lambda ev: ev.__setitem__(
            "target_sha256", "0" * 64))

    def test_window_fde_offset_control(self):
        self.run_mutated(lambda ev: ev["function"].__setitem__(
            "fde_section_offset", "0x0028a96d"))

    def test_window_next_fde_offset_control(self):
        self.run_mutated(lambda ev: ev["function"].__setitem__(
            "next_fde_section_offset", "0x00621619"))

    def test_window_fde_cie_control(self):
        self.run_mutated(lambda ev: ev["function"].__setitem__(
            "fde_cie", "0x00000001"))

    def test_callee_hash_control(self):
        self.run_mutated(lambda ev: ev["callee"].__setitem__(
            "sha256", "0" * 64))

    def test_callee_extent_control(self):
        self.run_mutated(lambda ev: ev["callee"].__setitem__("bytes", 792))

    def test_callee_padding_control(self):
        self.run_mutated(lambda ev: ev["callee"].__setitem__(
            "padding_bytes", 6))

    def test_callee_call_sites_control(self):
        def mutate(ev):
            ev["callee"]["direct_e8_call_sites"] = (
                ev["callee"]["direct_e8_call_sites"][:-1])
        self.run_mutated(mutate)

    def test_caller_list_control(self):
        def mutate(ev):
            ev["incoming"]["direct_e8_callers"] = ["0x4f9bfa0"]
        self.run_mutated(mutate)

    def test_tail_jump_control(self):
        self.run_mutated(lambda ev: ev["rule"].__setitem__(
            "tail_jump", "0x4f9bee1"))

    def test_edge_values_control(self):
        for i in range(len(self.evidence["rule"]["edges"])):
            def mutate(ev, i=i):
                ev["rule"]["edges"][i]["out"] = "0x0"
            with self.subTest(edge=i):
                self.run_mutated(mutate)

    def test_call_target_constant_control(self):
        self.tool.CALLEE_START = 0x5423271
        try:
            with self.assertRaises(ValueError):
                self.tool.run_all(EVIDENCE)
        finally:
            self.tool.CALLEE_START = 0x5423270

    def test_jump_target_constant_control(self):
        self.tool.JUMP_TARGET = 0x4F9BEE1
        try:
            with self.assertRaises(ValueError):
                self.tool.run_all(EVIDENCE)
        finally:
            self.tool.JUMP_TARGET = 0x4F9BEE0

    def test_window_start_control(self):
        self.run_mutated(lambda ev: ev["function"].__setitem__(
            "start_va", "0x4f9bfa1"))

    def test_frames_content_control(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev_path = os.path.join(tmp, "evidence.json")
            with open(ev_path, "w") as fh:
                json.dump(self.evidence, fh)
            with open(FRAMES) as fh:
                frames = fh.read()
            corrupted = frames.replace("0028a96c", "0028a96d")
            with open(os.path.join(tmp, "frames.txt"), "w") as fh:
                fh.write(corrupted)
            with self.assertRaises(ValueError):
                self.tool.run_all(ev_path)


if __name__ == "__main__":
    unittest.main()
