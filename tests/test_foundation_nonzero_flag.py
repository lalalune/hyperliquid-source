#!/usr/bin/env python3
"""Unit tests for the foundation nonzero-flag checker.

Run from the repository root:

    python3 -m unittest tests.test_foundation_nonzero_flag -v

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
    ROOT, "research", "work-items", "foundation-nonzero-flag-94",
    "evidence.json")
FRAMES = os.path.join(
    ROOT, "research", "work-items", "foundation-nonzero-flag-94",
    "frames.txt")
TOOL = os.path.join(ROOT, "tools", "foundation_nonzero_flag.py")


def load_tool():
    spec = importlib.util.spec_from_file_location(
        "foundation_nonzero_flag", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class NonzeroFlagTests(unittest.TestCase):
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
        self.run_mutated(lambda ev: ev["function"].__setitem__("bytes", 87))

    def test_window_padding_control(self):
        self.run_mutated(lambda ev: ev["function"].__setitem__(
            "padding_bytes", 3))

    def test_window_padding_hex_control(self):
        self.run_mutated(lambda ev: ev["function"].__setitem__(
            "padding_hex", "00" * 8))

    def test_target_digest_control(self):
        self.run_mutated(lambda ev: ev.__setitem__(
            "target_sha256", "0" * 64))

    def test_window_fde_offset_control(self):
        self.run_mutated(lambda ev: ev["function"].__setitem__(
            "fde_section_offset", "0x002daa21"))

    def test_window_next_fde_offset_control(self):
        self.run_mutated(lambda ev: ev["function"].__setitem__(
            "next_fde_section_offset", "0x002daa4d"))

    def test_window_prev_fde_offset_control(self):
        self.run_mutated(lambda ev: ev["function"].__setitem__(
            "prev_fde_section_offset", "0x002da9f5"))

    def test_window_cie_control(self):
        self.run_mutated(lambda ev: ev["function"].__setitem__(
            "fde_cie", "0x00000001"))

    def test_callee_start_control(self):
        self.run_mutated(lambda ev: ev["callee"].__setitem__(
            "start_va", "0x5656fd0"))

    def test_callee_sha_control(self):
        self.run_mutated(lambda ev: ev["callee"].__setitem__(
            "sha256", "0" * 64))

    def test_callee_length_control(self):
        self.run_mutated(lambda ev: ev["callee"].__setitem__("bytes", 216))

    def test_callee_padding_control(self):
        self.run_mutated(lambda ev: ev["callee"].__setitem__(
            "padding_bytes", 6))

    def test_callee_padding_hex_control(self):
        self.run_mutated(lambda ev: ev["callee"].__setitem__(
            "padding_hex", "cccccccccccccc"))

    def test_callee_sites_control(self):
        def mutate(ev):
            ev["callee"]["direct_e8_call_sites"] = (
                ev["callee"]["direct_e8_call_sites"][:-1])
        self.run_mutated(mutate)

    def test_caller_list_control(self):
        self.run_mutated(lambda ev: ev["incoming"].__setitem__(
            "direct_e8_callers", ["0x1234"]))

    def test_caller_fde_offset_control(self):
        self.run_mutated(lambda ev: ev["incoming"].__setitem__(
            "caller_fde_section_offset", "0x002d8c51"))

    def test_table_address_control(self):
        self.run_mutated(lambda ev: ev["rule"].__setitem__(
            "table_address", "0x918941"))

    def test_edge_flag_control(self):
        def mutate(ev):
            ev["rule"]["edges"][0]["flag"] = "0x1"
        self.run_mutated(mutate)

    def test_edge_n_control(self):
        def mutate(ev):
            ev["rule"]["edges"][1]["n"] = "0x2"
        self.run_mutated(mutate)

    def test_frames_mutation_control(self):
        self.run_mutated(
            lambda ev: None,
            frames_mutate=lambda text: text.replace(
                "pc=0000000005650a60..0000000005650ab8",
                "pc=0000000005650a60..0000000005650ab9"))


if __name__ == "__main__":
    unittest.main()
